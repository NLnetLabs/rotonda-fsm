//! Passive BGP listener.

use bytes::Bytes;
use clap::Parser;
use env_logger::Env;
#[allow(unused_imports)]
use log::{debug, info, warn, error};
use rotonda_fsm::bgp::session::{
    BasicConfig,
    BgpConfig,
    Command,
    DisconnectReason,
    Message,
    Session as BgpSession,
};
use routecore::bgp::message::{
    update::UpdateMessage,
    notification::NotificationMessage
};
use std::net::IpAddr;
use tokio::net::TcpListener;
use tokio::{signal, signal::unix::SignalKind};
use tokio::sync::{mpsc, Mutex, oneshot};


use std::path::PathBuf;
use std::fs::File;
use std::io::Write;

use std::sync::Arc;

use rotonda_fsm::util::to_pcap;


mod cli;
mod stats;

use cli::{CliCommand, CliMessage, CliReceiver, parse_cli};
use stats::StatsReport;



struct BgpSpeaker {
    // channels to session
    sessions: Arc<Mutex<Vec<mpsc::Sender<Command>>>>,
    local_addr: IpAddr,
    local_port: u16,
    local_asn: u32,
    remote_asn: u32,
    bgp_id: [u8; 4],
    pcap_fh: Option<File>,
}

impl BgpSpeaker {
    fn new(args: Args) -> Self {
        let pcap_fh = if let Some(path) = args.pcap_log {
            std::fs::OpenOptions::new().create(true).append(true).open(path).ok()
        } else {
            None
        };
        Self { 
            sessions: Arc::new(Mutex::new(vec!())),
            local_addr: args.addr,
            local_port: args.port,
            local_asn: args.asn,
            remote_asn: args.remote_asn,
            bgp_id: args.asn.to_be_bytes(),
            pcap_fh,
        }
    }

    async fn gather_stats(
        shared_sessions: Arc<Mutex<Vec<mpsc::Sender<Command>>>>
    ) -> StatsReport {
        let mut responses = vec!();
        let shared_sessions = shared_sessions.lock().await;
        for s in &*shared_sessions {
            let (tx, rx) = oneshot::channel();
            let to_send = Command::GetAttributes{resp: tx};
            responses.push(rx);
            let _ = s.send(to_send).await;
        }
        let mut overall_stats = StatsReport::new();
        for rx in responses {
            if let Ok(stats) = rx.await {
                //debug!("got response {:?}", stats);
                overall_stats += stats;
            }
        }
        overall_stats
    }

    async fn read_cli(
        shared_sessions: Arc<Mutex<Vec<mpsc::Sender<Command>>>>,
        mut cli: CliReceiver
    ) {
        'outer: loop {
            while let Some((cli_cmd, resp_rx)) = cli.recv().await {
                if let Some(cmd) = parse_cli(&cli_cmd)  {
                    match cmd {
                        CliCommand::Stats => {
                            let stats = Self::gather_stats(shared_sessions.clone());
                            info!("{:?}", stats.await);
                        }
                        CliCommand::Reconnect => { todo!() }
                        CliCommand::Exit => {
                            debug!("got Exit from CLI, emitting Disconnect commands to sessions");
                            for s in &*shared_sessions.lock().await {
                                let _ = s.send(Command::Disconnect(DisconnectReason::Shutdown)).await;
                            }
                            break 'outer;
                        }
                    };
                    let _ = resp_rx.send(
                        format!("got {cli_cmd} in run()!")
                        );
                } else {
                    println!("unknown command '{cli_cmd}'");
                }
            }
        }
    }

    async fn run(self, cli: CliReceiver) {
        let listener = TcpListener::bind((self.local_addr, self.local_port)).await.unwrap();
        info!("listening on {}:{}", self.local_addr, self.local_port);
        let cli_handle = Self::read_cli(self.sessions.clone(), cli);

        let accept_handle = tokio::spawn(async move {
            loop {
                if let Ok((socket, remote_ip)) = listener.accept().await  {
                    info!("BgpSpeaker::run: connection from {}", remote_ip);

                    let config = BasicConfig::new(
                        self.local_asn.into(),
                        self.bgp_id,
                        remote_ip.ip(),
                        self.remote_asn.into(),
                        None,
                    );

                    let socket_status = tokio::join!(
                        socket.writable(),
                        socket.readable()
                    );

                    debug!("{:?}", socket_status);

                    // tx: sender of PDUs/Stats, moved to Session
                    // rx: receive PDUs/Stats from Session 
                    let (tx, rx) = mpsc::channel::<Message>(100);
                    let fh = self.pcap_fh.as_ref().map(|f| f.try_clone().unwrap());

                    // returned tx_commands: send commands to Session
                    if let Ok((session, tx_commands)) = BgpSession::try_for_connection(
                        config, socket, tx
                        ).await {
                        let tx_commands_for_speaker = tx_commands.clone();
                        let mut sessions = self.sessions.lock().await;
                        sessions.push(tx_commands_for_speaker);
                        tokio::spawn( async move {
                            // rx: receive PDUs/Stats from Session
                            // tx_commands: send Commands to Session  
                            let mut p = Processor::new(rx, tx_commands, fh);
                            p.process(session).await;
                        });
                    } else {
                        error!("Could not set up BGP session");
                    }
                }
            }
        });

        tokio::select!{
            _ = cli_handle => {debug!("end of run because CLI is done")},
            _ = accept_handle => {debug!("end of run because accept() is done")},
        }
    }
}

struct Processor {
    // from Session
    rx: mpsc::Receiver<Message>,
    // to session
    _commands: mpsc::Sender<Command>,
    pcap_fh: Option<File>,
}

impl Processor {
    fn log_pcap<T: AsRef<[u8]>>(&mut self, msg: &T) {
        if let Some(ref mut f) = self.pcap_fh {
            let _ = writeln!(f, "{}", to_pcap(msg));
            let _ = f.flush();
        }
    }

    fn process_update(&mut self, upd: UpdateMessage<Bytes>) {
        self.log_pcap(&upd);
        if let Ok(Some(mp)) = upd.mp_announcements() {
            info!("update for {}/{}, {} announcements", 
                mp.afi(), mp.safi(),
                mp.iter().count(),
            );
        }
    }

    fn process_notification(&mut self, ntf: NotificationMessage<Bytes>) {
        self.log_pcap(&ntf);
    }

    pub fn new(
        rx: mpsc::Receiver<Message>,
        _commands: mpsc::Sender<Command>,
        pcap_fh: Option<File>,
    ) -> Processor {
        Processor { rx, _commands, pcap_fh }
    }

    async fn process<C: BgpConfig>(
        &mut self,
        mut session: BgpSession<C>,
    ) {
        debug!("Processor::process");

        loop {
            tokio::select! {
                _ = session.tick() => { },
                Some(msg) = self.rx.recv() => {
                    match msg {
                        Message::UpdateMessage(pdu) => self.process_update(pdu),
                        Message::NotificationMessage(pdu) => self.process_notification(pdu),
                        // TODO this should go via a oneshot back to an emitted CLI
                        // command
                        Message::Attributes(attr) => {
                            info!("got attributes: state: {:?}", attr.state())
                        }
                        Message::SessionNegotiated(config) => {
                            info!("Session negotiated: {:#?}", config);
                        }
                        Message::ConnectionLost(socket) => {
                            info!("connection lost: {}", socket);
                            break;
                        }
                    }
                }


            }
        }

    }
}


#[derive(Parser)]
struct Args {
    /// Address to listen on.
    #[arg(short)]
    addr: IpAddr,

    /// Port to listen on.
    #[arg(short, default_value_t = 179)]
    port: u16,

    /// Local ASN.
    #[arg(long)]
    asn: u32,

    /// Remote ASN.
    #[arg(long)]
    remote_asn: u32,

    /// File to log hexdumps of packets.
    #[arg(long)]
    pcap_log: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    env_logger::Builder::from_env(
        Env::default().default_filter_or("warn")
    ).init();

    let args = Args::parse();

    info!("starting bgpsink");


    // process user commands from interactive cli
    // TODO move into cli.rs
    let (tx, rx) = mpsc::channel::<CliMessage>(4);
    let tx2 = tx.clone();
    let cli = tokio::spawn( async move  {
        while !tx2.is_closed() {
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer).unwrap();
            let cmd = buffer.trim();

            if !cmd.is_empty() {
                let (resp_tx, resp_rx) = oneshot::channel();
                let _ = tx2.send((cmd.to_string(), resp_tx)).await;
                if let Ok(_resp) = resp_rx.await {
                    //debug!("got response: {}", resp);
                } else {
                    // also triggered when we do not actually process the cli
                    // command, simply because it is not a recognized command
                    //debug!("got an error?");
                }
            }
        }
    });

    let cli_ah = cli.abort_handle();

    let speaker = BgpSpeaker::new(args);
    let mut sighup = signal::unix::signal(SignalKind::hangup())?;
    tokio::select! {
        _ = speaker.run(rx) => {
            debug!("speaker.run done");
            //cli_ah.abort();
        },
        _ = sighup.recv() => {
            info!("SIGHUP, printing stats");
            // TODO sighup needs to be handled elsewhere, in Processor?
        }
        _ = signal::ctrl_c() => {
            info!("CTRL+C, houdoe");
            cli_ah.abort();
        }
    };

    Ok(())
}
