//! Passive BGP listener.

use bytes::Bytes;
use clap::Parser;
use env_logger::Env;
#[allow(unused_imports)]
use log::{debug, info, warn, error};
use rotonda_fsm::bgp::session::{Command, Config, Session as BgpSession, Message};
use routecore::bgp::message::{
    update::UpdateMessage,
    notification::NotificationMessage
};
use std::net::IpAddr;
use tokio::net::TcpListener;
use tokio::{signal, signal::unix::SignalKind};
use tokio::sync::mpsc;


use std::path::PathBuf;
use std::fs::File;
use std::io::Write;

use rotonda_fsm::util::to_pcap;

struct BgpSpeaker {
    local_addr: IpAddr,
    local_port: u16,
    local_asn: u32,
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
            //sessions: vec!(),
            local_addr: args.addr,
            local_port: args.port,
            local_asn: args.asn,
            bgp_id: args.asn.to_be_bytes(),
            pcap_fh
        }
    }

    async fn run(self) {
        let listener = TcpListener::bind((self.local_addr, self.local_port)).await.unwrap();
        info!("listening on {}:{}", self.local_addr, self.local_port);
        loop {
            debug!("awaiting accept()...");
            let (socket, remote_ip) = listener.accept().await.unwrap();
            info!("BgpSpeaker::run: connection from {}", remote_ip);
            let config = Config::new(
                self.local_asn.into(),
                self.bgp_id,
                remote_ip.ip()
            );
            let (tx, rx) = mpsc::channel(100);
            let fh = self.pcap_fh.as_ref().map(|f| f.try_clone().unwrap());
            if let Ok((session, tx_commands)) = BgpSession::try_for_connection(
                config, socket, tx
            ) {
                tokio::spawn( async move {
                    let mut p = Processor::new(rx,tx_commands, fh);
                    p.process(session).await;
                });
            } else {
                error!("Could not set up BGP session");
            }
        }
    }
}

struct Processor {
    rx: mpsc::Receiver<Message>,
    commands: mpsc::Sender<Command>,
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
        if let Some(as_path) = upd.aspath() {
            info!("got path {as_path} for {} {} prefix(es)",
            upd.nlris().iter().count(),
            upd.nlris().afi(),
            );
            if as_path.segments().count() == 0 {
                warn!("empty as_path!\n{}", to_pcap(&upd));
            }
            //for n in upd.nlris().iter() {
            //    info!("got route {as_path} {n}");
            //}
        }
        for w in upd.withdrawals().iter() {
            info!("withdraw: {w}");
        }
    }

    fn process_notification(&mut self, ntf: NotificationMessage<Bytes>) {
        self.log_pcap(&ntf);
    }

    pub(crate) fn new(
        rx: mpsc::Receiver<Message>,
        commands: mpsc::Sender<Command>,
        pcap_fh: Option<File>,
    ) -> Processor {
        Processor { rx, commands, pcap_fh }
    }

    async fn process(
        &mut self,
        session: BgpSession,
    ) {
        debug!("Processor::process");
        tokio::spawn(async {
            session.process().await;
        });

        let commands2 = self.commands.clone();
        tokio::spawn(async move {
            let mut print_stats = tokio::time::interval(
                std::time::Duration::from_secs(5)
            );
            print_stats.tick().await; // ticks immediately
            loop {
                print_stats.tick().await;
                debug!("in process stat interval loop");
                let cmd = Command::Attributes;
                let _ = commands2.send(cmd).await;
            }
        });

        while let Some(msg) = self.rx.recv().await {
            match msg {
                Message::UpdateMessage(pdu) => self.process_update(pdu),
                Message::NotificationMessage(pdu) => self.process_notification(pdu),
                Message::Attributes(attr) => {
                    info!("got attributes: state: {:?}", attr.state())
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

    let speaker = BgpSpeaker::new(args);
    let mut sighup = signal::unix::signal(SignalKind::hangup())?;
        tokio::select! {
            _ = speaker.run() => {},
            _ = sighup.recv() => {
                info!("SIGHUP, printing stats");
                // TODO sighup needs to be handled elsewhere, in Processor?
            }
            _ = signal::ctrl_c() => {
                info!("CTRL+C, houdoe");
            }
        };
    Ok(())
}
