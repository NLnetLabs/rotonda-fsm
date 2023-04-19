//! Passive BGP listener.

use bytes::Bytes;
use clap::Parser;
use env_logger::Env;
#[allow(unused_imports)]
use log::{debug, info, warn, error};
use rotonda_fsm::bgp::session::{Config, Session as BgpSession};
use routecore::bgp::message::update::UpdateMessage;
use std::net::IpAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;

use rotonda_fsm::util::to_pcap;

#[derive(Copy, Clone)]
struct BgpSpeaker {
    //sessions: Vec<&'a BgpSession>,
    local_addr: IpAddr,
    local_port: u16,
    local_asn: u32,
    bgp_id: [u8; 4],
}

impl BgpSpeaker {
    fn new(args: Args) -> Self {
        Self { 
            //sessions: vec!(),
            local_addr: args.addr,
            local_port: args.port,
            local_asn: args.asn,
            bgp_id: args.asn.to_be_bytes()
        }
    }

    //fn add_session<'s: 'a>(&mut self, session: &'a BgpSession) {
    //    self.sessions.push(session);
    //}

    async fn run(self) {
        let listener = TcpListener::bind((self.local_addr, self.local_port)).await.unwrap();
        info!("listening on {}:{}", self.local_addr, self.local_port);
        loop {
            let (socket, remote_ip) = listener.accept().await.unwrap();
            info!("BgpSpeaker::run: connection from {}", remote_ip);
            let config = Config::new(
                self.local_asn.into(),
                self.bgp_id,
                remote_ip.ip()
            );
            let (tx, rx) = mpsc::channel(100);
            if let Ok(session) = BgpSession::try_for_connection(
                config, socket, tx
            ) {
                tokio::spawn(async {
                    session.process().await;
                });
                tokio::spawn(async move {
                    self.handle_updates(rx).await;
                });
            } else {
                error!("Could not set up BGP session");
            }
        }
    }

    async fn handle_updates(self, mut rx: mpsc::Receiver<UpdateMessage<Bytes>>) {
        while let Some(upd) = rx.recv().await {
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
}

#[tokio::main]
async fn main() {
    
    env_logger::Builder::from_env(
        Env::default().default_filter_or("warn")
    ).init();

    let args = Args::parse();

    info!("starting bgpsink");

    let speaker = BgpSpeaker::new(args);
    tokio::select! {
        _ = speaker.run() => {},
        _ = signal::ctrl_c() => {
            info!("CTRL+C, houdoe");
        }
    }
}
