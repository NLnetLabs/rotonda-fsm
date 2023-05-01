use tokio::sync::{mpsc, oneshot};

type CliMessage = (String, oneshot::Sender<String>);
//type CliSender = mpsc::Sender<CliMessage>;
pub type CliReceiver = mpsc::Receiver<CliMessage>;

#[derive(Copy, Clone, Debug)]
pub enum CliCommand {
    Stats,
    Reconnect,
    Exit,
}

pub fn parse_cli(cmd: &str) -> Option<CliCommand> {
    match cmd {
        "stats" => Some(CliCommand::Stats),
        "reconnect" => Some(CliCommand::Reconnect),
        "exit"|"quit"|"q" => Some(CliCommand::Exit),
        _ => None
    }
}

