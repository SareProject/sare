use argh::FromArgs;

mod commands;
pub mod common;
pub mod error;

use crate::commands::keygen::KeyGenCommand;
use error::SareCLIError;

#[derive(FromArgs)]
/// Safe At Rest Encryption. A tool to stay Safe in the Quantum Age
struct SareCli {
    #[argh(subcommand)]
    cmd: SubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommand {
    KeyGen(KeyGenCommand),
}

fn main() -> Result<(), SareCLIError> {
    pretty_env_logger::init();
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    match args.cmd {
        SubCommand::KeyGen(keygen_command) => keygen_command.execute(),
    }
}
