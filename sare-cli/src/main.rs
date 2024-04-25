use argh::FromArgs;

#[derive(FromArgs)]
/// Safe At Rest Encryption. A tool to stay Safe in the Quantum Age
struct SareCli {
    #[argh(subcommand)]
    cmd: SubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommand {
    KeyGen(KeyGen),
}

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "keygen")]
struct KeyGen {}

fn generate_key_pair() -> Result<(), String> {
    todo!();
    //let output_file = File::create(output_path);
}

fn main() {
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    match args.cmd {
        SubCommand::KeyGen(_) => {
            if let Err(err) = generate_key_pair() {
                eprintln!("Error: {}", err);
            } else {
                println!("Key pair generated!");
            }
        }
    }
}
