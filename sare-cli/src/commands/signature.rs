use std::path::PathBuf;

use argh::FromArgs;

use crate::error::SareCLIError;

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum SignatureSubCommand {
    Generate(GenerateSignature),
    Verify(VerifySignature),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "generate")]
/// Generate new signature
struct GenerateSignature {
    #[argh(positional)]
    original_file: PathBuf,
    #[argh(positional)]
    sign_file: PathBuf,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "verify")]
/// Verify a signature
struct VerifySignature {
    #[argh(positional)]
    sign_file: PathBuf,
    #[argh(positional)]
    original_file: PathBuf,
}

#[derive(FromArgs)]
/// Generates/Verifies Signatures
#[argh(subcommand, name = "signature")]
pub struct SignatureCommand {
    #[argh(subcommand)]
    sub: SignatureSubCommand,
}

impl SignatureCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        match &self.sub {
            SignatureSubCommand::Generate(gen) => self.generate(&gen)?,
            SignatureSubCommand::Verify(verify) => self.verify(&verify)?,
        };
        Ok(())
    }

    fn generate(&self, gen: &GenerateSignature) -> Result<(), SareCLIError> {
        todo!()
    }

    fn verify(&self, verify: &VerifySignature) -> Result<(), SareCLIError> {
        todo!();
    }
}
