use std::{
    fs::{self, File},
    path::PathBuf,
};

use argh::FromArgs;
use sare_lib::{
    certificate::SignatureFormat,
    keys::{EncodablePublic, MasterKey},
};
use sare_lib::{signing::Signing, SignatureHeaderFormat};
use secrecy::ExposeSecret;

use crate::{commands::signature, common, db::SareDB, error::SareCLIError};

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
    /// masterkey id
    #[argh(option)]
    masterkey_id: Option<String>,
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
        let masterkey = common::get_master_key_from_cli(&gen.masterkey_id)?;

        let sign_engine = Signing::new(masterkey);

        let message = fs::read(&gen.original_file)?;

        let signature = sign_engine.sign_detached(&message);

        let bson_signature = signature.encode_with_magic_byte();

        fs::write(&gen.sign_file, bson_signature)?;

        println!("Signature successfully generated!");
        Ok(())
    }

    fn verify(&self, verify: &VerifySignature) -> Result<(), SareCLIError> {
        let signed_message = fs::read(&verify.sign_file)?;
        let original_message = fs::read(&verify.original_file)?;

        let signature_header_format =
            SignatureHeaderFormat::decode_with_magic_byte(&signed_message)?;
        let signature_format = &signature_header_format.signature;
        let is_verified = Signing::verify_detached(&signature_header_format, &original_message)?;

        if is_verified {
            println!("Verified: yes");
        } else {
            println!("Verified: no");
        };

        println!(
            "Signed by: {}",
            hex::encode_upper(signature_format.fullchain_fingerprint)
        );

        Ok(())
    }
}
