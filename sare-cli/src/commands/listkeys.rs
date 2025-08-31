use std::{
    fs::File,
    io::{BufReader, Read},
};

use argh::FromArgs;
use sare_lib::{
    certificate::Certificate,
    keys::{EncodableSecret, SharedPublicKey},
    CertificateFormat, Issuer,
};

use crate::{commands::revocation, common, db::SareDB, SareCLIError};

#[derive(FromArgs)]
/// Lists All SARE MasterKeys
#[argh(subcommand, name = "listkeys")]
pub struct ListKeysCommand {}

impl ListKeysCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;

        let sare_directory = common::prepare_sare_directory()?;

        for (master_key_id, key) in sare_db.key_associations {
            println!("Master Key ID: {}", master_key_id);
            println!("\tPublic Key ID: {}", key.public_key_id);

            let mut public_key_file = File::open(
                sare_directory
                    .join("public_keys")
                    .join(format!("PUB_{}.pem", key.public_key_id)),
            )?;

            let mut public_key_pem_content = String::new();
            public_key_file.read_to_string(&mut public_key_pem_content)?;

            let shared_public_key = SharedPublicKey::from_pem(public_key_pem_content)?;
            let validation_cert = shared_public_key.validation_certificate;

            if let Some(validation_data) = validation_cert {
                let expiry_date =
                    common::format_expiry_date(validation_data.certificate.expiry_date);

                println!(
                    "\t\tIssuer: {} Expiry: {}\n",
                    validation_data.certificate.issuer.to_string(),
                    expiry_date
                );
            } else {
                println!("\t\tValidation Certificate Not Found!\n",);
            }
        }

        Ok(())
    }
}
