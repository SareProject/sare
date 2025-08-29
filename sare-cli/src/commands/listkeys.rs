use std::{fs::File, io::BufReader};

use argh::FromArgs;
use sare_lib::{certificate::Certificate, keys::EncodableSecret, CertificateFormat};

use crate::{commands::revocation, common, db::SareDB, SareCLIError};

#[derive(FromArgs)]
/// Lists All SARE MasterKeys
#[argh(subcommand, name = "listkeys")]
pub struct ListKeysCommand {}

impl ListKeysCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;

        let sare_directory = common::prepare_sare_directory()?;

        for (master_key_id, key) in sare_db.master_key_and_associated_key {
            println!("Master Key ID: {}", master_key_id);
            println!("\tPublic Key ID: {}", key.public_key_id);

            let revocation_cert_file = File::open(
                sare_directory
                    .join("revocations")
                    .join(format!("REVOC_{}.asc", key.revocation_certificate_id)),
            )?;

            let cert = Certificate::import(revocation_cert_file)?;

            let revocation_data = cert.certificate.get_revocation_data();

            let revocation_timestamp = if let Some(rev_data) = revocation_data {
                rev_data.revocation_date
            } else {
                None
            };

            let revocation_expiry_date = common::format_expiry_date(revocation_timestamp);

            println!(
                "\tRevocation Certificate ID: {} \n\t\tIssuer: {} Expiry: {}",
                key.revocation_certificate_id, cert.certificate.issuer, revocation_expiry_date
            );
            println!();
        }

        Ok(())
    }
}
