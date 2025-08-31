use std::{collections::HashMap, process::Output};

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};

use serde::{Deserialize, Serialize};

use crate::common;
use crate::error::SareCLIError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SareDBAssociatedKey {
    pub public_key_id: String,
    pub revocation_certificate_id: String,
}

impl SareDBAssociatedKey {
    pub fn new(public_key_id: &str, revocation_certificate_id: &str) -> Self {
        SareDBAssociatedKey {
            public_key_id: public_key_id.to_ascii_uppercase(),
            revocation_certificate_id: revocation_certificate_id.to_ascii_uppercase(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SareDBRecipient {
    fullchain_public_key_id: String,
    verification_certificate_id: String,
    comment: String,
    date_added: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SareDB {
    #[serde(default)]
    pub version: u32,
    #[serde(flatten)]
    pub master_key_and_associated_key: HashMap<String, SareDBAssociatedKey>,
    #[serde(default)]
    pub recipients: Vec<SareDBRecipient>,
}

impl SareDB {

    pub fn empty() -> Self {
        SareDB::default()
    }

    pub fn add_key_association(&mut self, master_key_id: &str, associated_key: SareDBAssociatedKey) {
        self.master_key_and_associated_key
            .insert(master_key_id.to_ascii_uppercase(), associated_key);
    }

    pub fn add_recipient(&mut self, recipient: SareDBRecipient) {
        self.recipients.push(recipient);
    }

    pub fn import_from_json_file() -> Result<Self, SareCLIError> {
        let sare_directory = common::prepare_sare_directory()?;
        let db_path = sare_directory.join(common::DB_FILE);

        if let Ok(file) = File::open(&db_path) {
            let reader = BufReader::new(file);
            let sare_db = serde_json::from_reader(reader)?;
            Ok(sare_db)
        } else {
            Ok(SareDB::empty())
        }
    }

    pub fn save_to_json_file(&self) -> Result<(), SareCLIError> {
        let sare_directory = common::prepare_sare_directory()?;
        let db_path = sare_directory.join(common::DB_FILE);

        let json_output = serde_json::to_string_pretty(&self)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(db_path)?;
        file.write_all(json_output.as_bytes())?;

        Ok(())
    }

    pub fn get_key_association(&self, master_key_id: &str) -> Option<&SareDBAssociatedKey> {
        self.master_key_and_associated_key
            .get(&master_key_id.to_ascii_uppercase())
    }

    pub fn list_recipients(&self) -> &[SareDBRecipient] {
        &self.recipients
    }

}


impl Default for SareDB {
    fn default() -> Self {
        SareDB {
            version: 1, 
            master_key_and_associated_key: HashMap::new(),
            recipients: Vec::new(),
        }
    }
}