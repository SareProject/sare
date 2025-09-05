use std::collections::HashMap;
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
        Self {
            public_key_id: public_key_id.to_ascii_uppercase(),
            revocation_certificate_id: revocation_certificate_id.to_ascii_uppercase(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SareDBRecipient {
    pub fullchain_fingerprint: String,
    pub comment: Option<String>,
    pub date_added: u64,
}

impl SareDBRecipient {
    pub fn new(fullchain_fingerprint: &str, comment: Option<String>) -> Self {
        Self {
            fullchain_fingerprint: fullchain_fingerprint.to_ascii_uppercase(),
            comment,
            date_added: common::get_now_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SareDB {
    #[serde(default)]
    pub version: u32,
    pub key_associations: HashMap<String, SareDBAssociatedKey>,
    #[serde(default)]
    pub recipients: HashMap<String, SareDBRecipient>,
}

impl SareDB {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds or updates a master key association
    pub fn add_key_association(
        &mut self,
        master_key_id: &str,
        associated_key: SareDBAssociatedKey,
    ) {
        let key_id = master_key_id.to_ascii_uppercase();
        self.key_associations.insert(key_id.clone(), associated_key);
        println!("🔑 Added/Updated master key association: {}", key_id);
    }

    /// Adds a recipient to the DB
    pub fn add_recipient(&mut self, recipient_id: String, recipient: SareDBRecipient) {
        self.recipients.insert(recipient_id.clone(), recipient);
        println!("📬 Added recipient: {}", recipient_id);
    }

    /// Imports the DB from JSON file or returns an empty DB
    pub fn import_from_json_file() -> Result<Self, SareCLIError> {
        let sare_directory = common::prepare_sare_directory()?;
        let db_path = sare_directory.join(common::DB_FILE);

        if let Ok(file) = File::open(&db_path) {
            let reader = BufReader::new(file);
            let db = serde_json::from_reader(reader)?;
            println!("✅ Loaded DB from {:?}", db_path);
            Ok(db)
        } else {
            println!("⚠️  DB file not found, creating a new empty DB");
            Ok(Self::empty())
        }
    }

    /// Saves the DB to JSON file
    pub fn save_to_json_file(&self) -> Result<(), SareCLIError> {
        let sare_directory = common::prepare_sare_directory()?;
        let db_path = sare_directory.join(common::DB_FILE);

        let json_output = serde_json::to_string_pretty(&self)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&db_path)?;
        file.write_all(json_output.as_bytes())?;

        println!("💾 DB saved to {:?}", db_path);
        Ok(())
    }

    /// Retrieves an associated key by master key id
    pub fn get_key_association(&self, master_key_id: &str) -> Option<&SareDBAssociatedKey> {
        self.key_associations
            .get(&master_key_id.to_ascii_uppercase())
    }

    /// Returns all recipients
    pub fn list_recipients(&self) -> &HashMap<String, SareDBRecipient> {
        &self.recipients
    }
}

impl Default for SareDB {
    fn default() -> Self {
        Self {
            version: 1,
            key_associations: HashMap::new(),
            recipients: HashMap::new(),
        }
    }
}
