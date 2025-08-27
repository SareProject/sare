use std::{collections::HashMap, process::Output};

use std::fs::File;
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
pub struct SareDB {
    #[serde(flatten)]
    pub master_key_and_associated_key: HashMap<String, SareDBAssociatedKey>,
}

impl SareDB {
    pub fn new(master_key_id: &str, associated_key: SareDBAssociatedKey) -> Self {
        let mut master_key_and_associated_key = HashMap::new();
        master_key_and_associated_key.insert(master_key_id.to_ascii_uppercase(), associated_key);

        SareDB {
            master_key_and_associated_key,
        }
    }

    pub fn import_from_json_file() -> Result<Self, SareCLIError> {
        let sare_directory = common::prepare_sare_directory()?;

        let db_file = File::open(sare_directory.join(common::DB_FILE))?;
        let file_reader = BufReader::new(db_file);
        let sare_db = serde_json::from_reader(file_reader)?;

        Ok(sare_db)
    }

    pub fn insert_to_json_file(&self) -> Result<(), SareCLIError> {
        use std::collections::HashMap;
        use std::fs::OpenOptions;
        use std::io::{BufReader, Write};

        let sare_directory = common::prepare_sare_directory()?;
        let db_path = sare_directory.join(common::DB_FILE);

        let mut merged_db = if let Ok(file) = File::open(&db_path) {
            let reader = BufReader::new(file);
            serde_json::from_reader(reader)?
        } else {
            SareDB {
                master_key_and_associated_key: HashMap::new(),
            }
        };

        merged_db
            .master_key_and_associated_key
            .extend(self.master_key_and_associated_key.clone());

        let json_output = serde_json::to_string_pretty(&merged_db)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(db_path)?;
        file.write_all(json_output.as_bytes())?;

        Ok(())
    }
}
