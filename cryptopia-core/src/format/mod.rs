use bson::{bson, Bson};
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

#[derive(Debug)]
pub enum FormatError {
    FailedToDecode,
}

//TODO: Define in encryption module
#[derive(Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
}

const MAGIC_BYTES: &[u8; 9] = b"CRYPTOPIA";

#[derive(Serialize, Deserialize)]
pub struct SignatureMetadataFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct KEMMetadataFormat {
    kem_algorithm: KEMAlgorithm,
    dh_algorithm: DHAlgorithm,
    hkdf_algorithm: HKDFAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionMetadataFormat {
    encryption_algorithm: EncryptionAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct PKDFMetadataFormat {
    pkdf_algorithm: PKDFAlgorithm,
    pkdf_workfactor_scale: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MetadataFormat {
    kem_metadata: Option<KEMMetadataFormat>,
    signature_metadata: Option<SignatureMetadataFormat>,
    encryption_metadata: EncryptionMetadataFormat,
    pkdf_metadata: Option<PKDFMetadataFormat>,
    comment: Option<String>,
}

impl MetadataFormat {
    pub fn encode(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    pub fn decode(bson_metadata: &[u8]) -> Result<Self, FormatError> {
        let metadata = bson::from_slice::<MetadataFormat>(bson_metadata);

        // TODO: Needs Error Handling
        Ok(metadata.unwrap())
    }
}

pub struct HeaderFormat {
    version: u32,
    metadata: MetadataFormat,
    signature: Option<Vec<u8>>,
}

impl HeaderFormat {
    pub fn encode(&self) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::new();
        header.extend(MAGIC_BYTES);

        let mut header_buffer: Vec<u8> = Vec::new();

        let version: [u8; 4] = self.version.to_le_bytes();
        header_buffer.extend(version);

        let metadata_bson = self.metadata.encode();

        let metadata_length: [u8; 8] = metadata_bson.len().to_le_bytes();
        header_buffer.extend(metadata_length);
        header_buffer.extend(metadata_bson);

        if let Some(signature) = &self.signature {
            let signature_length: [u8; 8] = signature.len().to_le_bytes();
            header_buffer.extend(signature_length);
            header_buffer.extend(signature);
        } else {
            let signature_length: [u8; 8] = 0_usize.to_le_bytes();
            header_buffer.extend(signature_length)
        }

        let header_length: [u8; 8] = header_buffer.len().to_le_bytes();
        header.extend(header_length);
        header.extend(header_buffer);

        header
    }

    pub fn decode(header: &[u8]) -> Result<Self, FormatError> {
        // TODO: Needs error handling and size checking of the header
        // TODO: Needs Optimization

        let mut cursor = 0;
        let magic_bytes = &header[cursor..MAGIC_BYTES.len()];
        cursor = MAGIC_BYTES.len();

        if magic_bytes != MAGIC_BYTES {
            return Err(FormatError::FailedToDecode);
        }

        let mut header_length_le = Cursor::new(&header[cursor..cursor + 8]);
        cursor += 8;
        let header_length = header_length_le.read_u64::<LittleEndian>().unwrap();

        if header.len() < header_length as usize + MAGIC_BYTES.len() + 8 {
            return Err(FormatError::FailedToDecode);
        }

        let mut version_le = Cursor::new(&header[cursor..cursor + 4]);
        cursor += 4;
        let version_number = version_le.read_u32::<LittleEndian>().unwrap();

        let mut metadata_length_le = Cursor::new(&header[cursor..cursor + 8]);
        cursor += 8;
        let metadata_length = metadata_length_le.read_u64::<LittleEndian>().unwrap();

        let metadata_bson = &header[cursor..cursor + metadata_length as usize];
        let metadata = MetadataFormat::decode(&metadata_bson)?;

        cursor += metadata_length as usize;

        let mut signature_length_le = Cursor::new(&header[cursor..cursor + 8]);
        cursor += 8;
        let signature_length = signature_length_le.read_u64::<LittleEndian>().unwrap();

        let mut signature: Option<Vec<u8>> = None;

        if signature_length > 0 {
            signature = Some((&header[cursor..cursor + signature_length as usize]).to_vec());
            cursor += 8;
        }

        Ok(HeaderFormat {
            version: version_number,
            metadata: metadata,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_METADATA: &str = "zQAAAAprZW1fbWV0YWRhdGEACnNpZ25hdHVyZV9tZXRhZGF0YQADZW5jcnlwdGlvbl9tZXRhZGF0YQApAAAAAmVuY3J5cHRpb25fYWxnb3JpdGhtAAoAAABBRVMyNTZHQ00AAANwa2RmX21ldGFkYXRhAD8AAAACcGtkZl9hbGdvcml0aG0ABwAAAFNjcnlwdAAScGtkZl93b3JrZmFjdG9yX3NjYWxlADIAAAAAAAAAAAJjb21tZW50AA0AAABUZXN0IENvbW1lbnQAAA==";

    const ENCODED_HEADER: &str = "Q1JZUFRPUElB4QAAAAAAAAABAAAAzQAAAAAAAADNAAAACmtlbV9tZXRhZGF0YQAKc2lnbmF0dXJlX21ldGFkYXRhAANlbmNyeXB0aW9uX21ldGFkYXRhACkAAAACZW5jcnlwdGlvbl9hbGdvcml0aG0ACgAAAEFFUzI1NkdDTQAAA3BrZGZfbWV0YWRhdGEAPwAAAAJwa2RmX2FsZ29yaXRobQAHAAAAU2NyeXB0ABJwa2RmX3dvcmtmYWN0b3Jfc2NhbGUAMgAAAAAAAAAAAmNvbW1lbnQADQAAAFRlc3QgQ29tbWVudAAAAAAAAAAAAAA=";

    #[test]
    fn metadata_format_encode() {
        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: EncryptionAlgorithm::AES256GCM,
        };

        let pkdf_metadata = PKDFMetadataFormat {
            pkdf_algorithm: PKDFAlgorithm::Scrypt,
            pkdf_workfactor_scale: 50,
        };

        let metadata = MetadataFormat {
            kem_metadata: None,
            signature_metadata: None,
            encryption_metadata,
            pkdf_metadata: Some(pkdf_metadata),
            comment: Some("Test Comment".to_string()),
        };

        assert_eq!(ENCODED_METADATA, &base64::encode(metadata.encode()));
    }

    #[test]
    fn header_format_encode() {
        let header = HeaderFormat {
            version: 1,
            metadata: MetadataFormat::decode(&base64::decode(ENCODED_METADATA).unwrap()).unwrap(),
            signature: None,
        };

        assert_eq!(ENCODED_HEADER, base64::encode(header.encode()));
    }

    #[test]
    fn header_format_decode() {
        let expected_header = HeaderFormat {
            version: 1,
            metadata: MetadataFormat::decode(&base64::decode(ENCODED_METADATA).unwrap()).unwrap(),
            signature: None,
        };

        let decoded_header =
            HeaderFormat::decode(&base64::decode(ENCODED_HEADER).unwrap()).unwrap();

        assert_eq!(expected_header.encode(), decoded_header.encode());
    }
}
