use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use crate::format::encryption::*;
use crate::format::signature::*;
use crate::format::FormatError;
use crate::kdf::PKDFAlgorithm;

const MAGIC_BYTES: &[u8; 9] = b"CRYPTOPIA";

#[derive(Serialize, Deserialize)]
pub struct HeaderMetadataFormat {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    kem_metadata: Option<KEMMetadataFormat>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    signature_metadata: Option<SignatureMetadataFormat>,
    #[serde(flatten)]
    encryption_metadata: EncryptionMetadataFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

impl HeaderMetadataFormat {
    pub fn encode(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    pub fn decode(bson_metadata: &[u8]) -> Result<Self, FormatError> {
        let metadata = bson::from_slice::<HeaderMetadataFormat>(bson_metadata);

        // TODO: Needs Error Handling
        Ok(metadata.unwrap())
    }
}

pub struct HeaderFormat {
    version: u32,
    metadata: HeaderMetadataFormat,
    signature: Option<SignatureFormat>,
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
            let signature = signature.encode();
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
        let metadata = HeaderMetadataFormat::decode(metadata_bson)?;

        cursor += metadata_length as usize;

        let mut signature_length_le = Cursor::new(&header[cursor..cursor + 8]);
        cursor += 8;
        let signature_length = signature_length_le.read_u64::<LittleEndian>().unwrap();

        let mut signature: Option<SignatureFormat> = None;

        if signature_length > 0 {
            let bson_signature = &header[cursor..cursor + signature_length as usize];
            signature = Some(SignatureFormat::decode(bson_signature)?);
            cursor += 8;
        }

        Ok(HeaderFormat {
            version: version_number,
            metadata,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_METADATA: &str = "fQAAAAJlbmNyeXB0aW9uX2FsZ29yaXRobQAKAAAAQUVTMjU2R0NNAAJwa2RmX2FsZ29yaXRobQAHAAAAU2NyeXB0ABJwa2RmX3dvcmtmYWN0b3Jfc2NhbGUAMgAAAAAAAAACY29tbWVudAANAAAAVGVzdCBDb21tZW50AAA=";

    const ENCODED_HEADER: &str = "Q1JZUFRPUElBkQAAAAAAAAABAAAAfQAAAAAAAAB9AAAAAmVuY3J5cHRpb25fYWxnb3JpdGhtAAoAAABBRVMyNTZHQ00AAnBrZGZfYWxnb3JpdGhtAAcAAABTY3J5cHQAEnBrZGZfd29ya2ZhY3Rvcl9zY2FsZQAyAAAAAAAAAAJjb21tZW50AA0AAABUZXN0IENvbW1lbnQAAAAAAAAAAAAA";

    #[test]
    fn metadata_format_encode() {
        let pkdf_metadata = PKDFMetadataFormat {
            pkdf_algorithm: PKDFAlgorithm::Scrypt,
            pkdf_workfactor_scale: 50,
        };

        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: EncryptionAlgorithm::AES256GCM,
            pkdf_metadata: Some(pkdf_metadata),
            kem_metadata: None,
        };

        let metadata = HeaderMetadataFormat {
            kem_metadata: None,
            signature_metadata: None,
            encryption_metadata,
            comment: Some("Test Comment".to_string()),
        };

        assert_eq!(ENCODED_METADATA, &base64::encode(metadata.encode()));
    }

    #[test]
    fn header_format_encode() {
        let header = HeaderFormat {
            version: 1,
            metadata: HeaderMetadataFormat::decode(&base64::decode(ENCODED_METADATA).unwrap())
                .unwrap(),
            signature: None,
        };

        assert_eq!(ENCODED_HEADER, base64::encode(header.encode()));
    }

    #[test]
    fn header_format_decode() {
        let expected_header = HeaderFormat {
            version: 1,
            metadata: HeaderMetadataFormat::decode(&base64::decode(ENCODED_METADATA).unwrap())
                .unwrap(),
            signature: None,
        };

        let decoded_header =
            HeaderFormat::decode(&base64::decode(ENCODED_HEADER).unwrap()).unwrap();

        assert_eq!(expected_header.encode(), decoded_header.encode());
    }
}
