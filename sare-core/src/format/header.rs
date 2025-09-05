use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use crate::format::encryption::*;
use crate::format::signature::*;
use crate::format::{ErrSection, FormatError};

use super::EncodablePublic;

const MAGIC_BYTES: &[u8; 9] = b"SARECRYPT";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderMetadataFormat {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub signature_metadata: Option<SignatureMetadataFormat>,
    #[serde(flatten)]
    pub encryption_metadata: EncryptionMetadataFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
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

#[derive(Debug)]
pub struct HeaderFormat {
    pub version: u32,
    pub metadata: HeaderMetadataFormat,
    pub signature: Option<SignatureFormat>,
}

impl HeaderFormat {
    fn verify_magic_bytes(header: &[u8], cursor: &mut usize) -> Result<bool, FormatError> {
        let magic_bytes = &header[*cursor..*cursor + MAGIC_BYTES.len()];
        *cursor += MAGIC_BYTES.len();
        Ok(magic_bytes == MAGIC_BYTES)
    }

    fn read_u64(header: &[u8], cursor: &mut usize) -> Result<u64, FormatError> {
        let mut rdr = Cursor::new(&header[*cursor..*cursor + 8]);
        *cursor += 8;
        rdr.read_u64::<LittleEndian>()
            .map_err(|_| FormatError::FailedToDecode(ErrSection::HEADER))
    }

    fn read_u32(header: &[u8], cursor: &mut usize) -> Result<u32, FormatError> {
        let mut rdr = Cursor::new(&header[*cursor..*cursor + 4]);
        *cursor += 4;
        rdr.read_u32::<LittleEndian>()
            .map_err(|_| FormatError::FailedToDecode(ErrSection::HEADER))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::new();
        header.extend(MAGIC_BYTES);

        let mut header_buffer: Vec<u8> = Vec::new();

        header_buffer.extend(&self.version.to_le_bytes());

        let metadata_bson = self.metadata.encode();
        header_buffer.extend(&(metadata_bson.len() as u64).to_le_bytes());
        header_buffer.extend(metadata_bson);

        if let Some(signature) = &self.signature {
            let signature_bson = signature.encode_bson();
            header_buffer.extend(&(signature_bson.len() as u64).to_le_bytes());
            header_buffer.extend(signature_bson);
        } else {
            header_buffer.extend(&0u64.to_le_bytes());
        }

        header.extend(&(header_buffer.len() as u64).to_le_bytes());
        header.extend(header_buffer);

        header
    }

    pub fn decode(header: &[u8]) -> Result<Self, FormatError> {
        let mut cursor = 0;

        if !Self::verify_magic_bytes(header, &mut cursor)? {
            return Err(FormatError::FailedToDecode(ErrSection::HEADER));
        }

        let header_length = Self::read_u64(header, &mut cursor)?;

        if header.len() < (MAGIC_BYTES.len() + 8 + header_length as usize) {
            return Err(FormatError::FailedToDecode(ErrSection::HEADER));
        }

        let version = Self::read_u32(header, &mut cursor)?;
        let metadata_length = Self::read_u64(header, &mut cursor)?;

        let metadata_bson = &header[cursor..cursor + metadata_length as usize];
        let metadata = HeaderMetadataFormat::decode(metadata_bson)?;
        cursor += metadata_length as usize;

        let signature_length = Self::read_u64(header, &mut cursor)?;
        let signature = if signature_length > 0 {
            let signature_bson = &header[cursor..cursor + signature_length as usize];
            cursor += signature_length as usize;
            Some(SignatureFormat::decode_bson(signature_bson)?)
        } else {
            None
        };

        Ok(HeaderFormat {
            version,
            metadata,
            signature,
        })
    }

    pub fn peek_header_seek<R: Read + Seek>(reader: &mut R) -> std::io::Result<Vec<u8>> {
        let pos = reader.stream_position()?; // save current position

        let mut magic = [0u8; 9];
        reader.read_exact(&mut magic)?;

        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let header_len = u64::from_le_bytes(len_buf) as usize;

        let mut header_buf = vec![0u8; header_len];
        reader.read_exact(&mut header_buf)?;

        reader.seek(SeekFrom::Start(pos))?; // rewind

        let mut full = Vec::with_capacity(magic.len() + 8 + header_buf.len());
        full.extend_from_slice(&magic);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&header_buf);

        Ok(full)
    }

    pub fn separate_header<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
        let mut magic = [0u8; MAGIC_BYTES.len()];
        reader.read_exact(&mut magic)?;

        let mut len_buf = [0u8; 8];
        reader.read_exact(&mut len_buf)?;
        let header_len = u64::from_le_bytes(len_buf) as usize;

        let mut header_buf = vec![0u8; header_len];
        reader.read_exact(&mut header_buf)?;

        let mut full_header = Vec::with_capacity(magic.len() + len_buf.len() + header_buf.len());
        full_header.extend_from_slice(&magic);
        full_header.extend_from_slice(&len_buf);
        full_header.extend_from_slice(&header_buf);

        Ok(full_header)
    }

    pub fn is_asymmetric(&self) -> bool {
        let metadata = &self.metadata;

        metadata.encryption_metadata.kem_metadata.is_some()
    }

    pub fn is_signed(&self) -> bool {
        let metadata = &self.metadata;

        metadata.signature_metadata.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::EncryptionAlgorithm;
    use crate::kdf::PKDFAlgorithm;
    use base64::prelude::*;

    const ENCODED_METADATA: &str = "ygAAAAJlbmNyeXB0aW9uX2FsZ29yaXRobQAKAAAAQUVTMjU2R0NNAARwa2RmX3NhbHQAPQAAABAwAAAAAAAQMQAAAAAAEDIAAAAAABAzAAAAAAAQNAAAAAAAEDUAAAAAABA2AAAAAAAQNwAAAAAAAANwa2RmX2FsZ29yaXRobQAvAAAABFNjcnlwdAAiAAAAEDAACgAAABIxAAgAAAAAAAAAEjIACgAAAAAAAAAAAAJjb21tZW50AA0AAABUZXN0IENvbW1lbnQAAA==";

    const ENCODED_HEADER: &str = "U0FSRUNSWVBU3gAAAAAAAAABAAAAygAAAAAAAADKAAAAAmVuY3J5cHRpb25fYWxnb3JpdGhtAAoAAABBRVMyNTZHQ00ABHBrZGZfc2FsdAA9AAAAEDAAAAAAABAxAAAAAAAQMgAAAAAAEDMAAAAAABA0AAAAAAAQNQAAAAAAEDYAAAAAABA3AAAAAAAAA3BrZGZfYWxnb3JpdGhtAC8AAAAEU2NyeXB0ACIAAAAQMAAKAAAAEjEACAAAAAAAAAASMgAKAAAAAAAAAAAAAmNvbW1lbnQADQAAAFRlc3QgQ29tbWVudAAAAAAAAAAAAAA=";

    #[test]
    fn metadata_format_encode() {
        let pkdf_metadata = PKDFMetadataFormat {
            pkdf_salt: vec![0, 0, 0, 0, 0, 0, 0, 0],
            pkdf_algorithm: PKDFAlgorithm::Scrypt(10, 8, 10),
        };

        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: EncryptionAlgorithm::AES256GCM,
            nonce: None,
            pkdf_metadata: Some(pkdf_metadata),
            kem_metadata: None,
        };

        let metadata = HeaderMetadataFormat {
            signature_metadata: None,
            encryption_metadata,
            comment: Some("Test Comment".to_string()),
        };

        assert_eq!(ENCODED_METADATA, &BASE64_STANDARD.encode(metadata.encode()));
    }

    #[test]
    fn header_format_encode() {
        let header = HeaderFormat {
            version: 1,
            metadata: HeaderMetadataFormat::decode(
                &BASE64_STANDARD.decode(ENCODED_METADATA).unwrap(),
            )
            .unwrap(),
            signature: None,
        };

        assert_eq!(ENCODED_HEADER, BASE64_STANDARD.encode(header.encode()));
    }

    #[test]
    fn header_format_decode() {
        let expected_header = HeaderFormat {
            version: 1,
            metadata: HeaderMetadataFormat::decode(
                &BASE64_STANDARD.decode(ENCODED_METADATA).unwrap(),
            )
            .unwrap(),
            signature: None,
        };

        let decoded_header =
            HeaderFormat::decode(&BASE64_STANDARD.decode(ENCODED_HEADER).unwrap()).unwrap();

        assert_eq!(expected_header.encode(), decoded_header.encode());
    }
}
