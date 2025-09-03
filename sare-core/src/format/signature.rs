use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::format::error::{ErrSection, FormatError};
use crate::format::{signature, EncodablePublic};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use byteorder::{LittleEndian, ReadBytesExt};

pub const SIGNATURE_TAG: &str = "SARE MESSAGE";
pub const SIGNATURE_MAGIC_BYTE: &[u8; 8] = b"SARESIGN";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadataFormat {
    pub ec_algorithm: ECAlgorithm,
    pub pq_algorithm: PQAlgorithm,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureFormat {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub signature_metadata: Option<SignatureMetadataFormat>,
    pub ec_public_key: Vec<u8>,
    pub pq_public_key: Vec<u8>,
    pub message: Option<Vec<u8>>, // Some(msg) would be attached & None would be detached signatures
    pub ec_signature: Vec<u8>,
    pub pq_signature: Vec<u8>,
    pub fullchain_fingerprint: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureHeaderFormat {
    pub version: u32,
    pub signature: SignatureFormat,
}

impl SignatureHeaderFormat {
    fn verify_magic_bytes(header: &[u8], cursor: &mut usize) -> Result<bool, FormatError> {
        let magic_bytes = &header[*cursor..*cursor + SIGNATURE_MAGIC_BYTE.len()];
        *cursor += SIGNATURE_MAGIC_BYTE.len();
        Ok(magic_bytes == SIGNATURE_MAGIC_BYTE)
    }

    fn read_u32(header: &[u8], cursor: &mut usize) -> Result<u32, FormatError> {
        let mut rdr = Cursor::new(&header[*cursor..*cursor + 4]);
        *cursor += 4;
        rdr.read_u32::<LittleEndian>()
            .map_err(|_| FormatError::FailedToDecode(ErrSection::HEADER))
    }

    pub fn encode_with_magic_byte(&self) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::new();
        header.extend(SIGNATURE_MAGIC_BYTE);
        header.extend(self.version.to_le_bytes());
        header.extend_from_slice(&self.signature.encode_bson());

        header
    }

    pub fn decode_with_magic_byte(signature_header: &[u8]) -> Result<Self, FormatError> {
        let mut cursor = 0;

        if !Self::verify_magic_bytes(signature_header, &mut cursor)? {
            return Err(FormatError::FailedToDecode(ErrSection::HEADER));
        }

        let version = Self::read_u32(signature_header, &mut cursor)?;

        let bson_data = &signature_header[cursor..];
        let signature = SignatureFormat::decode_bson(bson_data)?;

        Ok(SignatureHeaderFormat { version, signature })
    }
}

impl EncodablePublic for SignatureFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(data: &[u8]) -> Result<Self, FormatError> {
        let metadata = bson::from_slice::<SignatureFormat>(data);

        Ok(metadata?)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(SIGNATURE_TAG, self.encode_bson());
        pem::encode(&pem)
    }

    fn decode_pem(pem_data: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_data)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}
