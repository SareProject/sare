use std::io::Cursor;

use sare_lib::{
    certificate::Certificate,
    encryption::{Decryptor, Encryptor},
    format::certificate::Issuer,
    keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey, SharedPublicKey},
};
use secrecy::SecretBox;

/// The tests exercise the streaming and framing logic, not the KDF strength,
/// so the key derivation runs with cheap scrypt parameters
const TEST_PKDF_PARAMS: sare_lib::keys::PKDFAlgorithm =
    sare_lib::keys::PKDFAlgorithm::Scrypt(10, 8, 1);

fn generate_masterkey() -> MasterKey {
    MasterKey::generate(
        HybridKEMAlgorithm::default(),
        HybridSignAlgorithm::default(),
    )
}

fn shared_public_key(masterkey: &MasterKey) -> SharedPublicKey {
    let mut buffer = Cursor::new(Vec::new());
    masterkey.export_public(&mut buffer).unwrap();
    let pem = String::from_utf8(buffer.into_inner()).unwrap();

    SharedPublicKey::from_pem(pem).unwrap()
}

/// SARE-01 and SARE-02: a file encrypted for a recipient must decrypt
/// back into the exact plaintext on the recipient side
#[test]
fn asymmetric_roundtrip() {
    let sender = generate_masterkey();
    let recipient = generate_masterkey();
    let recipient_public = shared_public_key(&recipient);

    let plaintext: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

    let mut encrypted = Cursor::new(Vec::new());
    Encryptor::new(sender)
        .encrypt_with_recipient(
            Cursor::new(plaintext.clone()),
            &mut encrypted,
            &recipient_public,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )
        .unwrap();

    let encrypted_bytes = encrypted.into_inner();

    // The payload is no longer an empty AEAD tag over nothing
    assert!(
        encrypted_bytes.len() > plaintext.len(),
        "the encrypted file must carry the whole plaintext"
    );

    let mut decrypted = Cursor::new(Vec::new());
    Decryptor::new(recipient)
        .decrypt_with_recipient(Cursor::new(encrypted_bytes.clone()), &mut decrypted)
        .unwrap();

    assert_eq!(plaintext, decrypted.into_inner());
}

/// SARE-03: symmetric decryption must handle plaintexts of every size,
/// especially around the 2048 byte STREAM chunk boundary
#[test]
fn symmetric_roundtrip_chunk_boundaries() {
    for size in [
        0,
        1,
        100,
        2047,
        2048,
        2049,
        3000,
        4096,
        2064,
        2065,
        100_000,
    ] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let passphrase = SecretBox::new(b"correct horse battery staple".to_vec().into());

        let mut encrypted = Cursor::new(Vec::new());
        let pkdf = Encryptor::get_pkdf(
            &passphrase,
            TEST_PKDF_PARAMS,
            1,
        );
        Encryptor::encrypt_with_passphrase(
            Cursor::new(plaintext.clone()),
            &mut encrypted,
            pkdf,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )
        .unwrap();

        let mut decrypted = Cursor::new(Vec::new());
        Decryptor::decrypt_with_passphrase(
            SecretBox::new(b"correct horse battery staple".to_vec().into()),
            Cursor::new(encrypted.into_inner()),
            &mut decrypted,
        )
        .unwrap();

        assert_eq!(
            plaintext,
            decrypted.into_inner(),
            "roundtrip failed for size {}",
            size
        );
    }
}

/// SARE-04: a wrong passphrase must return an error, never a panic
#[test]
fn symmetric_wrong_passphrase_is_an_error() {
    let passphrase = SecretBox::new(b"correct horse battery staple".to_vec().into());

    let mut encrypted = Cursor::new(Vec::new());
    let pkdf = Encryptor::get_pkdf(
        &passphrase,
        TEST_PKDF_PARAMS,
        1,
    );
    Encryptor::encrypt_with_passphrase(
        Cursor::new(b"secret contents".to_vec()),
        &mut encrypted,
        pkdf,
        sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
    )
    .unwrap();

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::decrypt_with_passphrase(
        SecretBox::new(b"wrong passphrase".to_vec().into()),
        Cursor::new(encrypted.into_inner()),
        &mut decrypted,
    );

    assert!(result.is_err(), "wrong passphrase must not decrypt");
    assert!(decrypted.get_ref().is_empty());
}

/// SARE-04: a tampered payload must return an error, never a panic
#[test]
fn tampered_payload_is_an_error() {
    let sender = generate_masterkey();
    let recipient = generate_masterkey();
    let recipient_public = shared_public_key(&recipient);

    let plaintext = b"attack at dawn".to_vec();

    let mut encrypted = Cursor::new(Vec::new());
    Encryptor::new(sender.clone())
        .encrypt_with_recipient(
            Cursor::new(plaintext.clone()),
            &mut encrypted,
            &recipient_public,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )
        .unwrap();

    let mut tampered = encrypted.into_inner();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::new(recipient)
        .decrypt_with_recipient(Cursor::new(tampered), &mut decrypted)
        .unwrap_err();

    assert!(
        result.to_string().contains("encrypt or decrypt"),
        "unexpected error: {}",
        result
    );
}

/// SARE-05 and SARE-08: a tampered signature must fail the decryption
/// and the header it was signed over must be verified
#[test]
fn tampered_signature_fails_decryption() {
    let sender = generate_masterkey();
    let recipient = generate_masterkey();
    let recipient_public = shared_public_key(&recipient);

    let plaintext = b"signed and encrypted".to_vec();

    let mut encrypted = Cursor::new(Vec::new());
    Encryptor::new(sender)
        .encrypt_with_recipient(
            Cursor::new(plaintext.clone()),
            &mut encrypted,
            &recipient_public,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )
        .unwrap();

    let mut tampered = encrypted.into_inner();

    // Flip a byte inside the signature BSON in the header
    let header_len =
        u64::from_le_bytes(tampered[9..17].try_into().unwrap()) as usize + 9 + 8 - 1;
    tampered[header_len] ^= 0xff;

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::new(recipient)
        .decrypt_with_recipient(Cursor::new(tampered), &mut decrypted);

    assert!(
        result.is_err(),
        "a tampered signature must never decrypt successfully"
    );
}

/// SARE-08: a header field the signature covers can not be modified in transit
#[test]
fn tampered_header_fails_decryption() {
    let sender = generate_masterkey();
    let recipient = generate_masterkey();
    let recipient_public = shared_public_key(&recipient);

    let plaintext = b"signed and encrypted".to_vec();

    let mut encrypted = Cursor::new(Vec::new());
    Encryptor::new(sender)
        .encrypt_with_recipient(
            Cursor::new(plaintext.clone()),
            &mut encrypted,
            &recipient_public,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )
        .unwrap();

    let mut tampered = encrypted.into_inner();

    // Modify the kdf salt inside the header BSON, the signature no longer matches
    let kdf_salt_index = tampered
        .windows(8)
        .position(|window| window == b"kdf_salt")
        .expect("header must contain the kdf salt field");

    let bson_value_index = kdf_salt_index + 8 + 1;
    tampered[bson_value_index] ^= 0xff;

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::new(recipient)
        .decrypt_with_recipient(Cursor::new(tampered), &mut decrypted);

    assert!(
        result.is_err(),
        "a modified header must never decrypt successfully"
    );
}

/// SARE-07: a corrupted header must return an error, never a panic
#[test]
fn corrupted_header_is_an_error() {
    let passphrase = SecretBox::new(b"correct horse battery staple".to_vec().into());

    let mut encrypted = Cursor::new(Vec::new());
    let pkdf = Encryptor::get_pkdf(
        &passphrase,
        TEST_PKDF_PARAMS,
        1,
    );
    Encryptor::encrypt_with_passphrase(
        Cursor::new(b"secret contents".to_vec()),
        &mut encrypted,
        pkdf,
        sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
    )
    .unwrap();

    let mut corrupted = encrypted.into_inner();

    // Corrupt a byte inside the BSON metadata
    corrupted[30] ^= 0xff;

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::decrypt_with_passphrase(
        SecretBox::new(b"correct horse battery staple".to_vec().into()),
        Cursor::new(corrupted),
        &mut decrypted,
    );

    assert!(result.is_err(), "a corrupted header must not decode");
}

/// SARE-07: an oversized header length field must return an error
/// instead of trying to allocate the requested memory
#[test]
fn huge_header_length_is_an_error() {
    let mut forged = Vec::new();
    forged.extend_from_slice(b"SARECRYPT");
    forged.extend_from_slice(&u64::MAX.to_le_bytes());

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::decrypt_with_passphrase(
        SecretBox::new(b"whatever".to_vec().into()),
        Cursor::new(forged),
        &mut decrypted,
    );

    assert!(result.is_err());
}

/// SARE-07: exaggerated KDF parameters from a header must be rejected
#[test]
fn exaggerated_kdf_parameters_are_rejected() {
    let passphrase = SecretBox::new(b"passphrase".to_vec().into());

    let mut encrypted = Cursor::new(Vec::new());
    let pkdf = Encryptor::get_pkdf(
        &passphrase,
        TEST_PKDF_PARAMS,
        1,
    );
    Encryptor::encrypt_with_passphrase(
        Cursor::new(b"secret contents".to_vec()),
        &mut encrypted,
        pkdf,
        sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
    )
    .unwrap();

    let mut amplified = encrypted.into_inner();

    // Overwrite the scrypt parameters in the header with p = 300000,
    // the encoded tuple is 10 bytes of little endian scalars at the end of the pkdf blob
    let scrypt_index = amplified
        .windows(6)
        .position(|window| window == b"Scrypt")
        .expect("header must contain the scrypt algorithm");

    // BSON: 0x00 log_n, 0x10 r (i32), 0x10 p (i32)
    let params_index = scrypt_index + 6 + 1;
    let (log_n, r, p) = (
        amplified[params_index],
        i32::from_le_bytes(amplified[params_index + 1..params_index + 5].try_into().unwrap()),
        i32::from_le_bytes(amplified[params_index + 5..params_index + 9].try_into().unwrap()),
    );

    // Keep the recommended log_n and r, blow up p
    amplified[params_index] = log_n;
    amplified[params_index + 1..params_index + 5].copy_from_slice(&r.to_le_bytes());
    amplified[params_index + 5..params_index + 9]
        .copy_from_slice(&300_000i32.to_le_bytes());
    let _ = p;

    let mut decrypted = Cursor::new(Vec::new());
    let result = Decryptor::decrypt_with_passphrase(
        SecretBox::new(b"passphrase".to_vec().into()),
        Cursor::new(amplified),
        &mut decrypted,
    );

    assert!(
        result.is_err(),
        "exaggerated scrypt parameters must be rejected"
    );
}

/// SARE-06: a validation certificate must not be issuable by the subject key
#[test]
fn validation_certificate_can_not_be_self_signed() {
    let masterkey = generate_masterkey();
    let issuer = Issuer::new("Zola Gonano".to_string(), "zola@example.com".to_string());

    let result = Certificate::new_validation(
        masterkey.clone(),
        &masterkey,
        None,
        &issuer,
    );

    assert!(result.is_err());
}

/// SARE-06: an attacker's self-signed certificate does not verify
/// against a trusted issuer key
#[test]
fn mallorys_self_signed_certificate_does_not_verify() {
    let mallory = generate_masterkey();
    let trusted_issuer = generate_masterkey();
    let issuer = Issuer::new("Trusted Party".to_string(), "issuer@example.com".to_string());

    // Mallory signs a validation certificate with her own key
    let mallory_masterkey = mallory.clone();
    let forged = Certificate::new(
        mallory_masterkey,
        sare_lib::format::certificate::CertificateFormat {
            issuer: issuer.clone(),
            expiry_date: None,
            certificate_type: sare_lib::format::certificate::CertificateType::Validation(
                sare_lib::format::certificate::ValidationCertificateFormat {
                    fullchain_public_key_fingerprint: mallory.get_fullchain_public_fingerprint(),
                },
            ),
        },
    );

    let now = 1_800_000_000;
    let verifies = forged
        .verify_with_issuer(&trusted_issuer.get_signing_public_key(), now)
        .unwrap();

    assert!(
        !verifies,
        "a self-signed certificate must not verify against another key"
    );
}

/// SARE-09: export_encryption_public must export the encryption key
#[test]
fn export_encryption_public_exports_the_encryption_key() {
    use sare_lib::keys::EncodablePublic;

    let masterkey = generate_masterkey();

    let mut exported = Cursor::new(Vec::new());
    masterkey.export_encryption_public(&mut exported).unwrap();
    let exported_pem = String::from_utf8(exported.into_inner()).unwrap();

    let expected_pem = masterkey.get_encryption_public_key().encode_pem();

    assert_eq!(expected_pem, exported_pem);
}

/// The master key must survive a full export/import roundtrip
#[test]
fn masterkey_import_roundtrip() {
    let masterkey = generate_masterkey();

    let mut exported = Cursor::new(Vec::new());
    masterkey.export(None, &mut exported).unwrap();

    let secret_key_format = MasterKey::decode_pem(Cursor::new(exported.into_inner())).unwrap();
    let imported = MasterKey::import(secret_key_format, None).unwrap();

    assert_eq!(
        masterkey.get_fullchain_public_fingerprint(),
        imported.get_fullchain_public_fingerprint()
    );

    // Importing an unencrypted key with a passphrase must be an error, not a panic
    let mut exported = Cursor::new(Vec::new());
    masterkey.export(None, &mut exported).unwrap();

    let secret_key_format = MasterKey::decode_pem(Cursor::new(exported.into_inner())).unwrap();
    let result =
        MasterKey::import(secret_key_format, Some(SecretBox::new(b"passphrase".to_vec().into())));

    assert!(result.is_err());
}
