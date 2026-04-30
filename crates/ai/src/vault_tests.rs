use tempfile::TempDir;

use super::*;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn encrypt_decrypt_round_trip() {
    let encrypted = encrypt_to_vault_text(b"top secret context", PASSWORD).unwrap();

    assert!(encrypted.starts_with(MAGIC_HEADER));
    assert!(!encrypted.contains("top secret context"));

    let decrypted = decrypt_to_string_with_password(&encrypted, PASSWORD).unwrap();
    assert_eq!(decrypted.as_str(), "top secret context");
}

#[test]
fn wrong_password_fails_cleanly() {
    let encrypted = encrypt_to_vault_text(b"top secret context", PASSWORD).unwrap();
    let error = decrypt_to_string_with_password(&encrypted, "wrong password").unwrap_err();

    assert!(matches!(error, VaultError::DecryptFailed));
}

#[test]
fn tampered_ciphertext_fails_cleanly() {
    let encrypted = encrypt_to_vault_text(b"top secret context", PASSWORD).unwrap();
    let parts: Vec<&str> = encrypted.trim_end().split(';').collect();
    let mut ciphertext = BASE64_STANDARD.decode(parts[5]).unwrap();
    ciphertext[0] ^= 1;
    let tampered = format!(
        "{MAGIC_HEADER};{};{};{}\n",
        parts[3],
        parts[4],
        BASE64_STANDARD.encode(ciphertext)
    );
    let error = decrypt_to_string_with_password(&tampered, PASSWORD).unwrap_err();
    assert!(matches!(error, VaultError::DecryptFailed));
}

#[test]
fn password_file_trims_line_endings() {
    let temp_dir = TempDir::new().unwrap();
    let password_file = temp_dir.path().join("vault-password");
    std::fs::write(&password_file, "password-from-file\r\n").unwrap();

    let password = read_password(Some(&password_file)).unwrap();

    assert_eq!(password.as_str(), "password-from-file");
}

#[test]
fn encrypt_decrypt_file_overwrites_in_place() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("secret.md");
    std::fs::write(&file_path, "# Secret\n\nBody").unwrap();

    encrypt_file(&file_path, PASSWORD).unwrap();
    let encrypted = std::fs::read_to_string(&file_path).unwrap();
    assert!(is_vault_payload(&encrypted));
    assert!(!encrypted.contains("Body"));

    decrypt_file(&file_path, PASSWORD).unwrap();
    let decrypted = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(decrypted, "# Secret\n\nBody");
}
