use std::{fs, path::Path};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Context as _;
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

pub const MAGIC_HEADER: &str = "$WARP_VAULT;1.0;AES256_GCM";
pub const PASSWORD_ENV_VAR: &str = "WARP_VAULT_PASSWORD";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("file is not a Warp vault payload")]
    NotVaultPayload,
    #[error("invalid Warp vault payload format")]
    InvalidFormat,
    #[error("missing vault password; set WARP_VAULT_PASSWORD or pass --vault-password-file")]
    MissingPassword,
    #[error("failed to read vault password file '{path}'")]
    PasswordFileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to derive vault encryption key: {0}")]
    KeyDerivation(String),
    #[error("failed to decode vault payload")]
    Decode(#[source] base64::DecodeError),
    #[error("failed to encrypt vault payload")]
    EncryptFailed,
    #[error("failed to decrypt vault payload; password may be wrong or file may be tampered with")]
    DecryptFailed,
    #[error("decrypted vault payload is not valid UTF-8")]
    InvalidUtf8,
}

#[derive(Debug, Clone)]
struct VaultPayload {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub fn is_vault_payload(contents: &str) -> bool {
    contents.trim_start().starts_with(MAGIC_HEADER)
}

pub fn read_password(password_file: Option<&Path>) -> Result<Zeroizing<String>, VaultError> {
    if let Some(path) = password_file {
        let password = fs::read_to_string(path).map_err(|source| VaultError::PasswordFileRead {
            path: path.display().to_string(),
            source,
        })?;
        return Ok(Zeroizing::new(trim_password_file_contents(password)));
    }

    match std::env::var(PASSWORD_ENV_VAR) {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(std::env::VarError::NotPresent) => Err(VaultError::MissingPassword),
        Err(std::env::VarError::NotUnicode(_)) => Err(VaultError::MissingPassword),
    }
}

pub fn encrypt_to_vault_text(plaintext: &[u8], password: &str) -> Result<String, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    encrypt_to_vault_text_with_salt_and_nonce(plaintext, password, salt, nonce)
}

pub fn decrypt_to_string(
    contents: &str,
    password_file: Option<&Path>,
) -> Result<Zeroizing<String>, VaultError> {
    let password = read_password(password_file)?;
    decrypt_to_string_with_password(contents, &password)
}

pub fn decrypt_to_string_with_password(
    contents: &str,
    password: &str,
) -> Result<Zeroizing<String>, VaultError> {
    let mut decrypted = decrypt_to_bytes_with_password(contents, password)?;
    let plaintext = std::mem::take(&mut *decrypted);
    match String::from_utf8(plaintext) {
        Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(VaultError::InvalidUtf8)
        }
    }
}

fn encrypt_to_vault_text_with_salt_and_nonce(
    plaintext: &[u8],
    password: &str,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<String, VaultError> {
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| VaultError::EncryptFailed)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| VaultError::EncryptFailed)?;

    Ok(format!(
        "{MAGIC_HEADER};{};{};{}\n",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(ciphertext)
    ))
}

fn decrypt_to_bytes_with_password(
    contents: &str,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let payload = parse_payload(contents)?;
    let key = derive_key(password, &payload.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| VaultError::DecryptFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&payload.nonce),
            payload.ciphertext.as_ref(),
        )
        .map_err(|_| VaultError::DecryptFailed)?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| VaultError::KeyDerivation(err.to_string()))?;
    Ok(Zeroizing::new(key))
}

fn parse_payload(contents: &str) -> Result<VaultPayload, VaultError> {
    let trimmed = contents.trim_start().trim_end_matches(['\r', '\n']);
    if !trimmed.starts_with(MAGIC_HEADER) {
        return Err(VaultError::NotVaultPayload);
    }

    let parts: Vec<&str> = trimmed.split(';').collect();
    let ["$WARP_VAULT", "1.0", "AES256_GCM", salt, nonce, ciphertext] = parts.as_slice() else {
        return Err(VaultError::InvalidFormat);
    };

    let salt = BASE64_STANDARD.decode(salt).map_err(VaultError::Decode)?;
    let nonce = BASE64_STANDARD.decode(nonce).map_err(VaultError::Decode)?;
    let ciphertext = BASE64_STANDARD
        .decode(ciphertext)
        .map_err(VaultError::Decode)?;

    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN || ciphertext.is_empty() {
        return Err(VaultError::InvalidFormat);
    }

    Ok(VaultPayload {
        salt,
        nonce,
        ciphertext,
    })
}

fn trim_password_file_contents(mut password: String) -> String {
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    password
}

pub fn encrypt_file(path: &Path, password: &str) -> anyhow::Result<()> {
    let plaintext = Zeroizing::new(
        fs::read(path).with_context(|| format!("Failed to read '{}'", path.display()))?,
    );
    let encrypted = encrypt_to_vault_text(&plaintext, password)?;
    fs::write(path, encrypted).with_context(|| format!("Failed to write '{}'", path.display()))
}

pub fn decrypt_file(path: &Path, password: &str) -> anyhow::Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read encrypted file '{}'", path.display()))?;
    let plaintext = decrypt_to_string_with_password(&contents, password)?;
    fs::write(path, plaintext.as_bytes())
        .with_context(|| format!("Failed to write decrypted file '{}'", path.display()))
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
