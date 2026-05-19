use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;

pub const DEV_CONTENT_KEY: [u8; 32] = [0x02; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncMode {
    A256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("unsupported enc mode: {0}")]
    UnsupportedMode(String),
    #[error("invalid key length")]
    InvalidKey,
    #[error("invalid iv/nonce length")]
    InvalidIv,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("encryption failed")]
    EncryptFailed,
}

impl EncMode {
    pub fn parse(enc: &str) -> Result<Self, AeadError> {
        match enc {
            "A256GCM" => Ok(Self::A256Gcm),
            "xchacha20poly1305" => Ok(Self::XChaCha20Poly1305),
            other => Err(AeadError::UnsupportedMode(other.to_string())),
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::A256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

pub fn encrypt(mode: EncMode, key: &[u8; 32], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
    match mode {
        EncMode::A256Gcm => {
            if iv.len() != 12 {
                return Err(AeadError::InvalidIv);
            }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = AesNonce::from_slice(iv);
            cipher.encrypt(n, plaintext)
                .map_err(|_| AeadError::EncryptFailed)
        }
        EncMode::XChaCha20Poly1305 => {
            if iv.len() != 24 {
                return Err(AeadError::InvalidIv);
            }
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = XNonce::from_slice(iv);
            cipher.encrypt(n, plaintext)
                .map_err(|_| AeadError::EncryptFailed)
        }
    }
}

pub fn decrypt(mode: EncMode, key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
    match mode {
        EncMode::A256Gcm => {
            if iv.len() != 12 {
                return Err(AeadError::InvalidIv);
            }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = AesNonce::from_slice(iv);
            cipher.decrypt(n, ciphertext)
                .map_err(|_| AeadError::DecryptFailed)
        }
        EncMode::XChaCha20Poly1305 => {
            if iv.len() != 24 {
                return Err(AeadError::InvalidIv);
            }
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = XNonce::from_slice(iv);
            cipher.decrypt(n, ciphertext)
                .map_err(|_| AeadError::DecryptFailed)
        }
    }
}
