use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid share length: expected {expected}, got {actual}")]
    InvalidShareLength { expected: usize, actual: usize },
    #[error("ml-kem error: {0}")]
    MlKem(String),
    #[error("x25519 error")]
    X25519,
}
