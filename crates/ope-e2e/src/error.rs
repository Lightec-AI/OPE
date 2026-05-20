use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("transport: {0}")]
    Transport(#[from] ope_transport::Error),
    #[error("envelope: {0}")]
    Envelope(#[from] ope_envelope::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("e2e: {0}")]
    E2e(String),
}
