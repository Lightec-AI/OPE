//! OPE Confidential AI: hybrid PQ application-layer E2E encryption.
//!
//! - **Request:** encrypt to static engine ML-KEM + X25519 (`enc=e2e-hybrid-pq`).
//! - **Response:** encrypt stream to client ephemeral hybrid session.
//! - **TLS:** unchanged; use standard HTTPS clients.

mod e2e_fields;
mod error;
mod identity;
mod kex;
pub mod mock;
mod request;
mod response;
mod stream;

pub use e2e_fields::E2eFields;
pub use error::Error;
pub use identity::{ClientSession, EngineIdentity, EngineStaticSecret};
pub use kex::{
    client_request_shared_secret, client_response_shared_secret, derive_content_key,
    derive_request_content_key, derive_response_content_key, engine_response_shared_secret,
    DIRECTION_REQUEST, DIRECTION_RESPONSE,
};
pub use mock::{mock_engine_from_seed, DEV_ENGINE_SEED};
pub use request::{decrypt_request, encrypt_request, ENC_E2E_HYBRID_PQ};
pub use response::{
    begin_response_session, decrypt_response_chunk, encrypt_response_chunk, e2e_with_server_share,
};
pub use stream::{decrypt_chunk, encrypt_chunk};
