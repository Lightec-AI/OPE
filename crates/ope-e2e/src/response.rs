//! Streaming response encryption to client ephemeral session.

use ope_crypto::encode;
use ope_envelope::Envelope;
use ope_transport::ServerKeyExchange;

use crate::e2e_fields::E2eFields;
use crate::identity::{ClientSession, EngineStaticSecret};
use crate::kex::{client_response_shared_secret, derive_response_content_key};
use crate::stream::{decrypt_chunk, encrypt_chunk};
use crate::Error;

/// Engine: derive response key and attach `server_share` to outbound envelope metadata.
pub fn begin_response_session(
    engine: &EngineStaticSecret,
    request: &Envelope,
    client: &ClientSession,
) -> Result<( [u8; 32], [u8; 12], ServerKeyExchange), Error> {
    let (shared, server) = engine.respond_to_client(&client.kex)?;
    let key = derive_response_content_key(
        &shared,
        &engine.engine_id,
        &request.kid,
        &request.nonce,
    )?;
    let iv_b64 = request
        .iv
        .as_ref()
        .ok_or_else(|| Error::E2e("request iv".into()))?;
    let iv_bytes = ope_crypto::decode(iv_b64).map_err(|_| Error::E2e("iv".into()))?;
    let iv: [u8; 12] = iv_bytes.try_into().map_err(|_| Error::E2e("iv len".into()))?;
    Ok((key, iv, server))
}

/// Engine: derive response key from only the **public** client share bytes
/// (`e2e.client_share` on the request), without needing a full [`ClientSession`].
///
/// This is the function a real engine calls: it holds no client secret, only the
/// ephemeral share received on the wire.
pub fn begin_response_session_from_share(
    engine: &EngineStaticSecret,
    request: &Envelope,
    client_share_b64: &str,
) -> Result<([u8; 32], [u8; 12], ServerKeyExchange), Error> {
    let share = ope_crypto::decode(client_share_b64)
        .map_err(|_| Error::E2e("client_share".into()))?;
    let (server, shared) = ServerKeyExchange::respond_to_share(&share)?;
    let key = derive_response_content_key(&shared, &engine.engine_id, &request.kid, &request.nonce)?;
    let iv_b64 = request
        .iv
        .as_ref()
        .ok_or_else(|| Error::E2e("request iv".into()))?;
    let iv_bytes = ope_crypto::decode(iv_b64).map_err(|_| Error::E2e("iv".into()))?;
    let iv: [u8; 12] = iv_bytes.try_into().map_err(|_| Error::E2e("iv len".into()))?;
    Ok((key, iv, server))
}

/// Encrypt one response stream chunk.
pub fn encrypt_response_chunk(
    key: &[u8; 32],
    iv_base: &[u8; 12],
    seq: u32,
    plaintext: &[u8],
) -> Result<String, Error> {
    encrypt_chunk(key, iv_base, seq, plaintext)
}

/// Client: decrypt chunk using request session + response `server_share`.
pub fn decrypt_response_chunk(
    request: &Envelope,
    client: &ClientSession,
    server_share_b64: &str,
    seq: u32,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, Error> {
    let server_bytes = ope_crypto::decode(server_share_b64)
        .map_err(|_| Error::E2e("server_share".into()))?;
    let server = ServerKeyExchange::from_bytes(&server_bytes)?;
    let shared = client_response_shared_secret(&client.kex, &server)?;
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("engine-dev");
    let key = derive_response_content_key(&shared, engine_id, &request.kid, &request.nonce)?;
    let iv_b64 = request.iv.as_ref().ok_or_else(|| Error::E2e("iv".into()))?;
    let iv_bytes = ope_crypto::decode(iv_b64).map_err(|_| Error::E2e("iv".into()))?;
    let iv: [u8; 12] = iv_bytes.try_into().map_err(|_| Error::E2e("iv len".into()))?;
    decrypt_chunk(&key, &iv, seq, ciphertext_b64)
}

/// Attach `server_share` to an `e2e` object for response headers.
pub fn e2e_with_server_share(e2e: &E2eFields, server: &ServerKeyExchange) -> E2eFields {
    let mut out = e2e.clone();
    out.server_share = Some(encode(&server.bytes));
    out.content_alg = E2eFields::ALG_STREAM.into();
    out
}
