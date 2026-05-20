//! Encrypt / decrypt Confidential AI requests (`enc=e2e-hybrid-pq`).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ope_crypto::{decode, encode};
use ope_envelope::{canonical::payload_hash, Envelope};
use rand::RngCore;
use serde_json::Value;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::e2e_fields::E2eFields;
use crate::identity::{ClientSession, EngineIdentity};
use crate::kex::{derive_content_key, client_request_shared_secret, DIRECTION_REQUEST};
use crate::Error;

pub const ENC_E2E_HYBRID_PQ: &str = "e2e-hybrid-pq";

/// Build `e2e` + encrypt payload; caller signs envelope afterward.
pub fn encrypt_request(
    envelope: &mut Envelope,
    engine: &EngineIdentity,
    payload: &Value,
    client_session: Option<&ClientSession>,
) -> Result<(), Error> {
    envelope.enc = ENC_E2E_HYBRID_PQ.to_string();
    envelope.engine_id = Some(engine.engine_id.clone());
    envelope.payload = Some(payload.clone());
    envelope.payload_hash = payload_hash(payload)?;

    let plaintext = serde_json::to_vec(payload).map_err(|e| Error::E2e(e.to_string()))?;

    let x25519_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_x25519_public = *X25519Public::from(&x25519_secret).as_bytes();
    let (shared, mlkem_ct) =
        client_request_shared_secret(engine, x25519_secret.to_bytes())?;

    let content_key = derive_content_key(
        &shared,
        DIRECTION_REQUEST,
        &engine.engine_id,
        &envelope.kid,
        &envelope.nonce,
    )?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let cipher = ChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = Nonce::from(iv);
    let ct = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| Error::Crypto(e.to_string()))?;

    envelope.payload = None;
    envelope.iv = Some(encode(&iv));
    envelope.ciphertext = Some(encode(&ct));

    let e2e = E2eFields {
        kex: E2eFields::KEX.into(),
        client_share: client_session.map(|s| encode(&s.kex.bytes)),
        mlkem_ciphertext: Some(encode(&mlkem_ct)),
        client_x25519: encode(&client_x25519_public),
        content_alg: E2eFields::ALG_CHACHA.into(),
        engine_mlkem_encap: engine.mlkem_encapsulation_key.clone(),
        engine_x25519: engine.x25519_public.clone(),
        server_share: None,
    };
    envelope.e2e = Some(serde_json::to_value(&e2e).map_err(|e| Error::E2e(e.to_string()))?);
    Ok(())
}

/// Engine decrypts request ciphertext.
pub fn decrypt_request(
    envelope: &Envelope,
    engine: &crate::identity::EngineStaticSecret,
) -> Result<Value, Error> {
    let e2e: E2eFields = serde_json::from_value(
        envelope
            .e2e
            .clone()
            .ok_or_else(|| Error::E2e("missing e2e".into()))?,
    )
    .map_err(|e| Error::E2e(e.to_string()))?;

    let mlkem_ct = decode(
        e2e
            .mlkem_ciphertext
            .as_ref()
            .ok_or_else(|| Error::E2e("missing mlkem_ciphertext".into()))?,
    )
    .map_err(|_| Error::E2e("mlkem ct".into()))?;
    let client_x25519: [u8; 32] = decode(&e2e.client_x25519)
        .map_err(|_| Error::E2e("client x25519".into()))?
        .try_into()
        .map_err(|_| Error::E2e("client x25519 len".into()))?;

    let shared = engine.request_shared_secret(&mlkem_ct, client_x25519)?;
    let content_key = derive_content_key(
        &shared,
        DIRECTION_REQUEST,
        &engine.engine_id,
        &envelope.kid,
        &envelope.nonce,
    )?;

    let iv_b64 = envelope
        .iv
        .as_ref()
        .ok_or_else(|| Error::E2e("missing iv".into()))?;
    let ct_b64 = envelope
        .ciphertext
        .as_ref()
        .ok_or_else(|| Error::E2e("missing ciphertext".into()))?;
    let iv = decode(iv_b64).map_err(|_| Error::E2e("iv".into()))?;
    let ct = decode(ct_b64).map_err(|_| Error::E2e("ct".into()))?;
    let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::E2e("iv len".into()))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = Nonce::from(iv_arr);
    let plaintext = cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let payload: Value =
        serde_json::from_slice(&plaintext).map_err(|e| Error::E2e(e.to_string()))?;

    let expected = payload_hash(&payload)?;
    if expected != envelope.payload_hash {
        return Err(Error::Envelope(ope_envelope::Error::PayloadHashMismatch));
    }
    Ok(payload)
}
