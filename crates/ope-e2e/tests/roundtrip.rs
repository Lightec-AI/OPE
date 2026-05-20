use ope_crypto::mock_keypair_from_seed;
use ope_crypto::DEV_VECTOR_001_SEED;
use ope_e2e::{
    begin_response_session, decrypt_request, decrypt_response_chunk, encrypt_request,
    encrypt_response_chunk, mock_engine_from_seed, ClientSession, DEV_ENGINE_SEED,
};
use ope_envelope::{sign_envelope, Envelope};
use serde_json::json;

#[test]
fn confidential_ai_request_response_roundtrip() {
    let (_, engine_pub) = mock_engine_from_seed(&DEV_ENGINE_SEED);
    let (engine_secret, _) = mock_engine_from_seed(&DEV_ENGINE_SEED);
    let client_session = ClientSession::generate().unwrap();
    let sender = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);

    let payload = json!({
        "model": "gpt-4.1@openai",
        "messages": [{"role": "user", "content": "secret prompt"}]
    });

    let mut envelope = Envelope {
        ope_version: Envelope::VERSION.into(),
        alg: Envelope::ALG_EDDSA.into(),
        enc: Envelope::ENC_NONE.into(),
        kid: "sender-dev".into(),
        recipient: "gateway-dev".into(),
        engine_id: None,
        ts: "2026-05-19T12:00:00Z".into(),
        nonce: "bm9uY2VfZGV2X2UxZQ".into(),
        payload_hash: String::new(),
        payload: None,
        ciphertext: None,
        iv: None,
        aad: None,
        meta: Some(json!({
            "model": "gpt-4.1@openai",
            "tenant": "tenant-a",
            "metering": {"units": 1}
        })),
        e2e: None,
        sig: None,
    };

    encrypt_request(&mut envelope, &engine_pub, &payload, Some(&client_session)).unwrap();
    sign_envelope(&mut envelope, &sender.secret).unwrap();

    let decrypted = decrypt_request(&envelope, &engine_secret).unwrap();
    assert_eq!(decrypted, payload);

    let (resp_key, iv, server) =
        begin_response_session(&engine_secret, &envelope, &client_session).unwrap();
    let chunk0 = encrypt_response_chunk(&resp_key, &iv, 0, b"token1 ").unwrap();
    let chunk1 = encrypt_response_chunk(&resp_key, &iv, 1, b"token2").unwrap();

    let pt0 = decrypt_response_chunk(
        &envelope,
        &client_session,
        &ope_crypto::encode(&server.bytes),
        0,
        &chunk0,
    )
    .unwrap();
    let pt1 = decrypt_response_chunk(
        &envelope,
        &client_session,
        &ope_crypto::encode(&server.bytes),
        1,
        &chunk1,
    )
    .unwrap();
    assert_eq!(pt0, b"token1 ");
    assert_eq!(pt1, b"token2");
}
