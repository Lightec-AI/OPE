//! Official hybrid KEX vectors: Google BoringSSL (ML-KEM-768), RFC 7748 (X25519), composed hybrid.

use std::fs;
use std::path::PathBuf;

use ope_transport::vectors::{
    decode_hex, BoringSslMlkem768Vector, HybridX25519Mlkem768Vector, Rfc7748X25519Vector,
};
use ope_transport::{
    client_from_test_material, client_shared_secret, combine_shared_secrets, mlkem_decapsulate,
    x25519_shared_secret, ServerKeyExchange, GROUP_X25519_MLKEM768,
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN,
    X25519MLKEM768_CLIENT_SHARE_LEN, X25519MLKEM768_SERVER_SHARE_LEN,
    X25519MLKEM768_SHARED_SECRET_LEN, X25519_SHARE_LEN,
};

fn transport_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/transport")
}

fn load_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = transport_vectors_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn fixed32(hex_str: &str, field: &str) -> [u8; 32] {
    let bytes = decode_hex(field, hex_str).expect(field);
    bytes.try_into().expect("length 32")
}

#[test]
fn boringssl_mlkem768_decapsulation_vectors() {
    for i in 0..3 {
        let v: BoringSslMlkem768Vector = load_json(&format!("boringssl-mlkem768-{i:03}.json"));
        let dk = decode_hex("decapsulation_key_hex", &v.decapsulation_key_hex).unwrap();
        let ct = decode_hex("ciphertext_hex", &v.ciphertext_hex).unwrap();
        let expected = decode_hex("mlkem_shared_secret_hex", &v.mlkem_shared_secret_hex).unwrap();

        let decaps = ope_transport::parse_decapsulation_key(&dk).unwrap();
        let ss = mlkem_decapsulate(&decaps, &ct).unwrap();
        assert_eq!(ss.as_slice(), expected.as_slice(), "{}", v.vector_id);
    }
}

#[test]
fn boringssl_mlkem768_keygen_encap_public_key_match() {
    for i in 0..3 {
        let v: BoringSslMlkem768Vector = load_json(&format!("boringssl-mlkem768-{i:03}.json"));
        let ek = decode_hex("encapsulation_key_hex", &v.encapsulation_key_hex).unwrap();
        assert_eq!(ek.len(), MLKEM768_ENCAPSULATION_KEY_LEN);
        // encap file public_key must match keygen public_key (same official index).
        let encap_ek = decode_hex("encapsulation_key_hex", &v.encapsulation_key_hex).unwrap();
        assert_eq!(ek, encap_ek, "{}", v.vector_id);
    }
}

#[test]
fn rfc7748_x25519_vector_001() {
    let v: Rfc7748X25519Vector = load_json("rfc7748-x25519-001.json");
    let alice_private = fixed32(&v.alice_private_hex, "alice_private_hex");
    let bob_public = fixed32(&v.bob_public_hex, "bob_public_hex");
    let bob_private = fixed32(&v.bob_private_hex, "bob_private_hex");
    let alice_public = fixed32(&v.alice_public_hex, "alice_public_hex");
    let expected = decode_hex("x25519_shared_secret_hex", &v.x25519_shared_secret_hex).unwrap();

    let alice_ss = x25519_shared_secret(alice_private, bob_public);
    let bob_ss = x25519_shared_secret(bob_private, alice_public);
    assert_eq!(alice_ss.as_slice(), expected.as_slice());
    assert_eq!(bob_ss.as_slice(), expected.as_slice());
}

#[test]
fn hybrid_x25519mlkem768_composed_vector_000() {
    let h: HybridX25519Mlkem768Vector = load_json("hybrid-x25519mlkem768-000.json");
    assert_eq!(h.tls_group, "X25519MLKEM768");
    assert_eq!(h.tls_group_id, GROUP_X25519_MLKEM768);

    let client_share = decode_hex("client_share_hex", &h.client_share_hex).unwrap();
    let server_share = decode_hex("server_share_hex", &h.server_share_hex).unwrap();
    assert_eq!(client_share.len(), X25519MLKEM768_CLIENT_SHARE_LEN);
    assert_eq!(server_share.len(), X25519MLKEM768_SERVER_SHARE_LEN);

    let rfc: Rfc7748X25519Vector = load_json("rfc7748-x25519-001.json");
    let alice_private = fixed32(&rfc.alice_private_hex, "alice_private_hex");

    let client = client_from_test_material(
        &decode_hex("decapsulation_key_hex", &h.decapsulation_key_hex).unwrap(),
        &client_share,
        alice_private,
    )
    .unwrap();

    let server = ServerKeyExchange::from_bytes(&server_share).unwrap();
    let computed = client_shared_secret(&client, &server).unwrap();

    let expected =
        decode_hex("hybrid_shared_secret_hex", &h.hybrid_shared_secret_hex).unwrap();
    assert_eq!(expected.len(), X25519MLKEM768_SHARED_SECRET_LEN);
    assert_eq!(computed.as_slice(), expected.as_slice());

    // Component secrets match upstream vectors.
    let ml = load_json::<BoringSslMlkem768Vector>("boringssl-mlkem768-000.json");
    let ml_ss = decode_hex("mlkem_shared_secret_hex", &ml.mlkem_shared_secret_hex).unwrap();
    let x_ss = decode_hex("x25519_shared_secret_hex", &h.x25519_shared_secret_hex).unwrap();
    let manual = combine_shared_secrets(&ml_ss, &x_ss);
    assert_eq!(computed, manual);
}

#[test]
fn hybrid_share_layout_matches_draft() {
    let h: HybridX25519Mlkem768Vector = load_json("hybrid-x25519mlkem768-000.json");
    let client = decode_hex("client_share_hex", &h.client_share_hex).unwrap();
    let server = decode_hex("server_share_hex", &h.server_share_hex).unwrap();

    assert_eq!(&client[..MLKEM768_ENCAPSULATION_KEY_LEN].len(), &MLKEM768_ENCAPSULATION_KEY_LEN);
    assert_eq!(client.len() - MLKEM768_ENCAPSULATION_KEY_LEN, X25519_SHARE_LEN);
    assert_eq!(&server[..MLKEM768_CIPHERTEXT_LEN].len(), &MLKEM768_CIPHERTEXT_LEN);
    assert_eq!(server.len() - MLKEM768_CIPHERTEXT_LEN, X25519_SHARE_LEN);
}
