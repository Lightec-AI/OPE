//! RB-05: forged, stale, replayed, and wrong-recipient requests must fail
//! before any plaintext exists.
//!
//! "Before plaintext" is asserted directly rather than inferred from the error:
//! the key resolver counts how many times a content key was asked for, and a
//! rejected envelope must never have asked.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ope_crypto::{
    encode, mock_keypair_from_seed, sha256, Keypair, DEV_ATTESTER_SEED, DEV_CONTENT_KEY,
    DEV_VECTOR_001_SEED,
};
use ope_envelope::{
    canonical::canonicalize_json, encrypt_envelope, sign_envelope, verify_and_open, Envelope,
    KeyResolver, MemoryReplayStore, OpenError, OpenOptions, ReplayError, ReplayStore,
};
use serde_json::{json, Value};

const RECIPIENT: &str = "teechat-gateway";
const KID: &str = "client-1";

/// Counts content-key requests so a test can prove decryption never started.
struct SpyResolver {
    sender: Option<ope_crypto::PublicKey>,
    content_key: Option<[u8; 32]>,
    content_key_calls: AtomicUsize,
}

impl SpyResolver {
    fn new(kp: &Keypair) -> Self {
        Self {
            sender: Some(kp.public),
            content_key: Some(DEV_CONTENT_KEY),
            content_key_calls: AtomicUsize::new(0),
        }
    }

    fn without_sender_key(kp: &Keypair) -> Self {
        let mut s = Self::new(kp);
        s.sender = None;
        s
    }

    fn calls(&self) -> usize {
        self.content_key_calls.load(Ordering::SeqCst)
    }
}

impl KeyResolver for SpyResolver {
    fn sender_key(&self, kid: &str) -> Option<ope_crypto::PublicKey> {
        if kid == KID {
            self.sender
        } else {
            None
        }
    }

    fn content_key(&self, _envelope: &Envelope) -> Option<[u8; 32]> {
        self.content_key_calls.fetch_add(1, Ordering::SeqCst);
        self.content_key
    }
}

struct BrokenReplayStore;

impl ReplayStore for BrokenReplayStore {
    fn reserve(&self, _kid: &str, _nonce: &str) -> Result<(), ReplayError> {
        Err(ReplayError::Unavailable("redis unreachable".into()))
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn base_envelope(enc: &str, nonce: &str, ts: &str) -> Envelope {
    Envelope {
        ope_version: Envelope::VERSION.into(),
        alg: Envelope::ALG_EDDSA.into(),
        enc: enc.into(),
        kid: KID.into(),
        recipient: RECIPIENT.into(),
        engine_id: None,
        ts: ts.into(),
        nonce: nonce.into(),
        payload_hash: String::new(),
        payload: None,
        ciphertext: None,
        iv: None,
        aad: None,
        meta: None,
        e2e: None,
        sig: None,
    }
}

/// Encrypted request the gateway itself can open (`A256GCM` with a content key).
fn sealed_request(kp: &Keypair, nonce: &str, ts: &str, payload: Value) -> Envelope {
    let mut env = base_envelope("A256GCM", nonce, ts);
    env.payload = Some(payload);
    encrypt_envelope(&mut env, &DEV_CONTENT_KEY).expect("encrypt");
    sign_envelope(&mut env, &kp.secret).expect("sign");
    env
}

fn plaintext_request(kp: &Keypair, nonce: &str, ts: &str, payload: Value) -> Envelope {
    let mut env = base_envelope(Envelope::ENC_NONE, nonce, ts);
    env.payload = Some(payload);
    sign_envelope(&mut env, &kp.secret).expect("sign");
    env
}

fn opts() -> OpenOptions {
    OpenOptions {
        max_skew: Duration::from_secs(300),
        expected_recipient: Some(RECIPIENT.into()),
        require_routed_model: false,
        allow_opaque_e2e: false,
    }
}

fn sender() -> Keypair {
    mock_keypair_from_seed(&DEV_VECTOR_001_SEED)
}

#[test]
fn admits_a_well_formed_request_and_returns_a_capability() {
    let kp = sender();
    let env = sealed_request(&kp, "n-ok", &now_rfc3339(), json!({"model": "m@teechat"}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();

    let cap = verify_and_open(&env, &resolver, &store, &opts()).expect("admitted");
    assert_eq!(cap.kid, KID);
    assert_eq!(cap.recipient, RECIPIENT);
    assert_eq!(cap.nonce, "n-ok");
    assert_eq!(cap.payload.unwrap()["model"], "m@teechat");
    assert_eq!(store.len(), 1);
}

#[test]
fn forged_signature_fails_before_any_plaintext() {
    let kp = sender();
    let impostor = mock_keypair_from_seed(&DEV_ATTESTER_SEED);
    let mut env = sealed_request(&kp, "n-forged", &now_rfc3339(), json!({"a": 1}));
    // Same envelope, signed by a key the recipient does not trust for this kid.
    env.sig = None;
    sign_envelope(&mut env, &impostor.secret).expect("re-sign");

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();

    assert_eq!(err.code(), "ope_invalid_signature");
    assert_eq!(
        resolver.calls(),
        0,
        "no content key requested for a forged envelope"
    );
    assert_eq!(store.len(), 0, "a forged envelope must not burn a nonce");
}

#[test]
fn stale_timestamp_fails_before_any_plaintext() {
    let kp = sender();
    let stale = (chrono::Utc::now() - chrono::Duration::hours(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let env = sealed_request(&kp, "n-stale", &stale, json!({"a": 1}));

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();

    assert_eq!(err.code(), "ope_invalid_timestamp");
    assert_eq!(resolver.calls(), 0);
    assert_eq!(store.len(), 0);
}

/// Regression (TeeChat OpenAPI 0.10.4→0.10.5): edge `chrono_like_now` once emitted
/// `{unix_secs}.000Z` (e.g. `1787191719.000Z`). That is not RFC3339; under
/// `signed-only` VERIFY the engine rejects with `ope_invalid_timestamp` and clients
/// surface timeouts. Real RFC3339 millis must pass; the unix form must fail closed
/// before any content key is requested.
#[test]
fn unix_secs_dot_z_timestamp_fails_before_any_plaintext() {
    let kp = sender();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bogus = format!("{now_unix}.000Z");
    assert!(
        bogus.parse::<chrono::DateTime<chrono::Utc>>().is_err(),
        "precondition: {bogus} must not parse as RFC3339"
    );

    let env = sealed_request(&kp, "n-unix-ts", &bogus, json!({"a": 1}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();

    assert_eq!(err.code(), "ope_invalid_timestamp");
    assert!(
        matches!(
            &err,
            OpenError::Envelope(ope_envelope::Error::InvalidTimestamp(msg))
                if msg.contains("invalid RFC3339") && msg.contains(&bogus)
        ),
        "expected invalid RFC3339 detail, got {err:?}"
    );
    assert_eq!(resolver.calls(), 0, "no content key for malformed ts");
    assert_eq!(store.len(), 0);
}

#[test]
fn rfc3339_millis_timestamp_is_admitted() {
    let kp = sender();
    let env = sealed_request(&kp, "n-rfc3339", &now_rfc3339(), json!({"a": 1}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    verify_and_open(&env, &resolver, &store, &opts()).expect("RFC3339 millis must admit");
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn wrong_recipient_fails_before_any_plaintext() {
    let kp = sender();
    let mut env = base_envelope("A256GCM", "n-wrong", &now_rfc3339());
    env.recipient = "some-other-gateway".into();
    env.payload = Some(json!({"a": 1}));
    encrypt_envelope(&mut env, &DEV_CONTENT_KEY).unwrap();
    sign_envelope(&mut env, &kp.secret).unwrap();

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();

    assert_eq!(err.code(), "ope_invalid_recipient");
    assert_eq!(resolver.calls(), 0);
    assert_eq!(store.len(), 0);
}

#[test]
fn unknown_kid_fails_before_any_plaintext_and_does_not_fall_back_to_a_wildcard() {
    let kp = sender();
    let env = sealed_request(&kp, "n-unknown", &now_rfc3339(), json!({"a": 1}));
    let resolver = SpyResolver::without_sender_key(&kp);
    let store = MemoryReplayStore::new();

    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();
    assert!(matches!(err, OpenError::UnknownKid(ref k) if k == KID));
    assert_eq!(resolver.calls(), 0);
    assert_eq!(store.len(), 0);
}

#[test]
fn replayed_request_fails_before_a_second_decrypt() {
    let kp = sender();
    let env = sealed_request(&kp, "n-replay", &now_rfc3339(), json!({"a": 1}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();

    verify_and_open(&env, &resolver, &store, &opts()).expect("first is admitted");
    assert_eq!(resolver.calls(), 1);

    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();
    assert_eq!(err.code(), "ope_replay_detected");
    assert_eq!(resolver.calls(), 1, "the replay never reached decryption");
}

#[test]
fn a_rejected_forgery_does_not_burn_the_nonce_of_the_genuine_request() {
    // Reserving before verifying would let anyone lock out a real request by
    // guessing its nonce.
    let kp = sender();
    let impostor = mock_keypair_from_seed(&DEV_ATTESTER_SEED);
    let ts = now_rfc3339();

    let mut forged = sealed_request(&kp, "n-shared", &ts, json!({"a": 1}));
    forged.sig = None;
    sign_envelope(&mut forged, &impostor.secret).unwrap();

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    assert!(verify_and_open(&forged, &resolver, &store, &opts()).is_err());
    assert_eq!(store.len(), 0);

    let genuine = sealed_request(&kp, "n-shared", &ts, json!({"a": 1}));
    verify_and_open(&genuine, &resolver, &store, &opts()).expect("genuine request still admitted");
}

#[test]
fn a_payload_that_does_not_match_the_signed_hash_is_refused() {
    let kp = sender();
    let mut env = base_envelope("A256GCM", "n-hash", &now_rfc3339());
    env.payload = Some(json!({"a": 1}));
    encrypt_envelope(&mut env, &DEV_CONTENT_KEY).unwrap();
    // Sign a hash for content that is not what the ciphertext holds.
    let other = canonicalize_json(&json!({"a": 2})).unwrap();
    env.payload_hash = encode(&sha256(&other));
    sign_envelope(&mut env, &kp.secret).unwrap();

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let err = verify_and_open(&env, &resolver, &store, &opts()).unwrap_err();
    assert_eq!(err.code(), "ope_payload_hash_mismatch");
}

#[test]
fn concurrent_duplicates_admit_exactly_one() {
    // The pre-RB-05 shape read a snapshot of the seen set and inserted
    // afterwards, so both copies could observe "not seen".
    let kp = sender();
    let env = sealed_request(&kp, "n-race", &now_rfc3339(), json!({"a": 1}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let admitted = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                if verify_and_open(&env, &resolver, &store, &opts()).is_ok() {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    assert_eq!(admitted.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn an_unreachable_replay_store_fails_closed_without_claiming_a_replay() {
    // "Could not check" and "check failed" are different incidents; reporting
    // the first as the second sends an operator hunting a forgery.
    let kp = sender();
    let env = sealed_request(&kp, "n-store", &now_rfc3339(), json!({"a": 1}));
    let resolver = SpyResolver::new(&kp);

    let err = verify_and_open(&env, &resolver, &BrokenReplayStore, &opts()).unwrap_err();
    assert_eq!(err.code(), "ope_replay_store_unavailable");
    assert!(!matches!(err, OpenError::Replay { .. }));
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn an_opaque_e2e_envelope_is_admitted_without_the_relay_holding_plaintext() {
    let kp = sender();
    let mut env = base_envelope(Envelope::ENC_E2E_HYBRID_PQ, "n-e2e", &now_rfc3339());
    env.engine_id = Some("engine-1".into());
    env.e2e = Some(json!({"kex": "X25519MLKEM768", "ephemeral_epoch": "epoch-1"}));
    env.meta = Some(json!({"model": "gpt@teechat"}));
    env.payload_hash = encode(&sha256(b"opaque"));
    env.ciphertext = Some(encode(b"sealed-to-engine"));
    env.iv = Some(encode(b"iv-bytes"));
    sign_envelope(&mut env, &kp.secret).unwrap();

    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();
    let cap = verify_and_open(
        &env,
        &resolver,
        &store,
        &OpenOptions {
            require_routed_model: true,
            allow_opaque_e2e: true,
            ..opts()
        },
    )
    .expect("relayed");

    assert!(cap.is_opaque());
    assert_eq!(cap.model.as_deref(), Some("gpt@teechat"));
    assert_eq!(cap.engine_id.as_deref(), Some("engine-1"));
    assert_eq!(resolver.calls(), 0, "a relay never asks for a content key");
}

#[test]
fn a_plaintext_envelope_still_requires_a_routed_model_when_asked() {
    let kp = sender();
    let env = plaintext_request(&kp, "n-model", &now_rfc3339(), json!({"model": "bare"}));
    let resolver = SpyResolver::new(&kp);
    let store = MemoryReplayStore::new();

    let err = verify_and_open(
        &env,
        &resolver,
        &store,
        &OpenOptions {
            require_routed_model: true,
            ..opts()
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), "ope_invalid_model_id");
}
