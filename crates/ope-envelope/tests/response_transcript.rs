//! RB-06 tamper vectors: every way a relay can edit a response stream must be
//! visible at the first offending frame, and the header must be verified before
//! any frame is consumed.

use ope_crypto::{encode, mock_keypair_from_seed, sha256, DEV_ATTESTER_SEED, DEV_VECTOR_001_SEED};
use ope_envelope::{
    SignedTranscriptHeader, TranscriptError, TranscriptExpectations, TranscriptFrame,
    TranscriptHeader, TranscriptReader, TranscriptWriter, DOMAIN_FRAME, DOMAIN_HEADER,
};

const NONCE: &str = "req-nonce-1";
const ENGINE: &str = "engine-a";
const EPOCH: &str = "epoch-2026-08-01";

fn header() -> TranscriptHeader {
    TranscriptHeader::new(NONCE, ENGINE, EPOCH, "A256GCM")
}

fn expectations() -> TranscriptExpectations {
    TranscriptExpectations {
        request_nonce: Some(NONCE.into()),
        engine_id: Some(ENGINE.into()),
        epoch_id: Some(EPOCH.into()),
    }
}

/// A three-frame response from the engine that holds `seed`.
fn transcript(seed: &[u8; 32]) -> (SignedTranscriptHeader, Vec<TranscriptFrame>) {
    let kp = mock_keypair_from_seed(seed);
    let (signed, mut writer) = TranscriptWriter::begin(header(), &kp.secret).unwrap();
    let frames = vec![
        writer.push(b"frame-0", false).unwrap(),
        writer.push(b"frame-1", false).unwrap(),
        writer.push(b"frame-2", true).unwrap(),
    ];
    (signed, frames)
}

fn engine_transcript() -> (SignedTranscriptHeader, Vec<TranscriptFrame>) {
    transcript(&DEV_VECTOR_001_SEED)
}

fn reader(signed: &SignedTranscriptHeader) -> TranscriptReader {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    TranscriptReader::begin(signed, &kp.public, &expectations()).expect("header verifies")
}

#[test]
fn an_untampered_transcript_round_trips_in_order() {
    let (signed, frames) = engine_transcript();
    let mut reader = reader(&signed);

    assert_eq!(reader.accept(&frames[0]).unwrap(), b"frame-0");
    assert_eq!(reader.accept(&frames[1]).unwrap(), b"frame-1");
    assert_eq!(reader.accept(&frames[2]).unwrap(), b"frame-2");
    assert!(reader.is_complete());
    reader.finish().expect("complete");
}

#[test]
fn a_header_signed_by_another_key_yields_no_reader_at_all() {
    // Verify-before-first-frame is structural: without a reader there is no
    // `accept` to call, so no frame can be consumed on a bad header.
    let (signed, _frames) = transcript(&DEV_ATTESTER_SEED);
    let engine = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);

    let err = TranscriptReader::begin(&signed, &engine.public, &expectations()).unwrap_err();
    assert_eq!(err, TranscriptError::InvalidHeaderSignature);
}

#[test]
fn an_edited_header_field_breaks_the_signature() {
    let (mut signed, _frames) = engine_transcript();
    signed.header.epoch_id = "epoch-attacker".into();
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);

    let err = TranscriptReader::begin(&signed, &kp.public, &expectations()).unwrap_err();
    assert_eq!(err, TranscriptError::InvalidHeaderSignature);
}

#[test]
fn a_genuine_response_to_a_different_request_is_refused() {
    // Correctly signed, correct engine, wrong question — the substitution a
    // per-frame AEAD cannot see.
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let other = TranscriptHeader::new("req-nonce-other", ENGINE, EPOCH, "A256GCM");
    let (signed, _writer) = TranscriptWriter::begin(other, &kp.secret).unwrap();

    let err = TranscriptReader::begin(&signed, &kp.public, &expectations()).unwrap_err();
    assert_eq!(
        err,
        TranscriptError::RequestMismatch {
            expected: NONCE.into(),
            actual: "req-nonce-other".into(),
        }
    );
}

#[test]
fn a_response_from_a_different_engine_or_epoch_is_refused() {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let (signed, _writer) = TranscriptWriter::begin(
        TranscriptHeader::new(NONCE, "engine-b", EPOCH, "A256GCM"),
        &kp.secret,
    )
    .unwrap();
    assert!(matches!(
        TranscriptReader::begin(&signed, &kp.public, &expectations()).unwrap_err(),
        TranscriptError::EngineMismatch { .. }
    ));

    let (signed, _writer) = TranscriptWriter::begin(
        TranscriptHeader::new(NONCE, ENGINE, "epoch-old", "A256GCM"),
        &kp.secret,
    )
    .unwrap();
    assert!(matches!(
        TranscriptReader::begin(&signed, &kp.public, &expectations()).unwrap_err(),
        TranscriptError::EpochMismatch { .. }
    ));
}

#[test]
fn a_substituted_frame_body_breaks_the_chain() {
    let (signed, mut frames) = engine_transcript();
    frames[1].ciphertext = encode(b"attacker-frame");
    let mut reader = reader(&signed);

    reader.accept(&frames[0]).unwrap();
    assert_eq!(
        reader.accept(&frames[1]).unwrap_err(),
        TranscriptError::ChainMismatch { seq: 1 }
    );
}

#[test]
fn reordered_frames_are_refused() {
    let (signed, frames) = engine_transcript();
    let mut reader = reader(&signed);

    assert_eq!(
        reader.accept(&frames[1]).unwrap_err(),
        TranscriptError::OutOfOrder {
            expected: 0,
            actual: 1
        }
    );
}

#[test]
fn a_duplicated_frame_is_refused() {
    let (signed, frames) = engine_transcript();
    let mut reader = reader(&signed);

    reader.accept(&frames[0]).unwrap();
    assert_eq!(
        reader.accept(&frames[0]).unwrap_err(),
        TranscriptError::OutOfOrder {
            expected: 1,
            actual: 0
        }
    );
}

#[test]
fn a_truncated_stream_is_refused_even_though_every_frame_was_valid() {
    let (signed, frames) = engine_transcript();
    let mut reader = reader(&signed);

    reader.accept(&frames[0]).unwrap();
    reader.accept(&frames[1]).unwrap();
    assert!(!reader.is_complete());
    assert_eq!(
        reader.finish().unwrap_err(),
        TranscriptError::Truncated { received: 2 }
    );
}

#[test]
fn a_relay_cannot_end_the_stream_early_by_flipping_the_final_flag() {
    // `final` is inside the chain link, so claiming completeness edits the hash.
    let (signed, mut frames) = engine_transcript();
    frames[0].final_ = true;
    let mut reader = reader(&signed);

    assert_eq!(
        reader.accept(&frames[0]).unwrap_err(),
        TranscriptError::ChainMismatch { seq: 0 }
    );
}

#[test]
fn frames_from_another_transcript_cannot_be_spliced_in() {
    // Same engine key, same frame bodies, different header: the chain is
    // anchored on the header, so even seq 0 does not fit.
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let (_other_signed, mut other_writer) = TranscriptWriter::begin(
        TranscriptHeader::new("req-nonce-other", ENGINE, EPOCH, "A256GCM"),
        &kp.secret,
    )
    .unwrap();
    let foreign = other_writer.push(b"frame-0", false).unwrap();

    let (signed, _frames) = engine_transcript();
    let mut reader = reader(&signed);
    assert_eq!(
        reader.accept(&foreign).unwrap_err(),
        TranscriptError::ChainMismatch { seq: 0 }
    );
}

#[test]
fn rejecting_an_injected_frame_leaves_the_stream_usable() {
    let (signed, frames) = engine_transcript();
    let injected = TranscriptFrame {
        seq: 0,
        ciphertext: encode(b"injected"),
        final_: false,
        chain: encode(&[0u8; 32]),
    };
    let mut reader = reader(&signed);

    assert!(reader.accept(&injected).is_err());
    assert_eq!(reader.frames_accepted(), 0);
    assert_eq!(reader.accept(&frames[0]).unwrap(), b"frame-0");
}

#[test]
fn frames_after_the_final_one_are_refused() {
    let (signed, frames) = engine_transcript();
    let mut reader = reader(&signed);
    for frame in &frames {
        reader.accept(frame).unwrap();
    }

    let extra = TranscriptFrame {
        seq: 3,
        ciphertext: encode(b"appended"),
        final_: true,
        chain: encode(&[0u8; 32]),
    };
    assert_eq!(
        reader.accept(&extra).unwrap_err(),
        TranscriptError::AfterFinal { seq: 3 }
    );
}

#[test]
fn a_writer_will_not_append_past_its_own_final_frame() {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let (_signed, mut writer) = TranscriptWriter::begin(header(), &kp.secret).unwrap();
    writer.push(b"only", true).unwrap();

    assert!(writer.is_closed());
    assert!(matches!(
        writer.push(b"more", false).unwrap_err(),
        TranscriptError::AfterFinal { .. }
    ));
}

#[test]
fn the_header_digest_is_domain_separated_from_frame_digests() {
    // Without distinct tags, a header digest and a frame link over the same
    // bytes could collide and let one stand in for the other.
    assert_ne!(DOMAIN_HEADER, DOMAIN_FRAME);

    let (signed, frames) = engine_transcript();
    let genesis = {
        let mut buf = Vec::from(DOMAIN_HEADER);
        buf.push(0x00);
        buf.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "content_alg": "A256GCM",
                "engine_id": ENGINE,
                "epoch_id": EPOCH,
                "ope_transcript": "1.0",
                "request_nonce": NONCE,
            }))
            .unwrap(),
        );
        sha256(&buf)
    };
    // The chain of frame 0 is under the frame tag, never the header tag.
    assert_ne!(frames[0].chain, encode(&genesis));

    let forged = TranscriptFrame {
        chain: encode(&genesis),
        ..frames[0].clone()
    };
    let mut reader = reader(&signed);
    assert_eq!(
        reader.accept(&forged).unwrap_err(),
        TranscriptError::ChainMismatch { seq: 0 }
    );
}

#[test]
fn the_signed_header_survives_a_json_round_trip() {
    let (signed, _frames) = engine_transcript();
    let wire = serde_json::to_string(&signed).unwrap();
    let parsed: SignedTranscriptHeader = serde_json::from_str(&wire).unwrap();

    assert_eq!(parsed, signed);
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    TranscriptReader::begin(&parsed, &kp.public, &expectations()).expect("verifies off the wire");
}
