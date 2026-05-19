use ope_conversation_sdk::{ConversationManifest, FileManifestEntry};

#[test]
fn manifest_validates() {
    let m = ConversationManifest {
        conversation_id: "conv-1".into(),
        created_at: "2026-05-19T00:00:00Z".into(),
        files: vec![FileManifestEntry {
            file_id: "f1".into(),
            sha256: "IfBq5V-pFYBzzfW2K3S-zNKdsplvqUQW5rzB9Y-K5R4".into(),
            path: "files/f1.bin".into(),
        }],
    };
    m.validate().unwrap();
}
