//! Local conversation storage layout (`ope.md` P4 / ROADMAP).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConversationError {
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}

/// File entry in a conversation manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestEntry {
    pub file_id: String,
    pub sha256: String,
    pub path: String,
}

/// Conversation folder manifest (`conversations/<id>/manifest.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationManifest {
    pub conversation_id: String,
    pub created_at: String,
    pub files: Vec<FileManifestEntry>,
}

impl ConversationManifest {
    pub fn validate(&self) -> Result<(), ConversationError> {
        if self.conversation_id.is_empty() {
            return Err(ConversationError::InvalidManifest(
                "conversation_id required".into(),
            ));
        }
        for f in &self.files {
            if f.file_id.is_empty() || f.sha256.len() != 43 {
                return Err(ConversationError::InvalidManifest(
                    "file_id and base64url sha256 required".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Recommended on-disk layout.
pub const LAYOUT_README: &str = r#"conversations/<conversation_id>/
  manifest.json       # ConversationManifest
  messages.jsonl      # optional message log
  files/              # attachments keyed by file_id
"#;
