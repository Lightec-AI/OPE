//! OPE L2: hybrid key exchange aligned with draft-ietf-tls-ecdhe-mlkem.

mod error;
mod hybrid;
mod sizes;
pub mod vectors;

pub use error::Error;
pub use hybrid::{
    client_from_test_material, client_shared_secret, combine_shared_secrets,
    mlkem_decapsulate, parse_decapsulation_key, x25519_shared_secret, ClientKeyExchange,
    ServerKeyExchange,
};
pub use sizes::{
    GROUP_X25519_MLKEM768, MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN,
    MLKEM768_SHARED_SECRET_LEN, X25519MLKEM768_CLIENT_SHARE_LEN, X25519MLKEM768_SERVER_SHARE_LEN,
    X25519MLKEM768_SHARED_SECRET_LEN, X25519_SHARE_LEN,
};
