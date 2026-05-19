use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let raw = b"hello-ope";
        let enc = encode(raw);
        assert_eq!(decode(&enc).unwrap(), raw);
    }
}
