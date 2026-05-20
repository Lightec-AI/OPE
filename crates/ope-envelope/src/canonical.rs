use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::envelope::Envelope;
use crate::Error;

/// RFC 8785-style JSON canonicalization (JCS subset used by OPE).
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                write!(out, "{i}").map_err(|e| Error::Canonical(e.to_string()))?;
            } else if let Some(u) = n.as_u64() {
                write!(out, "{u}").map_err(|e| Error::Canonical(e.to_string()))?;
            } else if let Some(f) = n.as_f64() {
                write_float(f, out)?;
            } else {
                return Err(Error::Canonical("unsupported number".into()));
            }
        }
        Value::String(s) => write_string(s, out)?,
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(map, out)?,
    }
    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut String) -> Result<(), Error> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(key, out)?;
        out.push(':');
        write_canonical(&map[*key], out)?;
    }
    out.push('}');
    Ok(())
}

fn write_string(s: &str, out: &mut String) -> Result<(), Error> {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                write!(out, "\\u{:04x}", c as u32).map_err(|e| Error::Canonical(e.to_string()))?;
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(())
}

/// ES6 number string for finite floats (JCS requires no NaN/Infinity).
fn write_float(f: f64, out: &mut String) -> Result<(), Error> {
    if !f.is_finite() {
        return Err(Error::Canonical("non-finite number".into()));
    }
    if f == 0.0 && f.is_sign_negative() {
        out.push_str("-0");
        return Ok(());
    }
    let s = serde_json::Number::from_f64(f)
        .ok_or_else(|| Error::Canonical("invalid float".into()))?
        .to_string();
    out.push_str(&s);
    Ok(())
}

/// Fields included in the Ed25519 signature per ope.md §5.
pub fn signed_fields_object(envelope: &Envelope) -> Result<Value, Error> {
    let mut obj = serde_json::json!({
        "ope_version": envelope.ope_version,
        "alg": envelope.alg,
        "enc": envelope.enc,
        "kid": envelope.kid,
        "recipient": envelope.recipient,
        "ts": envelope.ts,
        "nonce": envelope.nonce,
        "payload_hash": envelope.payload_hash,
    });

    if let Some(ct) = &envelope.ciphertext {
        obj["ciphertext"] = serde_json::json!(ct);
    }
    if let Some(iv) = &envelope.iv {
        obj["iv"] = serde_json::json!(iv);
    }
    if let Some(aad) = &envelope.aad {
        obj["aad"] = aad.clone();
    }
    if let Some(engine_id) = &envelope.engine_id {
        obj["engine_id"] = serde_json::json!(engine_id);
    }
    if let Some(e2e) = &envelope.e2e {
        obj["e2e"] = e2e.clone();
    }

    Ok(obj)
}

pub fn payload_hash(payload: &Value) -> Result<String, Error> {
    let bytes = canonicalize_json(payload)?;
    let digest = ope_crypto::sha256(&bytes);
    Ok(ope_crypto::encode(&digest))
}

pub fn signing_bytes(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    let signed = signed_fields_object(envelope)?;
    canonicalize_json(&signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_sorted() {
        let v = json!({"b": 1, "a": 2});
        let c = canonicalize_json(&v).unwrap();
        assert_eq!(String::from_utf8(c).unwrap(), r#"{"a":2,"b":1}"#);
    }
}
