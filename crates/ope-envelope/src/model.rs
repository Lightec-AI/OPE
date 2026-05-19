//! OPE-OpenAI routed model ID: `base@provider-slug`.

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedModel {
    pub base: String,
    pub provider: String,
}

/// Parse `payload.model` per ope.md §8.1.
pub fn parse_routed_model(model: &str) -> Result<RoutedModel, Error> {
    let Some((base, provider)) = model.rsplit_once('@') else {
        return Err(Error::InvalidModelId(format!(
            "model must be base@provider-slug, got: {model}"
        )));
    };
    if base.is_empty() || provider.is_empty() {
        return Err(Error::InvalidModelId(format!("empty segment in: {model}")));
    }
    if !provider
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::InvalidModelId(format!(
            "invalid provider slug: {provider}"
        )));
    }
    if base.contains('@') {
        return Err(Error::InvalidModelId(format!("multiple @ in: {model}")));
    }
    Ok(RoutedModel {
        base: base.to_string(),
        provider: provider.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid() {
        let m = parse_routed_model("gpt-4.1@openai").unwrap();
        assert_eq!(m.base, "gpt-4.1");
        assert_eq!(m.provider, "openai");
    }

    #[test]
    fn rejects_missing_suffix() {
        assert!(parse_routed_model("gpt-4.1").is_err());
    }
}
