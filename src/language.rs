//! The optional `language` of a send: the language of the built-in (default)
//! Otp/Verification templates. Set it with [`SendPayload::language`]; it is
//! sent at the top level of the request body, next to `channel`/`template`.
//!
//! [`SendPayload::language`]: crate::types::SendPayload::language

use crate::error::CatzError;

/// The languages the built-in Otp/Verification templates come in.
pub const SUPPORTED_LANGUAGES: [&str; 5] = ["en", "de", "ja", "ar", "hi"];

/// Reduces a language to its BCP-47 primary subtag: `"de"`, `"DE"`,
/// `"de-DE"` and `"de_DE"` all become `"de"`. Anything that is not one of
/// en, de, ja, ar, hi is a [`CatzError::Validation`].
///
/// ```
/// assert_eq!(catzconnect::language::normalize_language("de-DE").unwrap(), "de");
/// assert!(catzconnect::language::normalize_language("fr").is_err());
/// ```
pub fn normalize_language(language: &str) -> Result<&'static str, CatzError> {
    let tag = language.trim();
    let well_formed = !tag.is_empty()
        && tag
            .split(['-', '_'])
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()));
    let primary = tag.split(['-', '_']).next().unwrap_or("").to_ascii_lowercase();
    if well_formed {
        if let Some(l) = SUPPORTED_LANGUAGES.iter().find(|l| **l == primary) {
            return Ok(l);
        }
    }
    Err(CatzError::Validation(format!(
        "Unsupported 'language' \"{language}\": use one of en, de, ja, ar, hi (or a BCP-47 tag such as de-DE)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_supported_languages() {
        for (input, want) in [("en", "en"), ("DE", "de"), ("de-DE", "de"), ("ja_JP", "ja"), (" ar-EG ", "ar"), ("hi-Latn-IN", "hi")] {
            assert_eq!(normalize_language(input).unwrap(), want, "{input}");
        }
    }

    #[test]
    fn rejects_unknown_languages_clearly() {
        for bad in ["fr", "fr-FR", "", "-", "de--DE", "english", "d e", "de-"] {
            let err = normalize_language(bad).unwrap_err().to_string();
            assert!(err.contains("en, de, ja, ar, hi"), "{bad}: {err}");
        }
    }
}
