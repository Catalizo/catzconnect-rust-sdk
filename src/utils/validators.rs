use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::CatzError;

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("invalid email regex"));

pub fn validate_email(email: &str) -> Result<(), CatzError> {
    if EMAIL_RE.is_match(email) {
        Ok(())
    } else {
        Err(CatzError::Validation(format!("Invalid email: {email}")))
    }
}
