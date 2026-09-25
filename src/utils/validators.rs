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

/// A WhatsApp recipient: digits, optionally written with +, spaces, dashes or
/// brackets. The server normalises it; this rejects what can never work.
pub fn validate_phone(phone: &str) -> Result<(), CatzError> {
    if phone.contains('@') {
        return Err(CatzError::Validation(format!(
            "WhatsApp messages go to phone numbers, not email addresses: {phone}"
        )));
    }
    if !phone.chars().all(|c| c.is_ascii_digit() || " ()+-".contains(c)) {
        return Err(CatzError::Validation(format!("Invalid phone number: {phone}")));
    }
    let digits = phone.chars().filter(|c| c.is_ascii_digit()).count();
    if !(7..=15).contains(&digits) {
        return Err(CatzError::Validation(format!("Invalid phone number: {phone}")));
    }
    Ok(())
}
