use crate::{
    error::CatzError,
    types::{Channel, MessageType, SendInput, Template},
    utils::validators::{validate_email, validate_phone},
};

pub fn verify_payload(input: &SendInput) -> Result<(), CatzError> {
    match (&input.channel, &input.message_type, &input.template) {
        (Channel::Email, MessageType::Verification, Template::Otp) => {
            let to = input
                .payload
                .to
                .as_deref()
                .ok_or_else(|| CatzError::Validation("Missing 'to' in payload".into()))?;

            if input.payload.otp.is_none() {
                return Err(CatzError::Validation("Missing 'otp' in payload".into()));
            }

            validate_email(to)?;

            Ok(())
        }
        (Channel::Email, MessageType::Transactional, Template::Custom) => {
            let to = input
                .payload
                .to
                .as_deref()
                .ok_or_else(|| CatzError::Validation("Missing 'to' in payload".into()))?;

            if input.payload.subject.is_none() {
                return Err(CatzError::Validation("Missing 'subject' in payload".into()));
            }

            if input.payload.body.is_none() {
                return Err(CatzError::Validation("Missing 'body' in payload".into()));
            }

            validate_email(to)?;

            Ok(())
        }
        (Channel::WhatsApp, MessageType::Verification, Template::Otp) => {
            let to = required(&input.payload.to, "to")?;
            validate_phone(to)?;
            let otp = required(&input.payload.otp, "otp")?;
            // Meta's authentication templates take up to 15 letters or digits.
            if otp.is_empty() || otp.len() > 15 || !otp.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(CatzError::Validation("'otp' must be up to 15 letters or digits".into()));
            }
            Ok(())
        }
        (Channel::WhatsApp, MessageType::Transactional, Template::Custom) => {
            let to = required(&input.payload.to, "to")?;
            validate_phone(to)?;
            let body = required(&input.payload.body, "body")?;
            let len = body.chars().count()
                + input.payload.subject.as_deref().map_or(0, |s| s.chars().count() + 6);
            if len > 4096 {
                return Err(CatzError::Validation("WhatsApp messages are limited to 4096 characters".into()));
            }
            Ok(())
        }
        (Channel::Push, MessageType::Notification, Template::Notification) => {
            let to = required(&input.payload.to, "to")?;
            if to.contains('@') {
                return Err(CatzError::Validation(
                    "'to' must be an FCM registration token, not an email address".into(),
                ));
            }
            required(&input.payload.body, "body")?;
            for (name, v) in [("image", &input.payload.image), ("link", &input.payload.link)] {
                if let Some(v) = v.as_deref() {
                    if !v.starts_with("https://") {
                        return Err(CatzError::Validation(format!("'{name}' must be an https:// URL")));
                    }
                }
            }
            Ok(())
        }
        _ => Err(CatzError::Validation(
            "Unsupported channel/message_type/template combination".into(),
        )),
    }
}

fn required<'a>(v: &'a Option<String>, name: &str) -> Result<&'a str, CatzError> {
    v.as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| CatzError::Validation(format!("Missing '{name}' in payload")))
}
