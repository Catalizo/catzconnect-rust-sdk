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
            let to = input.payload.to.as_deref().filter(|s| !s.trim().is_empty());
            let user = input.payload.external_user_id.as_deref().filter(|s| !s.trim().is_empty());
            match (to, user) {
                (Some(_), Some(_)) => {
                    return Err(CatzError::Validation(
                        "Give either 'to' (one device token) or 'external_user_id' (a user's registered devices), not both".into(),
                    ));
                }
                (None, None) => {
                    return Err(CatzError::Validation(
                        "Missing 'to' in payload — the device's FCM registration token — or 'external_user_id' for a user's registered devices".into(),
                    ));
                }
                _ => {}
            }
            if let Some(to) = to {
                if to.contains('@') {
                    return Err(CatzError::Validation(
                        "'to' must be an FCM registration token, not an email address".into(),
                    ));
                }
            }
            if let Some(user) = user {
                if user.chars().count() > 128 {
                    return Err(CatzError::Validation(
                        "'external_user_id' must be a string of up to 128 characters".into(),
                    ));
                }
                if input.payload.device_key.is_some() {
                    return Err(CatzError::Validation(
                        "'device_key' cannot be used with 'external_user_id' — each registered device's own key is used".into(),
                    ));
                }
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
        // A panel email template by name; the server fills it from data.
        (Channel::Email, _, Template::Named(name)) => {
            if name.trim().is_empty() {
                return Err(CatzError::Validation("Template name is empty".into()));
            }
            let to = required(&input.payload.to, "to")?;
            validate_email(to)?;
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
