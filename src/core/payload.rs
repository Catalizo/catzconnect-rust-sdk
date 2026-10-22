use crate::{
    error::CatzError,
    types::{Channel, MessageType, SendExtras, SendInput, Template},
    utils::validators::{validate_email, validate_phone},
};

/// Email subscription topic keys: `[a-z0-9]` then up to 39 of `[a-z0-9_-]`.
pub fn is_email_topic_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 40
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Push topic names: 1–64 of `A-Z a-z 0-9 _ . ~ -`.
pub fn is_push_topic(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.~-".contains(&c))
}

/// RFC 3339 with a zone: `YYYY-MM-DDTHH:MM[:SS[.frac]](Z|±HH:MM)`.
pub fn is_rfc3339_with_zone(s: &str) -> bool {
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d(:[0-5]\d(\.\d+)?)?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$").unwrap()
    });
    RE.is_match(s.trim())
}

fn verify_topic_and_push(input: &SendInput, extras: &SendExtras) -> Result<(), CatzError> {
    let v = |m: &str| Err(CatzError::Validation(m.into()));
    if let Some(t) = &extras.topic {
        if !matches!(input.channel, Channel::Email) {
            return v("'topic' applies to the Email channel only — for push topics use push.topic");
        }
        if !is_email_topic_key(t) {
            return v("'topic' must be a topic key: lower-case letters, digits, _ and -, up to 40 characters");
        }
    }
    let Some(p) = &extras.push else { return Ok(()) };
    if !matches!(input.channel, Channel::Push) {
        return v("'push' applies to the Push channel only");
    }
    if p.broadcast && p.topic.is_some() {
        return v("Give push.broadcast or push.topic, not both");
    }
    if p.topic.as_deref().is_some_and(|t| !is_push_topic(t)) {
        return v("'push.topic' must be 1–64 characters of letters, digits, _ . ~ -");
    }
    if p.send_at.as_deref().is_some_and(|s| !is_rfc3339_with_zone(s)) {
        return v("'push.send_at' must be an RFC 3339 time with a time zone, e.g. 2026-11-02T09:00:00Z");
    }
    if p.broadcast || p.topic.is_some() {
        let set = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.trim().is_empty());
        if set(&input.payload.to) || set(&input.payload.external_user_id) {
            return v("push.broadcast and push.topic send to many devices: leave 'to' and 'external_user_id' out");
        }
        if input.payload.device_key.is_some() {
            return v("'device_key' is only for one device token — registered devices use their own keys");
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn verify_payload(input: &SendInput) -> Result<(), CatzError> {
    verify_payload_with(input, &SendExtras::default())
}

pub fn verify_payload_with(input: &SendInput, extras: &SendExtras) -> Result<(), CatzError> {
    if extras.tracking.is_some() && !matches!(input.channel, Channel::Email) {
        return Err(CatzError::Validation("'tracking' applies to the Email channel only".into()));
    }
    verify_topic_and_push(input, extras)?;
    if extras.whatsapp.is_some() && !matches!(input.channel, Channel::WhatsApp) {
        return Err(CatzError::Validation("'whatsapp' applies to the WhatsApp channel only".into()));
    }
    let media = extras.whatsapp.as_ref().and_then(|w| w.media.as_ref());
    match (&input.channel, &input.message_type, &input.template) {
        // A WhatsApp media message: Custom with whatsapp.media (any type).
        (Channel::WhatsApp, _, Template::Custom) if media.is_some() => {
            let to = required(&input.payload.to, "to")?;
            validate_phone(to)?;
            crate::whatsapp::verify_media(media.unwrap_or(&Default::default()))
        }
        // An approved WhatsApp template by its Meta name.
        (Channel::WhatsApp, MessageType::Transactional | MessageType::Verification | MessageType::Promotional | MessageType::Notification, Template::Named(name)) => {
            if !crate::whatsapp::is_template_name(name) {
                return Err(CatzError::Validation(
                    "A WhatsApp template name is lower-case letters, digits and underscores (the name approved at Meta)".into(),
                ));
            }
            let to = required(&input.payload.to, "to")?;
            validate_phone(to)?;
            if let Some(otp) = input.payload.otp.as_deref() {
                if otp.is_empty() || otp.len() > 15 || !otp.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(CatzError::Validation("'otp' must be up to 15 letters or digits".into()));
                }
            }
            if let Some(w) = &extras.whatsapp {
                if w.media.is_some() {
                    return Err(CatzError::Validation(
                        "'whatsapp.media' goes with Template::Custom; use 'whatsapp.header' for a template's media".into(),
                    ));
                }
                crate::whatsapp::verify_options(w)?;
            }
            Ok(())
        }
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
            // A broadcast / topic push has no single recipient (checked above).
            let many = extras.push.as_ref().is_some_and(|p| p.broadcast || p.topic.is_some());
            match (to, user) {
                (None, None) if many => {}
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
        // SMS: Otp, Custom, or an SMS template from the panel by name.
        (Channel::Sms, _, _) => crate::sms::verify(input),
        (Channel::Voice, _, _) => crate::voice::verify(input),
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
