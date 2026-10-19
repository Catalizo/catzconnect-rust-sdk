//! Phone calls (text-to-speech) through `send()` with [`Channel::Voice`]:
//! the server's checks, so a refused request fails before it is encrypted
//! and sent.
//!
//! [`Channel::Voice`]: crate::types::Channel::Voice

use serde_json::{Map, Value};

use crate::{
    error::CatzError,
    sms::normalise_e164,
    types::SendInput,
};

/// Longest Custom text a phone call speaks.
pub const MAX_CHARS: usize = 1000;
/// Most times a phone call repeats its message.
pub const MAX_REPEAT: u8 = 3;

/// A language tag such as `en-US`, `hi-IN`, `es-419` or `fr`.
pub fn is_valid_language(s: &str) -> bool {
    let mut parts = s.split('-');
    let Some(first) = parts.next() else { return false };
    if !(2..=3).contains(&first.len()) || !first.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    rest.len() <= 2
        && rest
            .iter()
            .all(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// `female`, `male`, or a provider voice name such as `Polly.Joanna`.
pub fn is_valid_voice_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.trim() == s
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | ' '))
}

/// The server's error for a Custom text it would refuse.
pub fn validate_text(text: &str) -> Result<(), CatzError> {
    let t = text.trim();
    if t.is_empty() {
        return Err(CatzError::Validation("The text to speak is empty".into()));
    }
    if t.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(CatzError::Validation("The text to speak contains control characters".into()));
    }
    let n = t.chars().count();
    if n > MAX_CHARS {
        return Err(CatzError::Validation(format!(
            "The text to speak is {n} characters; the limit is {MAX_CHARS}"
        )));
    }
    Ok(())
}

/// `data.repeat` as the server reads it: a whole number 1–3.
pub fn parse_repeat(s: &str) -> Result<u8, CatzError> {
    match s.trim().parse::<u8>() {
        Ok(n) if (1..=MAX_REPEAT).contains(&n) => Ok(n),
        _ => Err(CatzError::Validation("'data.repeat' must be a whole number from 1 to 3".into())),
    }
}

fn trimmed(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// The server's checks for a Voice send: an E.164 `to`; `Otp` with `otp`
/// (up to 15 letters or digits, read out one by one); `Custom` with `body`
/// (≤ 1,000 characters); any other name is a Voice template from the panel
/// filled from `data`. `data.language`, `data.voice` and `data.repeat` are
/// optional. `identity` is ignored.
pub(crate) fn verify(input: &SendInput) -> Result<(), CatzError> {
    let v = |m: &str| Err(CatzError::Validation(m.to_string()));
    let p = &input.payload;

    let Some(raw_to) = trimmed(&p.to) else {
        return v("Missing 'to' in payload — the number to call in E.164, e.g. +14155550100");
    };
    if normalise_e164(raw_to).is_none() {
        return Err(CatzError::Validation(format!(
            "'{raw_to}' is not an E.164 phone number — use + and the country code, e.g. +919876543210"
        )));
    }

    if let Some(data) = &p.data {
        for (k, val) in data {
            match k.as_str() {
                "repeat" => {
                    parse_repeat(val)?;
                }
                "language" if !is_valid_language(val) => {
                    return v("'data.language' must be a language tag such as en-US");
                }
                "voice" if !is_valid_voice_name(val) => {
                    return v("'data.voice' must be female, male or a provider voice name");
                }
                _ => {}
            }
        }
    }

    let name = input.template.name().trim();
    if name.is_empty() {
        return v("Missing 'template' — Otp, Custom, or the name of a Voice template");
    }
    if name.eq_ignore_ascii_case("otp") {
        let Some(otp) = trimmed(&p.otp) else {
            return v("Missing 'otp' in payload");
        };
        if otp.len() > 15 || !otp.chars().all(|c| c.is_ascii_alphanumeric()) {
            return v("'otp' must be up to 15 letters or digits");
        }
    } else if name.eq_ignore_ascii_case("custom") {
        let Some(body) = trimmed(&p.body) else {
            return v("Missing 'body' in payload — the text to speak");
        };
        validate_text(body)?;
    }
    // A panel Voice template: the server renders it from data.
    Ok(())
}

/// The JSON body (before encryption) for a Voice send: only the fields the
/// server reads.
pub(crate) fn build_payload(input: &SendInput) -> Value {
    let p = &input.payload;
    let name = input.template.name().trim();
    let template = if name.eq_ignore_ascii_case("otp") {
        "Otp"
    } else if name.eq_ignore_ascii_case("custom") {
        "Custom"
    } else {
        name
    };
    let to = trimmed(&p.to).and_then(normalise_e164).or_else(|| p.to.clone());

    let mut m = Map::new();
    m.insert("message_type".into(), format!("{:?}", input.message_type).into());
    m.insert("channel".into(), "Voice".into());
    m.insert("template".into(), template.into());
    // Required by the server, ignored for Voice.
    m.insert("identity".into(), input.identity.clone().into());
    m.insert("to".into(), to.into());
    for (k, val) in [("otp", &p.otp), ("body", &p.body), ("provider", &p.provider)] {
        if let Some(t) = trimmed(val) {
            m.insert(k.into(), t.into());
        }
    }
    if let Some(data) = p.data.as_ref().filter(|d| !d.is_empty()) {
        let obj: Map<String, Value> = data
            .iter()
            .map(|(k, v)| {
                let v = if k == "repeat" {
                    parse_repeat(v).map(|n| n.to_string()).unwrap_or_else(|_| v.clone())
                } else {
                    v.clone()
                };
                (k.clone(), Value::from(v))
            })
            .collect();
        m.insert("data".into(), Value::Object(obj));
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Channel, MessageType, SendPayload, Template};
    use std::collections::HashMap;

    fn voice(t: MessageType, tpl: Template, p: SendPayload) -> SendInput {
        SendInput { message_type: t, channel: Channel::Voice, template: tpl, identity: String::new(), payload: p }
    }

    #[test]
    fn channel_parses_case_insensitively() {
        assert!(matches!("voice".parse::<Channel>().unwrap(), Channel::Voice));
        assert!(matches!("Voice".parse::<Channel>().unwrap(), Channel::Voice));
        assert_eq!(Channel::Voice.name(), "Voice");
        assert!("fax".parse::<Channel>().is_err());
    }

    #[test]
    fn builds_the_voice_payload() {
        let data: HashMap<String, String> =
            [("language", "en-US"), ("voice", "female"), ("repeat", "02")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let input = voice(
            MessageType::Verification,
            Template::Named("otp".into()),
            SendPayload { to: Some("+1 (415) 555-0100".into()), otp: Some("123456".into()), data: Some(data), provider: Some("Twilio main".into()), ..Default::default() },
        );
        crate::core::payload::verify_payload(&input).unwrap();
        let b = build_payload(&input);
        assert_eq!(b["channel"], "Voice");
        assert_eq!(b["template"], "Otp");
        assert_eq!(b["to"], "+14155550100");
        assert_eq!(b["otp"], "123456");
        assert_eq!(b["provider"], "Twilio main");
        assert_eq!(b["data"]["repeat"], "2");
        assert_eq!(b["data"]["language"], "en-US");
        assert_eq!(b["identity"], "");
    }

    #[test]
    fn validation_matches_server() {
        let to = || Some("+14155550100".to_string());
        let d = |k: &str, v: &str| Some([(k.to_string(), v.to_string())].into_iter().collect::<HashMap<_, _>>());
        let custom = |p: SendPayload| voice(MessageType::Notification, Template::Custom, p);
        let bad = [
            (custom(SendPayload { to: Some("4155550100".into()), body: Some("hi".into()), ..Default::default() }), "E.164"),
            (custom(SendPayload { to: to(), ..Default::default() }), "Missing 'body'"),
            (custom(SendPayload { to: to(), body: Some("a".repeat(1001)), ..Default::default() }), "1000"),
            (custom(SendPayload { to: to(), body: Some("a\u{7}".into()), ..Default::default() }), "control"),
            (custom(SendPayload { to: to(), body: Some("hi".into()), data: d("repeat", "4"), ..Default::default() }), "repeat"),
            (custom(SendPayload { to: to(), body: Some("hi".into()), data: d("repeat", "0"), ..Default::default() }), "repeat"),
            (custom(SendPayload { to: to(), body: Some("hi".into()), data: d("language", "english"), ..Default::default() }), "language"),
            (voice(MessageType::Verification, Template::Otp, SendPayload { to: to(), ..Default::default() }), "Missing 'otp'"),
        ];
        for (input, want) in bad {
            let err = crate::core::payload::verify_payload(&input).unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
        crate::core::payload::verify_payload(&custom(SendPayload { to: to(), body: Some("é".repeat(1000)), ..Default::default() })).unwrap();
        crate::core::payload::verify_payload(&voice(
            MessageType::Transactional,
            Template::Named("Appointment".into()),
            SendPayload { to: to(), data: d("time", "10:00"), ..Default::default() },
        ))
        .unwrap();
        assert!(is_valid_language("es-419") && is_valid_language("fr") && !is_valid_language("en_US"));
    }
}
