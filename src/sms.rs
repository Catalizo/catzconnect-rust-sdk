//! SMS helpers that mirror the server's checks for `Channel::Sms`, so a
//! request the server would refuse fails before it is encrypted and sent.

use serde_json::{Map, Value};

use crate::{
    error::CatzError,
    types::{MessageType, SendInput},
};

/// Longest body the server accepts, in segments (~1,530 GSM-7 or ~670
/// UCS-2 characters).
pub const MAX_SEGMENTS: usize = 10;

/// How an SMS body is encoded on the air interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsEncoding {
    Gsm7,
    Ucs2,
}

impl SmsEncoding {
    /// `"gsm7"` or `"ucs2"`, as the server reports it.
    pub fn as_str(&self) -> &'static str {
        match self {
            SmsEncoding::Gsm7 => "gsm7",
            SmsEncoding::Ucs2 => "ucs2",
        }
    }
}

/// How the server will encode a body and how many segments it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmsAnalysis {
    pub encoding: SmsEncoding,
    /// Septets (GSM-7) or UTF-16 code units (UCS-2).
    pub units: usize,
    /// Billable parts.
    pub segments: usize,
    /// Characters as a person would count them.
    pub chars: usize,
}

/// Normalises a phone number to E.164 the way the server does: spaces,
/// dashes, dots and brackets are removed; the result must be `+` and 8–15
/// digits, not starting with 0.
pub fn normalise_e164(raw: &str) -> Option<String> {
    let cleaned: String = raw.trim().chars().filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')')).collect();
    let ok = cleaned.strip_prefix('+').is_some_and(|d| {
        (8..=15).contains(&d.len()) && d.chars().all(|c| c.is_ascii_digit()) && !d.starts_with('0')
    });
    ok.then_some(cleaned)
}

/// A sender override: an E.164 number, or 2–11 letters, digits and spaces
/// with at least one letter.
pub fn is_valid_sender(s: &str) -> bool {
    if s.starts_with('+') {
        return normalise_e164(s).is_some_and(|n| n == s);
    }
    let n = s.chars().count();
    (2..=11).contains(&n)
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ')
        && s.chars().any(|c| c.is_ascii_alphabetic())
        && !s.starts_with(' ')
        && !s.ends_with(' ')
}

/// An India DLT template id: 6–30 digits.
pub fn is_valid_dlt_id(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.chars().all(|c| c.is_ascii_digit())
}

/// GSM 03.38 default alphabet (ESC excluded).
const GSM_BASIC: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
/// Extension table, each written as ESC + character (two septets).
const GSM_EXTENSION: &str = "^{}\\[~]|€\u{0c}";

fn gsm_cost(c: char) -> Option<usize> {
    if GSM_BASIC.contains(c) {
        Some(1)
    } else if GSM_EXTENSION.contains(c) {
        Some(2)
    } else {
        None
    }
}

fn segments(costs: &[usize], total: usize, single: usize, multi: usize) -> usize {
    if total <= single {
        return 1;
    }
    let mut parts = 1;
    let mut used = 0;
    for &c in costs {
        if used + c > multi {
            parts += 1;
            used = 0;
        }
        used += c;
    }
    parts
}

/// GSM-7 when every character is in the GSM alphabet (extension characters
/// cost two septets), otherwise UCS-2. 160/153 septets or 70/67 code units
/// per part; a character is never split across parts.
pub fn analyse(text: &str) -> SmsAnalysis {
    let chars = text.chars().count();
    let gsm: Option<Vec<usize>> = text.chars().map(gsm_cost).collect();
    let (encoding, costs, single, multi) = match gsm {
        Some(costs) => (SmsEncoding::Gsm7, costs, 160, 153),
        None => (SmsEncoding::Ucs2, text.chars().map(char::len_utf16).collect(), 70, 67),
    };
    let units: usize = costs.iter().sum();
    SmsAnalysis { encoding, units, segments: segments(&costs, units, single, multi), chars }
}

/// The server's error for a body it would refuse.
pub fn validate_body(body: &str) -> Result<SmsAnalysis, CatzError> {
    if body.trim().is_empty() {
        return Err(CatzError::Validation("The message is empty".into()));
    }
    if body.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(CatzError::Validation("The message contains control characters".into()));
    }
    let a = analyse(body);
    if a.segments > MAX_SEGMENTS {
        return Err(CatzError::Validation(format!(
            "The message is {} segments long; the limit is {} ({} characters in {})",
            a.segments,
            MAX_SEGMENTS,
            if a.encoding == SmsEncoding::Gsm7 { 1530 } else { 670 },
            a.encoding.as_str().to_uppercase()
        )));
    }
    Ok(a)
}

fn trimmed(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// The server's checks for an SMS send: `Otp` with `Verification` and `otp`;
/// `Custom` with `Transactional`/`Promotional` and `body`; any other name
/// is an SMS template from the panel, filled from `data`. Names match
/// case-insensitively, as on the server. `identity` is ignored.
pub(crate) fn verify(input: &SendInput) -> Result<(), CatzError> {
    let v = |m: &str| Err(CatzError::Validation(m.to_string()));
    let p = &input.payload;

    let Some(raw_to) = trimmed(&p.to) else {
        return v("Missing 'to' in payload — the recipient's number in E.164, e.g. +919876543210");
    };
    let Some(to) = normalise_e164(raw_to) else {
        return Err(CatzError::Validation(format!(
            "'{raw_to}' is not an E.164 phone number — use + and the country code, e.g. +919876543210"
        )));
    };

    if matches!(input.message_type, MessageType::Notification) {
        return v("SMS supports type Verification (template Otp), Transactional or Promotional — not Notification");
    }

    if let Some(sender) = trimmed(&p.sender) {
        if trimmed(&p.gateway).is_none() {
            return v("'sender' can only be used together with 'gateway'");
        }
        if !is_valid_sender(sender) {
            return v("'sender' must be an E.164 number or a 2–11 character sender ID");
        }
    }

    let dlt = trimmed(&p.dlt_template_id);
    if dlt.is_some_and(|d| !is_valid_dlt_id(d)) {
        return v("'dlt_template_id' must be the numeric DLT template ID");
    }

    let name = input.template.name().trim();
    if name.is_empty() {
        return v("Missing 'template' — Otp, Custom, or the name of an SMS template");
    }
    let verification = matches!(input.message_type, MessageType::Verification);

    if name.eq_ignore_ascii_case("otp") {
        if !verification {
            return v("template Otp goes with type Verification");
        }
        let Some(otp) = trimmed(&p.otp) else {
            return v("Missing 'otp' in payload");
        };
        if otp.len() > 15 || !otp.chars().all(|c| c.is_ascii_alphanumeric()) {
            return v("'otp' must be up to 15 letters or digits");
        }
    } else if name.eq_ignore_ascii_case("custom") {
        if verification {
            return v("type Verification goes with template Otp; use Transactional for Custom");
        }
        let Some(body) = trimmed(&p.body) else {
            return v("Missing 'body' in payload");
        };
        validate_body(body)?;
        // India needs a DLT template id; a Custom body can only get it from the payload.
        if to.starts_with("+91") && dlt.is_none() {
            return v("India (+91) requires a DLT template ID: pass 'dlt_template_id' for Custom messages");
        }
    }
    // A panel SMS template: the server renders it from data and checks its length.
    Ok(())
}

/// The JSON body (before encryption) for an SMS send: only the fields the
/// server reads.
pub(crate) fn build_payload(input: &SendInput) -> Value {
    let p = &input.payload;
    let mut m = Map::new();
    m.insert("message_type".into(), format!("{:?}", input.message_type).into());
    m.insert("channel".into(), input.channel.name().into());
    m.insert("template".into(), input.template.name().into());
    // Required by the server, ignored for SMS.
    m.insert("identity".into(), input.identity.clone().into());
    m.insert("to".into(), p.to.clone().into());
    for (k, val) in [
        ("otp", &p.otp),
        ("body", &p.body),
        ("gateway", &p.gateway),
        ("sender", &p.sender),
        ("dlt_template_id", &p.dlt_template_id),
    ] {
        if trimmed(val).is_some() {
            m.insert(k.into(), val.clone().into());
        }
    }
    if let Some(data) = p.data.as_ref().filter(|d| !d.is_empty()) {
        let obj: Map<String, Value> = data.iter().map(|(k, v)| (k.clone(), Value::from(v.clone()))).collect();
        m.insert("data".into(), Value::Object(obj));
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Channel, SendPayload, Template};

    #[test]
    fn analysis_matches_server() {
        let cases: Vec<(String, SmsEncoding, usize, usize)> = vec![
            ("Your verification code is 123456".into(), SmsEncoding::Gsm7, 32, 1),
            ("a".repeat(160), SmsEncoding::Gsm7, 160, 1),
            ("a".repeat(161), SmsEncoding::Gsm7, 161, 2),
            ("a".repeat(307), SmsEncoding::Gsm7, 307, 3),
            ("€".repeat(81), SmsEncoding::Gsm7, 162, 2),
            (format!("{}€{}", "a".repeat(152), "a".repeat(152)), SmsEncoding::Gsm7, 306, 3),
            ("a".repeat(1531), SmsEncoding::Gsm7, 1531, 11),
            ("Ж".repeat(670), SmsEncoding::Ucs2, 670, 10),
            ("😀".repeat(36), SmsEncoding::Ucs2, 72, 2),
            (String::new(), SmsEncoding::Gsm7, 0, 1),
        ];
        for (text, enc, units, segs) in cases {
            let a = analyse(&text);
            assert_eq!((a.encoding, a.units, a.segments), (enc, units, segs), "{:.20}", text);
        }
    }

    #[test]
    fn e164_and_sender() {
        assert_eq!(normalise_e164(" +1 (415) 555.0100 ").as_deref(), Some("+14155550100"));
        assert_eq!(normalise_e164("919876543210"), None);
        assert_eq!(normalise_e164("+0123456789"), None);
        assert!(is_valid_sender("CATZ") && is_valid_sender("+14155550100"));
        assert!(!is_valid_sender("C") && !is_valid_sender("12345") && !is_valid_sender("+1 4155550100"));
        assert!(is_valid_dlt_id("1207161234567890123") && !is_valid_dlt_id("12345"));
    }

    fn sms(t: MessageType, tpl: Template, p: SendPayload) -> SendInput {
        SendInput { message_type: t, channel: Channel::Sms, template: tpl, identity: String::new(), payload: p }
    }

    #[test]
    fn verify_and_build() {
        let ok = sms(
            MessageType::Promotional,
            Template::Custom,
            SendPayload {
                to: Some("+91 98765 43210".into()),
                body: Some("Sale".into()),
                dlt_template_id: Some("1207161234567890123".into()),
                gateway: Some("g1".into()),
                sender: Some("CATZIN".into()),
                title: Some("ignored".into()),
                ..Default::default()
            },
        );
        crate::core::payload::verify_payload(&ok).unwrap();
        let built = build_payload(&ok);
        assert_eq!(
            built,
            serde_json::json!({"message_type":"Promotional","channel":"SMS","template":"Custom","identity":"",
                "to":"+91 98765 43210","body":"Sale","gateway":"g1","sender":"CATZIN","dlt_template_id":"1207161234567890123"})
        );

        let otp = sms(
            MessageType::Verification,
            Template::Named("otp".into()),
            SendPayload { to: Some("+14155550100".into()), otp: Some("AB12".into()), ..Default::default() },
        );
        crate::core::payload::verify_payload(&otp).unwrap();

        let bad = [
            (sms(MessageType::Transactional, Template::Custom, SendPayload { to: Some("+919876543210".into()), body: Some("x".into()), ..Default::default() }), "India (+91)"),
            (sms(MessageType::Transactional, Template::Otp, SendPayload { to: Some("+14155550100".into()), otp: Some("1".into()), ..Default::default() }), "goes with type Verification"),
            (sms(MessageType::Verification, Template::Custom, SendPayload { to: Some("+14155550100".into()), body: Some("x".into()), ..Default::default() }), "use Transactional"),
            (sms(MessageType::Transactional, Template::Custom, SendPayload { to: Some("+14155550100".into()), body: Some("a".repeat(1531)), ..Default::default() }), "segments long"),
            (sms(MessageType::Transactional, Template::Custom, SendPayload { to: Some("+14155550100".into()), body: Some("x".into()), sender: Some("CATZ".into()), ..Default::default() }), "together with"),
            (sms(MessageType::Notification, Template::Custom, SendPayload { to: Some("+14155550100".into()), body: Some("x".into()), ..Default::default() }), "SMS supports type"),
            (sms(MessageType::Verification, Template::Otp, SendPayload { to: Some("4155550100".into()), otp: Some("1".into()), ..Default::default() }), "not an E.164"),
        ];
        for (input, want) in bad {
            let err = crate::core::payload::verify_payload(&input).unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    #[test]
    fn result_from_response() {
        let r = serde_json::json!({"success":true,"message":"Success","data":{"message_id":"m1","segments":2,"encoding":"ucs2"}});
        assert_eq!(
            crate::types::SmsSendResult::from_response(&r),
            Some(crate::types::SmsSendResult { message_id: "m1".into(), segments: 2, encoding: "ucs2".into() })
        );
        assert_eq!(crate::types::SmsSendResult::from_response(&serde_json::json!({"success":true})), None);
    }
}
