//! WhatsApp approved-template parameters and media messages, with the
//! server's checks. Set on [`crate::types::SendPayload::whatsapp`].

use serde::Serialize;
use std::collections::HashMap;

use crate::error::CatzError;

/// A template header: text, media (by `link` or Meta media `id`) or a location.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct WhatsAppHeader {
    /// `text` | `image` | `video` | `document` | `location`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// A dynamic button parameter (`index` is the 0-based button position).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct WhatsAppButton {
    pub index: u8,
    /// `url` | `quick_reply` | `copy_code` | `otp`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// A media message (`Template::Custom`): exactly one of `link` (https) or `id`.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct WhatsAppMedia {
    /// `image` | `document` | `video` | `audio`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// Body parameters: positional `{{1}}…`, or named (NAMED templates).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum WhatsAppBody {
    Positional(Vec<String>),
    Named(HashMap<String, String>),
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct WhatsAppOptions {
    /// Meta language code (`en`, `en_US`, `es_419`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<WhatsAppHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<WhatsAppBody>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub buttons: Vec<WhatsAppButton>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<WhatsAppMedia>,
}

/// Email: per-message open / click tracking; `None` inherits.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct TrackingOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clicks: Option<bool>,
}

fn bad(m: impl Into<String>) -> CatzError {
    CatzError::Validation(m.into())
}

/// Meta template names: lower-case letters, digits, underscores.
pub fn is_template_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 512 && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn media_ref(kind: &str, link: &Option<String>, id: &Option<String>, filename: &Option<String>, w: &str) -> Result<(), CatzError> {
    match (link.as_deref().filter(|v| !v.is_empty()), id.as_deref().filter(|v| !v.is_empty())) {
        (Some(l), None) => {
            if !l.starts_with("https://") || l.len() > 2048 || l.contains(char::is_whitespace) {
                return Err(bad(format!("{w}.link must be an https:// URL")));
            }
        }
        (None, Some(i)) => {
            if i.len() > 64 || !i.chars().all(|c| c.is_ascii_digit()) {
                return Err(bad(format!("{w}.id must be a Meta media id (digits)")));
            }
        }
        _ => return Err(bad(format!("{w}: give exactly one of 'link' (https) or 'id' (Meta media id)"))),
    }
    if let Some(f) = filename {
        if kind != "document" {
            return Err(bad(format!("{w}.filename is for documents only")));
        }
        if f.chars().count() > 240 || f.contains('/') || f.contains('\\') {
            return Err(bad(format!("{w}.filename must be up to 240 characters without slashes")));
        }
    }
    Ok(())
}

pub fn verify_media(m: &WhatsAppMedia) -> Result<(), CatzError> {
    if !["image", "document", "video", "audio"].contains(&m.kind.as_str()) {
        return Err(bad("'whatsapp.media.type' must be image, document, video or audio"));
    }
    media_ref(&m.kind, &m.link, &m.id, &m.filename, "'whatsapp.media'")?;
    if let Some(c) = &m.caption {
        if m.kind == "audio" {
            return Err(bad("'whatsapp.media.caption' is not allowed for audio"));
        }
        if c.chars().count() > 1024 {
            return Err(bad("'whatsapp.media.caption' is at most 1024 characters"));
        }
    }
    Ok(())
}

fn param(v: &str, w: &str) -> Result<(), CatzError> {
    if v.trim().is_empty() || v.chars().count() > 1024 || v.contains('\n') || v.contains('\t') || v.contains("     ") {
        return Err(bad(format!("{w} must be non-empty text of up to 1024 characters without new lines, tabs or 5+ spaces in a row")));
    }
    Ok(())
}

pub fn verify_options(o: &WhatsAppOptions) -> Result<(), CatzError> {
    if let Some(l) = &o.language {
        let ok = {
            let (a, b) = l.split_once('_').map(|(a, b)| (a, Some(b))).unwrap_or((l.as_str(), None));
            (2..=3).contains(&a.len())
                && a.chars().all(|c| c.is_ascii_alphabetic())
                && b.map_or(true, |b| (2..=4).contains(&b.len()) && b.chars().all(|c| c.is_ascii_alphanumeric()))
        };
        if !ok {
            return Err(bad("'whatsapp.language' must be a Meta language code such as en, en_US or es_419"));
        }
    }
    if let Some(h) = &o.header {
        match h.kind.as_str() {
            "text" => {
                let t = h.text.as_deref().unwrap_or("");
                if t.trim().is_empty() || t.chars().count() > 60 {
                    return Err(bad("'whatsapp.header.text' must be 1–60 characters"));
                }
            }
            "image" | "video" | "document" => media_ref(&h.kind, &h.link, &h.id, &h.filename, "'whatsapp.header'")?,
            "location" => {
                if h.latitude.is_none() || h.longitude.is_none() {
                    return Err(bad("'whatsapp.header' location needs latitude and longitude"));
                }
            }
            _ => return Err(bad("'whatsapp.header.type' must be text, image, video, document or location")),
        }
    }
    match &o.body {
        Some(WhatsAppBody::Positional(v)) => {
            for (i, p) in v.iter().enumerate() {
                param(p, &format!("'whatsapp.body[{i}]'"))?;
            }
        }
        Some(WhatsAppBody::Named(m)) => {
            for (k, p) in m {
                param(p, &format!("'whatsapp.body.{k}'"))?;
            }
        }
        None => {}
    }
    let mut seen = std::collections::HashSet::new();
    for b in &o.buttons {
        if b.index > 9 {
            return Err(bad("'whatsapp.buttons[].index' must be 0–9"));
        }
        if !seen.insert(b.index) {
            return Err(bad(format!("'whatsapp.buttons' lists index {} twice", b.index)));
        }
        match b.kind.as_str() {
            "url" => {
                let t = b.text.as_deref().unwrap_or("");
                if t.is_empty() || t.contains(char::is_whitespace) || t.len() > 2000 {
                    return Err(bad("A url button needs 'text': the URL suffix without spaces"));
                }
            }
            "quick_reply" => {
                if b.payload.as_deref().is_some_and(|p| p.chars().count() > 256) {
                    return Err(bad("A quick_reply 'payload' is at most 256 characters"));
                }
            }
            "copy_code" => {
                let c = b.code.as_deref().unwrap_or("");
                if c.is_empty() || c.chars().count() > 20 {
                    return Err(bad("A copy_code button needs 'code' of up to 20 characters"));
                }
            }
            "otp" => {
                let c = b.code.as_deref().unwrap_or("");
                if c.is_empty() || c.len() > 15 || !c.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                    return Err(bad("An otp button needs 'code': up to 15 letters or digits"));
                }
            }
            _ => return Err(bad("'whatsapp.buttons[].type' must be url, quick_reply, copy_code or otp")),
        }
    }
    if let Some(m) = &o.media {
        verify_media(m)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_checked_and_serialised() {
        let o = WhatsAppOptions {
            language: Some("en_US".into()),
            header: Some(WhatsAppHeader { kind: "text".into(), text: Some("#1".into()), ..Default::default() }),
            body: Some(WhatsAppBody::Positional(vec!["Ravi".into()])),
            buttons: vec![WhatsAppButton { index: 0, kind: "url".into(), text: Some("abc".into()), ..Default::default() }],
            media: None,
        };
        verify_options(&o).unwrap();
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["header"]["type"], "text");
        assert_eq!(v["body"][0], "Ravi");
        assert!(v.get("media").is_none());
        let named = WhatsAppOptions { body: Some(WhatsAppBody::Named([("first_name".to_string(), "Ana".to_string())].into())), ..Default::default() };
        assert_eq!(serde_json::to_value(&named).unwrap()["body"]["first_name"], "Ana");

        let bad_lang = WhatsAppOptions { language: Some("english".into()), ..Default::default() };
        assert!(verify_options(&bad_lang).is_err());
        let bad_body = WhatsAppOptions { body: Some(WhatsAppBody::Positional(vec!["a\nb".into()])), ..Default::default() };
        assert!(verify_options(&bad_body).is_err());
        let dup = WhatsAppOptions {
            buttons: vec![
                WhatsAppButton { index: 0, kind: "quick_reply".into(), ..Default::default() },
                WhatsAppButton { index: 0, kind: "quick_reply".into(), ..Default::default() },
            ],
            ..Default::default()
        };
        assert!(verify_options(&dup).is_err());
        assert!(is_template_name("order_update"));
        assert!(!is_template_name("Order Update"));
    }

    #[test]
    fn media_rules() {
        let ok = WhatsAppMedia { kind: "document".into(), link: Some("https://x/i.pdf".into()), filename: Some("i.pdf".into()), ..Default::default() };
        verify_media(&ok).unwrap();
        assert!(verify_media(&WhatsAppMedia { kind: "audio".into(), link: Some("https://x/a".into()), caption: Some("c".into()), ..Default::default() }).is_err());
        assert!(verify_media(&WhatsAppMedia { kind: "image".into(), link: Some("http://x/a".into()), ..Default::default() }).is_err());
        assert!(verify_media(&WhatsAppMedia { kind: "image".into(), link: Some("https://x/a".into()), id: Some("1".into()), ..Default::default() }).is_err());
        assert!(verify_media(&WhatsAppMedia { kind: "image".into(), id: Some("123".into()), filename: Some("x".into()), ..Default::default() }).is_err());
    }
}
