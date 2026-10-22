use serde::{Deserialize, Serialize};

/// Push: send to many devices or later. `broadcast` / `topic` leave `to`
/// and `external_user_id` empty; `send_at` (RFC 3339 with a zone, up to 30
/// days ahead) also works with `to` or `external_user_id`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PushOptions {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub broadcast: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Verification,
    Transactional,
    Notification,
    /// SMS only.
    Promotional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Channel {
    Email,
    WhatsApp,
    Push,
    /// Sent to the API as `"SMS"`.
    #[serde(rename = "SMS")]
    Sms,
    /// A phone call that speaks the message (text-to-speech). `"voice"`
    /// parses too (see [`std::str::FromStr`]).
    Voice,
}

impl std::str::FromStr for Channel {
    type Err = crate::error::CatzError;

    /// Case-insensitive: `"voice"`, `"Voice"`, `"sms"`, `"email"`, …
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "email" => Ok(Channel::Email),
            "whatsapp" => Ok(Channel::WhatsApp),
            "push" => Ok(Channel::Push),
            "sms" => Ok(Channel::Sms),
            "voice" => Ok(Channel::Voice),
            _ => Err(crate::error::CatzError::Validation(format!("Unknown channel '{s}'"))),
        }
    }
}

impl Channel {
    /// The name sent to the API.
    pub fn name(&self) -> &'static str {
        match self {
            Channel::Email => "Email",
            Channel::WhatsApp => "WhatsApp",
            Channel::Push => "Push",
            Channel::Sms => "SMS",
            Channel::Voice => "Voice",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Template {
    Otp,
    Custom,
    Notification,
    /// A template created in the panel (Email → Templates, or an SMS
    /// template on the SMS channel), sent by name. Its `{{variables}}` are
    /// filled from `payload.data`.
    Named(String),
}

impl Template {
    /// The name sent to the API.
    pub fn name(&self) -> &str {
        match self {
            Template::Otp => "Otp",
            Template::Custom => "Custom",
            Template::Notification => "Notification",
            Template::Named(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SendInput {
    pub message_type: MessageType,
    pub channel: Channel,
    pub template: Template,
    /// The sender identity. Ignored by the SMS channel (use `String::new()`).
    pub identity: String,
    pub payload: SendPayload,
}

/// Build with `..Default::default()` so fields added in later versions do not
/// break your code:
///
/// ```ignore
/// SendPayload { to: Some(to), otp: Some(otp), ..Default::default() }
/// ```
#[derive(Debug, Clone, Default)]
pub struct SendPayload {
    /// Email address (Email), phone number with country code (WhatsApp),
    /// FCM registration token (Push), or an E.164 number such as
    /// `+919876543210` (SMS, Voice).
    pub to: Option<String>,
    pub otp: Option<String>,
    /// Language of the built-in (default) Otp/Verification templates: `en`,
    /// `de`, `ja`, `ar` or `hi`. A BCP-47 tag such as `"de-DE"` is accepted
    /// and sent as `"de"`. Sent at the top level of the request, next to
    /// `channel`/`template`; `None` leaves it out (server default: English).
    /// Panel templates are not affected; for Voice, `data["language"]` still
    /// overrides the spoken language; WhatsApp needs the Authentication
    /// template approved in that language. All channels.
    pub language: Option<String>,
    /// Required for Email. Optional for WhatsApp, where it is a bold first line.
    pub subject: Option<String>,
    pub body: Option<String>,

    // ── Push only ──
    pub title: Option<String>,
    /// Push: delivered to the app (string values only). Email or SMS with
    /// `Template::Named`: the values for the template's `{{variables}}`.
    pub data: Option<std::collections::HashMap<String, String>>,
    /// https URL.
    pub image: Option<String>,
    /// https URL opened when the notification is tapped.
    pub link: Option<String>,
    /// The device's X25519 public key, base64. Seals the content so only that
    /// device can read it.
    pub device_key: Option<String>,
    /// Push: send to every device your app registered for this user (with
    /// `POST /push/register`) instead of one token in `to`. Give one of `to`
    /// or `external_user_id`; `device_key` is not allowed with it, because
    /// each registered device's own key is used.
    pub external_user_id: Option<String>,

    // ── SMS only ──
    /// Send through this gateway (its id or label) instead of routing. It
    /// must be one of the API key's SMS gateways.
    pub gateway: Option<String>,
    /// Sender override: an E.164 number or a 2–11 character sender ID. Only
    /// together with `gateway`, and only when that gateway allows it.
    pub sender: Option<String>,
    /// India DLT content template id (digits) for Custom bodies and the
    /// default OTP text. Required for +91 numbers unless the panel template
    /// carries one.
    pub dlt_template_id: Option<String>,

    // ── Voice only ──
    /// Call through this phone provider (its id or label) instead of
    /// routing. It must be one of the API key's call providers. Voice
    /// options go in `data`: `language` (e.g. `en-US`), `voice` (`female`,
    /// `male` or a provider voice name) and `repeat` (`"1"`–`"3"`).
    pub provider: Option<String>,
}

/// Per-message options added in 2.0.0, passed next to [`SendInput`] with
/// [`crate::CatzConnect::send_with_extras`] (or `send_full`). Kept out of
/// [`SendPayload`] so `SendPayload { … }` literals written for 1.6 still
/// compile. `#[non_exhaustive]`: build it with the methods, which also keeps
/// later additions from breaking your code.
///
/// ```
/// use catzconnect::types::{PushOptions, SendExtras};
/// let x = SendExtras::new().idempotency_key("order-42").reference("order 42");
/// let p = SendExtras::new().push(PushOptions { broadcast: true, ..Default::default() });
/// assert_eq!(x.idempotency_key.as_deref(), Some("order-42"));
/// assert!(p.push.unwrap().broadcast);
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct SendExtras {
    // ── WhatsApp ──
    /// Approved-template parameters (`Template::Named` = the Meta template
    /// name) or a media message (`Template::Custom` with `media`).
    pub whatsapp: Option<crate::whatsapp::WhatsAppOptions>,

    // ── Email ──
    /// Open / click tracking for this message.
    pub tracking: Option<crate::whatsapp::TrackingOverride>,
    /// A subscription topic key of your organization (Email → Preferences
    /// in the panel): its opt-outs apply and the message's unsubscribe link
    /// unsubscribes from that topic only.
    pub topic: Option<String>,

    // ── Push ──
    /// Broadcast to every device, a topic, or a scheduled send. The answer's
    /// `data` then has `broadcast_id`, `audience`, `status: "scheduled"`,
    /// `send_at`; follow it with [`crate::devapi::PushApi`]. Server keys only.
    pub push: Option<PushOptions>,

    // ── Every channel ──
    /// Retry-safe sends: the same key with the same request within 24 hours
    /// returns the first answer instead of sending again (sent as the
    /// `Idempotency-Key` header and the `idempotency_key` field). 1–255
    /// visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// Your own id for the message (≤ 128 chars), to find it again with
    /// [`crate::devapi::Messages::list`].
    pub reference: Option<String>,
}

impl SendExtras {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn whatsapp(mut self, w: crate::whatsapp::WhatsAppOptions) -> Self {
        self.whatsapp = Some(w);
        self
    }

    pub fn tracking(mut self, t: crate::whatsapp::TrackingOverride) -> Self {
        self.tracking = Some(t);
        self
    }

    pub fn topic(mut self, t: impl Into<String>) -> Self {
        self.topic = Some(t.into());
        self
    }

    pub fn push(mut self, p: PushOptions) -> Self {
        self.push = Some(p);
        self
    }

    pub fn idempotency_key(mut self, k: impl Into<String>) -> Self {
        self.idempotency_key = Some(k.into());
        self
    }

    pub fn reference(mut self, r: impl Into<String>) -> Self {
        self.reference = Some(r.into());
        self
    }
}

/// The `data` of a successful SMS send. The message is queued, not yet
/// delivered; webhook events (`sms.sent`, `sms.delivered`, `sms.failed`,
/// `sms.unknown` — the provider was called but did not answer, so it is not
/// resent) carry `message_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsSendResult {
    pub message_id: String,
    /// Billable parts.
    pub segments: u32,
    /// `"gsm7"` or `"ucs2"`.
    pub encoding: String,
}

impl SmsSendResult {
    /// Reads `data` out of the server's `{success, message, data}` answer.
    pub fn from_response(response: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(response.get("data")?.clone()).ok()
    }
}

/// The `data` of a successful Voice send: the phone call is queued, not yet
/// placed. `voice.*` webhook events carry `message_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceSendResult {
    pub message_id: String,
}

impl VoiceSendResult {
    /// Reads `data` out of the server's `{success, message, data}` answer.
    pub fn from_response(response: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(response.get("data")?.clone()).ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedBody {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub status: String,
}

/// Explicit credentials. `{:?}` never prints the API key or the private key.
#[derive(Clone)]
pub struct EnvValues {
    pub api_key: String,
    pub private_key: String,
    pub server_public_key: String,
}

/// The first 4 characters of a long secret and its length, never the secret.
fn redact_secret(s: &str) -> String {
    if s.is_empty() {
        return "[empty]".into();
    }
    let prefix: String = if s.chars().count() > 8 { s.chars().take(4).collect() } else { String::new() };
    format!("{prefix}…[redacted, {} chars]", s.chars().count())
}

impl std::fmt::Debug for EnvValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvValues")
            .field("api_key", &redact_secret(&self.api_key))
            .field("private_key", &"[redacted]")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

#[cfg(test)]
mod env_values_tests {
    use super::EnvValues;

    #[test]
    fn debug_redacts_secrets() {
        let e = EnvValues {
            api_key: "live_abcdefghijklmnopqrstuvwxyz".into(),
            private_key: "PRIVATEKEYSECRET==".into(),
            server_public_key: "SERVERPUB==".into(),
        };
        for s in [format!("{e:?}"), format!("{e:#?}"), format!("{:?}", Some(e.clone()))] {
            assert!(!s.contains("abcdefghijklmnopqrstuvwxyz"), "{s}");
            assert!(!s.contains("PRIVATEKEYSECRET"), "{s}");
            assert!(s.contains("SERVERPUB=="), "{s}");
        }
    }
}