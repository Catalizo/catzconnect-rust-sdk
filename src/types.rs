use serde::{Deserialize, Serialize};

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
}

impl Channel {
    /// The name sent to the API.
    pub fn name(&self) -> &'static str {
        match self {
            Channel::Email => "Email",
            Channel::WhatsApp => "WhatsApp",
            Channel::Push => "Push",
            Channel::Sms => "SMS",
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
    /// `+919876543210` (SMS).
    pub to: Option<String>,
    pub otp: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedBody {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct EnvValues {
    pub api_key: String,
    pub private_key: String,
    pub server_public_key: String,
}