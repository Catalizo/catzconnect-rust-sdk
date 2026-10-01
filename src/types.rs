use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Verification,
    Transactional,
    Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Channel {
    Email,
    WhatsApp,
    Push,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Template {
    Otp,
    Custom,
    Notification,
    /// An email template created in the panel (Email → Templates), sent by
    /// name. Its `{{variables}}` are filled from `payload.data`.
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
    /// Email address (Email), phone number with country code (WhatsApp), or
    /// FCM registration token (Push).
    pub to: Option<String>,
    pub otp: Option<String>,
    /// Required for Email. Optional for WhatsApp, where it is a bold first line.
    pub subject: Option<String>,
    pub body: Option<String>,

    // ── Push only ──
    pub title: Option<String>,
    /// Push: delivered to the app (string values only). Email with
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