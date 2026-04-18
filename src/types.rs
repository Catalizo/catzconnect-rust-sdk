use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Verification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Channel {
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Template {
    Otp,
}

#[derive(Debug, Clone)]
pub struct SendInput {
    pub message_type: MessageType,
    pub channel: Channel,
    pub template: Template,
    pub payload: SendPayload,
}

#[derive(Debug, Clone, Default)]
pub struct SendPayload {
    pub to: Option<String>,
    pub otp: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedBody {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub status: String,
    pub request_id: Option<String>,
}
