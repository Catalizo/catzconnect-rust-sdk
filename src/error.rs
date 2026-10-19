use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatzError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),

    #[error("Invalid key length — expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("API error ({status}): {body}")]
    ApiError { status: u16, body: String },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Unsupported combination: {0}.{1}.{2}")]
    UnsupportedCombination(String, String, String),
}

impl CatzError {
    /// For [`CatzError::ApiError`]: the server's machine-readable `code`
    /// (`plan_required`, `minutes_cap_reached`, `engine_unavailable`,
    /// `too_many_participants`, `provider_not_allowed`, …) when it sent one.
    pub fn api_code(&self) -> Option<String> {
        self.api_json()?.get("code")?.as_str().map(str::to_string)
    }

    /// For [`CatzError::ApiError`]: the server's `message` sentence.
    pub fn api_message(&self) -> Option<String> {
        self.api_json()?.get("message")?.as_str().map(str::to_string)
    }

    fn api_json(&self) -> Option<serde_json::Value> {
        match self {
            CatzError::ApiError { body, .. } => serde_json::from_str(body).ok(),
            _ => None,
        }
    }
}
