//! # CatzConnect SDK (Rust)
//!
//! A secure, minimal SDK for sending encrypted communication requests
//! (e.g., email OTP, Transactional) to the CatzConnect API.
//!
//! ## Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! catzconnect = "1.0.3"
//! tokio   = { version = "1", features = ["full"] }
//! dotenvy = "0.15"
//! ```
//!
//! ```rust,no_run
//! use catzconnect::{CatzConnect, types::{Channel, MessageType, SendInput, SendPayload, Template}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     dotenvy::dotenv().ok();
//!
//!     let resp = CatzConnect::send(SendInput {
//!         message_type: MessageType::Verification,
//!         channel:      Channel::Email,
//!         template:     Template::Otp,
//!         identity:     "user@domain.com".to_string(),
//!         payload: SendPayload {
//!             to:  Some("user@example.com".into()),
//!             otp: Some("123456".into()),
//!             subject: None,
//!             body: None,
//!         },
//!     }, None)
//!     .await?;
//!
//!     println!("{resp}");
//!     Ok(())
//! }
//! ```
//!
//! ```rust,no_run
//! use catzconnect::{CatzConnect, types::{Channel, MessageType, SendInput, SendPayload, Template}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     dotenvy::dotenv().ok();
//!
//!     let resp = CatzConnect::send(SendInput {
//!         message_type: MessageType::Transactional,
//!         channel:      Channel::Email,
//!         template:     Template::Custom,
//!         identity:     "user@domain.com".to_string(),
//!         payload: SendPayload {
//!             to:  Some("user@example.com".into()),
//!             otp: None,
//!             subject: Some("hello world".into()),
//!             body: Some("welcome to catzconnect".into()),
//!         },
//!     }, None)
//!     .await?;
//!
//!     println!("{resp}");
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod types;

mod core;
mod utils;

use serde_json::json;

use core::{crypto, http::HttpClient, payload::verify_payload};
pub use error::CatzError;
use types::{
    Channel,
    MessageType,
    Template,
    SendInput,
    EnvValues,
};

pub struct CatzConnect;

impl CatzConnect {
    /// Validates, encrypts, and sends `input` to the CatzConnect API.
    ///
    /// Reads from the environment (or a `.env` file loaded via `dotenvy`):
    /// - `CATZCONNECT_API_KEY`           — Bearer token (required)
    /// - `CATZCONNECT_PRIVATE_KEY`       — Base64-encoded X25519 private key (required)
    /// - `CATZCONNECT_SERVER_PUBLIC_KEY` — Base64-encoded X25519 server public key (required)
    /// - `CATZCONNECT_BASE_URL`          — API base URL (optional, default: `https://api.catzconnect.com`)
    ///
    /// # Errors
    ///
    /// Returns [`CatzError`] on validation failure, encryption failure, or a
    /// non-2xx HTTP response from the API.
    pub async fn send(input: SendInput, env: Option<EnvValues>) -> Result<serde_json::Value, CatzError> {
        // 1. Validate
        verify_payload(&input)?;

        // 2. Build flat payload mirroring the TypeScript finalPayload spread:
        //    { message_type, channel, template, ...payload }
        //    serde_json preserve_order feature → IndexMap → insertion order matches JS
        let final_payload = match (
            &input.channel,
            &input.message_type,
            &input.template,
        ) {
            (Channel::Email, MessageType::Verification, Template::Otp) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     format!("{:?}", input.template),
                "identity":     input.identity,
                "to":           input.payload.to,
                "otp":          input.payload.otp,
            }),

            (Channel::Email, MessageType::Transactional, Template::Custom) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     format!("{:?}", input.template),
                "identity":     input.identity,
                "to":           input.payload.to,
                "subject":      input.payload.subject,
                "body":         input.payload.body,
            }),

            _ => {
                return Err(CatzError::Validation(
                    "Unsupported channel/message_type/template combination".into(),
                ));
            }
        };

        // 3. Encrypt
        let encrypted = crypto::encrypt(&final_payload, env.clone())?;

        // 4. Send
        let client = HttpClient::from_env(env)?;
        let response = client.post("/sdk/send", &encrypted).await?;

        Ok(response)
    }
}