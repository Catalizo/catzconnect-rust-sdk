//! # CatzConnect SDK (Rust)
//!
//! A secure, minimal SDK for sending encrypted communication requests
//! (e.g., email OTP) to the CatzConnect API.
//!
//! ## Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! catzconnect = "1.0.0"
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
//!         payload: SendPayload {
//!             to:  Some("user@example.com".into()),
//!             otp: Some("123456".into()),
//!         },
//!     })
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
use types::SendInput;

pub struct CatzConnect;

impl CatzConnect {
    /// Validates, encrypts, and sends `input` to the CatzConnect API.
    ///
    /// Reads from the environment (or a `.env` file loaded via `dotenvy`):
    /// - `API_KEY`           — Bearer token (required)
    /// - `PRIVATE_KEY`       — Base64-encoded X25519 private key (required)
    /// - `SERVER_PUBLIC_KEY` — Base64-encoded X25519 server public key (required)
    /// - `BASE_URL`          — API base URL (optional, default: `https://api.catzconnect.com`)
    ///
    /// # Errors
    ///
    /// Returns [`CatzError`] on validation failure, encryption failure, or a
    /// non-2xx HTTP response from the API.
    pub async fn send(input: SendInput) -> Result<serde_json::Value, CatzError> {
        // 1. Validate
        verify_payload(&input)?;

        // 2. Build flat payload mirroring the TypeScript finalPayload spread:
        //    { message_type, channel, template, ...payload }
        //    serde_json preserve_order feature → IndexMap → insertion order matches JS
        let final_payload = json!({
            "message_type": format!("{:?}", input.message_type),
            "channel":       format!("{:?}", input.channel),
            "template":      format!("{:?}", input.template),
            "to":            input.payload.to,
            "otp":           input.payload.otp,
        });

        // 3. Encrypt
        let encrypted = crypto::encrypt(&final_payload)?;

        // 4. Send
        let client = HttpClient::from_env()?;
        let response = client.post("/sdk/send", &encrypted).await?;

        Ok(response)
    }
}