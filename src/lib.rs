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
//!             ..Default::default()
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
//!             subject: Some("hello world".into()),
//!             body: Some("welcome to catzconnect".into()),
//!             ..Default::default()
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

pub(crate) mod core;
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

            (Channel::WhatsApp, MessageType::Verification, Template::Otp) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     format!("{:?}", input.template),
                "identity":     input.identity,
                "to":           input.payload.to,
                "otp":          input.payload.otp,
            }),

            (Channel::WhatsApp, MessageType::Transactional, Template::Custom) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     format!("{:?}", input.template),
                "identity":     input.identity,
                "to":           input.payload.to,
                "subject":      input.payload.subject,
                "body":         input.payload.body,
            }),

            (Channel::Push, MessageType::Notification, Template::Notification) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     format!("{:?}", input.template),
                "identity":     input.identity,
                "to":           input.payload.to,
                "title":        input.payload.title,
                "body":         input.payload.body,
                "data":         input.payload.data,
                "image":        input.payload.image,
                "link":         input.payload.link,
                "device_key":   input.payload.device_key,
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
/// Cross-language interop with the Go SDK. Runs only with CATZ_INTEROP_DIR set:
/// writes a Rust-encrypted fixture for Go to open, and opens Go's if present.
#[cfg(test)]
mod interop {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use blake2::{digest::{Update, VariableOutput}, Blake2bVar};
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    use serde_json::{json, Value};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn b2(d: &[u8]) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(d);
        let mut o = [0u8; 32];
        h.finalize_variable(&mut o).unwrap();
        o
    }

    /// The server's side: server private key + client public key.
    fn server_decrypt(server_priv: &[u8], client_pub: &[u8], nonce: &str, ct: &str) -> Value {
        let s = StaticSecret::from(<[u8; 32]>::try_from(server_priv).unwrap());
        let c = PublicKey::from(<[u8; 32]>::try_from(client_pub).unwrap());
        let master = b2(s.diffie_hellman(&c).as_bytes());
        let key = b2(&[&master[..], b"CONNECT-@-2026-HS-@-CATZ"].concat());
        let n = STANDARD.decode(nonce).unwrap();
        let plain = ChaCha20Poly1305::new_from_slice(&key).unwrap()
            .decrypt(Nonce::from_slice(&n), STANDARD.decode(ct).unwrap().as_ref())
            .expect("Rust could not decrypt Go's ciphertext");
        serde_json::from_slice(&plain).unwrap()
    }

    #[test]
    fn go_and_rust_interoperate() {
        let Ok(dir) = std::env::var("CATZ_INTEROP_DIR") else { return };

        // Rust → Go: encrypt with fixed keys, publish for the Go test.
        let client = StaticSecret::from([7u8; 32]);
        let server = StaticSecret::from([9u8; 32]);
        let env = crate::types::EnvValues {
            api_key: "k".into(),
            private_key: STANDARD.encode(client.to_bytes()),
            server_public_key: STANDARD.encode(PublicKey::from(&server).as_bytes()),
        };
        let payload = json!({"message_type":"Notification","channel":"Push","template":"Notification",
            "identity":"proj","to":"tok","body":"from rust","device_key":"DK","data":{"order":"42"}});
        let enc = crate::core::crypto::encrypt(&payload, Some(env)).unwrap();
        std::fs::write(format!("{dir}/rust_enc.json"), json!({
            "server_priv": STANDARD.encode(server.to_bytes()),
            "client_pub": STANDARD.encode(PublicKey::from(&client).as_bytes()),
            "nonce": enc.nonce, "ciphertext": enc.ciphertext,
        }).to_string()).unwrap();

        // Go → Rust: open what the Go SDK wrote, if it has run.
        if let Ok(raw) = std::fs::read_to_string(format!("{dir}/go_enc.json")) {
            let f: Value = serde_json::from_str(&raw).unwrap();
            let got = server_decrypt(
                &STANDARD.decode(f["server_priv"].as_str().unwrap()).unwrap(),
                &STANDARD.decode(f["client_pub"].as_str().unwrap()).unwrap(),
                f["nonce"].as_str().unwrap(), f["ciphertext"].as_str().unwrap(),
            );
            assert_eq!(got["body"], "from go");
            assert_eq!(got["device_key"], "DK");
            assert_eq!(got["data"]["order"], "42");
            assert!(got["ts"].is_number());
            println!("GO -> RUST: decrypted {}", got);
        }
    }
}
