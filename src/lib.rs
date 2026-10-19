//! # CatzConnect SDK (Rust)
//!
//! A secure, minimal SDK for sending encrypted communication requests
//! (email, WhatsApp, push, SMS and phone calls) to the CatzConnect API, and
//! for Voice & Video calls ([`CatzConnect::calls`]).
//!
//! ## Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! catzconnect = "1.5"
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

pub mod calls;
pub mod error;
pub mod language;
pub mod sms;
pub mod voice;
pub mod types;
pub mod webhook;

/// Server-side: the `user_hash` for `POST /push/register` (see [`webhook::compute_user_hash`]).
pub use webhook::compute_user_hash;

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
    SmsSendResult,
    VoiceSendResult,
};

pub struct CatzConnect;

impl CatzConnect {
    /// Voice & Video calls (create, token, get, end), with credentials from
    /// the environment. See [`calls::Calls`].
    ///
    /// ```rust,no_run
    /// use catzconnect::{CatzConnect, calls::{CallMode, CreateCallInput}};
    /// # async fn run() -> Result<(), catzconnect::CatzError> {
    /// let call = CatzConnect::calls().create(CreateCallInput {
    ///     mode: CallMode::Video,
    ///     from: "alice".into(),
    ///     to:   vec!["bob".into()],
    ///     ..Default::default()
    /// }).await?;
    /// let token = CatzConnect::calls().token("alice", None).await?;
    /// println!("{} {}", call.id, token.ws_url);
    /// # Ok(()) }
    /// ```
    pub fn calls() -> calls::Calls {
        calls::Calls::new(None)
    }

    /// [`CatzConnect::calls`] with explicit credentials.
    pub fn calls_with(env: EnvValues) -> calls::Calls {
        calls::Calls::new(Some(env))
    }

    /// Places a phone call (`input.channel` must be [`Channel::Voice`]) and
    /// returns the queued call's id.
    pub async fn send_voice(input: SendInput, env: Option<EnvValues>) -> Result<VoiceSendResult, CatzError> {
        if !matches!(input.channel, Channel::Voice) {
            return Err(CatzError::Validation(format!(
                "send_voice is for the Voice channel, not {}",
                input.channel.name()
            )));
        }
        let response = Self::send(input, env).await?;
        VoiceSendResult::from_response(&response).ok_or_else(|| {
            CatzError::Validation(format!("Unexpected Voice response: {response}"))
        })
    }

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
        // 1–2. Validate and build
        let final_payload = Self::build_payload(&input)?;

        // 3. Encrypt
        let encrypted = crypto::encrypt(&final_payload, env.clone())?;

        // 4. Send
        let client = HttpClient::from_env(env)?;
        let response = client.post("/sdk/send", &encrypted).await?;

        Ok(response)
    }

    /// The JSON body (before encryption) that [`CatzConnect::send`] posts
    /// for `input`, after validating it. `payload.language`, when set, is
    /// normalised (`"de-DE"` → `"de"`) and added at the top level; without
    /// it the body is exactly what earlier versions sent.
    pub fn build_payload(input: &SendInput) -> Result<serde_json::Value, CatzError> {
        // 1. Validate
        verify_payload(input)?;
        let language = match input.payload.language.as_deref() {
            Some(l) => Some(language::normalize_language(l)?),
            None => None,
        };

        // 2. Build flat payload mirroring the TypeScript finalPayload spread:
        //    { message_type, channel, template, ...payload }
        //    serde_json preserve_order feature → IndexMap → insertion order matches JS
        let mut final_payload = match (
            &input.channel,
            &input.message_type,
            &input.template,
        ) {
            (Channel::Email, MessageType::Verification, Template::Otp) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "otp":          input.payload.otp,
            }),

            (Channel::Email, MessageType::Transactional, Template::Custom) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "subject":      input.payload.subject,
                "body":         input.payload.body,
            }),

            (Channel::WhatsApp, MessageType::Verification, Template::Otp) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "otp":          input.payload.otp,
            }),

            (Channel::WhatsApp, MessageType::Transactional, Template::Custom) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "subject":      input.payload.subject,
                "body":         input.payload.body,
            }),

            (Channel::Push, MessageType::Notification, Template::Notification) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "title":        input.payload.title,
                "body":         input.payload.body,
                "data":         input.payload.data,
                "image":        input.payload.image,
                "link":         input.payload.link,
                "device_key":   input.payload.device_key,
                "external_user_id": input.payload.external_user_id,
            }),

            (Channel::Email, _, Template::Named(_)) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "data":         input.payload.data,
            }),

            (Channel::Sms, _, _) => sms::build_payload(&input),

            (Channel::Voice, _, _) => voice::build_payload(&input),

            _ => {
                return Err(CatzError::Validation(
                    "Unsupported channel/message_type/template combination".into(),
                ));
            }
        };

        if let (Some(lang), Some(obj)) = (language, final_payload.as_object_mut()) {
            obj.insert("language".into(), serde_json::Value::String(lang.into()));
        }

        Ok(final_payload)
    }

    /// Sends an SMS (`input.channel` must be [`Channel::Sms`]) and returns the
    /// queued message's id, segments and encoding.
    ///
    /// ```rust,no_run
    /// use catzconnect::{CatzConnect, types::{Channel, MessageType, SendInput, SendPayload, Template}};
    ///
    /// # async fn run() -> Result<(), catzconnect::CatzError> {
    /// let sent = CatzConnect::send_sms(SendInput {
    ///     message_type: MessageType::Verification,
    ///     channel:      Channel::Sms,
    ///     template:     Template::Otp,
    ///     identity:     String::new(), // ignored for SMS
    ///     payload: SendPayload {
    ///         to:  Some("+14155550100".into()),
    ///         otp: Some("123456".into()),
    ///         ..Default::default()
    ///     },
    /// }, None).await?;
    /// println!("{} ({} segment(s), {})", sent.message_id, sent.segments, sent.encoding);
    /// # Ok(()) }
    /// ```
    pub async fn send_sms(input: SendInput, env: Option<EnvValues>) -> Result<SmsSendResult, CatzError> {
        if !matches!(input.channel, Channel::Sms) {
            return Err(CatzError::Validation(format!(
                "send_sms is for the SMS channel, not {}",
                input.channel.name()
            )));
        }
        let response = Self::send(input, env).await?;
        SmsSendResult::from_response(&response).ok_or_else(|| {
            CatzError::Validation(format!("Unexpected SMS response: {response}"))
        })
    }
}
#[cfg(test)]
mod language_tests {
    use super::*;
    use types::SendPayload;

    fn otp(channel: Channel, to: &str, language: Option<&str>) -> SendInput {
        SendInput {
            message_type: MessageType::Verification,
            channel,
            template: Template::Otp,
            identity: "a@b.co".into(),
            payload: SendPayload {
                to: Some(to.into()),
                otp: Some("123456".into()),
                language: language.map(Into::into),
                ..Default::default()
            },
        }
    }

    #[test]
    fn language_is_omitted_when_unset_and_normalised_when_set() {
        let p = CatzConnect::build_payload(&otp(Channel::Email, "u@x.co", None)).unwrap();
        assert!(p.get("language").is_none(), "{p}");
        let p = CatzConnect::build_payload(&otp(Channel::Email, "u@x.co", Some("de-DE"))).unwrap();
        assert_eq!(p["language"], "de");
        assert_eq!(p["channel"], "Email");
        let p = CatzConnect::build_payload(&otp(Channel::Sms, "+14155550100", Some("HI"))).unwrap();
        assert_eq!(p["language"], "hi");
        let p = CatzConnect::build_payload(&otp(Channel::WhatsApp, "+919876543210", Some("ar"))).unwrap();
        assert_eq!(p["language"], "ar");
    }

    #[test]
    fn voice_keeps_data_language_next_to_language() {
        let mut input = otp(Channel::Voice, "+14155550100", Some("ja-JP"));
        input.payload.data = Some([("language".to_string(), "en-US".to_string())].into());
        let p = CatzConnect::build_payload(&input).unwrap();
        assert_eq!(p["language"], "ja");
        assert_eq!(p["data"]["language"], "en-US");
    }

    #[test]
    fn unsupported_language_is_a_validation_error() {
        let err = CatzConnect::build_payload(&otp(Channel::Email, "u@x.co", Some("fr-FR"))).unwrap_err();
        assert!(matches!(err, CatzError::Validation(ref m) if m.contains("\"fr-FR\"") && m.contains("en, de, ja, ar, hi")), "{err}");
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
