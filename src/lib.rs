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
pub mod whatsapp;
pub mod devapi;

/// Server-side: the `user_hash` for `POST /push/register` (see [`webhook::compute_user_hash`]).
pub use webhook::compute_user_hash;

pub(crate) mod core;
mod utils;

use serde_json::json;

use core::{crypto, http::HttpClient, payload::verify_payload_with};
pub use error::CatzError;

/// Per-call options for [`CatzConnect::send_with_options`]. The default is
/// what [`CatzConnect::send`] does: `CATZCONNECT_BASE_URL` (or the default
/// API), https only unless `CATZCONNECT_ALLOW_INSECURE_HTTP` is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendOptions {
    /// Overrides `CATZCONNECT_BASE_URL` (staging, tests).
    pub base_url: Option<String>,
    /// Accept a plain `http://` base URL to a host other than localhost,
    /// 127.0.0.1, ::1 or 10.0.2.2 (the key then travels unencrypted).
    pub allow_insecure_http: bool,
}

impl SendOptions {
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }
}
use types::{
    Channel,
    MessageType,
    Template,
    SendInput,
    SendExtras,
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
        Self::send_with_options(input, env, SendOptions::default()).await
    }

    /// [`CatzConnect::send`] with per-call options: a base URL that wins
    /// over `CATZCONNECT_BASE_URL`, and the opt-in for a plain `http://`
    /// base URL to a non-local host (the same switches [`calls::Calls`] has).
    ///
    /// ```rust,no_run
    /// # use catzconnect::{CatzConnect, SendOptions, types::SendInput};
    /// # async fn run(input: SendInput) -> Result<(), catzconnect::CatzError> {
    /// let opts = SendOptions::default().with_base_url("http://staging.internal:8080").allow_insecure_http(true);
    /// CatzConnect::send_with_options(input, None, opts).await?;
    /// # Ok(()) }
    /// ```
    pub async fn send_with_options(
        input: SendInput,
        env: Option<EnvValues>,
        options: SendOptions,
    ) -> Result<serde_json::Value, CatzError> {
        Self::send_full(input, SendExtras::default(), env, options).await
    }

    /// [`CatzConnect::send`] with the 2.0.0 per-message options
    /// ([`SendExtras`]: idempotency key, reference, WhatsApp templates /
    /// media, Email tracking and topic, push broadcasts / schedules).
    ///
    /// ```rust,no_run
    /// # use catzconnect::{CatzConnect, types::{SendExtras, SendInput}};
    /// # async fn run(input: SendInput) -> Result<(), catzconnect::CatzError> {
    /// let extras = SendExtras::new().idempotency_key("order-42").reference("order 42");
    /// CatzConnect::send_with_extras(input, extras, None).await?;
    /// # Ok(()) }
    /// ```
    pub async fn send_with_extras(
        input: SendInput,
        extras: SendExtras,
        env: Option<EnvValues>,
    ) -> Result<serde_json::Value, CatzError> {
        Self::send_full(input, extras, env, SendOptions::default()).await
    }

    /// [`CatzConnect::send_with_extras`] and [`CatzConnect::send_with_options`] together.
    pub async fn send_full(
        input: SendInput,
        extras: SendExtras,
        env: Option<EnvValues>,
        options: SendOptions,
    ) -> Result<serde_json::Value, CatzError> {
        // 1–2. Validate and build
        let final_payload = Self::build_payload_with_extras(&input, &extras)?;

        // 3. Encrypt
        let encrypted = crypto::encrypt(&final_payload, env.clone())?;

        // 4. Send
        let client = HttpClient::with_options(env, options.base_url, options.allow_insecure_http)?;
        let idem = final_payload.get("idempotency_key").and_then(|v| v.as_str()).map(str::to_string);
        let headers: Vec<(&str, String)> = idem.map(|k| vec![("Idempotency-Key", k)]).unwrap_or_default();
        let response = client.post_with_headers("/sdk/send", &encrypted, &headers).await?;

        Ok(response)
    }

    /// The JSON body (before encryption) that [`CatzConnect::send`] posts
    /// for `input`, after validating it. `payload.language`, when set, is
    /// normalised (`"de-DE"` → `"de"`) and added at the top level; without
    /// it the body is exactly what earlier versions sent.
    pub fn build_payload(input: &SendInput) -> Result<serde_json::Value, CatzError> {
        Self::build_payload_with_extras(input, &SendExtras::default())
    }

    /// [`CatzConnect::build_payload`] with [`SendExtras`]; with the default
    /// extras the body is exactly what `build_payload` returns.
    pub fn build_payload_with_extras(input: &SendInput, extras: &SendExtras) -> Result<serde_json::Value, CatzError> {
        // 1. Validate
        verify_payload_with(input, extras)?;
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
            (Channel::WhatsApp, _, Template::Custom) if extras.whatsapp.as_ref().is_some_and(|w| w.media.is_some()) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "body":         input.payload.body,
                "whatsapp":     extras.whatsapp,
            }),

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

            (Channel::WhatsApp, _, Template::Named(_)) => json!({
                "message_type": format!("{:?}", input.message_type),
                "channel":      format!("{:?}", input.channel),
                "template":     input.template.name(),
                "identity":     input.identity,
                "to":           input.payload.to,
                "otp":          input.payload.otp,
                "whatsapp":     extras.whatsapp,
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
        // Left out when unset, so existing sends post the same body as before.
        if let Some(obj) = final_payload.as_object_mut() {
            if matches!(input.channel, Channel::Email) {
                if let Some(t) = &extras.tracking {
                    obj.insert("tracking".into(), serde_json::to_value(t)?);
                }
                if let Some(t) = &extras.topic {
                    obj.insert("topic".into(), t.clone().into());
                }
            }
            if matches!(input.channel, Channel::Push) {
                if let Some(p) = extras.push.as_ref().filter(|p| p.broadcast || p.topic.is_some() || p.send_at.is_some()) {
                    obj.insert("push".into(), serde_json::to_value(p)?);
                }
            }
            if let Some(k) = extras.idempotency_key.as_deref() {
                obj.insert("idempotency_key".into(), devapi::validate_idempotency_key(k)?.into());
            }
            if let Some(r) = devapi::validate_reference(extras.reference.as_deref())? {
                obj.insert("reference".into(), r.into());
            }
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

#[cfg(test)]
mod devapi_send_tests {
    use super::*;
    use types::{PushOptions, SendPayload};
    use whatsapp::{TrackingOverride, WhatsAppBody, WhatsAppMedia, WhatsAppOptions};

    fn input(channel: Channel, mt: MessageType, template: Template, payload: SendPayload) -> SendInput {
        SendInput { message_type: mt, channel, template, identity: "919578456444".into(), payload }
    }
    fn email() -> SendPayload {
        SendPayload { to: Some("a@b.co".into()), subject: Some("s".into()), body: Some("b".into()), ..Default::default() }
    }
    fn bp(i: &SendInput, x: SendExtras) -> Result<serde_json::Value, CatzError> {
        CatzConnect::build_payload_with_extras(i, &x)
    }

    #[test]
    fn a_1_6_send_payload_literal_still_compiles() {
        // Every field of 1.6.x, no `..Default::default()`: must keep compiling.
        let p = SendPayload {
            to: Some("a@b.co".into()), otp: None, language: None, subject: Some("s".into()), body: Some("b".into()),
            title: None, data: None, image: None, link: None, device_key: None, external_user_id: None,
            gateway: None, sender: None, dlt_template_id: None, provider: None,
        };
        let i = input(Channel::Email, MessageType::Transactional, Template::Custom, p);
        assert_eq!(CatzConnect::build_payload(&i).unwrap(), bp(&i, SendExtras::default()).unwrap());
    }

    #[test]
    fn idempotency_reference_and_tracking() {
        let i = input(Channel::Email, MessageType::Transactional, Template::Custom, email());
        let p = bp(&i, SendExtras::new()
            .tracking(TrackingOverride { opens: Some(false), clicks: None })
            .idempotency_key("order-42").reference("order 42")).unwrap();
        assert_eq!(p["idempotency_key"], "order-42");
        assert_eq!(p["reference"], "order 42");
        assert_eq!(p["tracking"], serde_json::json!({"opens": false}));
        let plain = CatzConnect::build_payload(&i).unwrap();
        for k in ["idempotency_key", "reference", "tracking", "whatsapp"] {
            assert!(plain.get(k).is_none(), "{k}");
        }
        assert!(bp(&i, SendExtras::new().idempotency_key("has space")).is_err());
        let sms = input(Channel::Sms, MessageType::Transactional, Template::Custom, SendPayload {
            to: Some("+15550100".into()), body: Some("x".into()), ..Default::default()
        });
        assert!(bp(&sms, SendExtras::new().tracking(TrackingOverride::default())).is_err());
    }

    #[test]
    fn email_topic_and_push_options() {
        let e = bp(&input(Channel::Email, MessageType::Transactional, Template::Custom, email()), SendExtras::new().topic("newsletter")).unwrap();
        assert_eq!(e["topic"], "newsletter");
        let err = bp(&input(Channel::Email, MessageType::Transactional, Template::Custom, email()), SendExtras::new().topic("News Letter")).unwrap_err();
        assert!(err.to_string().contains("topic key"), "{err}");
        let err = bp(&input(Channel::Sms, MessageType::Transactional, Template::Custom, SendPayload {
            to: Some("+15550100".into()), body: Some("x".into()), ..Default::default()
        }), SendExtras::new().topic("newsletter")).unwrap_err();
        assert!(err.to_string().contains("Email channel only"), "{err}");

        let push = |p: SendPayload| input(Channel::Push, MessageType::Notification, Template::Notification, p);
        let body = || SendPayload { body: Some("x".into()), ..Default::default() };
        let b = bp(&push(SendPayload { body: Some("Sale".into()), ..Default::default() }),
            SendExtras::new().push(PushOptions { topic: Some("deals".into()), send_at: Some("2026-11-02T09:00:00Z".into()), ..Default::default() })).unwrap();
        assert_eq!(b["push"], serde_json::json!({"topic": "deals", "send_at": "2026-11-02T09:00:00Z"}));
        let all = bp(&push(body()), SendExtras::new().push(PushOptions { broadcast: true, ..Default::default() })).unwrap();
        assert_eq!(all["push"], serde_json::json!({"broadcast": true}));
        let tok = "t".repeat(40);
        let one = bp(&push(SendPayload { to: Some(tok.clone()), body: Some("x".into()), ..Default::default() }),
            SendExtras::new().push(PushOptions { send_at: Some("2026-11-02T09:00:00+02:00".into()), ..Default::default() })).unwrap();
        assert_eq!(one["to"], tok.as_str());
        for (p, o, want) in [
            (SendPayload { to: Some(tok.clone()), body: Some("x".into()), ..Default::default() }, PushOptions { broadcast: true, ..Default::default() }, "leave 'to'"),
            (body(), PushOptions { broadcast: true, topic: Some("a".into()), ..Default::default() }, "not both"),
            (body(), PushOptions { topic: Some("a/b".into()), ..Default::default() }, "push.topic"),
            (body(), PushOptions { broadcast: true, send_at: Some("2026-11-02 09:00".into()), ..Default::default() }, "RFC 3339"),
            (SendPayload { body: Some("x".into()), device_key: Some("k".into()), ..Default::default() }, PushOptions { topic: Some("a".into()), ..Default::default() }, "device_key"),
        ] {
            let err = bp(&push(p), SendExtras::new().push(o)).unwrap_err();
            assert!(err.to_string().contains(want), "{err} / {want}");
        }
        let err = bp(&input(Channel::Email, MessageType::Transactional, Template::Custom, email()),
            SendExtras::new().push(PushOptions { broadcast: true, ..Default::default() })).unwrap_err();
        assert!(err.to_string().contains("Push channel only"), "{err}");
    }

    #[test]
    fn whatsapp_templates_and_media() {
        let to = || SendPayload { to: Some("+919876543210".into()), ..Default::default() };
        let t = bp(&input(Channel::WhatsApp, MessageType::Transactional, Template::Named("order_update".into()), to()),
            SendExtras::new().whatsapp(WhatsAppOptions { language: Some("en_US".into()), body: Some(WhatsAppBody::Positional(vec!["Ravi".into()])), ..Default::default() })).unwrap();
        assert_eq!(t["template"], "order_update");
        assert_eq!(t["whatsapp"]["body"][0], "Ravi");
        let m = bp(&input(Channel::WhatsApp, MessageType::Transactional, Template::Custom, SendPayload {
            to: Some("+919876543210".into()), body: Some("Invoice".into()), ..Default::default()
        }), SendExtras::new().whatsapp(WhatsAppOptions { media: Some(WhatsAppMedia { kind: "document".into(), link: Some("https://x/i.pdf".into()), ..Default::default() }), ..Default::default() })).unwrap();
        assert_eq!(m["whatsapp"]["media"]["type"], "document");
        assert_eq!(m["body"], "Invoice");
        assert!(CatzConnect::build_payload(&input(Channel::WhatsApp, MessageType::Transactional, Template::Named("Order Update".into()), to())).is_err());
        assert!(bp(&input(Channel::Email, MessageType::Transactional, Template::Custom, email()), SendExtras::new().whatsapp(WhatsAppOptions::default())).is_err());
    }

    #[test]
    fn api_errors_expose_code_and_details() {
        let e = CatzError::ApiError { status: 400, body: r#"{"success":false,"message":"wrong","code":"otp_invalid","attempts_remaining":2}"#.into() };
        assert_eq!(e.api_code().as_deref(), Some(devapi::codes::OTP_INVALID));
        assert_eq!(e.api_details().unwrap()["attempts_remaining"], 2);
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
