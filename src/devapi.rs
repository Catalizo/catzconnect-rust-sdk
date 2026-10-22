//! Message status, hosted OTP, the management API and the push device
//! registry, plus the API's error codes.
//!
//! ```rust,no_run
//! # async fn run() -> Result<(), catzconnect::CatzError> {
//! use catzconnect::devapi::{Messages, Otp, OtpStartInput};
//! let m = Messages::new(None).get("6f0c1b9e-1111-4222-8333-944455556666").await?;
//! println!("{} {}", m["status"], m["events"]);
//! let s = Otp::new(None).start(OtpStartInput { channel: "SMS".into(), to: "+919876543210".into(), ..Default::default() }).await?;
//! # Ok(()) }
//! ```

use serde_json::{json, Map, Value};

use crate::core::{crypto, http::HttpClient};
use crate::error::CatzError;
use crate::types::EnvValues;

/// Machine codes the API sends in `code` ([`CatzError::api_code`]).
pub mod codes {
    pub const ORGANIZATION_SUSPENDED: &str = "organization_suspended";
    pub const SENDING_PAUSED: &str = "sending_paused";
    pub const FEATURE_NOT_IN_PLAN: &str = "feature_not_in_plan";
    pub const PLAN_REQUIRED: &str = "plan_required";
    pub const CHANNEL_LIMIT_REACHED: &str = "channel_limit_reached";
    pub const DAILY_LIMIT_REACHED: &str = "daily_limit_reached";
    pub const MONTHLY_LIMIT_REACHED: &str = "monthly_limit_reached";
    pub const MINUTES_CAP_REACHED: &str = "minutes_cap_reached";
    pub const KEY_EXPIRED: &str = "key_expired";
    pub const IP_NOT_ALLOWED: &str = "ip_not_allowed";
    pub const KEY_RATE_LIMITED: &str = "key_rate_limited";
    pub const KEY_SEND_LIMIT: &str = "key_send_limit";
    pub const NOT_ALLOWED_FOR_APP_KEYS: &str = "not_allowed_for_app_keys";
    pub const NOT_ALLOWED_FOR_TEST_KEYS: &str = "not_allowed_for_test_keys";
    pub const MANAGEMENT_SCOPE_REQUIRED: &str = "management_scope_required";
    pub const WHATSAPP_INVALID_TEMPLATE: &str = "whatsapp_invalid_template";
    pub const WHATSAPP_TEMPLATE_NOT_APPROVED: &str = "whatsapp_template_not_approved";
    pub const WHATSAPP_TEMPLATE_LANGUAGE_REQUIRED: &str = "whatsapp_template_language_required";
    pub const WHATSAPP_INVALID_TEMPLATE_PARAMS: &str = "whatsapp_invalid_template_params";
    pub const WHATSAPP_INVALID_MEDIA: &str = "whatsapp_invalid_media";
    pub const WHATSAPP_WINDOW_CLOSED: &str = "whatsapp_window_closed";
    pub const IDEMPOTENCY_CONFLICT: &str = "idempotency_conflict";
    pub const IDEMPOTENCY_IN_PROGRESS: &str = "idempotency_in_progress";
    pub const INVALID_IDEMPOTENCY_KEY: &str = "invalid_idempotency_key";
    pub const INVALID_REFERENCE: &str = "invalid_reference";
    pub const MESSAGE_NOT_FOUND: &str = "message_not_found";
    pub const OTP_INVALID: &str = "otp_invalid";
    pub const OTP_EXPIRED: &str = "otp_expired";
    pub const OTP_NOT_FOUND: &str = "otp_not_found";
    pub const OTP_ALREADY_VERIFIED: &str = "otp_already_verified";
    pub const OTP_ATTEMPTS_EXCEEDED: &str = "otp_attempts_exceeded";
    pub const OTP_RESEND_COOLDOWN: &str = "otp_resend_cooldown";
    pub const OTP_SEND_LIMIT: &str = "otp_send_limit";
    pub const UNSUPPORTED_CHANNEL: &str = "unsupported_channel";
    pub const UNKNOWN_OPERATION: &str = "unknown_operation";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const NOT_FOUND: &str = "not_found";
    pub const CONFLICT: &str = "conflict";
    pub const INVALID_TOPIC: &str = "invalid_topic";
    pub const TOPIC_EMAIL_ONLY: &str = "topic_email_only";
    pub const RECIPIENT_SUPPRESSED: &str = "recipient_suppressed";
    pub const WHATSAPP_OPTED_OUT: &str = "whatsapp_opted_out";
    pub const NOT_CANCELABLE: &str = "not_cancelable";
    pub const NOT_RESENDABLE: &str = "not_resendable";
    pub const CONTENT_GONE: &str = "content_gone";

    /// Refusals worth retrying later with the same request.
    pub fn is_retryable(code: &str) -> bool {
        matches!(code, SENDING_PAUSED | KEY_RATE_LIMITED | KEY_SEND_LIMIT | IDEMPOTENCY_IN_PROGRESS | OTP_RESEND_COOLDOWN)
    }
}

fn bad(m: impl Into<String>) -> CatzError {
    CatzError::Validation(m.into())
}

/// An Idempotency-Key: 1–255 visible ASCII characters, no spaces.
pub fn validate_idempotency_key(k: &str) -> Result<String, CatzError> {
    let t = k.trim();
    if t.is_empty() || t.len() > 255 || !t.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(bad("'idempotency_key' must be 1–255 visible ASCII characters without spaces"));
    }
    Ok(t.to_string())
}

/// A reference: up to 128 characters without control characters (blank = none).
pub fn validate_reference(r: Option<&str>) -> Result<Option<String>, CatzError> {
    let Some(t) = r.map(str::trim).filter(|t| !t.is_empty()) else { return Ok(None) };
    if t.chars().count() > 128 || t.chars().any(char::is_control) {
        return Err(bad("'reference' must be up to 128 characters without line breaks or control characters"));
    }
    Ok(Some(t.to_string()))
}

fn is_uuid(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Shared client settings (credentials, base URL) of the APIs below.
#[derive(Clone, Default)]
pub struct Client {
    env: Option<EnvValues>,
    base_url: Option<String>,
    allow_insecure_http: bool,
}

impl Client {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self { env, base_url: None, allow_insecure_http: false }
    }
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// POSTs an encrypted `/sdk/*` body; returns `data` (or the whole answer).
    pub async fn call(&self, path: &str, body: Value) -> Result<Value, CatzError> {
        let encrypted = crypto::encrypt(&body, self.env.clone())?;
        let client = HttpClient::with_options(self.env.clone(), self.base_url.clone(), self.allow_insecure_http)?;
        let res = client.post(path, &encrypted).await?;
        if res.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(CatzError::ApiError { status: 200, body: res.to_string() });
        }
        Ok(res.get("data").cloned().unwrap_or(res))
    }
}

// ─── message status ──────────────────────────────────────────────────────

/// Filters of [`Messages::list`]: `recipient`, `reference` and/or
/// `broadcast_id` (the deliveries of one push broadcast).
#[derive(Debug, Clone, Default)]
pub struct ListMessagesInput {
    pub recipient: Option<String>,
    pub reference: Option<String>,
    pub broadcast_id: Option<String>,
    /// email | sms | whatsapp | push | voice.
    pub channel: Option<String>,
    /// 1–100 (default 20).
    pub limit: Option<u32>,
    /// The previous page's `next_before`.
    pub before: Option<String>,
}

pub fn build_list_payload(i: &ListMessagesInput) -> Result<Value, CatzError> {
    let mut m = Map::new();
    if let Some(r) = i.recipient.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        m.insert("recipient".into(), r.into());
    }
    if let Some(r) = validate_reference(i.reference.as_deref())? {
        m.insert("reference".into(), r.into());
    }
    if let Some(b) = i.broadcast_id.as_deref().map(str::trim) {
        if !is_uuid(b) {
            return Err(bad("'broadcast_id' must be a broadcast id (UUID)"));
        }
        m.insert("broadcast_id".into(), b.into());
    }
    if m.is_empty() {
        return Err(bad("Give recipient, reference or broadcast_id"));
    }
    if let Some(c) = &i.channel {
        let c = c.to_ascii_lowercase();
        if !["email", "sms", "whatsapp", "push", "voice"].contains(&c.as_str()) {
            return Err(bad("'channel' must be email, sms, whatsapp, push or voice"));
        }
        m.insert("channel".into(), c.into());
    }
    if let Some(l) = i.limit {
        if !(1..=100).contains(&l) {
            return Err(bad("'limit' must be from 1 to 100"));
        }
        m.insert("limit".into(), l.into());
    }
    if let Some(b) = &i.before {
        m.insert("before".into(), b.clone().into());
    }
    Ok(Value::Object(m))
}

/// Status and event timeline of sent messages. Answers are the server's
/// JSON: `{message_id, channel, status, provider_status, to, template,
/// reference, key_id, test, error, created_at, updated_at, events}`.
pub struct Messages(pub Client);

impl Messages {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self(Client::new(env))
    }
    /// One message (with `events`) by the `message_id` a send returned.
    pub async fn get(&self, message_id: &str) -> Result<Value, CatzError> {
        if !is_uuid(message_id.trim()) {
            return Err(bad("'message_id' must be a message id (UUID)"));
        }
        self.0.call("/sdk/messages/get", json!({ "message_id": message_id.trim() })).await
    }
    /// `{messages, next_before}`.
    pub async fn list(&self, input: ListMessagesInput) -> Result<Value, CatzError> {
        self.0.call("/sdk/messages/list", build_list_payload(&input)?).await
    }
}

// ─── hosted OTP ──────────────────────────────────────────────────────────

/// [`Otp::start`] input; `None` numbers keep the server defaults (6 digits,
/// 600 s, 5 attempts, 30 s cooldown).
#[derive(Debug, Clone, Default)]
pub struct OtpStartInput {
    /// Email, SMS, WhatsApp or Voice.
    pub channel: String,
    pub to: String,
    pub identity: Option<String>,
    pub template: Option<String>,
    pub language: Option<String>,
    pub code_length: Option<u32>,
    pub ttl_seconds: Option<u32>,
    pub max_attempts: Option<u32>,
    pub resend_cooldown_seconds: Option<u32>,
    pub gateway: Option<String>,
    pub sender: Option<String>,
    pub dlt_template_id: Option<String>,
    pub provider: Option<String>,
    pub whatsapp: Option<crate::whatsapp::WhatsAppOptions>,
    pub data: Option<std::collections::HashMap<String, String>>,
    pub reference: Option<String>,
}

fn otp_channel(c: &str) -> Option<&'static str> {
    match c.trim().to_ascii_lowercase().as_str() {
        "email" => Some("Email"),
        "sms" => Some("SMS"),
        "whatsapp" => Some("WhatsApp"),
        "voice" => Some("Voice"),
        _ => None,
    }
}

pub fn build_otp_start_payload(i: &OtpStartInput) -> Result<Value, CatzError> {
    let ch = otp_channel(&i.channel).ok_or_else(|| bad("'channel' must be Email, SMS, WhatsApp or Voice"))?;
    if i.to.trim().is_empty() {
        return Err(bad("Missing 'to'"));
    }
    let mut m = Map::new();
    m.insert("channel".into(), ch.into());
    m.insert("to".into(), i.to.trim().into());
    for (k, v) in [
        ("identity", &i.identity), ("template", &i.template), ("language", &i.language), ("gateway", &i.gateway),
        ("sender", &i.sender), ("dlt_template_id", &i.dlt_template_id), ("provider", &i.provider),
    ] {
        if let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            m.insert(k.into(), v.into());
        }
    }
    for (k, v, min, max) in [
        ("code_length", i.code_length, 4, 10), ("ttl_seconds", i.ttl_seconds, 60, 3600),
        ("max_attempts", i.max_attempts, 1, 10), ("resend_cooldown_seconds", i.resend_cooldown_seconds, 10, 3600),
    ] {
        if let Some(n) = v {
            if !(min..=max).contains(&n) {
                return Err(bad(format!("'{k}' must be from {min} to {max}")));
            }
            m.insert(k.into(), n.into());
        }
    }
    if let Some(w) = &i.whatsapp {
        m.insert("whatsapp".into(), serde_json::to_value(w)?);
    }
    if let Some(d) = &i.data {
        m.insert("data".into(), serde_json::to_value(d)?);
    }
    if let Some(r) = validate_reference(i.reference.as_deref())? {
        m.insert("reference".into(), r.into());
    }
    Ok(Value::Object(m))
}

/// [`Otp::verify`] input: `verification_id`, or `channel` and `to`.
#[derive(Debug, Clone, Default)]
pub struct OtpVerifyInput {
    pub verification_id: Option<String>,
    pub channel: Option<String>,
    pub to: Option<String>,
    pub code: String,
}

pub fn build_otp_verify_payload(i: &OtpVerifyInput) -> Result<Value, CatzError> {
    let code: String = i.code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if code.is_empty() || code.len() > 15 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(bad("'code' must be the 1–15 letters or digits that were sent"));
    }
    if let Some(id) = i.verification_id.as_deref() {
        if !is_uuid(id.trim()) {
            return Err(bad("'verification_id' must be a UUID"));
        }
        return Ok(json!({ "verification_id": id.trim(), "code": code }));
    }
    match (i.channel.as_deref().and_then(otp_channel), i.to.as_deref().map(str::trim).filter(|t| !t.is_empty())) {
        (Some(ch), Some(to)) => Ok(json!({ "channel": ch, "to": to, "code": code })),
        _ => Err(bad("Give verification_id, or channel and to")),
    }
}

/// Hosted one-time codes. Refusals are [`CatzError::ApiError`] with codes
/// `otp_invalid` (`api_details()["attempts_remaining"]`), `otp_expired`,
/// `otp_attempts_exceeded`, `otp_resend_cooldown` (`retry_after`),
/// `otp_send_limit`, `otp_not_found`, `otp_already_verified`.
pub struct Otp(pub Client);

impl Otp {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self(Client::new(env))
    }
    /// Sends a code; `code` is in the answer for test keys only.
    pub async fn start(&self, input: OtpStartInput) -> Result<Value, CatzError> {
        self.0.call("/sdk/otp/start", build_otp_start_payload(&input)?).await
    }
    /// `{verified: true, …}`, or an error when the code is wrong.
    pub async fn verify(&self, input: OtpVerifyInput) -> Result<Value, CatzError> {
        self.0.call("/sdk/otp/verify", build_otp_verify_payload(&input)?).await
    }
}

// ─── management API ──────────────────────────────────────────────────────

/// Every `(resource, op)` of the management API.
pub const MANAGE_OPERATIONS: &[(&str, &str)] = &[
    ("templates", "list"), ("templates", "get"), ("templates", "save"), ("templates", "delete"),
    ("templates", "variant_save"), ("templates", "variant_delete"),
    ("webhooks", "list"), ("webhooks", "save"), ("webhooks", "delete"),
    ("suppressions", "list"), ("suppressions", "add"), ("suppressions", "remove"),
    ("keys", "list"), ("keys", "create"), ("keys", "rotate"), ("keys", "revoke"), ("keys", "policy"),
];

/// Templates, webhooks, suppressions and API keys of your organization.
/// Needs a live server key with the management scope on a plan with the
/// management API.
pub struct Manage(pub Client);

impl Manage {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self(Client::new(env))
    }
    /// Runs one operation, e.g. `call("templates", "save", json!({...}))`.
    pub async fn call(&self, resource: &str, op: &str, body: Value) -> Result<Value, CatzError> {
        if !MANAGE_OPERATIONS.contains(&(resource, op)) {
            return Err(bad(format!("Unknown management operation {resource}/{op}")));
        }
        if let ("keys", "create") = (resource, op) {
            if let Some(k) = body.get("kind").and_then(Value::as_str) {
                if k != "server" && k != "test" {
                    return Err(bad("'kind' must be server or test"));
                }
            }
        }
        self.0.call(&format!("/sdk/manage/{resource}/{op}"), body).await
    }

    /// Add to a channel's suppression list: `email` (address), `sms` /
    /// `whatsapp` / `voice` (E.164 number) or `push` (external_user_id);
    /// `topic` (email only) limits it to one subscription topic.
    pub async fn add_suppression(&self, s: SuppressionInput) -> Result<Value, CatzError> {
        if s.channel.as_deref().unwrap_or("").is_empty() {
            return Err(bad("Missing 'channel'"));
        }
        self.call("suppressions", "add", build_suppression_body(&s)?).await
    }

    /// Remove by `id`, or `channel` + `address` (every topic, or `topic`).
    pub async fn remove_suppression(&self, s: SuppressionInput) -> Result<Value, CatzError> {
        if let Some(id) = &s.id {
            if !is_uuid(id.trim()) {
                return Err(bad("'id' must be a suppression id (UUID)"));
            }
            return self.call("suppressions", "remove", json!({ "id": id.trim() })).await;
        }
        self.call("suppressions", "remove", build_suppression_body(&s)?).await
    }
}

/// One suppression entry for [`Manage::add_suppression`] /
/// [`Manage::remove_suppression`].
#[derive(Debug, Clone, Default)]
pub struct SuppressionInput {
    pub id: Option<String>,
    pub channel: Option<String>,
    pub address: String,
    /// Email only.
    pub topic: Option<String>,
    pub detail: Option<String>,
}

pub fn build_suppression_body(s: &SuppressionInput) -> Result<Value, CatzError> {
    if s.address.trim().is_empty() {
        return Err(bad("Missing 'address'"));
    }
    let mut m = Map::new();
    m.insert("address".into(), s.address.trim().into());
    if let Some(c) = &s.channel {
        m.insert("channel".into(), c.clone().into());
    }
    if let Some(t) = &s.topic {
        let email = s.channel.as_deref().map_or(s.address.contains('@'), |c| c.eq_ignore_ascii_case("email"));
        if !email {
            return Err(bad("'topic' applies to email suppressions only"));
        }
        if !crate::core::payload::is_email_topic_key(t) {
            return Err(bad("'topic' must be a topic key"));
        }
        m.insert("topic".into(), t.clone().into());
    }
    if let Some(d) = &s.detail {
        m.insert("detail".into(), d.clone().into());
    }
    Ok(Value::Object(m))
}

// ─── push broadcasts and topics (/sdk/push/*) ────────────────────────────

/// 1–`max` push topic names.
pub fn check_push_topics(topics: &[String], max: usize) -> Result<(), CatzError> {
    if topics.is_empty() || topics.len() > max {
        return Err(bad(format!("'topics' must list 1–{max} topic names")));
    }
    if topics.iter().any(|t| !crate::core::payload::is_push_topic(t)) {
        return Err(bad("A push topic is 1–64 characters of letters, digits, _ . ~ -"));
    }
    Ok(())
}

/// [`PushApi::subscribe`] / [`PushApi::unsubscribe`] input: registered
/// devices by `tokens` (≤ 1000) and/or every device of `external_user_id`.
#[derive(Debug, Clone, Default)]
pub struct PushTopicChange {
    /// The Firebase project id (the send's `identity`).
    pub identity: String,
    pub topic: String,
    pub tokens: Vec<String>,
    pub external_user_id: Option<String>,
}

pub fn build_topic_change_payload(i: &PushTopicChange) -> Result<Value, CatzError> {
    if i.identity.trim().is_empty() {
        return Err(bad("Missing 'identity'"));
    }
    check_push_topics(std::slice::from_ref(&i.topic), 1)?;
    if i.tokens.len() > 1000 {
        return Err(bad("'tokens' must list at most 1000 tokens"));
    }
    let user = i.external_user_id.as_deref().map(str::trim).filter(|u| !u.is_empty());
    if i.tokens.is_empty() && user.is_none() {
        return Err(bad("Give tokens (registered devices) or external_user_id"));
    }
    let mut m = Map::new();
    m.insert("identity".into(), i.identity.trim().into());
    m.insert("topic".into(), i.topic.clone().into());
    if !i.tokens.is_empty() {
        m.insert("tokens".into(), json!(i.tokens));
    }
    if let Some(u) = user {
        m.insert("external_user_id".into(), u.into());
    }
    Ok(Value::Object(m))
}

/// Broadcasts / scheduled pushes (created by a send with
/// [`crate::types::PushOptions`]) and push topic subscriptions, from your
/// server: server keys with the Push channel (app and test keys are
/// refused). Answers are the server's `data`.
pub struct PushApi(pub Client);

impl PushApi {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self(Client::new(env))
    }
    /// Status and counters (`status`, `queued`, `skipped`, `over_quota`, …).
    pub async fn broadcast(&self, broadcast_id: &str) -> Result<Value, CatzError> {
        if !is_uuid(broadcast_id.trim()) {
            return Err(bad("'broadcast_id' must be a broadcast id (UUID)"));
        }
        self.0.call("/sdk/push/broadcast", json!({ "broadcast_id": broadcast_id.trim() })).await
    }
    /// Stop one that has not finished (`not_cancelable` once it has).
    pub async fn cancel(&self, broadcast_id: &str) -> Result<Value, CatzError> {
        if !is_uuid(broadcast_id.trim()) {
            return Err(bad("'broadcast_id' must be a broadcast id (UUID)"));
        }
        self.0.call("/sdk/push/cancel", json!({ "broadcast_id": broadcast_id.trim() })).await
    }
    /// `{topic, devices}`.
    pub async fn subscribe(&self, input: PushTopicChange) -> Result<Value, CatzError> {
        self.0.call("/sdk/push/topic/subscribe", build_topic_change_payload(&input)?).await
    }
    /// `{topic, devices}`.
    pub async fn unsubscribe(&self, input: PushTopicChange) -> Result<Value, CatzError> {
        self.0.call("/sdk/push/topic/unsubscribe", build_topic_change_payload(&input)?).await
    }
    /// `{topics: [{topic, devices, last_subscribed_at}]}`.
    pub async fn topics(&self, identity: &str) -> Result<Value, CatzError> {
        if identity.trim().is_empty() {
            return Err(bad("Missing 'identity'"));
        }
        self.0.call("/sdk/push/topics", json!({ "identity": identity.trim() })).await
    }
}

// ─── push device registry ────────────────────────────────────────────────

/// `POST /push/register` input (publishable key, no API key).
#[derive(Debug, Clone, Default)]
pub struct RegisterDeviceInput {
    pub publishable_key: String,
    pub token: String,
    /// ios | android | web.
    pub platform: String,
    pub external_user_id: Option<String>,
    /// [`crate::compute_user_hash`], computed on your server.
    pub user_hash: Option<String>,
    pub app_version: Option<String>,
    pub device_key: Option<String>,
}

fn check_pk(k: &str) -> Result<(), CatzError> {
    if !(10..=100).contains(&k.trim().len()) {
        return Err(bad("'publishable_key' is required"));
    }
    Ok(())
}
fn check_token(t: &str) -> Result<(), CatzError> {
    if !(32..=4096).contains(&t.trim().len()) {
        return Err(bad("'token' must be the device's FCM registration token"));
    }
    Ok(())
}

pub fn build_register_payload(i: &RegisterDeviceInput) -> Result<Value, CatzError> {
    check_pk(&i.publishable_key)?;
    check_token(&i.token)?;
    if !["ios", "android", "web"].contains(&i.platform.as_str()) {
        return Err(bad("'platform' must be ios, android or web"));
    }
    let mut m = Map::new();
    m.insert("publishable_key".into(), i.publishable_key.trim().into());
    m.insert("token".into(), i.token.trim().into());
    m.insert("platform".into(), i.platform.clone().into());
    if let Some(u) = &i.external_user_id {
        if u.is_empty() || u.chars().count() > 128 || u.chars().any(char::is_control) {
            return Err(bad("'external_user_id' must be 1–128 characters"));
        }
        m.insert("external_user_id".into(), u.clone().into());
    }
    if let Some(v) = &i.app_version {
        if v.chars().count() > 40 {
            return Err(bad("'app_version' is at most 40 characters"));
        }
        m.insert("app_version".into(), v.clone().into());
    }
    for (k, v) in [("user_hash", &i.user_hash), ("device_key", &i.device_key)] {
        if let Some(v) = v {
            m.insert(k.into(), v.clone().into());
        }
    }
    Ok(Value::Object(m))
}

/// The public device endpoints. Answers are the server's `data`.
#[derive(Clone, Default)]
pub struct PushDevices {
    base_url: Option<String>,
    allow_insecure_http: bool,
}

impl PushDevices {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }
    async fn post(&self, path: &str, body: Value) -> Result<Value, CatzError> {
        let res = crate::core::http::post_public(self.base_url.clone(), self.allow_insecure_http, path, &body).await?;
        Ok(res.get("data").cloned().unwrap_or(res))
    }
    /// `{device_id, created}`.
    pub async fn register(&self, input: RegisterDeviceInput) -> Result<Value, CatzError> {
        self.post("/push/register", build_register_payload(&input)?).await
    }
    /// `{removed}`; never fails for an unknown token.
    pub async fn unregister(&self, publishable_key: &str, token: &str) -> Result<Value, CatzError> {
        check_pk(publishable_key)?;
        check_token(token)?;
        self.post("/push/unregister", json!({ "publishable_key": publishable_key.trim(), "token": token.trim() })).await
    }
    /// Subscribe this registered device to 1–20 push topics: `{topics}`
    /// (404 when the token was not registered first).
    pub async fn subscribe_topics(&self, publishable_key: &str, token: &str, topics: &[String]) -> Result<Value, CatzError> {
        check_pk(publishable_key)?;
        check_token(token)?;
        check_push_topics(topics, 20)?;
        self.post("/push/topics/subscribe", json!({ "publishable_key": publishable_key.trim(), "token": token.trim(), "topics": topics })).await
    }
    /// Unsubscribe this registered device from push topics.
    pub async fn unsubscribe_topics(&self, publishable_key: &str, token: &str, topics: &[String]) -> Result<Value, CatzError> {
        check_pk(publishable_key)?;
        check_token(token)?;
        check_push_topics(topics, 20)?;
        self.post("/push/topics/unsubscribe", json!({ "publishable_key": publishable_key.trim(), "token": token.trim(), "topics": topics })).await
    }
    /// `{recorded, verified}`; `message_id` is the notification's
    /// `catz_id`. Without the device's token the open is recorded but not
    /// verified, so no `push.opened` webhook fires: prefer
    /// [`opened_with_token`](Self::opened_with_token).
    pub async fn opened(&self, publishable_key: &str, message_id: &str) -> Result<Value, CatzError> {
        self.opened_with_token(publishable_key, message_id, None).await
    }
    /// `{recorded, verified}`, reported with the FCM registration token of
    /// the device that opened the notification: the open is verified (only
    /// the device it was delivered to can report it) and the first verified
    /// report fires the `push.opened` webhook. `None` (or a blank token)
    /// behaves like [`opened`](Self::opened).
    pub async fn opened_with_token(&self, publishable_key: &str, message_id: &str, token: Option<&str>) -> Result<Value, CatzError> {
        check_pk(publishable_key)?;
        if !is_uuid(message_id.trim()) {
            return Err(bad("'message_id' must be the catz_id from the notification"));
        }
        let mut body = json!({ "publishable_key": publishable_key.trim(), "message_id": message_id.trim() });
        if let Some(t) = token.map(str::trim).filter(|t| !t.is_empty()) {
            check_token(t)?;
            body["token"] = Value::String(t.to_string());
        }
        self.post("/push/opened", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6f0c1b9e-1111-4222-8333-944455556666";

    #[test]
    fn keys_and_references() {
        assert_eq!(validate_idempotency_key(" order-42 ").unwrap(), "order-42");
        assert!(validate_idempotency_key("has space").is_err());
        assert!(validate_idempotency_key(&"k".repeat(256)).is_err());
        assert_eq!(validate_reference(Some("  ")).unwrap(), None);
        assert!(validate_reference(Some("a\nb")).is_err());
        assert!(codes::is_retryable(codes::SENDING_PAUSED));
        assert!(!codes::is_retryable(codes::KEY_EXPIRED));
    }

    #[test]
    fn payload_builders() {
        let l = build_list_payload(&ListMessagesInput { recipient: Some("+15550100".into()), channel: Some("SMS".into()), limit: Some(5), ..Default::default() }).unwrap();
        assert_eq!(l, json!({"recipient": "+15550100", "channel": "sms", "limit": 5}));
        assert!(build_list_payload(&ListMessagesInput::default()).is_err());

        let s = build_otp_start_payload(&OtpStartInput { channel: "sms".into(), to: "+15550100".into(), code_length: Some(8), ..Default::default() }).unwrap();
        assert_eq!(s, json!({"channel": "SMS", "to": "+15550100", "code_length": 8}));
        assert!(build_otp_start_payload(&OtpStartInput { channel: "push".into(), to: "x".into(), ..Default::default() }).is_err());
        assert!(build_otp_start_payload(&OtpStartInput { channel: "email".into(), to: "a@b.co".into(), ttl_seconds: Some(5), ..Default::default() }).is_err());
        let v = build_otp_verify_payload(&OtpVerifyInput { verification_id: Some(ID.into()), code: "123 456".into(), ..Default::default() }).unwrap();
        assert_eq!(v, json!({"verification_id": ID, "code": "123456"}));
        assert!(build_otp_verify_payload(&OtpVerifyInput { code: "1234".into(), ..Default::default() }).is_err());

        let t = "t".repeat(40);
        let r = build_register_payload(&RegisterDeviceInput { publishable_key: "pk_push_abcdef".into(), token: t.clone(), platform: "web".into(), user_hash: Some("h".into()), ..Default::default() }).unwrap();
        assert_eq!(r["user_hash"], "h");
        assert!(build_register_payload(&RegisterDeviceInput { publishable_key: "pk_push_abcdef".into(), token: t, platform: "tv".into(), ..Default::default() }).is_err());
        assert!(is_uuid(ID) && !is_uuid("nope"));
    }

    #[test]
    fn broadcasts_topics_and_suppressions() {
        let l = build_list_payload(&ListMessagesInput { broadcast_id: Some(ID.into()), ..Default::default() }).unwrap();
        assert_eq!(l, json!({"broadcast_id": ID}));
        assert!(build_list_payload(&ListMessagesInput { broadcast_id: Some("x".into()), ..Default::default() }).is_err());

        let t = "t".repeat(40);
        let p = build_topic_change_payload(&PushTopicChange { identity: "my-firebase".into(), topic: "deals".into(), tokens: vec![t.clone()], external_user_id: Some("u1".into()) }).unwrap();
        assert_eq!(p, json!({"identity": "my-firebase", "topic": "deals", "tokens": [t], "external_user_id": "u1"}));
        assert!(build_topic_change_payload(&PushTopicChange { identity: "p".into(), topic: "deals".into(), ..Default::default() }).is_err());
        assert!(build_topic_change_payload(&PushTopicChange { identity: "p".into(), topic: "bad topic".into(), external_user_id: Some("u".into()), ..Default::default() }).is_err());
        assert!(check_push_topics(&[], 20).is_err());
        assert!(check_push_topics(&vec!["a".to_string(); 21], 20).is_err());
        assert!(check_push_topics(&["deals".into(), "news.eu".into()], 20).is_ok());

        let s = build_suppression_body(&SuppressionInput { channel: Some("email".into()), address: "a@b.co".into(), topic: Some("newsletter".into()), detail: Some("asked".into()), ..Default::default() }).unwrap();
        assert_eq!(s, json!({"address": "a@b.co", "channel": "email", "topic": "newsletter", "detail": "asked"}));
        assert!(build_suppression_body(&SuppressionInput { channel: Some("sms".into()), address: "+15550100".into(), topic: Some("newsletter".into()), ..Default::default() }).is_err());
        assert!(build_suppression_body(&SuppressionInput { channel: Some("push".into()), address: " ".into(), ..Default::default() }).is_err());
        for c in [codes::INVALID_TOPIC, codes::TOPIC_EMAIL_ONLY, codes::RECIPIENT_SUPPRESSED, codes::NOT_CANCELABLE, codes::NOT_RESENDABLE, codes::WHATSAPP_OPTED_OUT, codes::CONTENT_GONE] {
            assert!(!c.is_empty());
        }
    }

    #[tokio::test]
    async fn push_and_suppression_calls_validate_before_sending() {
        let p = PushApi::new(None);
        assert!(matches!(p.cancel("nope").await, Err(CatzError::Validation(_))));
        assert!(matches!(p.broadcast("nope").await, Err(CatzError::Validation(_))));
        assert!(matches!(p.topics(" ").await, Err(CatzError::Validation(_))));
        let m = Manage::new(None);
        assert!(matches!(m.add_suppression(SuppressionInput { address: "a@b.co".into(), ..Default::default() }).await, Err(CatzError::Validation(_))));
        assert!(matches!(m.remove_suppression(SuppressionInput { id: Some("x".into()), ..Default::default() }).await, Err(CatzError::Validation(_))));
        let d = PushDevices::new();
        assert!(matches!(d.subscribe_topics("pk_push_abcdef", &"t".repeat(40), &[]).await, Err(CatzError::Validation(_))));
    }

    #[tokio::test]
    async fn manage_refuses_unknown_operations_before_sending() {
        let m = Manage::new(None);
        assert!(matches!(m.call("keys", "explode", json!({})).await, Err(CatzError::Validation(_))));
        assert!(matches!(m.call("keys", "create", json!({"name": "x", "kind": "app"})).await, Err(CatzError::Validation(_))));
    }
}
