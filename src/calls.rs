//! Voice & Video calls from your backend: create a call, mint a user token
//! for the browser/app client, read a call, end it. Every request uses the
//! same API key, encryption and headers as [`CatzConnect::send`].
//!
//! ```rust,no_run
//! use catzconnect::{CatzConnect, calls::{CallMode, CreateCallInput}};
//! # async fn run() -> Result<(), catzconnect::CatzError> {
//! let call = CatzConnect::calls().create(CreateCallInput {
//!     mode: CallMode::Video,
//!     from: "alice".into(),
//!     to:   vec!["bob".into()],
//!     ..Default::default()
//! }).await?;
//! let tok = CatzConnect::calls().token("alice", Some(3600)).await?;
//! // give tok.token and tok.ws_url to alice's browser; it joins call.id
//! # Ok(()) }
//! ```
//!
//! Refusals are [`CatzError::ApiError`]; [`CatzError::api_code`] gives the
//! server's code (`plan_required`, `minutes_cap_reached`, …).
//!
//! [`CatzConnect::send`]: crate::CatzConnect::send

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    core::{crypto, http::HttpClient},
    error::CatzError,
    types::EnvValues,
};

/// Most callees per call (the caller makes 50).
pub const MAX_CALLEES: usize = 49;
/// Longest external user id, in characters.
pub const USER_ID_MAX: usize = 128;
/// Largest `metadata`, as JSON bytes.
pub const METADATA_MAX_BYTES: usize = 4096;
pub const TOKEN_TTL_MIN: u32 = 60;
pub const TOKEN_TTL_MAX: u32 = 86400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallMode {
    #[default]
    Audio,
    Video,
}

impl CallMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CallMode::Audio => "audio",
            CallMode::Video => "video",
        }
    }
}

/// The input to [`Calls::create`]. Build with `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct CreateCallInput {
    pub mode: CallMode,
    /// The caller's external user id (your user id, ≤ 128 characters).
    pub from: String,
    /// The callees: 1–49 unique user ids, not including `from`.
    pub to: Vec<String>,
    /// `"auto"` (default: the org's setting), `"catz"`, or a configured
    /// provider's id or label in the key's scope.
    pub engine: Option<String>,
    /// Ring the callees (WebSocket + push). Server default: true.
    pub ring: Option<bool>,
    /// Your own JSON object, ≤ 4 KB, delivered with `incoming`.
    pub metadata: Option<Value>,
    /// Participant cap (caller included), 2–50.
    pub max_participants: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallParticipant {
    pub user_id: String,
    /// `caller` or `callee`.
    pub role: String,
    /// `invited`, `ringing`, `joined`, `left`, `declined` or `missed`.
    pub state: String,
    #[serde(default)]
    pub joined_at: Option<String>,
    #[serde(default)]
    pub left_at: Option<String>,
    #[serde(default)]
    pub seconds: Option<i64>,
    /// `direct`, `relay` or `provider`.
    #[serde(default)]
    pub connection: Option<String>,
}

/// The configured provider a call runs on (engine not `catz`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallProvider {
    /// The provider row id.
    pub id: String,
    /// Its label in the panel.
    #[serde(default)]
    pub label: Option<String>,
    /// Registry name: `agora`, `livekit`, …
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub id: String,
    /// `catz` or a provider id.
    pub engine: String,
    /// None for engine `catz`.
    #[serde(default)]
    pub provider: Option<CallProvider>,
    pub mode: CallMode,
    /// `ringing`, `active`, `ended`, `missed`, `declined`, `canceled` or `failed`.
    pub status: String,
    #[serde(default)]
    pub room: String,
    #[serde(default)]
    pub participants: Vec<CallParticipant>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub duration_secs: Option<i64>,
    #[serde(default)]
    pub billed_minutes: Option<i64>,
    #[serde(default)]
    pub end_reason: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

/// A user token for the browser/app client; it never contains the API key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallToken {
    pub token: String,
    /// As the server sent it (a timestamp string or unix seconds).
    #[serde(default)]
    pub expires_at: Value,
    /// The signaling URL for the client.
    #[serde(default)]
    pub ws_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndCallResult {
    pub success: bool,
    pub message: String,
}

fn invalid(m: impl Into<String>) -> CatzError {
    CatzError::Validation(m.into())
}

/// Non-empty, ≤ 128 characters, no control characters.
pub fn validate_user_id(id: &str, field: &str) -> Result<(), CatzError> {
    if id.trim().is_empty() {
        return Err(invalid(format!("Missing {field}")));
    }
    if id.chars().count() > USER_ID_MAX {
        return Err(invalid(format!("{field} must be at most {USER_ID_MAX} characters")));
    }
    if id.chars().any(char::is_control) {
        return Err(invalid(format!("{field} contains control characters")));
    }
    Ok(())
}

fn validate_call_id(id: &str) -> Result<String, CatzError> {
    let t = id.trim();
    if t.is_empty() {
        return Err(invalid("Missing call id"));
    }
    if t.len() > 128 || t.chars().any(char::is_control) {
        return Err(invalid("Invalid call id"));
    }
    Ok(t.to_string())
}

/// The JSON body (before encryption) [`Calls::create`] posts, after the
/// server's checks.
pub fn build_create_payload(input: &CreateCallInput) -> Result<Value, CatzError> {
    validate_user_id(&input.from, "'from'")?;
    if input.to.is_empty() {
        return Err(invalid("'to' must list at least one user id"));
    }
    if input.to.len() > MAX_CALLEES {
        return Err(invalid(format!("'to' can list at most {MAX_CALLEES} user ids")));
    }
    let mut seen = std::collections::HashSet::new();
    for u in &input.to {
        validate_user_id(u, "'to' entry")?;
        if *u == input.from {
            return Err(invalid("'to' must not include the caller ('from')"));
        }
        if !seen.insert(u.as_str()) {
            return Err(invalid(format!("'to' lists '{u}' twice")));
        }
    }

    let mut m = Map::new();
    m.insert("mode".into(), input.mode.as_str().into());
    m.insert("from".into(), input.from.clone().into());
    m.insert("to".into(), json!(input.to));
    if let Some(e) = &input.engine {
        let e = e.trim();
        if e.is_empty() {
            return Err(invalid("'engine' must be \"auto\", \"catz\" or a provider id or label"));
        }
        m.insert("engine".into(), e.into());
    }
    if let Some(r) = input.ring {
        m.insert("ring".into(), r.into());
    }
    if let Some(md) = &input.metadata {
        if !md.is_object() {
            return Err(invalid("'metadata' must be a JSON object"));
        }
        if serde_json::to_string(md)?.len() > METADATA_MAX_BYTES {
            return Err(invalid("'metadata' must be at most 4 KB as JSON"));
        }
        m.insert("metadata".into(), md.clone());
    }
    if let Some(n) = input.max_participants {
        if !(2..=(MAX_CALLEES as u32 + 1)).contains(&n) {
            return Err(invalid(format!("'max_participants' must be from 2 to {}", MAX_CALLEES + 1)));
        }
        if input.to.len() + 1 > n as usize {
            return Err(invalid(format!("{} participants do not fit 'max_participants' {n}", input.to.len() + 1)));
        }
        m.insert("max_participants".into(), n.into());
    }
    Ok(Value::Object(m))
}

/// The JSON body [`Calls::token`] posts.
pub fn build_token_payload(user_id: &str, ttl_seconds: Option<u32>) -> Result<Value, CatzError> {
    validate_user_id(user_id, "'user_id'")?;
    let mut m = Map::new();
    m.insert("user_id".into(), user_id.into());
    if let Some(t) = ttl_seconds {
        if !(TOKEN_TTL_MIN..=TOKEN_TTL_MAX).contains(&t) {
            return Err(invalid(format!("'ttl_seconds' must be from {TOKEN_TTL_MIN} to {TOKEN_TTL_MAX}")));
        }
        m.insert("ttl_seconds".into(), t.into());
    }
    Ok(Value::Object(m))
}

/// A field at the top level (`{success, call}`) or under `data`.
fn field<'a>(res: &'a Value, name: &str) -> Option<&'a Value> {
    res.get(name).or_else(|| res.get("data").and_then(|d| d.get(name)))
}

fn decode_call(res: &Value) -> Result<Call, CatzError> {
    let v = field(res, "call").ok_or_else(|| invalid(format!("Unexpected response: no call in {res}")))?;
    Ok(serde_json::from_value(v.clone())?)
}

/// The calls API: [`crate::CatzConnect::calls`].
#[derive(Debug, Clone, Default)]
pub struct Calls {
    env: Option<EnvValues>,
    base_url: Option<String>,
    allow_insecure_http: bool,
}

impl Calls {
    pub fn new(env: Option<EnvValues>) -> Self {
        Self { env, base_url: None, allow_insecure_http: false }
    }

    /// Accept a plain `http://` base URL to a host other than localhost,
    /// 127.0.0.1, ::1 or 10.0.2.2 (also `CATZCONNECT_ALLOW_INSECURE_HTTP=1`).
    /// Default false: such a URL fails with [`CatzError::Validation`]
    /// before anything is sent.
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Overrides `CATZCONNECT_BASE_URL` for these calls (staging, tests).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    async fn post(&self, path: &str, payload: Value) -> Result<Value, CatzError> {
        let encrypted = crypto::encrypt(&payload, self.env.clone())?;
        let client = HttpClient::with_options(self.env.clone(), self.base_url.clone(), self.allow_insecure_http)?;
        let res = client.post(path, &encrypted).await?;
        let res = crypto::open_response(res, &self.env)?;
        if res.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(CatzError::ApiError { status: 200, body: res.to_string() });
        }
        Ok(res)
    }

    /// Creates a call and (unless `ring: Some(false)`) rings the callees.
    pub async fn create(&self, input: CreateCallInput) -> Result<Call, CatzError> {
        let res = self.post("/sdk/calls/create", build_create_payload(&input)?).await?;
        decode_call(&res)
    }

    /// Mints a user token; `ttl_seconds` 60–86400, `None` for the server default (3600).
    pub async fn token(&self, user_id: &str, ttl_seconds: Option<u32>) -> Result<CallToken, CatzError> {
        let res = self.post("/sdk/calls/token", build_token_payload(user_id, ttl_seconds)?).await?;
        let token = field(&res, "token").and_then(Value::as_str).filter(|t| !t.is_empty());
        let Some(token) = token else {
            return Err(invalid("Unexpected response: no token"));
        };
        Ok(CallToken {
            token: token.to_string(),
            expires_at: field(&res, "expires_at").cloned().unwrap_or(Value::Null),
            ws_url: field(&res, "ws_url").and_then(Value::as_str).unwrap_or_default().to_string(),
        })
    }

    /// Reads a call with participants, duration, billed minutes and end reason.
    pub async fn get(&self, call_id: &str) -> Result<Call, CatzError> {
        let res = self.post("/sdk/calls/get", json!({ "call_id": validate_call_id(call_id)? })).await?;
        decode_call(&res)
    }

    /// Ends a call for everyone.
    pub async fn end(&self, call_id: &str, reason: Option<&str>) -> Result<EndCallResult, CatzError> {
        let mut body = json!({ "call_id": validate_call_id(call_id)? });
        if let Some(r) = reason.map(str::trim).filter(|r| !r.is_empty()) {
            body["reason"] = r.into();
        }
        let res = self.post("/sdk/calls/end", body).await?;
        Ok(EndCallResult {
            success: res.get("success").and_then(Value::as_bool).unwrap_or(true),
            message: res.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use blake2::{digest::{Update, VariableOutput}, Blake2bVar};
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn b2(d: &[u8]) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).unwrap();
        h.update(d);
        let mut o = [0u8; 32];
        h.finalize_variable(&mut o).unwrap();
        o
    }

    struct Keys {
        server: StaticSecret,
        client_pub: PublicKey,
        env: EnvValues,
    }

    fn keys() -> Keys {
        let client = StaticSecret::from([3u8; 32]);
        let server = StaticSecret::from([5u8; 32]);
        Keys {
            env: EnvValues {
                api_key: "live_rs\n".into(),
                private_key: STANDARD.encode(client.to_bytes()),
                server_public_key: STANDARD.encode(PublicKey::from(&server).as_bytes()),
            },
            client_pub: PublicKey::from(&client),
            server,
        }
    }

    fn server_key(k: &Keys) -> [u8; 32] {
        let master = b2(k.server.diffie_hellman(&k.client_pub).as_bytes());
        b2(&[&master[..], b"CONNECT-@-2026-HS-@-CATZ"].concat())
    }

    fn server_open(k: &Keys, body: &Value) -> Value {
        let n = STANDARD.decode(body["nonce"].as_str().unwrap()).unwrap();
        let ct = STANDARD.decode(body["ciphertext"].as_str().unwrap()).unwrap();
        let plain = ChaCha20Poly1305::new_from_slice(&server_key(k)).unwrap().decrypt(Nonce::from_slice(&n), ct.as_ref()).unwrap();
        serde_json::from_slice(&plain).unwrap()
    }

    fn server_seal(k: &Keys, v: &Value) -> Value {
        let n = [1u8; 12];
        let ct = ChaCha20Poly1305::new_from_slice(&server_key(k)).unwrap()
            .encrypt(Nonce::from_slice(&n), v.to_string().as_bytes()).unwrap();
        json!({"nonce": STANDARD.encode(n), "ciphertext": STANDARD.encode(ct)})
    }

    #[derive(Debug, Clone)]
    struct Seen {
        path: String,
        auth: String,
        ua: String,
        body: Value,
    }

    /// A one-request-per-connection HTTP/1.1 server answering from `reply`.
    async fn mock(reply: impl Fn(&str) -> (u16, Value) + Send + Sync + 'static) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let reply = Arc::new(reply);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let seen = seen2.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let (head_end, len) = loop {
                        let n = sock.read(&mut tmp).await.unwrap();
                        if n == 0 { return; }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                            let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).map(|v| v.trim().parse::<usize>().unwrap()).unwrap_or(0);
                            break (i + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let n = sock.read(&mut tmp).await.unwrap();
                        if n == 0 { break; }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                    let header = |name: &str| head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    }).unwrap_or_default();
                    let body: Value = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap();
                    seen.lock().unwrap().push(Seen { path: path.clone(), auth: header("authorization"), ua: header("user-agent"), body });
                    let (status, v) = reply(&path);
                    let text = v.to_string();
                    let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len());
                    sock.write_all(resp.as_bytes()).await.unwrap();
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}/"), seen)
    }

    fn call_json() -> Value {
        json!({"id":"c1","engine":"catz","mode":"video","status":"ringing","room":"c1",
            "participants":[{"user_id":"alice","role":"caller","state":"joined"}],"created_at":"2026-10-18T00:00:00Z"})
    }

    #[tokio::test]
    async fn create_get_token_end_round_trip() {
        let k = keys();
        let sealed_token = server_seal(&k, &json!({"token":"ct1.a.b","expires_at":99,"ws_url":"wss://x/rtc/v1/ws"}));
        let (url, seen) = mock(move |path| match path {
            "/sdk/calls/create" => (200, json!({"success":true,"call":call_json()})),
            "/sdk/calls/get" => (200, json!({"success":true,"message":"ok","data":{"call":call_json()}})),
            "/sdk/calls/token" => (200, json!({"success":true,"data":sealed_token.clone()})),
            _ => (200, json!({"success":true,"message":"Call ended"})),
        }).await;
        let calls = Calls::new(Some(k.env.clone())).with_base_url(url);

        let call = calls.create(CreateCallInput {
            mode: CallMode::Video, from: "alice".into(), to: vec!["bob".into()],
            engine: Some("catz".into()), ring: Some(false), metadata: Some(json!({"order":7})), max_participants: Some(4),
        }).await.unwrap();
        assert_eq!(call.id, "c1");
        assert_eq!(call.mode, CallMode::Video);
        assert_eq!(call.participants[0].user_id, "alice");

        assert_eq!(calls.get("c1").await.unwrap().status, "ringing");
        let tok = calls.token("alice", Some(600)).await.unwrap();
        assert_eq!(tok, CallToken { token: "ct1.a.b".into(), expires_at: json!(99), ws_url: "wss://x/rtc/v1/ws".into() });
        let end = calls.end("c1", Some(" done ")).await.unwrap();
        assert_eq!(end, EndCallResult { success: true, message: "Call ended".into() });

        let seen = seen.lock().unwrap().clone();
        let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["/sdk/calls/create", "/sdk/calls/get", "/sdk/calls/token", "/sdk/calls/end"]);
        assert_eq!(seen[0].auth, "Bearer live_rs");
        assert_eq!(seen[0].ua, format!("catzconnect-rust-sdk/{}", env!("CARGO_PKG_VERSION")));
        let b = server_open(&k, &seen[0].body);
        assert_eq!(b["mode"], "video");
        assert_eq!(b["to"], json!(["bob"]));
        assert_eq!(b["ring"], false);
        assert_eq!(b["max_participants"], 4);
        assert_eq!(b["metadata"]["order"], 7);
        assert!(b["ts"].is_number());
        assert_eq!(server_open(&k, &seen[1].body)["call_id"], "c1");
        assert_eq!(server_open(&k, &seen[2].body)["ttl_seconds"], 600);
        assert_eq!(server_open(&k, &seen[3].body)["reason"], "done");
    }

    fn otp_input() -> crate::types::SendInput {
        use crate::types::{Channel, MessageType, SendInput, SendPayload, Template};
        SendInput {
            message_type: MessageType::Verification,
            channel: Channel::Email,
            template: Template::Otp,
            identity: "a@b.co".into(),
            payload: SendPayload { to: Some("u@x.co".into()), otp: Some("123456".into()), ..Default::default() },
        }
    }

    #[tokio::test]
    async fn send_with_options_takes_the_base_url_and_the_http_opt_in() {
        let k = keys();
        // A plain-http remote base URL is refused before anything is sent…
        let err = crate::CatzConnect::send_with_options(
            otp_input(),
            Some(k.env.clone()),
            crate::SendOptions::default().with_base_url("http://api.example.com"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CatzError::Validation(ref m) if m.contains("plain http://")), "{err}");

        // …and the per-call base URL is the one used.
        let (url, seen) = mock(|_| (200, json!({"success":true,"message":"queued","data":{"id":"m1"}}))).await;
        let out = crate::CatzConnect::send_with_options(
            otp_input(),
            Some(k.env.clone()),
            crate::SendOptions::default().with_base_url(url).allow_insecure_http(true),
        )
        .await
        .unwrap();
        assert_eq!(out["success"], true);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].path, "/sdk/send");
        let b = server_open(&k, &seen[0].body);
        assert_eq!(b["otp"], "123456");
        assert!(b["ts"].is_number());
    }

    #[test]
    fn provider_is_an_object() {
        let c: Call = serde_json::from_value(json!({"id":"c2","engine":"livekit",
            "provider":{"id":"6f1c","label":"LK main","name":"livekit"},"mode":"video","status":"ringing","room":"r"})).unwrap();
        assert_eq!(c.provider, Some(CallProvider { id: "6f1c".into(), label: Some("LK main".into()), name: "livekit".into() }));
        let d: Call = serde_json::from_value(json!({"id":"c1","engine":"catz","provider":null,"mode":"audio","status":"ringing","room":"c1"})).unwrap();
        assert_eq!(d.provider, None);
    }

    #[tokio::test]
    async fn refusals_carry_the_code() {
        let k = keys();
        let (url, _) = mock(|path| if path.ends_with("create") {
            (402, json!({"success":false,"message":"Your plan has used its call minutes.","code":"minutes_cap_reached"}))
        } else {
            (200, json!({"success":false,"message":"Not on this plan","code":"plan_required"}))
        }).await;
        let calls = Calls::new(Some(k.env.clone())).with_base_url(url);
        let err = calls.create(CreateCallInput { from: "a".into(), to: vec!["b".into()], ..Default::default() }).await.unwrap_err();
        assert!(matches!(err, CatzError::ApiError { status: 402, .. }), "{err}");
        assert_eq!(err.api_code().as_deref(), Some("minutes_cap_reached"));
        assert_eq!(err.api_message().as_deref(), Some("Your plan has used its call minutes."));
        let err = calls.token("a", None).await.unwrap_err();
        assert_eq!(err.api_code().as_deref(), Some("plan_required"));
    }

    #[test]
    fn validation_mirrors_the_server() {
        let ok = || CreateCallInput { from: "a".into(), to: vec!["b".into()], ..Default::default() };
        let many: Vec<String> = (0..50).map(|i| format!("u{i}")).collect();
        let cases: Vec<(CreateCallInput, &str)> = vec![
            (CreateCallInput { from: " ".into(), ..ok() }, "Missing 'from'"),
            (CreateCallInput { from: "x".repeat(129), ..ok() }, "128"),
            (CreateCallInput { from: "a\u{1}".into(), ..ok() }, "control"),
            (CreateCallInput { to: vec![], ..ok() }, "at least one"),
            (CreateCallInput { to: many.clone(), ..ok() }, "at most 49"),
            (CreateCallInput { to: vec!["b".into(), "b".into()], ..ok() }, "twice"),
            (CreateCallInput { to: vec!["a".into()], ..ok() }, "caller"),
            (CreateCallInput { metadata: Some(json!({"x": "y".repeat(4100)})), ..ok() }, "4 KB"),
            (CreateCallInput { metadata: Some(json!([1])), ..ok() }, "object"),
            (CreateCallInput { to: vec!["b".into(), "c".into()], max_participants: Some(2), ..ok() }, "do not fit"),
        ];
        for (input, want) in cases {
            let err = build_create_payload(&input).unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
        assert!(build_create_payload(&CreateCallInput { to: many[..49].to_vec(), ..ok() }).is_ok());
        assert!(build_create_payload(&CreateCallInput { from: "é".repeat(128), ..ok() }).is_ok());
        assert!(build_token_payload("a", Some(59)).is_err());
        assert!(build_token_payload("a", Some(86401)).is_err());
        assert_eq!(build_token_payload("a", None).unwrap(), json!({"user_id":"a"}));
    }
}
