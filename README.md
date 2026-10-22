# CatzConnect SDK (Rust)

A secure, minimal SDK for sending encrypted communication requests (e.g., email OTP) to the CatzConnect API.

---

## ✨ Features

* 🔐 End-to-end payload encryption (X25519 ECDH + BLAKE2b-256 + ChaCha20-Poly1305 IETF)
* ⚡ Stateless design — no `init()` required
* 🧠 Automatic payload validation
* 🔑 API key via environment variable (Bearer token)
* 🦀 Pure Rust — no libsodium C dependency

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
catzconnect = "2"
tokio   = { version = "1", features = ["full"] }
dotenvy = "0.15"
```

---

## ⚙️ Environment Setup

Create a `.env` file (or export these variables):

```env
CATZCONNECT_API_KEY=your_api_key
CATZCONNECT_PRIVATE_KEY=your_base64_private_key
CATZCONNECT_SERVER_PUBLIC_KEY=server_base64_public_key
```

> ⚠️ Never expose these values in public environments.

`CATZCONNECT_BASE_URL` (optional, default `https://api.catzconnect.com`) must be
`https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1`,
`[::1]` and `10.0.2.2` (local development); any other `http://` URL fails with
`CatzError::Validation` before anything is sent, since the API key would travel
unencrypted. To allow it anyway set `CATZCONNECT_ALLOW_INSECURE_HTTP=1` (or, for
the calls API, `CatzConnect::calls().allow_insecure_http(true)`).

`format!("{:?}", env)` on an `EnvValues` never prints the API key or the private
key.

---

## 🚀 Usage

```rust
use catzconnect::{
    CatzConnect,
    types::{Channel, MessageType, SendInput, SendPayload, Template},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok(); // load .env

    let response = CatzConnect::send(SendInput {
        message_type: MessageType::Verification,
        channel:      Channel::Email,
        template:     Template::Otp,
        identity:     "user@domain.com",
        payload: SendPayload {
            to:  Some("user@example.com".into()),
            otp: Some("123456".into()),
        },
    }, None)
    .await?;

    println!("{response}");
    Ok(())
}
```

---

## 📬 Supported Operation

### Email Verification OTP

```rust
SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Email,
    template:     Template::Otp,
    identity:     "user@domain.com",
    payload: SendPayload {
        to:  Some("user@example.com".into()), // required, valid email
        otp: Some("123456".into()),                    // required
        language: Some("de".into()),                   // optional: localized default template
        ..Default::default()
    },
}
```

### Email Transactional

```rust
SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Transactional,
    template:     Template::Custom,
    identity:     "user@domain.com",
    payload: SendPayload {
        to:  Some("user@example.com".into()), // required, valid email
        subject: Some("hello world".into()),               // required
        body: Some("welcome to catzconnect".into()),       // required
    },
}
```

---

## 🔐 How It Works

1. **Validate Input** — ensures required fields are present and the email is valid
2. **Encrypt Payload**
   - X25519 ECDH shared secret: `scalarmult(client_priv, server_pub)`
   - `master  = BLAKE2b-256(shared)`
   - `key_enc = BLAKE2b-256(master || "CONNECT-@-2026-HS-@-CATZ")`
   - ChaCha20-Poly1305 IETF encrypt with a random 12-byte nonce
3. **Send Request** — `POST /sdk/send` with `{ nonce, ciphertext }` JSON and `Authorization: Bearer <key>`

---

## ❌ Error Handling

```rust
match CatzConnect::send(input).await {
    Ok(resp)  => println!("Success: {resp}"),
    Err(e)    => eprintln!("Error: {e}"),
}
```

All errors implement `std::error::Error` via `thiserror`.

---

## 🧩 Example Response

```json
{ "status": "success" }
```

---

## 🛠 Development

```bash
cargo build
cargo test
cargo clippy
```

## Language of the default OTP templates

`SendPayload::language` (optional) picks the language of the **built-in**
Otp/Verification templates for Email, SMS, Voice and WhatsApp: `en`, `de`,
`ja`, `ar` or `hi`. A BCP-47 tag such as `"de-DE"` is accepted and sent as
`"de"`, at the top level of the request body next to `channel`/`template`.
Anything else is a `CatzError::Validation` (`Unsupported 'language' "fr": use
one of en, de, ja, ar, hi …`) before any request. `None` leaves the field out,
so the server uses English as before. Templates you created in the panel are
not affected.

```rust
CatzConnect::send(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Email,
    template:     Template::Otp,
    identity:     "noreply@yourdomain.com".into(),
    payload: SendPayload {
        to:       Some("user@example.com".into()),
        otp:      Some("123456".into()),
        language: Some("de-DE".into()), // sent as "language": "de"
        ..Default::default()
    },
}, None).await?;
```

`catzconnect::language::normalize_language("de-DE")` returns `"de"`;
`SUPPORTED_LANGUAGES` lists the codes. `CatzConnect::build_payload(&input)`
returns the (unencrypted) body `send` would post. `CatzConnect` is stateless,
so there is no client-wide default: set `language` per send.

## Building a payload

Use `..Default::default()` so fields added in later versions don't break your code:

```rust
SendPayload { to: Some(to), otp: Some(otp), ..Default::default() }
```

## WhatsApp

```rust
CatzConnect::send(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::WhatsApp,
    template:     Template::Otp,
    identity:     "919578456444".into(),          // your connected WhatsApp number
    payload: SendPayload {
        to:  Some("+91 98765 43210".into()),       // phone number with country code
        otp: Some("123456".into()),
        language: Some("hi".into()),               // optional: Meta template language code
        ..Default::default()
    },
}, None).await?;
```

`Transactional` / `Custom` takes `to`, `body`, and an optional `subject` sent as a bold
first line. With `language` the server asks Meta for the Authentication template
in that language — it must be approved in that language on your WhatsApp
Business Account, or Meta rejects the message. OTPs need an approved Authentication template; custom messages only
reach people who messaged your number in the last 24 hours.

## Push notifications (end-to-end encrypted)

```rust
CatzConnect::send(SendInput {
    message_type: MessageType::Notification,
    channel:      Channel::Push,
    template:     Template::Notification,
    identity:     "your-firebase-project-id".into(),
    payload: SendPayload {
        to:         Some(fcm_token),
        device_key: Some(device_public_key),       // seals the content to that device
        title:      Some("Order shipped".into()),
        body:       Some("Arriving Friday".into()),
        ..Default::default()
    },
}, None).await?;
```

The device generates its keys and decrypts — see `PUSH.md`.

## Email templates from the panel

```rust
let resp = CatzConnect::send(SendInput {
    message_type: MessageType::Transactional,
    channel:      Channel::Email,
    template:     Template::Named("Order shipped".into()), // the template's name in the panel
    identity:     "noreply@yourdomain.com".into(),
    payload: SendPayload {
        to:   Some("user@example.com".into()),
        data: Some([("name".to_string(), "Ann".to_string())].into()),
        ..Default::default()
    },
}, None).await?;
```

## Push to a user's registered devices

Set `external_user_id: Some("user-42".into())` instead of `to` to send to every
device your app registered for that user with `POST /push/register`.
`device_key` must be `None`; each device's registered key is used.

## Verifying webhooks

```rust
let ok = catzconnect::webhook::verify_signature(&raw_body, signature_header, &secret);
```

`verify_signature_at(body, header, secret, now_unix, tolerance_secs)` takes an
explicit clock. SHA-256 and HMAC are built in; no extra dependency.

## SMS

`to` is an E.164 number (`+` and the country code; spaces, dashes, dots and
brackets are removed). `identity` is ignored — use `String::new()`.
`CatzConnect::send_sms` returns `SmsSendResult { message_id, segments, encoding }`.

```rust
// One-time code: Verification + Otp (up to 15 letters or digits).
let sent = CatzConnect::send_sms(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Sms,
    template:     Template::Otp,
    identity:     String::new(),
    payload: SendPayload {
        to:  Some("+14155550100".into()),
        otp: Some("123456".into()),
        ..Default::default()
    },
}, None).await?;
println!("{} {} {}", sent.message_id, sent.segments, sent.encoding); // … 1 gsm7

// The default OTP text in German ("de-DE" is sent as "de").
CatzConnect::send_sms(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Sms,
    template:     Template::Otp,
    identity:     String::new(),
    payload: SendPayload {
        to: Some("+4915112345678".into()), otp: Some("123456".into()), language: Some("de-DE".into()),
        ..Default::default()
    },
}, None).await?;

// Free text: Transactional or Promotional + Custom. India needs a DLT id.
CatzConnect::send_sms(SendInput {
    message_type: MessageType::Promotional,
    channel:      Channel::Sms,
    template:     Template::Custom,
    identity:     String::new(),
    payload: SendPayload {
        to:              Some("+91 98765 43210".into()),
        body:            Some("Sale ends tonight".into()),
        dlt_template_id: Some("1207161234567890123".into()),
        gateway:         Some("MSG91 India".into()), // optional: one of the key's gateways
        sender:          Some("CATZIN".into()),      // optional: only with gateway
        ..Default::default()
    },
}, None).await?;

// An SMS template from the panel: Template::Named("Order shipped".into()) with payload.data.
```

Validation matches the server: E.164 `to`; `Otp` only with `Verification`,
`Custom` only with `Transactional`/`Promotional`; `sender` only with `gateway`;
numeric `dlt_template_id`; Custom bodies at most 10 segments (1,530 GSM-7 /
670 UCS-2 characters) and a DLT id for +91. `catzconnect::sms::analyse(text)`
reports the encoding and segments; `sms::normalise_e164` normalises a number.

> 1.3.0 adds `Channel::Sms` and `MessageType::Promotional`. An exhaustive
> `match` on either enum without a wildcard arm must add the new variant.

## Phone calls (Voice)

`Channel::Voice` places a phone call that speaks the message (`"voice"`
parses too: `"voice".parse::<Channel>()`). `to` is E.164; `identity` is
ignored.

```rust
use std::collections::HashMap;
use catzconnect::{CatzConnect, types::{Channel, MessageType, SendInput, SendPayload, Template}};

let data: HashMap<String, String> = [("language", "en-US"), ("voice", "female"), ("repeat", "2")]
    .into_iter().map(|(k, v)| (k.into(), v.into())).collect();

// A one-time code, read out digit by digit.
let sent = CatzConnect::send_voice(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Voice,
    template:     Template::Otp,
    identity:     String::new(),
    payload: SendPayload { to: Some("+14155550100".into()), otp: Some("482913".into()), data: Some(data), ..Default::default() },
}, None).await?;
println!("{}", sent.message_id); // voice.* webhook events carry it

// The default OTP script in Japanese; TTS language and voice follow it.
// data["language"], when set, still overrides the spoken language.
CatzConnect::send_voice(SendInput {
    message_type: MessageType::Verification,
    channel:      Channel::Voice,
    template:     Template::Otp,
    identity:     String::new(),
    payload: SendPayload { to: Some("+819012345678".into()), otp: Some("482913".into()), language: Some("ja".into()), ..Default::default() },
}, None).await?;

// Free text (≤ 1,000 characters) through one of the key's phone providers.
CatzConnect::send(SendInput {
    message_type: MessageType::Notification,
    channel:      Channel::Voice,
    template:     Template::Custom,
    identity:     String::new(),
    payload: SendPayload {
        to:       Some("+919876543210".into()),
        body:     Some("Your table is ready.".into()),
        provider: Some("Exotel India".into()),
        ..Default::default()
    },
}, None).await?;
```

Checked before sending: E.164 `to`; `Otp` needs `otp` (≤ 15 letters/digits);
`Custom` needs `body` (1–1,000 characters, no control characters);
`data["language"]` like `en-US`, `data["voice"]` `female`/`male`/a provider
voice, `data["repeat"]` `1`–`3`. `catzconnect::voice` has the helpers.

## Voice & Video calls

Calls between your app's users. Your backend creates the call and a
short-lived user token; the browser (or app) connects with the token.
Requests use the same key, encryption and headers as `send`.

```rust
use catzconnect::{CatzConnect, calls::{CallMode, CreateCallInput}};

let calls = CatzConnect::calls(); // or CatzConnect::calls_with(env)

let call = calls.create(CreateCallInput {
    mode: CallMode::Video,           // or CallMode::Audio
    from: "alice".into(),            // your user ids, ≤ 128 characters
    to:   vec!["bob".into()],        // 1–49, unique, not including `from`
    // engine: Some("catz".into()), ring: Some(true),
    // metadata: Some(serde_json::json!({"order": "A-1042"})), max_participants: Some(4),
    ..Default::default()
}).await?;

let tok = calls.token("alice", Some(3600)).await?; // 60–86400 s; None = server default
// give tok.token and tok.ws_url to alice's browser

let detail = calls.get(&call.id).await?;            // participants, duration_secs, billed_minutes, end_reason
calls.end(&call.id, Some("support_closed")).await?;
```

Refusals are `CatzError::ApiError { status, body }`; `err.api_code()` gives
the server's code (`plan_required`, `minutes_cap_reached`,
`engine_unavailable`, `too_many_participants`, `provider_not_allowed`) and
`err.api_message()` its sentence. Inputs are checked first, as the server
does: user ids non-empty, ≤ 128 characters, no control characters; 1–49
unique callees without the caller; metadata a JSON object ≤ 4 KB; TTL
60–86400.

### In the browser

Hand the token (never the API key) to the user's page and use the
TypeScript SDK's browser entry, `catzconnect/call` (no dependencies; native
WebRTC):

```ts
import { CatzCallClient } from "catzconnect/call";

const client = new CatzCallClient({ getToken: () => fetch("/call-token").then((r) => r.text()), url: wsUrl });
client.on("incoming", ({ callId }) => client.accept(callId));
client.on("track", ({ pid, stream }) => (videoFor(pid).srcObject = stream));
client.on("local-stream", ({ stream }) => (selfView.srcObject = stream));
await client.connect();
await client.join(callId, { audio: true, video: true });
```

It keeps the call up by itself: direct path first, relay fallback (UDP →
TCP → TLS), ICE restart on failure or network change, WebSocket reconnect
with resume, token renewal through `getToken`. See the TypeScript README for
every event and method, and a React example.

**Provider hand-off.** When the call runs on a provider engine (Agora,
Twilio Video, LiveKit, …), the browser client emits `provider` with
`{ name, room, token, app_id?, url?, extra? }` instead of opening peer
connections; join with that provider's own SDK.

> 2.0.0 adds `CatzConnect::send_with_options` (`SendOptions`: per-call base
> URL and the plain-`http://` opt-in for the send path), refuses a
> plain-`http://` base URL to a non-local host (see *Environment Setup*) and
> redacts `EnvValues`' `Debug` output.
>
> 1.5.0 adds `SendPayload::language` (and `CatzConnect::build_payload`); a
> `SendPayload { … }` literal without `..Default::default()` must add it.
>
> 1.4.0 adds `Channel::Voice` and `SendPayload::provider`. An exhaustive
> `match` on `Channel` without a wildcard arm must add the new variant;
> build `SendPayload` with `..Default::default()`.

## Message status, retry-safe sends, test keys, hosted OTP (2.0.0)

The 2.0.0 per-message options are a separate `types::SendExtras` (built
with its methods), passed with `CatzConnect::send_with_extras` (or
`send_full`, with `SendOptions` too). `SendPayload` is unchanged from 1.5, so
existing `SendPayload { … }` literals keep compiling.

```rust,ignore
use catzconnect::devapi::{Messages, Otp, OtpStartInput, OtpVerifyInput};
use catzconnect::types::SendExtras;
let payload = SendPayload { to: Some("+919876543210".into()), body: Some("Shipped".into()), ..Default::default() };
let extras = SendExtras::new().idempotency_key("ship-42").reference("order-42");
CatzConnect::send_with_extras(SendInput { payload, ..input }, extras, None).await?;
let m = Messages::new(None).get(&message_id).await?;             // status + events
let s = Otp::new(None).start(OtpStartInput { channel: "SMS".into(), to: "+919876543210".into(), ..Default::default() }).await?;
let v = Otp::new(None).verify(OtpVerifyInput { verification_id: Some(id), code: typed, ..Default::default() }).await;
if let Err(e) = &v { if e.api_code().as_deref() == Some(catzconnect::devapi::codes::OTP_INVALID) { /* e.api_details() */ } }
```

WhatsApp approved templates: `Template::Named("order_update".into())` with
`SendExtras::new().whatsapp(…)`; media: `Template::Custom` + `media`. Test keys are
validated but never delivered or billed. Management API: `devapi::Manage::new(None).call("keys", "create", json!({...}))`.
Webhooks: `webhook::parse_event(body, header, secret)` (`.test`).

## Email topics, push broadcasts and topics (2.0.0)

```rust
use catzconnect::devapi::{PushApi, PushTopicChange};
use catzconnect::types::{PushOptions, SendExtras};

// Push to a topic, later (server key); data.broadcast_id comes back.
let payload = SendPayload { body: Some("Today only".into()), ..Default::default() };
let extras = SendExtras::new()
    .push(PushOptions { topic: Some("deals".into()), send_at: Some("2026-11-02T09:00:00Z".into()), ..Default::default() });
// Email: SendExtras::new().topic("newsletter") — its opt-outs apply.
let push = PushApi::new(None);
push.subscribe(PushTopicChange { identity: "my-firebase".into(), topic: "deals".into(), external_user_id: Some("u1".into()), ..Default::default() }).await?;
```

App and test keys are refused for broadcasts / topics. `webhook::EVENTS`
includes `email.complained`, `email.unsubscribed`, `push.opened`,
`sms.inbound`, `sms.opt_out`, `whatsapp.opt_out`.
