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
catzconnect = "1.3"
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
        ..Default::default()
    },
}, None).await?;
```

`Transactional` / `Custom` takes `to`, `body`, and an optional `subject` sent as a bold
first line. OTPs need an approved Authentication template; custom messages only
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
