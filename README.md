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
catzconnect = "1.0.3"
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
