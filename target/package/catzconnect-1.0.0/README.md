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
catzconnect = "1.0.0"
tokio   = { version = "1", features = ["full"] }
dotenvy = "0.15"
```

---

## ⚙️ Environment Setup

Create a `.env` file (or export these variables):

```env
API_KEY=your_api_key
PRIVATE_KEY=your_base64_private_key
SERVER_PUBLIC_KEY=server_base64_public_key
# BASE_URL=https://api.catzconnect.com  # optional
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
        payload: SendPayload {
            to:  Some("user@example.com".into()),
            otp: Some(123456),
        },
    })
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
    payload: SendPayload {
        to:  Some("user@example.com".into()), // required, valid email
        otp: Some(123456),                    // required
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
{ "status": "success", "request_id": "abc123" }
```

---

## 🛠 Development

```bash
cargo build
cargo test
cargo clippy
```
