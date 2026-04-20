use std::time::{SystemTime, UNIX_EPOCH};

use base64::{
    alphabet,
    engine::{self, general_purpose::STANDARD, GeneralPurpose},
    Engine,
};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{error::CatzError, types::EncryptedBody, types::EnvValues};

fn lenient_engine() -> GeneralPurpose {
    GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, CatzError> {
    let normalised: String = s
        .trim()
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    STANDARD
        .decode(&normalised)
        .or_else(|_| {
            let pad = (4 - normalised.len() % 4) % 4;
            let padded = format!("{}{}", normalised, "=".repeat(pad));
            lenient_engine().decode(&padded)
        })
        .map_err(CatzError::Base64)
}

fn blake2b_32(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 ≤ 64");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out)
        .expect("output length matches");
    out
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn encrypt(payload: &Value, env: Option<EnvValues>) -> Result<EncryptedBody, CatzError> {
    let priv_b64 = match &env {
        Some(e) => e.private_key.clone(),
        None => {
            std::env::var("PRIVATE_KEY").map_err(|_| CatzError::MissingEnv("PRIVATE_KEY".into()))?
        }
    };

    let pub_b64 = match &env {
        Some(e) => e.server_public_key.clone(),
        None => std::env::var("SERVER_PUBLIC_KEY")
            .map_err(|_| CatzError::MissingEnv("SERVER_PUBLIC_KEY".into()))?,
    };

    let priv_bytes = b64_decode(&priv_b64)?;
    let pub_bytes = b64_decode(&pub_b64)?;

    let priv_arr: [u8; 32] = priv_bytes
        .try_into()
        .map_err(|v: Vec<u8>| CatzError::InvalidKeyLength(v.len()))?;
    let pub_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|v: Vec<u8>| CatzError::InvalidKeyLength(v.len()))?;

    let client_secret = StaticSecret::from(priv_arr);
    let server_pub = PublicKey::from(pub_arr);
    let shared = client_secret.diffie_hellman(&server_pub);

    let master = blake2b_32(shared.as_bytes());

    const LABEL: &[u8] = b"CONNECT-@-2026-HS-@-CATZ";
    let mut km = Vec::with_capacity(32 + LABEL.len());
    km.extend_from_slice(&master);
    km.extend_from_slice(LABEL);
    let key_enc = blake2b_32(&km);

    let mut fp = payload.clone();
    if let Some(obj) = fp.as_object_mut() {
        obj.insert("ts".into(), json!(now_ms()));
    }

    let message = serde_json::to_string(&fp)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher =
        ChaCha20Poly1305::new_from_slice(&key_enc).map_err(|_| CatzError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(&nonce, message.as_bytes())
        .map_err(|_| CatzError::EncryptionFailed)?;

    Ok(EncryptedBody {
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(ciphertext),
    })
}
