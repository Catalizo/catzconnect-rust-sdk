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

/// X25519 → BLAKE2b-256 → BLAKE2b-256(master ‖ label): the key the server derives.
fn derive_key(env: &Option<EnvValues>) -> Result<[u8; 32], CatzError> {
    let priv_b64 = match env {
        Some(e) => e.private_key.clone(),
        None => {
            std::env::var("CATZCONNECT_PRIVATE_KEY").map_err(|_| CatzError::MissingEnv("PRIVATE_KEY".into()))?
        }
    };

    let pub_b64 = match env {
        Some(e) => e.server_public_key.clone(),
        None => std::env::var("CATZCONNECT_SERVER_PUBLIC_KEY")
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
    Ok(blake2b_32(&km))
}

pub fn encrypt(payload: &Value, env: Option<EnvValues>) -> Result<EncryptedBody, CatzError> {
    let key_enc = derive_key(&env)?;

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

fn sealed(v: &Value) -> Option<(&str, &str)> {
    let m = v.as_object()?;
    if m.len() != 2 {
        return None;
    }
    Some((m.get("nonce")?.as_str()?, m.get("ciphertext")?.as_str()?))
}

/// Opens an encrypted `{nonce, ciphertext}` envelope — at the top level or as
/// `data` — with the request key, merging the decrypted object in. Plain
/// JSON (what `/sdk/*` returns today) is returned unchanged.
pub fn open_response(res: Value, env: &Option<EnvValues>) -> Result<Value, CatzError> {
    let top = sealed(&res).is_some();
    let (nonce_b64, ct_b64) = match sealed(&res).or_else(|| res.get("data").and_then(sealed)) {
        Some((n, c)) => (n.to_string(), c.to_string()),
        None => return Ok(res),
    };
    let key = derive_key(env)?;
    let nonce = b64_decode(&nonce_b64)?;
    if nonce.len() != 12 {
        return Err(CatzError::EncryptionFailed);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| CatzError::EncryptionFailed)?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), b64_decode(&ct_b64)?.as_ref())
        .map_err(|_| CatzError::Validation("The response is encrypted with a key this SDK cannot open".into()))?;
    let opened: Value = serde_json::from_slice(&plain)?;
    if top {
        return Ok(if opened.is_object() { opened } else { json!({ "data": opened }) });
    }
    let mut out = res;
    if let (Some(o), Some(m)) = (out.as_object_mut(), opened.as_object()) {
        for (k, v) in m {
            o.insert(k.clone(), v.clone());
        }
    }
    if let Some(o) = out.as_object_mut() {
        o.insert("data".into(), opened);
    }
    Ok(out)
}
