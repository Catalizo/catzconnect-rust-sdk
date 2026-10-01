//! Verify webhook deliveries from CatzConnect.
//!
//! ```rust,no_run
//! # fn handle(raw_body: &[u8], signature_header: &str) {
//! let secret = std::env::var("CATZCONNECT_WEBHOOK_SECRET").unwrap_or_default();
//! if !catzconnect::webhook::verify_signature(raw_body, signature_header, &secret) {
//!     // answer 400 and stop
//! }
//! # }
//! ```
//!
//! The `Catz-Signature` header is `t=<unix seconds>,v1=<hex HMAC-SHA256>`;
//! the MAC is taken over `"<t>.<raw body>"` with the webhook's signing secret
//! (`whsec_…`) as the key. SHA-256 and HMAC are implemented here so the crate
//! needs no extra dependency for them.

use std::time::{SystemTime, UNIX_EPOCH};

/// How far (in seconds) a delivery's timestamp may be from now.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// Check a `Catz-Signature` header against the raw request body, rejecting
/// timestamps more than [`DEFAULT_TOLERANCE_SECS`] from the system clock.
pub fn verify_signature(raw_body: &[u8], header: &str, secret: &str) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_signature_at(raw_body, header, secret, now, DEFAULT_TOLERANCE_SECS)
}

/// [`verify_signature`] with an explicit clock and tolerance. A tolerance of
/// 0 skips the timestamp check.
pub fn verify_signature_at(raw_body: &[u8], header: &str, secret: &str, now: u64, tolerance: u64) -> bool {
    if header.is_empty() || secret.is_empty() {
        return false;
    }

    let mut ts: Option<&str> = None;
    let mut sigs: Vec<&str> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.split_once('=') else { continue };
        match k.trim() {
            "t" => ts = Some(v.trim()),
            "v1" => sigs.push(v.trim()),
            _ => {}
        }
    }

    let Some(ts) = ts else { return false };
    let Ok(t) = ts.parse::<u64>() else { return false };
    if sigs.is_empty() {
        return false;
    }
    if tolerance > 0 && now.abs_diff(t) > tolerance {
        return false;
    }

    let mut message = Vec::with_capacity(ts.len() + 1 + raw_body.len());
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(raw_body);
    let expected = hmac_sha256(secret.as_bytes(), &message);

    sigs.iter().any(|s| match decode_hex(s) {
        Some(got) if got.len() == 32 => constant_time_eq(&expected, &got),
        _ => false,
    })
}

/// The `user_hash` for `POST /push/register`: hex HMAC-SHA256 of the
/// `external_user_id`, keyed with the push project's identity secret
/// (`pis_…`, Push → Projects in the panel).
///
/// Compute it on your server and hand it to your app with the user id. The
/// identity secret must never ship inside the app — anyone holding it could
/// register their device as any of your users. Without a valid hash the
/// device is registered with no user.
pub fn compute_user_hash(external_user_id: &str, identity_secret: &str) -> String {
    hmac_sha256(identity_secret.as_bytes(), external_user_id.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// FIPS 180-4 SHA-256.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_rfc4231_case_2_and_6() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Key longer than the block size.
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // The same vector the server's own test uses (services/webhook).
    const HEADER: &str = "t=1700000000,v1=38877139021993b830af32feea6e18a8da83eb2f6e49ee50bd9e4cf4ca4d3789";

    // The same vector the server's own test uses (services/push/devices).
    #[test]
    fn user_hash_vector() {
        assert_eq!(compute_user_hash("user-42", "pis_test"), "22182382240b0a5afc85fca04d38b5c9e519ecb9a540c5ff50785e7d73b60a2c");
        assert_ne!(compute_user_hash("user-43", "pis_test"), "22182382240b0a5afc85fca04d38b5c9e519ecb9a540c5ff50785e7d73b60a2c");
    }

    #[test]
    fn verifies_server_signature() {
        let body = br#"{"a":1}"#;
        assert!(verify_signature_at(body, HEADER, "whsec_test", 1_700_000_100, 300));
        assert!(!verify_signature_at(br#"{"a":2}"#, HEADER, "whsec_test", 1_700_000_100, 300));
        assert!(!verify_signature_at(body, HEADER, "whsec_other", 1_700_000_100, 300));
        assert!(!verify_signature_at(body, HEADER, "whsec_test", 1_700_001_000, 300));
        assert!(!verify_signature_at(body, "garbage", "whsec_test", 1_700_000_100, 300));
    }
}
