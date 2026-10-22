use hyper::{body::to_bytes, client::HttpConnector, Body, Client, Request};
use hyper_tls::HttpsConnector;
use serde_json::Value;

use crate::{error::CatzError, types::EncryptedBody, types::EnvValues};

type HttpsClient = Client<HttpsConnector<HttpConnector>>;

/// Hosts that never leave the machine (10.0.2.2 is the Android emulator's host).
const LOCAL_HOSTS: [&str; 4] = ["localhost", "127.0.0.1", "::1", "10.0.2.2"];

/// `CATZCONNECT_ALLOW_INSECURE_HTTP` set to 1 / true / yes.
pub fn insecure_http_from_env() -> bool {
    std::env::var("CATZCONNECT_ALLOW_INSECURE_HTTP")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Accepts `https://` always, and plain `http://` only for localhost,
/// 127.0.0.1, ::1 and 10.0.2.2 or when `allow_insecure` is set, so the API
/// key is never sent unencrypted by mistake. Refusals are
/// [`CatzError::Validation`].
pub fn check_base_url(url: &str, allow_insecure: bool) -> Result<(), CatzError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| CatzError::Validation(format!("CATZCONNECT_BASE_URL is not a valid URL: {url:?}")))?;
    let host = match uri.host() {
        Some(h) if !h.is_empty() => h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase(),
        _ => return Err(CatzError::Validation(format!("CATZCONNECT_BASE_URL is not a valid URL: {url:?}"))),
    };
    match uri.scheme_str().map(str::to_ascii_lowercase).as_deref() {
        Some("https") => Ok(()),
        Some("http") if allow_insecure || LOCAL_HOSTS.contains(&host.as_str()) => Ok(()),
        Some("http") => Err(CatzError::Validation(format!(
            "CATZCONNECT_BASE_URL uses plain http:// to {host}: the API key would travel unencrypted. \
             Use https://, or set CATZCONNECT_ALLOW_INSECURE_HTTP=1 / Calls::allow_insecure_http(true) to allow it anyway"
        ))),
        other => Err(CatzError::Validation(format!(
            "CATZCONNECT_BASE_URL must start with https:// (got {:?})",
            other.unwrap_or("")
        ))),
    }
}

pub struct HttpClient {
    inner: HttpsClient,
    base_url: String,
    api_key: String,
}

impl HttpClient {
    pub fn from_env(env: Option<EnvValues>) -> Result<Self, CatzError> {
        Self::with_base_url(env, None)
    }

    /// Like [`HttpClient::from_env`], with an explicit base URL that wins over
    /// `CATZCONNECT_BASE_URL`.
    pub fn with_base_url(env: Option<EnvValues>, base_url: Option<String>) -> Result<Self, CatzError> {
        Self::with_options(env, base_url, false)
    }

    /// Like [`HttpClient::with_base_url`]; `allow_insecure_http` accepts a
    /// plain `http://` base URL to a non-local host (see [`check_base_url`]).
    pub fn with_options(
        env: Option<EnvValues>,
        base_url: Option<String>,
        allow_insecure_http: bool,
    ) -> Result<Self, CatzError> {
        let raw_key = match &env {
            Some(e) => e.api_key.clone(),
            None => std::env::var("CATZCONNECT_API_KEY")
                .map_err(|_| CatzError::MissingEnv("API_KEY".into()))?,
        };

        let api_key = raw_key.trim().to_string();
        if api_key.is_empty() {
            return Err(CatzError::MissingEnv("API_KEY is empty".into()));
        }

        let base_url = base_url
            .or_else(|| std::env::var("CATZCONNECT_BASE_URL").ok())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.catzconnect.com".into());
        check_base_url(&base_url, allow_insecure_http || insecure_http_from_env())?;

        let connector = HttpsConnector::new();
        let inner = Client::builder().build(connector);

        Ok(Self { inner, base_url, api_key })
    }

    pub async fn post(&self, path: &str, body: &EncryptedBody) -> Result<Value, CatzError> {
        self.post_with_headers(path, body, &[]).await
    }

    /// [`HttpClient::post`] with extra request headers (`Idempotency-Key`).
    pub async fn post_with_headers(&self, path: &str, body: &EncryptedBody, extra: &[(&str, String)]) -> Result<Value, CatzError> {
        let url = format!("{}{}", self.base_url, path);
        let json_body = serde_json::to_string(body)?;
        let content_length = json_body.len();

        let mut builder = Request::post(&url);
        for (k, v) in extra {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder
            .header("Content-Type", "application/json")
            .header("Content-Length", content_length)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("User-Agent", concat!("catzconnect-rust-sdk/", env!("CARGO_PKG_VERSION")))
            .header("Accept", "application/json")
            .body(Body::from(json_body))
            .map_err(|e| CatzError::Http(e.to_string()))?;

        let res = self
            .inner
            .request(req)
            .await
            .map_err(|e| CatzError::Http(e.to_string()))?;

        let status = res.status();
        let bytes = to_bytes(res.into_body())
            .await
            .map_err(|e| CatzError::Http(e.to_string()))?;

        if !status.is_success() {
            let body_text = String::from_utf8_lossy(&bytes).to_string();
            return Err(CatzError::ApiError {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let value: Value = serde_json::from_slice(&bytes)?;
        Ok(value)
    }
}

/// POSTs plain JSON without an API key (the push device endpoints,
/// authorised by the project's publishable key).
pub async fn post_public(base_url: Option<String>, allow_insecure_http: bool, path: &str, body: &Value) -> Result<Value, CatzError> {
    let base_url = base_url
        .or_else(|| std::env::var("CATZCONNECT_BASE_URL").ok())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.catzconnect.com".into());
    check_base_url(&base_url, allow_insecure_http || insecure_http_from_env())?;
    let client: HttpsClient = Client::builder().build(HttpsConnector::new());
    let json_body = serde_json::to_string(body)?;
    let req = Request::post(format!("{base_url}{path}"))
        .header("Content-Type", "application/json")
        .header("Content-Length", json_body.len())
        .header("Accept", "application/json")
        .header("User-Agent", concat!("catzconnect-rust-sdk/", env!("CARGO_PKG_VERSION")))
        .body(Body::from(json_body))
        .map_err(|e| CatzError::Http(e.to_string()))?;
    let res = client.request(req).await.map_err(|e| CatzError::Http(e.to_string()))?;
    let status = res.status();
    let bytes = to_bytes(res.into_body()).await.map_err(|e| CatzError::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(CatzError::ApiError { status: status.as_u16(), body: String::from_utf8_lossy(&bytes).to_string() });
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(CatzError::ApiError { status: status.as_u16(), body: value.to_string() });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_https_only_except_local_hosts() {
        for u in ["https://api.example.com", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "http://10.0.2.2:8080"] {
            assert!(check_base_url(u, false).is_ok(), "{u}");
        }
        for u in ["http://api.example.com", "http://localhost.example.com", "ftp://api.example.com", "api.example.com", ""] {
            assert!(matches!(check_base_url(u, false), Err(CatzError::Validation(_))), "{u}");
        }
        assert!(check_base_url("http://api.example.com", true).is_ok());
    }

    #[test]
    fn client_refuses_plain_http_base_url() {
        let env = EnvValues { api_key: "live_k".into(), private_key: "p".into(), server_public_key: "s".into() };
        let err = HttpClient::with_options(Some(env.clone()), Some("http://api.example.com/".into()), false)
            .err()
            .expect("refused");
        assert!(err.to_string().contains("plain http://"), "{err}");
        assert!(HttpClient::with_options(Some(env), Some("http://api.example.com/".into()), true).is_ok());
    }
}
