use hyper::{body::to_bytes, client::HttpConnector, Body, Client, Request};
use hyper_tls::HttpsConnector;
use serde_json::Value;

use crate::{error::CatzError, types::EncryptedBody, types::EnvValues};

type HttpsClient = Client<HttpsConnector<HttpConnector>>;

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

        let connector = HttpsConnector::new();
        let inner = Client::builder().build(connector);

        Ok(Self { inner, base_url, api_key })
    }

    pub async fn post(&self, path: &str, body: &EncryptedBody) -> Result<Value, CatzError> {
        let url = format!("{}{}", self.base_url, path);
        let json_body = serde_json::to_string(body)?;
        let content_length = json_body.len();

        let req = Request::post(&url)
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
