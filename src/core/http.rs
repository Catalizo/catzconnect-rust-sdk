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
        let raw_key = match &env {
            Some(e) => e.api_key.clone(),
            None => std::env::var("CATZCONNECT_API_KEY")
                .map_err(|_| CatzError::MissingEnv("API_KEY".into()))?,
        };

        let api_key = raw_key.trim().to_string();
        if api_key.is_empty() {
            return Err(CatzError::MissingEnv("API_KEY is empty".into()));
        }

        let base_url = std::env::var("CATZCONNECT_BASE_URL")
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .unwrap_or_else(|_| "https://api.catzconnect.com".into());

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
            .header("User-Agent", "catzconnect-rust-sdk/1.0.0")
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
