//! Per-doc storage keys, issued through the backend.
//!
//! Y-Sweet never talks to the encryption service directly. It asks the
//! backend's `POST /internal/ysweet/storage-key` (server-token auth) for a
//! doc's key, which comes back sealed to Y-Sweet's public key (`doc_keys`), so
//! the backend relaying it cannot read it. Key material must never be logged.

use serde::Deserialize;
use std::time::Duration;

const STORAGE_KEY_PATH: &str = "/internal/ysweet/storage-key";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A doc's key together with its wrapped form (`enc-wdek`).
#[derive(Clone, PartialEq, Eq)]
pub struct DocKey {
    pub key: [u8; 32],
    pub wrapped_key: String,
}

impl std::fmt::Debug for DocKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DocKey(<redacted>)")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedResponse {
    wrapped_key: Option<String>,
    grant: Option<String>,
}

/// Errors deliberately carry no key material.
#[derive(Debug, thiserror::Error)]
pub enum StorageKeyError {
    #[error("storage-key request failed: {0}")]
    Request(String),
    #[error("storage-key endpoint returned status {0}")]
    Status(u16),
    #[error("storage-key response was malformed: {0}")]
    Malformed(&'static str),
}

pub struct StorageKeyProvider {
    client: reqwest::Client,
    url: String,
    server_token: String,
}

impl StorageKeyProvider {
    pub fn new(backend_url: &str, server_token: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            client,
            url: format!("{}{}", backend_url.trim_end_matches('/'), STORAGE_KEY_PATH),
            server_token,
        })
    }

    /// `doc_id`'s key, sealed to y-sweet's public key by the encryption service: the backend
    /// relays it and cannot read it. The backend finds the key from the doc's object (a new key
    /// for a doc that has none). `(wrapped_key, grant)`.
    pub async fn sealed(&self, doc_id: &str) -> Result<(String, String), StorageKeyError> {
        let resp: SealedResponse = self
            .post(serde_json::json!({ "docId": doc_id }))
            .await?;
        match (resp.wrapped_key, resp.grant) {
            (Some(w), Some(g)) if !w.is_empty() && !g.is_empty() => Ok((w, g)),
            _ => Err(StorageKeyError::Malformed("missing wrappedKey or grant")),
        }
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
    ) -> Result<T, StorageKeyError> {
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(&self.server_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| StorageKeyError::Request(e.without_url().to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(StorageKeyError::Status(status.as_u16()));
        }
        resp.json::<T>()
            .await
            .map_err(|_| StorageKeyError::Malformed("invalid JSON body"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_key() {
        let k = DocKey {
            key: [9u8; 32],
            wrapped_key: "ENC:v1|dek|secret".to_string(),
        };
        let s = format!("{:?}", k);
        assert!(!s.contains("secret"));
        assert!(!s.contains('9'));
    }

    #[test]
    fn url_joins_without_double_slash() {
        let p = StorageKeyProvider::new("http://backend:3000/", "t".to_string()).unwrap();
        assert_eq!(p.url, "http://backend:3000/internal/ysweet/storage-key");
    }
}
