//! Per-doc customer-supplied encryption keys (CSEK), issued by the backend.
//!
//! Y-Sweet never talks to the encryption service directly. It asks the
//! backend's `POST /api/ysweet/storage-key` (server-token auth) either to
//! generate a fresh key for a doc, or to unwrap a key stored in the object's
//! metadata. Key material must never be logged.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use std::time::Duration;

const STORAGE_KEY_PATH: &str = "/api/ysweet/storage-key";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A doc's plaintext CSEK together with its wrapped form (`enc-wdek`).
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
struct GenerateResponse {
    key: String,
    wrapped_key: String,
}

#[derive(Deserialize)]
struct UnwrapResponse {
    key: String,
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

    /// Asks the backend for a new key for `doc_id`, wrapped under the doc's
    /// workspace storage key.
    pub async fn generate(&self, doc_id: &str) -> Result<DocKey, StorageKeyError> {
        let resp: GenerateResponse = self.post(serde_json::json!({ "docId": doc_id })).await?;
        if resp.wrapped_key.is_empty() {
            return Err(StorageKeyError::Malformed("empty wrappedKey"));
        }
        Ok(DocKey {
            key: decode_key(&resp.key)?,
            wrapped_key: resp.wrapped_key,
        })
    }

    /// Asks the backend to unwrap `wrapped_key` (an object's `enc-wdek`).
    pub async fn unwrap(
        &self,
        doc_id: &str,
        wrapped_key: &str,
    ) -> Result<[u8; 32], StorageKeyError> {
        let resp: UnwrapResponse = self
            .post(serde_json::json!({ "docId": doc_id, "wrappedKey": wrapped_key }))
            .await?;
        decode_key(&resp.key)
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

/// Decodes a base64 key and checks it is exactly 32 bytes (AES-256).
pub fn decode_key(b64: &str) -> Result<[u8; 32], StorageKeyError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|_| StorageKeyError::Malformed("key is not valid base64"))?;
    bytes
        .try_into()
        .map_err(|_| StorageKeyError::Malformed("key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_32_byte_key() {
        let raw = [7u8; 32];
        assert_eq!(decode_key(&BASE64.encode(raw)).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length_key() {
        assert!(matches!(
            decode_key(&BASE64.encode([1u8; 16])),
            Err(StorageKeyError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(matches!(
            decode_key("not base64!!"),
            Err(StorageKeyError::Malformed(_))
        ));
    }

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
        assert_eq!(p.url, "http://backend:3000/api/ysweet/storage-key");
    }
}
