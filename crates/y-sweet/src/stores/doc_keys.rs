//! Per-doc keys from the encryption service directly, and doc encryption in Y-Sweet itself.
//!
//! Each doc has its own 32-byte key, issued by the encryption service and wrapped under the
//! doc's workspace storage key; the wrapped form is kept in the object's metadata
//! (`enc-wdek`), as with CSEK docs. Y-Sweet asks the service's `/ysweet/storage/generate-key`
//! for a new doc's key and `/ysweet/storage/unwrap-key` for an existing one, with its own key
//! (`x-ysweet-key`), so no key passes through the backend. The backend is asked only which
//! workspace owns a new doc (`POST /internal/ysweet/doc-workspace`, server-token auth).
//!
//! The doc is then encrypted here, and GCS stores only ciphertext:
//!
//!   object = "XYD1" | iv (12) | AES-256-GCM(doc) | tag (16),   AAD = "XYD1" | doc id
//!
//! The doc id in the AAD keeps one doc's object from being served as another's. Key material
//! and doc bytes must never be logged.

use super::storage_keys::{decode_key, DocKey, StorageKeyError};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::time::Duration;

const GENERATE_PATH: &str = "/ysweet/storage/generate-key";
const UNWRAP_PATH: &str = "/ysweet/storage/unwrap-key";
const DOC_WORKSPACE_PATH: &str = "/internal/ysweet/doc-workspace";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Start of every doc this module encrypts.
pub const MAGIC: &[u8; 4] = b"XYD1";
const TAG_LEN: usize = 16;

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocWorkspaceResponse {
    workspace_id: String,
}

pub struct DirectKeyProvider {
    client: reqwest::Client,
    enc_url: String,
    enc_key: String,
    backend_url: String,
    server_token: String,
}

impl DirectKeyProvider {
    pub fn new(
        enc_url: &str,
        enc_key: String,
        backend_url: &str,
        server_token: String,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            client,
            enc_url: enc_url.trim_end_matches('/').to_string(),
            enc_key,
            backend_url: backend_url.trim_end_matches('/').to_string(),
            server_token,
        })
    }

    /// A new key for `doc_id`, wrapped under its workspace's storage key.
    pub async fn generate(&self, doc_id: &str) -> Result<DocKey, StorageKeyError> {
        let workspace = self.workspace(doc_id).await?;
        let resp: GenerateResponse = self
            .post_enc(
                GENERATE_PATH,
                serde_json::json!({ "workspaceId": workspace.workspace_id }),
            )
            .await?;
        if resp.wrapped_key.is_empty() {
            return Err(StorageKeyError::Malformed("empty wrappedKey"));
        }
        Ok(DocKey {
            key: decode_key(&resp.key)?,
            wrapped_key: resp.wrapped_key,
        })
    }

    /// The key in `wrapped_key` (an object's `enc-wdek`).
    pub async fn unwrap(&self, wrapped_key: &str) -> Result<[u8; 32], StorageKeyError> {
        let resp: UnwrapResponse = self
            .post_enc(
                UNWRAP_PATH,
                serde_json::json!({ "wrappedKey": wrapped_key }),
            )
            .await?;
        decode_key(&resp.key)
    }

    async fn workspace(&self, doc_id: &str) -> Result<DocWorkspaceResponse, StorageKeyError> {
        let resp = self
            .client
            .post(format!("{}{}", self.backend_url, DOC_WORKSPACE_PATH))
            .bearer_auth(&self.server_token)
            .json(&serde_json::json!({ "docId": doc_id }))
            .send()
            .await
            .map_err(|e| StorageKeyError::Request(e.without_url().to_string()))?;
        read_json(resp).await.and_then(|r: DocWorkspaceResponse| {
            if r.workspace_id.is_empty() {
                Err(StorageKeyError::Malformed("empty workspaceId"))
            } else {
                Ok(r)
            }
        })
    }

    async fn post_enc<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, StorageKeyError> {
        let resp = self
            .client
            .post(format!("{}{}", self.enc_url, path))
            .header("x-ysweet-key", &self.enc_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| StorageKeyError::Request(e.without_url().to_string()))?;
        read_json(resp).await
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, StorageKeyError> {
    let status = resp.status();
    if !status.is_success() {
        return Err(StorageKeyError::Status(status.as_u16()));
    }
    resp.json::<T>()
        .await
        .map_err(|_| StorageKeyError::Malformed("invalid JSON body"))
}

/// Errors deliberately carry no key material or doc bytes.
#[derive(Debug, thiserror::Error)]
pub enum DocCryptoError {
    #[error("doc encryption failed")]
    Seal,
    #[error("stored doc is not an encrypted doc")]
    NotEncrypted,
    #[error("stored doc failed to decrypt")]
    Open,
}

fn doc_aad(doc_id: &str) -> Vec<u8> {
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(doc_id.as_bytes());
    aad
}

fn aead_key(key: &[u8; 32]) -> Result<LessSafeKey, DocCryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| DocCryptoError::Seal)
}

/// Whether `bytes` start like a doc encrypted here.
pub fn is_encrypted_doc(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// `plaintext` encrypted with the doc's key: the bytes to store.
pub fn seal_doc(key: &[u8; 32], doc_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, DocCryptoError> {
    let mut iv = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut iv)
        .map_err(|_| DocCryptoError::Seal)?;
    let mut buf = plaintext.to_vec();
    aead_key(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(doc_aad(doc_id)),
            &mut buf,
        )
        .map_err(|_| DocCryptoError::Seal)?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + buf.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// The plaintext of a doc `seal_doc` encrypted with `key` for `doc_id`.
pub fn open_doc(key: &[u8; 32], doc_id: &str, sealed: &[u8]) -> Result<Vec<u8>, DocCryptoError> {
    if !is_encrypted_doc(sealed) || sealed.len() < MAGIC.len() + NONCE_LEN + TAG_LEN {
        return Err(DocCryptoError::NotEncrypted);
    }
    let iv: [u8; NONCE_LEN] = sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN]
        .try_into()
        .expect("nonce length");
    let mut buf = sealed[MAGIC.len() + NONCE_LEN..].to_vec();
    let plain = aead_key(key)
        .map_err(|_| DocCryptoError::Open)?
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(doc_aad(doc_id)),
            &mut buf,
        )
        .map_err(|_| DocCryptoError::Open)?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn doc_round_trips() {
        for doc in [&b""[..], b"hello", &[1u8; 100_000][..]] {
            let sealed = seal_doc(&KEY, "doc-1", doc).unwrap();
            assert!(is_encrypted_doc(&sealed));
            assert_eq!(sealed.len(), MAGIC.len() + NONCE_LEN + doc.len() + TAG_LEN);
            assert_eq!(open_doc(&KEY, "doc-1", &sealed).unwrap(), doc);
        }
    }

    #[test]
    fn same_doc_encrypts_differently_each_time() {
        assert_ne!(
            seal_doc(&KEY, "doc-1", b"same").unwrap(),
            seal_doc(&KEY, "doc-1", b"same").unwrap()
        );
    }

    #[test]
    fn wrong_key_doc_or_bytes_fail() {
        let sealed = seal_doc(&KEY, "doc-1", b"hello").unwrap();
        assert!(open_doc(&[8u8; 32], "doc-1", &sealed).is_err());
        assert!(open_doc(&KEY, "doc-2", &sealed).is_err());
        let mut flipped = sealed.clone();
        let n = flipped.len();
        flipped[n - 1] ^= 1;
        assert!(open_doc(&KEY, "doc-1", &flipped).is_err());
        assert!(open_doc(&KEY, "doc-1", b"plain doc").is_err());
        assert!(open_doc(&KEY, "doc-1", &sealed[..MAGIC.len() + NONCE_LEN]).is_err());
    }
}
