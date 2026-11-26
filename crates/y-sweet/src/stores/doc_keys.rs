//! Docs encrypted by Y-Sweet itself with their per-doc key.
//!
//! Each doc has its own 32-byte key, issued by the encryption service and wrapped under the
//! doc's workspace storage key; the wrapped form is kept in the object's metadata (`enc-wdek`),
//! as with CSEK docs. Y-Sweet gets the key through the backend's storage-key route with
//! `grant`: the encryption service seals it to Y-Sweet's RSA public key (the canvas socket
//! grant key, under its own label), so the backend relays it without being able to read it.
//! The grant names the doc and the wrapped key it belongs to (`doc_key_from_grant` checks both).
//!
//! The doc is then encrypted here, and GCS stores only ciphertext:
//!
//!   object = "XYD1" | iv (12) | AES-256-GCM(doc) | tag (16),   AAD = "XYD1" | doc id
//!
//! The doc id in the AAD keeps one doc's object from being served as another's. Key material
//! and doc bytes must never be logged.

use crate::ws_crypto::WsGrantKey;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{engine::general_purpose::STANDARD, Engine};

/// Start of every doc this module encrypts.
pub const MAGIC: &[u8; 4] = b"XYD1";
const TAG_LEN: usize = 16;

/// The doc key in `grant`, after checking it was sealed for `doc_id` and for `wrapped_key`
/// (the `enc-wdek` stored beside the doc) and has not expired.
pub fn doc_key_from_grant(
    grant_key: &WsGrantKey,
    grant: &str,
    doc_id: &str,
    wrapped_key: &str,
) -> Result<[u8; 32], DocCryptoError> {
    let g = grant_key
        .unwrap_doc_key_grant(grant)
        .map_err(|_| DocCryptoError::Grant("does not open"))?;
    if g.doc != doc_id {
        return Err(DocCryptoError::Grant("is for another doc"));
    }
    if g.wk != STANDARD.encode(digest(&SHA256, wrapped_key.as_bytes()).as_ref()) {
        return Err(DocCryptoError::Grant("is for another wrapped key"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(u64::MAX);
    if g.exp < now {
        return Err(DocCryptoError::Grant("has expired"));
    }
    Ok(g.key)
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
    #[error("doc key grant {0}")]
    Grant(&'static str),
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

    fn grant(doc: &str, wrapped: &str, exp: u64) -> String {
        let wk = STANDARD.encode(digest(&SHA256, wrapped.as_bytes()).as_ref());
        crate::ws_crypto::test::wrap_doc_key_grant(&format!(
            r#"{{"k":"{}","doc":"{doc}","wk":"{wk}","exp":{exp}}}"#,
            STANDARD.encode(KEY)
        ))
    }

    #[test]
    fn grant_must_match_doc_wrapped_key_and_time() {
        let gk = WsGrantKey::from_base64(crate::ws_crypto::test::private_key()).unwrap();
        let later = u64::MAX / 2;
        let w = "ENC:v1|ws|abc";
        assert_eq!(
            doc_key_from_grant(&gk, &grant("doc-1", w, later), "doc-1", w).unwrap(),
            KEY
        );
        assert!(doc_key_from_grant(&gk, &grant("doc-2", w, later), "doc-1", w).is_err());
        assert!(
            doc_key_from_grant(&gk, &grant("doc-1", "ENC:v1|ws|other", later), "doc-1", w).is_err()
        );
        assert!(doc_key_from_grant(&gk, &grant("doc-1", w, 1), "doc-1", w).is_err());
        assert!(doc_key_from_grant(&gk, "not-a-grant", "doc-1", w).is_err());
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
