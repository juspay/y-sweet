//! Stub of the canvas doc encryption used with `Y_SWEET_STORE_LOCAL_ENCRYPTION`. Nothing encrypts
//! or decrypts here, and Y-Sweet refuses to start with local encryption on (`AVAILABLE` is `false`).

use aws_lc_rs::rsa::OaepPrivateDecryptingKey;
// Unused here; declared so the dependency set stays fixed in Cargo.lock.
use base64 as _;
use serde as _;
use serde_json as _;

/// Whether this build can encrypt docs.
pub const AVAILABLE: bool = false;
/// Start of every encrypted doc. Kept here so a build without encryption refuses such a doc
/// instead of serving its ciphertext.
pub const MAGIC: &[u8; 4] = b"XYD1";

#[derive(Debug, thiserror::Error)]
pub enum DocCryptoError {
    #[error("doc encryption is not available in this build")]
    Unavailable,
}

/// Whether `bytes` start like an encrypted doc.
pub fn is_encrypted_doc(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub fn doc_key_from_grant(
    _grant_key: &OaepPrivateDecryptingKey,
    _grant: &str,
    _doc_id: &str,
    _wrapped_key: &str,
) -> Result<[u8; 32], DocCryptoError> {
    Err(DocCryptoError::Unavailable)
}

pub fn seal_doc(
    _key: &[u8; 32],
    _doc_id: &str,
    _plaintext: &[u8],
) -> Result<Vec<u8>, DocCryptoError> {
    Err(DocCryptoError::Unavailable)
}

pub fn open_doc(_key: &[u8; 32], _doc_id: &str, _sealed: &[u8]) -> Result<Vec<u8>, DocCryptoError> {
    Err(DocCryptoError::Unavailable)
}
