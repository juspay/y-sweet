//! Per-doc keys for the docs Y-Sweet encrypts itself (`Y_SWEET_STORE_ENCRYPTION`).
//!
//! Each doc has its own key, issued by the encryption service and wrapped under the doc's
//! workspace storage key; the wrapped form is kept in the object's metadata (`enc-wdek`), as with
//! CSEK docs. Y-Sweet gets the key through the backend's storage-key route: the key comes sealed
//! to Y-Sweet's grant key, so the backend relays it without being able to read it.
//!
//! Opening the grant and encrypting the doc are done by `xyne_doc_crypto`. Key material and doc
//! bytes must never be logged.

use crate::ws_crypto::WsGrantKey;
pub use xyne_doc_crypto::{is_encrypted_doc, open_doc, seal_doc, DocCryptoError};

/// The doc key in `grant`, checked to be for `doc_id` and `wrapped_key` (the `enc-wdek` stored
/// beside the doc).
pub fn doc_key_from_grant(
    grant_key: &WsGrantKey,
    grant: &str,
    doc_id: &str,
    wrapped_key: &str,
) -> Result<[u8; 32], DocCryptoError> {
    xyne_doc_crypto::doc_key_from_grant(grant_key.oaep(), grant, doc_id, wrapped_key)
}
