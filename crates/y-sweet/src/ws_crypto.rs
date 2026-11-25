//! Per-socket frame encryption. The encryption service mints the socket key K and encrypts it to
//! y-sweet's RSA public key; only y-sweet's private key (`WsGrantKey`) opens it. Every frame is AES-256-GCM under K with nonce
//! `direction ‖ u64 counter`, so replay, reorder and reflection fail to decrypt.
use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA256_MGF1SHA256,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

pub const CLIENT_TO_SERVER: [u8; 4] = [0, 0, 0, 1];
pub const SERVER_TO_CLIENT: [u8; 4] = [0, 0, 0, 2];
const WRAP_LABEL: &[u8] = b"ysweet-w/v2";

/// A socket key and what it was minted for, unwrapped from the backend's `wsKey`.
#[derive(Clone, Deserialize)]
pub struct Grant {
    #[serde(rename = "k", deserialize_with = "key_from_base64")]
    pub key: [u8; 32],
    pub doc: String,
    pub sid: String,
    /// Unix milliseconds.
    pub exp: u64,
}

fn key_from_base64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(d)?;
    STANDARD
        .decode(s)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| serde::de::Error::custom("k must be 32 base64 bytes"))
}

/// y-sweet's RSA private key. The encryption service holds only its public key.
pub struct WsGrantKey(OaepPrivateDecryptingKey);

impl WsGrantKey {
    /// `b64` is the PKCS#8 DER of an RSA key of at least 3072 bits.
    pub fn from_base64(b64: &str) -> Result<Self> {
        let raw = STANDARD.decode(b64.trim()).context("not base64")?;
        let key = PrivateDecryptingKey::from_pkcs8(&raw)
            .map_err(|_| anyhow!("must be a PKCS#8 RSA private key"))?;
        if key.key_size_bits() < 3072 {
            bail!("RSA key must be at least 3072 bits");
        }
        Ok(Self(
            OaepPrivateDecryptingKey::new(key).map_err(|_| anyhow!("bad RSA key"))?,
        ))
    }

    /// A new pair: `(private, public)`, base64 DER. The public half goes to the encryption service.
    pub fn generate() -> Result<(String, String)> {
        let key = PrivateDecryptingKey::generate(KeySize::Rsa3072)
            .map_err(|_| anyhow!("keygen failed"))?;
        let private = key.as_der().map_err(|_| anyhow!("export failed"))?;
        let public = key
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("export failed"))?;
        Ok((
            STANDARD.encode(private.as_ref()),
            STANDARD.encode(public.as_ref()),
        ))
    }

    /// `w` is base64 RSA-OAEP-SHA256 of the JSON grant, label `ysweet-w/v2`.
    pub fn unwrap_grant(&self, w: &str) -> Result<Grant> {
        let raw = STANDARD.decode(w).context("wsKey is not base64")?;
        let mut buf = vec![0u8; self.0.min_output_size()];
        let plain = self
            .0
            .decrypt(&OAEP_SHA256_MGF1SHA256, &raw, &mut buf, Some(WRAP_LABEL))
            .map_err(|_| anyhow!("wsKey failed to decrypt"))?;
        serde_json::from_slice(plain).context("wsKey grant is not valid JSON")
    }
}

/// One direction of one socket: a key, the direction tag and the next counter.
pub struct FrameCipher {
    key: LessSafeKey,
    direction: [u8; 4],
    counter: u64,
}

impl FrameCipher {
    pub fn new(key: &[u8], direction: [u8; 4]) -> Result<Self> {
        if key.len() != 32 {
            bail!("key must be 32 bytes");
        }
        let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("bad AES key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            direction,
            counter: 0,
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.direction);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        Nonce::assume_unique_for_key(nonce)
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .expect("AES-GCM seal");
        buf
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let mut buf = frame.to_vec();
        let nonce = self.next_nonce();
        let len = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| anyhow!("frame failed to decrypt"))?
            .len();
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    fn pair() -> (FrameCipher, FrameCipher, FrameCipher, FrameCipher) {
        let k = [7u8; 32];
        (
            FrameCipher::new(&k, CLIENT_TO_SERVER).unwrap(),
            FrameCipher::new(&k, SERVER_TO_CLIENT).unwrap(),
            FrameCipher::new(&k, SERVER_TO_CLIENT).unwrap(),
            FrameCipher::new(&k, CLIENT_TO_SERVER).unwrap(),
        )
    }

    use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};
    use std::sync::OnceLock;

    /// One test pair for the whole run: RSA keygen is slow.
    pub fn private_key() -> &'static str {
        static KEY: OnceLock<(String, String)> = OnceLock::new();
        &KEY.get_or_init(|| WsGrantKey::generate().unwrap()).0
    }

    fn public_der() -> Vec<u8> {
        let raw = STANDARD.decode(private_key()).unwrap();
        let key = PrivateDecryptingKey::from_pkcs8(&raw).unwrap();
        key.public_key().as_der().unwrap().as_ref().to_vec()
    }

    /// Encrypts a grant the way the encryption service does.
    pub fn wrap_grant(grant_json: &str) -> String {
        let key =
            OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&public_der()).unwrap())
                .unwrap();
        let mut out = vec![0u8; key.ciphertext_size()];
        let w = key
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                grant_json.as_bytes(),
                &mut out,
                Some(WRAP_LABEL),
            )
            .unwrap();
        STANDARD.encode(w)
    }

    fn key() -> WsGrantKey {
        WsGrantKey::from_base64(private_key()).unwrap()
    }

    #[test]
    fn unwraps_a_grant() {
        let grant = r#"{"k":"khBP5Pvmrtt9EqgErVyPfbsI4kCx/W1AJxsHAwbNpCE=","doc":"doc-123","sid":"sid-abc","exp":1700000030000}"#;
        let g = key().unwrap_grant(&wrap_grant(grant)).unwrap();
        assert_eq!(
            STANDARD.encode(g.key),
            "khBP5Pvmrtt9EqgErVyPfbsI4kCx/W1AJxsHAwbNpCE="
        );
        assert_eq!(g.doc, "doc-123");
        assert_eq!(g.sid, "sid-abc");
        assert_eq!(g.exp, 1700000030000);
    }

    #[test]
    fn rejects_bad_grants() {
        const GRANT: &str =
            r#"{"k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","doc":"d","sid":"s","exp":1}"#;
        let mut w = STANDARD.decode(wrap_grant(GRANT)).unwrap();
        assert!(key().unwrap_grant(&STANDARD.encode(&w)).is_ok());
        *w.last_mut().unwrap() ^= 1;
        assert!(key().unwrap_grant(&STANDARD.encode(&w)).is_err());
        let (other, _) = WsGrantKey::generate().unwrap();
        let other = WsGrantKey::from_base64(&other).unwrap();
        assert!(other.unwrap_grant(&wrap_grant(GRANT)).is_err());
        assert!(key().unwrap_grant("short").is_err());
        assert!(WsGrantKey::from_base64("not base64!").is_err());
        let small = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        assert!(
            WsGrantKey::from_base64(&STANDARD.encode(small.as_der().unwrap().as_ref())).is_err()
        );
    }

    #[test]
    fn round_trip_both_directions() {
        let (mut c_seal, mut c_open, mut s_seal, mut s_open) = pair();
        for msg in [&b"hello"[..], b"", b"third"] {
            let ct = c_seal.seal(msg);
            assert_ne!(&ct[..], msg);
            assert_eq!(s_open.open(&ct).unwrap(), msg);
            assert_eq!(c_open.open(&s_seal.seal(msg)).unwrap(), msg);
        }
    }

    #[test]
    fn rejects_reorder() {
        let (mut c_seal, _, _, mut s_open) = pair();
        let _f0 = c_seal.seal(b"zero");
        let f1 = c_seal.seal(b"one");
        assert!(s_open.open(&f1).is_err());
    }

    #[test]
    fn rejects_replay() {
        let (mut c_seal, _, _, mut s_open) = pair();
        let f0 = c_seal.seal(b"zero");
        assert!(s_open.open(&f0).is_ok());
        assert!(s_open.open(&f0).is_err());
    }

    #[test]
    fn rejects_reflection() {
        let (_, _, mut s_seal, mut s_open) = pair();
        assert!(s_open.open(&s_seal.seal(b"echo")).is_err());
    }

    #[test]
    fn rejects_tampered_tag() {
        let (mut c_seal, _, _, mut s_open) = pair();
        let mut ct = c_seal.seal(b"tamper");
        *ct.last_mut().unwrap() ^= 1;
        assert!(s_open.open(&ct).is_err());
        assert!(s_open.open(b"short").is_err());
    }
}
