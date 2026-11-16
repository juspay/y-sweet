//! Per-socket frame encryption. The client sends `0xE0 ‖ 0x01 ‖ RSA-OAEP-SHA256(K)` first, then
//! every frame is AES-256-GCM under K with nonce `direction ‖ u64 counter`, so replay,
//! reorder and reflection fail to decrypt.
use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    digest::{digest, SHA256},
    encoding::AsDer,
    rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA256_MGF1SHA256},
};
use base64::{engine::general_purpose::STANDARD, Engine};

const HANDSHAKE_TAG: u8 = 0xE0;
const HANDSHAKE_VERSION: u8 = 0x01;
pub const CLIENT_TO_SERVER: [u8; 4] = [0, 0, 0, 1];
pub const SERVER_TO_CLIENT: [u8; 4] = [0, 0, 0, 2];

/// SHA-256 of the whole handshake frame. A ticket can be bound to it.
pub fn handshake_hash(frame: &[u8]) -> [u8; 32] {
    digest(&SHA256, frame)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

pub struct WsKey {
    key: OaepPrivateDecryptingKey,
    public_key: String,
}

impl WsKey {
    /// Takes a base64 PKCS#8 DER RSA private key of at least 2048 bits.
    pub fn from_base64_pkcs8(b64: &str) -> Result<Self> {
        let der = STANDARD
            .decode(b64.split_whitespace().collect::<String>())
            .context("not base64")?;
        let private = PrivateDecryptingKey::from_pkcs8(&der)
            .map_err(|e| anyhow!("not a PKCS#8 RSA private key: {e}"))?;
        if private.key_size_bits() < 2048 {
            bail!("RSA key must be at least 2048 bits");
        }
        let spki = private
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("cannot encode public key"))?;
        Ok(Self {
            public_key: STANDARD.encode(spki.as_ref()),
            key: OaepPrivateDecryptingKey::new(private)
                .map_err(|_| anyhow!("cannot build OAEP key"))?,
        })
    }

    /// Base64 SPKI DER, for WebCrypto `importKey("spki", ...)`.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Returns `(sealer, opener)` for the server side of the socket.
    pub fn handshake(&self, frame: &[u8]) -> Result<(FrameCipher, FrameCipher)> {
        let [HANDSHAKE_TAG, HANDSHAKE_VERSION, wrapped @ ..] = frame else {
            bail!("not a handshake frame");
        };
        let mut out = vec![0u8; self.key.min_output_size()];
        let k = self
            .key
            .decrypt(&OAEP_SHA256_MGF1SHA256, wrapped, &mut out, None)
            .map_err(|_| anyhow!("cannot unwrap key"))?;
        Ok((
            FrameCipher::new(k, SERVER_TO_CLIENT)?,
            FrameCipher::new(k, CLIENT_TO_SERVER)?,
        ))
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
    use aws_lc_rs::rsa::{KeySize, OaepPublicEncryptingKey, PublicEncryptingKey};

    pub fn gen_key_b64() -> String {
        let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        STANDARD.encode(key.as_der().unwrap().as_ref())
    }

    /// Client side: returns the handshake frame plus `(sealer, opener)`.
    pub fn client_handshake(key: &WsKey) -> (Vec<u8>, FrameCipher, FrameCipher) {
        let k = [7u8; 32];
        let spki = STANDARD.decode(key.public_key()).unwrap();
        let public =
            OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&spki).unwrap()).unwrap();
        let mut wrapped = vec![0u8; public.ciphertext_size()];
        let wrapped = public
            .encrypt(&OAEP_SHA256_MGF1SHA256, &k, &mut wrapped, None)
            .unwrap();
        let frame = [&[HANDSHAKE_TAG, HANDSHAKE_VERSION][..], wrapped].concat();
        (
            frame,
            FrameCipher::new(&k, CLIENT_TO_SERVER).unwrap(),
            FrameCipher::new(&k, SERVER_TO_CLIENT).unwrap(),
        )
    }

    fn pair() -> (FrameCipher, FrameCipher, FrameCipher, FrameCipher) {
        let key = WsKey::from_base64_pkcs8(&gen_key_b64()).unwrap();
        let (frame, c_seal, c_open) = client_handshake(&key);
        let (s_seal, s_open) = key.handshake(&frame).unwrap();
        (c_seal, c_open, s_seal, s_open)
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

    #[test]
    fn rejects_bad_handshake() {
        let key = WsKey::from_base64_pkcs8(&gen_key_b64()).unwrap();
        let (frame, _, _) = client_handshake(&key);
        assert!(key.handshake(&[]).is_err());
        assert!(key.handshake(&frame[1..]).is_err());
        let mut bad_version = frame.clone();
        bad_version[1] = 2;
        assert!(key.handshake(&bad_version).is_err());
        let mut tampered = frame.clone();
        tampered[10] ^= 1;
        assert!(key.handshake(&tampered).is_err());
        let other = WsKey::from_base64_pkcs8(&gen_key_b64()).unwrap();
        assert!(other.handshake(&frame).is_err());
    }

    #[test]
    fn rejects_malformed_or_small_keys() {
        assert!(WsKey::from_base64_pkcs8("not base64!").is_err());
        assert!(WsKey::from_base64_pkcs8(&STANDARD.encode(b"junk")).is_err());
    }
}
