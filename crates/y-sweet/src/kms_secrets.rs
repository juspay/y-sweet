//! Secrets encrypted with Cloud KMS, decrypted once at startup.
//!
//! The same scheme as the xyne-spaces backend (`kmsSecrets.ts`, `kmsCiphertextSource.ts`):
//! when `SECRETS_KMS_KEY_NAME` is set, the values of [`KMS_ENCRYPTED_KEYS`] are base64 KMS
//! ciphertext. They are read from `/etc/secrets/kms/<NAME>` when that directory exists (a
//! mounted Secret), otherwise from the env vars of the same names. Each is decrypted with the
//! pod's own identity (Application Default Credentials, Workload Identity on GKE) and kept in
//! memory only, never written back to the environment. One failure stops startup; errors name
//! the variable, never its value.
//!
//! To produce a value:
//!   printf '%s' "$VALUE" | gcloud kms encrypt --key=<key> --keyring=<ring> --location=<loc> \
//!     --project=<project> --plaintext-file=- --ciphertext-file=- | base64

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::HashMap, path::Path};

pub const KMS_KEY_NAME_ENV: &str = "SECRETS_KMS_KEY_NAME";
pub const KMS_CIPHERTEXT_DIR: &str = "/etc/secrets/kms";

/// Env vars that hold KMS ciphertext whenever `SECRETS_KMS_KEY_NAME` is set.
pub const KMS_ENCRYPTED_KEYS: &[&str] = &[
    "Y_SWEET_AUTH",
    "Y_SWEET_SERVER_TOKEN",
    "Y_SWEET_WS_GRANT_PRIVATE_KEY",
];

/// Kubernetes' own entries in a Secret volume (`..data`, `..2026_10_30_…`) never match.
fn is_key_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// `(name, ciphertext)` for every env-var-named file in `dir`, sorted; `None` if `dir` does not
/// exist. Empty files are skipped.
pub fn read_ciphertexts_from_dir(dir: &Path) -> Result<Option<Vec<(String, String)>>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("Failed to read {}", dir.display())),
    };
    let mut names = Vec::new();
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if is_key_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let ciphertext = std::fs::read_to_string(dir.join(&name))
            .with_context(|| format!("Failed to read the ciphertext for {name}"))?;
        let ciphertext = ciphertext.trim();
        if !ciphertext.is_empty() {
            out.push((name, ciphertext.to_string()));
        }
    }
    Ok(Some(out))
}

/// The ciphertexts to decrypt: the mounted directory wins over the listed env vars.
pub fn read_ciphertexts(
    dir: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>> {
    if let Some(from_files) = read_ciphertexts_from_dir(dir)? {
        return Ok(from_files);
    }
    Ok(KMS_ENCRYPTED_KEYS
        .iter()
        .filter_map(|key| {
            env(key)
                .filter(|v| !v.is_empty())
                .map(|v| (key.to_string(), v))
        })
        .collect())
}

/// The decrypted secrets, by env var name. Empty when `SECRETS_KMS_KEY_NAME` is unset, so the
/// plain env vars and flags are used as before.
pub async fn load_kms_secrets() -> Result<HashMap<String, String>> {
    let key_name = match std::env::var(KMS_KEY_NAME_ENV) {
        Ok(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => return Ok(HashMap::new()),
    };
    let ciphertexts = read_ciphertexts(Path::new(KMS_CIPHERTEXT_DIR), |k| std::env::var(k).ok())?;
    let kms = google_cloud_kms_v1::client::KeyManagementService::builder()
        .build()
        .await
        .context("Failed to create the KMS client")?;
    let mut out = HashMap::new();
    for (key, ciphertext) in ciphertexts {
        let plaintext = async {
            let bytes = STANDARD
                .decode(ciphertext.as_bytes())
                .map_err(|_| anyhow!("ciphertext is not base64"))?;
            let resp = kms
                .decrypt()
                .set_name(&key_name)
                .set_ciphertext(bytes)
                .send()
                .await
                .map_err(|e| anyhow!("{e}"))?;
            let text = String::from_utf8(resp.plaintext.to_vec())
                .map_err(|_| anyhow!("plaintext is not UTF-8"))?;
            Ok::<_, anyhow::Error>(text.trim().to_string())
        }
        .await
        .map_err(|e| anyhow!("KMS decryption failed for {key}: {e}"))?;
        out.insert(key, plaintext);
    }
    tracing::info!(
        count = out.len(),
        keys = ?out.keys().collect::<Vec<_>>(),
        "Decrypted KMS secrets"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("y-sweet-kms-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn key_names() {
        assert!(is_key_name("Y_SWEET_AUTH"));
        assert!(is_key_name("A1"));
        assert!(!is_key_name("..data"));
        assert!(!is_key_name("..2026_10_30_12_00_00.123"));
        assert!(!is_key_name("lower"));
        assert!(!is_key_name("1ABC"));
        assert!(!is_key_name(""));
    }

    #[test]
    fn missing_dir_is_none() {
        let dir = std::env::temp_dir().join("y-sweet-kms-does-not-exist");
        assert!(read_ciphertexts_from_dir(&dir).unwrap().is_none());
    }

    #[test]
    fn dir_reads_named_files_sorted_trimmed() {
        let dir = temp_dir("dir");
        std::fs::write(dir.join("Y_SWEET_SERVER_TOKEN"), "  c2VydmVy\n").unwrap();
        std::fs::write(dir.join("Y_SWEET_AUTH"), "YXV0aA==\n").unwrap();
        std::fs::write(dir.join("EMPTY"), "\n").unwrap();
        std::fs::write(dir.join("..data"), "x").unwrap();
        let got = read_ciphertexts_from_dir(&dir).unwrap().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            got,
            vec![
                ("Y_SWEET_AUTH".to_string(), "YXV0aA==".to_string()),
                ("Y_SWEET_SERVER_TOKEN".to_string(), "c2VydmVy".to_string()),
            ]
        );
    }

    #[test]
    fn dir_wins_over_env() {
        let dir = temp_dir("wins");
        std::fs::write(dir.join("Y_SWEET_AUTH"), "ZmlsZQ==").unwrap();
        let got = read_ciphertexts(&dir, |_| Some("ZW52".to_string())).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            got,
            vec![("Y_SWEET_AUTH".to_string(), "ZmlsZQ==".to_string())]
        );
    }

    #[test]
    fn env_fallback_only_listed_keys() {
        let dir = std::env::temp_dir().join("y-sweet-kms-no-dir");
        let got = read_ciphertexts(&dir, |k| match k {
            "Y_SWEET_AUTH" => Some("YQ==".to_string()),
            "Y_SWEET_SERVER_TOKEN" => Some(String::new()),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, vec![("Y_SWEET_AUTH".to_string(), "YQ==".to_string())]);
    }
}
