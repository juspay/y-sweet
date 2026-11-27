pub mod doc_keys;
pub mod filesystem;
pub mod gcs;
pub mod s3;
pub mod storage_keys;

use crate::ws_crypto::WsGrantKey;
use anyhow::Context;
use gcs::GcsOptions;
use std::sync::Arc;
use storage_keys::StorageKeyProvider;

/// Builds GCS store options from the encryption-related settings. Fails if
/// encryption is requested without the backend URL, server token and grant key
/// needed to fetch keys, so Y-Sweet never starts up writing docs unencrypted.
///
/// Docs are encrypted by Y-Sweet itself with per-doc keys that the backend relays sealed to
/// `grant_key` (the canvas socket grant private key); CSEK docs stay readable.
pub fn gcs_options(
    store_encryption: bool,
    backend_url: Option<&str>,
    server_token: Option<&str>,
    grant_key: Option<&str>,
) -> anyhow::Result<GcsOptions> {
    if !store_encryption {
        return Ok(GcsOptions::default());
    }
    if !xyne_doc_crypto::AVAILABLE {
        anyhow::bail!("Y_SWEET_STORE_ENCRYPTION is not supported by this build");
    }
    let key_provider = {
        let backend_url = backend_url.filter(|u| !u.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("Y_SWEET_STORE_ENCRYPTION requires Y_SWEET_BACKEND_URL to be set")
        })?;
        let server_token = server_token.filter(|t| !t.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("Y_SWEET_STORE_ENCRYPTION requires Y_SWEET_SERVER_TOKEN to be set")
        })?;
        Arc::new(StorageKeyProvider::new(backend_url, server_token.to_owned())?)
    };
    let raw = grant_key.filter(|k| !k.is_empty()).ok_or_else(|| {
        anyhow::anyhow!("Y_SWEET_STORE_ENCRYPTION requires Y_SWEET_WS_GRANT_PRIVATE_KEY to be set")
    })?;
    let grant_key =
        Arc::new(WsGrantKey::from_base64(raw).context("Invalid Y_SWEET_WS_GRANT_PRIVATE_KEY")?);
    Ok(GcsOptions {
        encryption: Some((key_provider, grant_key)),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum StoreTarget {
    S3 {
        bucket: String,
        prefix: Option<String>,
    },
    Gcs {
        bucket: String,
        prefix: Option<String>,
    },
    Filesystem(String),
}

fn parse_bucket_url(url_str: &str) -> anyhow::Result<(String, Option<String>)> {
    let url = url::Url::parse(url_str)?;
    let bucket = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid store URL, no bucket: {}", url_str))?
        .to_owned();
    let prefix = url.path().trim_matches('/').to_owned();
    let prefix = (!prefix.is_empty()).then_some(prefix);
    Ok((bucket, prefix))
}

pub fn parse_store_target(store_path: &str) -> anyhow::Result<StoreTarget> {
    if store_path.starts_with("s3://") {
        let (bucket, prefix) = parse_bucket_url(store_path)?;
        Ok(StoreTarget::S3 { bucket, prefix })
    } else if store_path.starts_with("gs://") {
        let (bucket, prefix) = parse_bucket_url(store_path)?;
        Ok(StoreTarget::Gcs { bucket, prefix })
    } else {
        Ok(StoreTarget::Filesystem(store_path.to_string()))
    }
}

pub fn target_from_bucket_env(bucket: &str, prefix: Option<String>) -> anyhow::Result<StoreTarget> {
    if bucket.starts_with("s3://") || bucket.starts_with("gs://") {
        let target = parse_store_target(bucket)?;
        match (target, prefix) {
            (
                StoreTarget::S3 {
                    bucket,
                    prefix: None,
                },
                p,
            ) => Ok(StoreTarget::S3 { bucket, prefix: p }),
            (
                StoreTarget::Gcs {
                    bucket,
                    prefix: None,
                },
                p,
            ) => Ok(StoreTarget::Gcs { bucket, prefix: p }),
            _ => anyhow::bail!(
                "STORAGE_BUCKET must not contain a path when used with STORAGE_PREFIX: {}",
                bucket
            ),
        }
    } else {
        Ok(StoreTarget::S3 {
            bucket: bucket.to_string(),
            prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_s3_url_with_prefix() {
        let t = parse_store_target("s3://my-bucket/some/prefix").unwrap();
        assert!(matches!(t, StoreTarget::S3 { ref bucket, ref prefix }
            if bucket == "my-bucket" && prefix.as_deref() == Some("some/prefix")));
    }

    #[test]
    fn parses_s3_url_without_prefix() {
        let t = parse_store_target("s3://my-bucket").unwrap();
        assert!(matches!(t, StoreTarget::S3 { ref bucket, ref prefix }
            if bucket == "my-bucket" && prefix.is_none()));
    }

    #[test]
    fn parses_gs_url_with_prefix() {
        let t = parse_store_target("gs://my-bucket/docs").unwrap();
        assert!(matches!(t, StoreTarget::Gcs { ref bucket, ref prefix }
            if bucket == "my-bucket" && prefix.as_deref() == Some("docs")));
    }

    #[test]
    fn parses_filesystem_path() {
        let t = parse_store_target("/var/data/ysweet").unwrap();
        assert!(matches!(t, StoreTarget::Filesystem(ref p) if p == "/var/data/ysweet"));
    }

    #[test]
    fn trailing_slash_means_no_prefix() {
        let t = parse_store_target("s3://my-bucket/").unwrap();
        assert!(matches!(t, StoreTarget::S3 { ref prefix, .. } if prefix.is_none()));
    }

    #[test]
    fn bucket_env_bare_name_is_s3() {
        let t = target_from_bucket_env("my-bucket", Some("p".to_string())).unwrap();
        assert!(matches!(t, StoreTarget::S3 { ref bucket, ref prefix }
            if bucket == "my-bucket" && prefix.as_deref() == Some("p")));
    }

    #[test]
    fn bucket_env_gs_scheme_is_gcs() {
        let t = target_from_bucket_env("gs://my-bucket", None).unwrap();
        assert!(matches!(t, StoreTarget::Gcs { ref bucket, .. } if bucket == "my-bucket"));
    }

    #[test]
    fn bucket_env_s3_scheme_is_s3() {
        let t = target_from_bucket_env("s3://my-bucket", None).unwrap();
        assert!(matches!(t, StoreTarget::S3 { ref bucket, .. } if bucket == "my-bucket"));
    }

    #[test]
    fn encryption_requires_backend_url_token_and_grant_key() {
        let (b, t) = (Some("http://b"), Some("t"));
        let key = Some(crate::ws_crypto::test::private_key());
        if !xyne_doc_crypto::AVAILABLE {
            assert!(gcs_options(true, b, t, key).is_err());
            return;
        }
        assert!(gcs_options(true, None, t, key).is_err());
        assert!(gcs_options(true, b, None, key).is_err());
        assert!(gcs_options(true, Some(""), t, key).is_err());
        assert!(gcs_options(true, b, Some(""), key).is_err());
        assert!(gcs_options(true, b, t, None).is_err());
        assert!(gcs_options(true, b, t, Some("")).is_err());
        assert!(gcs_options(true, b, t, Some("not-a-key")).is_err());
        assert!(gcs_options(true, b, t, key).unwrap().encryption.is_some());
    }

    #[test]
    fn encryption_off_needs_no_backend() {
        assert!(gcs_options(false, None, None, None).unwrap().encryption.is_none());
    }

    #[test]
    fn s3_url_with_no_bucket_is_an_error() {
        assert!(parse_store_target("s3://").is_err());
    }
}
