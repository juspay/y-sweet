pub mod doc_keys;
pub mod filesystem;
pub mod gcs;
pub mod s3;
pub mod storage_keys;

use doc_keys::DirectKeyProvider;
use gcs::GcsOptions;
use std::sync::Arc;
use storage_keys::StorageKeyProvider;

/// Builds GCS store options from the encryption-related settings. Fails if
/// encryption is requested without the backend URL and server token needed
/// to fetch keys, so Y-Sweet never starts up writing docs unencrypted.
///
/// With `enc_url` set, per-doc keys come from the encryption service directly and docs are
/// encrypted by Y-Sweet itself instead of with a CSEK; CSEK docs stay readable.
pub fn gcs_options(
    store_encryption: bool,
    backend_url: Option<&str>,
    server_token: Option<&str>,
    enc_url: Option<&str>,
    enc_key: Option<&str>,
) -> anyhow::Result<GcsOptions> {
    let enc_url = enc_url.filter(|u| !u.is_empty());
    if enc_url.is_some() && !store_encryption {
        anyhow::bail!("Y_SWEET_ENC_URL requires Y_SWEET_STORE_ENCRYPTION to be on");
    }
    let key_provider = if store_encryption {
        let backend_url = backend_url.filter(|u| !u.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("Y_SWEET_STORE_ENCRYPTION requires Y_SWEET_BACKEND_URL to be set")
        })?;
        let server_token = server_token.filter(|t| !t.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("Y_SWEET_STORE_ENCRYPTION requires Y_SWEET_SERVER_TOKEN to be set")
        })?;
        Some(Arc::new(StorageKeyProvider::new(
            backend_url,
            server_token.to_owned(),
        )?))
    } else {
        None
    };
    let direct_keys = match enc_url {
        Some(enc_url) => {
            let enc_key = enc_key.filter(|k| !k.is_empty()).ok_or_else(|| {
                anyhow::anyhow!("Y_SWEET_ENC_URL requires Y_SWEET_ENC_KEY to be set")
            })?;
            // store_encryption is on, so the backend URL and token were checked above.
            Some(Arc::new(DirectKeyProvider::new(
                enc_url,
                enc_key.to_owned(),
                backend_url.unwrap_or_default(),
                server_token.unwrap_or_default().to_owned(),
            )?))
        }
        None => None,
    };
    Ok(GcsOptions {
        key_provider,
        direct_keys,
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
    fn encryption_requires_backend_url_and_token() {
        assert!(gcs_options(true, None, Some("t"), None, None).is_err());
        assert!(gcs_options(true, Some("http://b"), None, None, None).is_err());
        assert!(gcs_options(true, Some(""), Some("t"), None, None).is_err());
        assert!(gcs_options(true, Some("http://b"), Some(""), None, None).is_err());
        let opts = gcs_options(true, Some("http://b"), Some("t"), None, None).unwrap();
        assert!(opts.key_provider.is_some());
        assert!(opts.direct_keys.is_none());
    }

    #[test]
    fn direct_keys_need_store_encryption_and_key() {
        let (b, t, e) = (Some("http://b"), Some("t"), Some("http://e"));
        assert!(gcs_options(false, b, t, e, Some("k")).is_err());
        assert!(gcs_options(true, b, t, e, None).is_err());
        assert!(gcs_options(true, b, t, e, Some("")).is_err());
        let opts = gcs_options(true, b, t, e, Some("k")).unwrap();
        assert!(opts.key_provider.is_some());
        assert!(opts.direct_keys.is_some());
        let opts = gcs_options(true, b, t, Some(""), None).unwrap();
        assert!(opts.direct_keys.is_none());
    }

    #[test]
    fn encryption_off_needs_no_backend() {
        let opts = gcs_options(false, None, None, None, None).unwrap();
        assert!(opts.key_provider.is_none());
    }

    #[test]
    fn s3_url_with_no_bucket_is_an_error() {
        assert!(parse_store_target("s3://").is_err());
    }
}
