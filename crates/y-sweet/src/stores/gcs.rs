use super::storage_keys::{DocKey, StorageKeyProvider};
use async_trait::async_trait;
use google_cloud_storage::client::{Storage, StorageControl};
use google_cloud_storage::model::Object;
use google_cloud_storage::model_ext::KeyAes256;
use moka::future::Cache;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use y_sweet_core::store::{Result, Store, StoreError};

/// Object metadata written alongside every encrypted doc, matching the
/// backend's `SafeStorageService` format.
const META_ENC_VERSION: &str = "enc-v";
const META_WRAPPED_KEY: &str = "enc-wdek";
const ENC_VERSION: &str = "1";

const DOC_KEY_SUFFIX: &str = "/data.ysweet";

/// Docs are unloaded by GC without the store being told, so cached keys
/// expire after this long without a read or write. Active docs touch their
/// entry on every checkpoint.
const KEY_CACHE_IDLE: Duration = Duration::from_secs(30 * 60);
const KEY_CACHE_MAX_ENTRIES: u64 = 10_000;

fn bucket_resource(bucket: &str) -> String {
    format!("projects/_/buckets/{}", bucket)
}

fn prefixed_key(prefix: &Option<String>, key: &str) -> String {
    if let Some(prefix) = prefix {
        format!("{}/{}", prefix, key)
    } else {
        key.to_string()
    }
}

fn gax_status(err: &google_cloud_gax::error::Error) -> Option<u16> {
    err.http_status_code()
}

fn map_gax_error(op: &str, err: google_cloud_gax::error::Error) -> StoreError {
    match gax_status(&err) {
        Some(401) | Some(403) => StoreError::NotAuthorized(format!("{}: {}", op, err)),
        Some(404) => StoreError::DoesNotExist(format!("{}: {}", op, err)),
        _ => StoreError::ConnectionError(format!("{}: {}", op, err)),
    }
}

fn is_not_found(err: &google_cloud_gax::error::Error) -> bool {
    gax_status(err) == Some(404)
}

/// Recovers the doc id from an unprefixed store key (`<docId>/data.ysweet`).
fn doc_id_from_key(key: &str) -> Option<&str> {
    key.strip_suffix(DOC_KEY_SUFFIX)
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

fn wrapped_key_of(object: &Object) -> Option<&str> {
    object
        .metadata
        .get(META_WRAPPED_KEY)
        .map(String::as_str)
        .filter(|w| !w.is_empty())
}

fn aes_key(key: &[u8; 32]) -> Result<KeyAes256> {
    KeyAes256::new(key).map_err(|_| StoreError::ConnectionError("invalid CSEK length".to_string()))
}

fn encryption_error(op: &str, doc_id: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::ConnectionError(format!("{} for doc {}: {}", op, doc_id, err))
}

#[derive(Clone, Default)]
pub struct GcsOptions {
    /// Overrides the JSON API endpoint for object reads and writes
    /// (e.g. the CSEK enforcement proxy).
    pub endpoint: Option<String>,
    /// Overrides the gRPC endpoint for metadata and deletes.
    pub control_endpoint: Option<String>,
    /// When set, every doc is encrypted with a per-doc CSEK.
    pub key_provider: Option<Arc<StorageKeyProvider>>,
}

struct Encryption {
    provider: Arc<StorageKeyProvider>,
    /// `doc_id -> key`. Only holds keys for objects that are (or are about to
    /// be) written encrypted; never for an unencrypted object.
    keys: Cache<String, DocKey>,
}

pub struct GcsStore {
    storage: Storage,
    control: StorageControl,
    bucket: String,
    prefix: Option<String>,
    bucket_checked: OnceLock<()>,
    encryption: Option<Encryption>,
}

impl GcsStore {
    pub async fn new(bucket: String, prefix: Option<String>) -> anyhow::Result<Self> {
        Self::with_options(bucket, prefix, GcsOptions::default()).await
    }

    pub async fn with_options(
        bucket: String,
        prefix: Option<String>,
        options: GcsOptions,
    ) -> anyhow::Result<Self> {
        let mut storage = Storage::builder();
        let mut control = StorageControl::builder();
        if let Some(endpoint) = &options.endpoint {
            storage = storage.with_endpoint(endpoint);
        }
        if let Some(endpoint) = &options.control_endpoint {
            control = control.with_endpoint(endpoint);
        }
        let encryption = options.key_provider.map(|provider| Encryption {
            provider,
            keys: Cache::builder()
                .max_capacity(KEY_CACHE_MAX_ENTRIES)
                .time_to_idle(KEY_CACHE_IDLE)
                .build(),
        });
        Ok(GcsStore {
            storage: storage.build().await?,
            control: control.build().await?,
            bucket,
            prefix,
            bucket_checked: OnceLock::new(),
            encryption,
        })
    }

    /// Fetches object metadata only; needs no CSEK. `None` if absent.
    async fn object_metadata(&self, object_key: &str) -> Result<Option<Object>> {
        match self
            .control
            .get_object()
            .set_bucket(bucket_resource(&self.bucket))
            .set_object(object_key)
            .send()
            .await
        {
            Ok(object) => Ok(Some(object)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(map_gax_error("get_object", e)),
        }
    }

    async fn read_all(
        &self,
        object_key: &str,
        key: Option<KeyAes256>,
        generation: Option<i64>,
    ) -> Result<Option<Vec<u8>>> {
        let mut req = self
            .storage
            .read_object(bucket_resource(&self.bucket), object_key);
        if let Some(key) = key {
            req = req.set_key(key);
        }
        if let Some(generation) = generation {
            req = req.set_generation(generation);
        }
        let mut resp = match req.send().await {
            Ok(resp) => resp,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(map_gax_error("read_object", e)),
        };
        let mut contents = Vec::new();
        while let Some(chunk) = resp
            .next()
            .await
            .transpose()
            .map_err(|e| StoreError::ConnectionError(format!("read_object body: {}", e)))?
        {
            contents.extend_from_slice(&chunk);
        }
        Ok(Some(contents))
    }

    async fn get_encrypted(
        &self,
        enc: &Encryption,
        key: &str,
        object_key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(object) = self.object_metadata(object_key).await? else {
            return Ok(None);
        };
        let Some(wrapped_key) = wrapped_key_of(&object) else {
            // Legacy unencrypted doc: read as-is. It gets a new key, and is
            // rewritten encrypted, on its first write.
            return self
                .read_all(object_key, None, Some(object.generation))
                .await;
        };
        let doc_id = doc_id_from_key(key).ok_or_else(|| {
            StoreError::ConnectionError(format!("cannot derive doc id from key {}", key))
        })?;
        let doc_key = self.unwrap_key(enc, doc_id, wrapped_key).await?;
        let aes = aes_key(&doc_key.key)?;
        enc.keys.insert(doc_id.to_string(), doc_key).await;
        self.read_all(object_key, Some(aes), Some(object.generation))
            .await
    }

    async fn unwrap_key(
        &self,
        enc: &Encryption,
        doc_id: &str,
        wrapped_key: &str,
    ) -> Result<DocKey> {
        let key = enc
            .provider
            .unwrap(doc_id, wrapped_key)
            .await
            .map_err(|e| encryption_error("unwrap storage key", doc_id, e))?;
        Ok(DocKey {
            key,
            wrapped_key: wrapped_key.to_string(),
        })
    }

    /// Returns the key to write `doc_id` with: the cached one, else the one
    /// already on the object, else a newly generated one. Errors rather than
    /// ever falling back to an unencrypted write.
    async fn key_for_write(
        &self,
        enc: &Encryption,
        doc_id: &str,
        object_key: &str,
    ) -> Result<DocKey> {
        if let Some(doc_key) = enc.keys.get(doc_id).await {
            return Ok(doc_key);
        }
        let existing = self.object_metadata(object_key).await?;
        let doc_key = match existing.as_ref().and_then(wrapped_key_of) {
            Some(wrapped_key) => self.unwrap_key(enc, doc_id, wrapped_key).await?,
            None => enc
                .provider
                .generate(doc_id)
                .await
                .map_err(|e| encryption_error("generate storage key", doc_id, e))?,
        };
        enc.keys.insert(doc_id.to_string(), doc_key.clone()).await;
        Ok(doc_key)
    }

    async fn init_inner(&self) -> Result<()> {
        if self.bucket_checked.get().is_some() {
            return Ok(());
        }
        match self
            .control
            .get_bucket()
            .set_name(bucket_resource(&self.bucket))
            .send()
            .await
        {
            Ok(_) => {
                let _ = self.bucket_checked.set(());
                Ok(())
            }
            Err(e) if is_not_found(&e) => Err(StoreError::BucketDoesNotExist(format!(
                "Bucket {} does not exist.",
                self.bucket
            ))),
            Err(e) => Err(map_gax_error("get_bucket", e)),
        }
    }
}

#[async_trait]
impl Store for GcsStore {
    async fn init(&self) -> Result<()> {
        self.init_inner().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.init_inner().await?;
        let object_key = prefixed_key(&self.prefix, key);
        match &self.encryption {
            Some(enc) => self.get_encrypted(enc, key, &object_key).await,
            None => self.read_all(&object_key, None, None).await,
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.init_inner().await?;
        let object_key = prefixed_key(&self.prefix, key);
        let write = self.storage.write_object(
            bucket_resource(&self.bucket),
            &object_key,
            bytes::Bytes::from(value),
        );
        let write = match &self.encryption {
            Some(enc) => {
                let doc_id = doc_id_from_key(key).ok_or_else(|| {
                    StoreError::ConnectionError(format!(
                        "refusing unencrypted write: cannot derive doc id from key {}",
                        key
                    ))
                })?;
                let doc_key = self.key_for_write(enc, doc_id, &object_key).await?;
                write.set_key(aes_key(&doc_key.key)?).set_metadata([
                    (META_ENC_VERSION, ENC_VERSION.to_string()),
                    (META_WRAPPED_KEY, doc_key.wrapped_key),
                ])
            }
            None => write,
        };
        write
            .send_buffered()
            .await
            .map_err(|e| map_gax_error("write_object", e))?;
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.init_inner().await?;
        if let (Some(enc), Some(doc_id)) = (&self.encryption, doc_id_from_key(key)) {
            enc.keys.invalidate(doc_id).await;
        }
        let key = prefixed_key(&self.prefix, key);
        match self
            .control
            .delete_object()
            .set_bucket(bucket_resource(&self.bucket))
            .set_object(&key)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(map_gax_error("delete_object", e)),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.init_inner().await?;
        let key = prefixed_key(&self.prefix, key);
        Ok(self.object_metadata(&key).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_resource_name_format() {
        assert_eq!(bucket_resource("my-bucket"), "projects/_/buckets/my-bucket");
    }

    #[test]
    fn prefixed_key_joins_with_slash() {
        assert_eq!(
            prefixed_key(&Some("pre".to_string()), "doc.ysweet"),
            "pre/doc.ysweet"
        );
        assert_eq!(prefixed_key(&None, "doc.ysweet"), "doc.ysweet");
    }

    #[test]
    fn doc_id_is_recovered_from_store_key() {
        assert_eq!(
            doc_id_from_key("canvas-123/data.ysweet"),
            Some("canvas-123")
        );
        assert_eq!(doc_id_from_key("data.ysweet"), None);
        assert_eq!(doc_id_from_key("/data.ysweet"), None);
        assert_eq!(doc_id_from_key("a/b/data.ysweet"), None);
        assert_eq!(doc_id_from_key("canvas-123/other"), None);
    }

    #[test]
    fn wrapped_key_read_from_metadata() {
        let object = Object::new().set_metadata([(META_WRAPPED_KEY, "ENC:v1|dek|abc")]);
        assert_eq!(wrapped_key_of(&object), Some("ENC:v1|dek|abc"));

        let empty = Object::new().set_metadata([(META_WRAPPED_KEY, "")]);
        assert_eq!(wrapped_key_of(&empty), None);

        let plain = Object::new().set_metadata([(META_ENC_VERSION, ENC_VERSION)]);
        assert_eq!(wrapped_key_of(&plain), None);
    }

    #[tokio::test]
    async fn key_cache_is_bounded_and_invalidates() {
        let cache: Cache<String, DocKey> = Cache::builder().max_capacity(2).build();
        let k = |w: &str| DocKey {
            key: [1u8; 32],
            wrapped_key: w.to_string(),
        };
        cache.insert("a".into(), k("wa")).await;
        assert_eq!(cache.get("a").await.unwrap().wrapped_key, "wa");
        cache.invalidate("a").await;
        assert!(cache.get("a").await.is_none());

        for i in 0..10 {
            cache.insert(i.to_string(), k("w")).await;
        }
        cache.run_pending_tasks().await;
        assert!(cache.entry_count() <= 2);
    }
}
