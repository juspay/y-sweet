use crate::metrics::Metrics;
use crate::ws_crypto::{self, FrameCipher, Grant, WsGrantKey};
use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        DefaultBodyLimit, Extension, Path, Query, Request, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, HeaderName},
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::typed_header::TypedHeader;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::{mapref::one::MappedRef, DashMap};
use futures::{SinkExt, StreamExt};
use moka::{future::Cache, policy::EvictionPolicy};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc::{channel, Receiver},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{span, Instrument, Level};
use url::Url;
use y_sweet_core::{
    api_types::{
        validate_doc_name, AuthDocRequest, Authorization, ClientToken, DocCreationRequest,
        NewDocResponse,
    },
    auth::{Authenticator, ExpirationTimeEpochMillis, DEFAULT_EXPIRATION_SECONDS},
    doc_connection::DocConnection,
    doc_sync::DocWithSyncKv,
    store::Store,
    sync::awareness::Awareness,
    sync_kv::SyncKv,
};

const PLANE_VERIFIED_USER_DATA_HEADER: &str = "x-verified-user-data";

// Every 20 seconds, we send a ping to the client.
const PING_EVERY: Duration = Duration::from_secs(20);
// If we haven't received a pong in the last 40 seconds, we close the connection.
// All modern browsers will respond to websocket pings with a pong message.
const PONG_TIMEOUT: Duration = Duration::from_secs(40);

// Defaults for the periodic mid-session access re-check; overridable via
// Server::new (see main.rs's Y_SWEET_VALIDATE_* CLI/env options).
pub const DEFAULT_VALIDATE_POLL_EVERY: Duration = Duration::from_secs(10);
pub const DEFAULT_VALIDATE_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_VALIDATE_RETRY_DELAY: Duration = Duration::from_millis(500);

const CONNECT_VALIDATE_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(500),
    Duration::from_secs(1),
];

// `~` is outside the base64url and key-id alphabets, so a signed token never starts with this.
const TICKET_PREFIX: &str = "tkt~";
const TICKET_TTL: Duration = Duration::from_secs(30);
const TICKET_MAX_CAPACITY: u64 = 100_000;

// Covers a grant's whole life: it expires 30 s after the encryption service mints it.
// In memory, so it holds for one replica only.
const GRANT_MEMORY: Duration = Duration::from_secs(60);
const GRANT_LIFETIME_MS: u64 = 30_000;

#[derive(Clone)]
struct Ticket {
    doc_id: String,
    user_id: String,
    authorization: Authorization,
    // moka's `remove` still returns entries past their TTL until they are evicted.
    expires_at: std::time::Instant,
    grant: Option<Grant>,
}

#[derive(Clone)]
struct VerifiedIdentity(Authorization, Option<String>, Option<Grant>);

enum SocketCrypto {
    Plain,
    Encrypted(Grant),
}

fn current_time_epoch_millis() -> u64 {
    let now = std::time::SystemTime::now();
    let duration_since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    duration_since_epoch.as_millis() as u64
}

#[derive(Debug)]
pub struct AppError(StatusCode, anyhow::Error);
impl std::error::Error for AppError {}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("Something went wrong: {}", self.1)).into_response()
    }
}
impl<E> From<(StatusCode, E)> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from((status_code, err): (StatusCode, E)) -> Self {
        Self(status_code, err.into())
    }
}
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status code: {} {}", self.0, self.1)?;
        Ok(())
    }
}

fn normalize_path_prefix(prefix: String) -> String {
    let trimmed = prefix.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub struct Server {
    docs: Arc<DashMap<String, DocWithSyncKv>>,
    doc_worker_tracker: TaskTracker,
    store: Option<Arc<Box<dyn Store>>>,
    checkpoint_freq: Duration,
    authenticator: Option<Authenticator>,
    url_prefix: Option<Url>,
    path_prefix: Option<String>,
    cancellation_token: CancellationToken,
    /// Whether to garbage collect docs that are no longer in use.
    /// Disabled for single-doc mode, since we only have one doc.
    doc_gc: bool,
    max_body_size: Option<usize>,
    /// Whether to skip garbage collection in Yrs documents.
    skip_gc: bool,
    metrics: Metrics,
    backend_url: Option<String>,
    /// Shared secret sent as `Authorization: Bearer <token>` on every call to
    /// the backend's `/api/ysweet/validate`, so the backend can confirm the
    /// caller is actually y-sweet and not just anyone hitting that route.
    server_token: Option<String>,
    http_client: reqwest::Client,
    validate_poll_every: Duration,
    validate_retry_attempts: u32,
    validate_retry_delay: Duration,
    tickets: Cache<String, Ticket>,
    ws_grant_key: Option<WsGrantKey>,
    /// SHA-256 of every wsKey turned into a ticket, so one socket key never serves two sockets.
    seen_grants: Cache<[u8; 32], ()>,
    revoked_sids: Cache<String, ()>,
    sessions: DashMap<String, Vec<(u64, CancellationToken)>>,
    next_conn_id: std::sync::atomic::AtomicU64,
    /// Grants minted before this were not in `seen_grants`, so they may already be used.
    started_ms: u64,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        store: Option<Box<dyn Store>>,
        checkpoint_freq: Duration,
        authenticator: Option<Authenticator>,
        url_prefix: Option<Url>,
        path_prefix: Option<String>,
        cancellation_token: CancellationToken,
        doc_gc: bool,
        max_body_size: Option<usize>,
        skip_gc: bool,
        backend_url: Option<String>,
        server_token: Option<String>,
        validate_poll_every: Duration,
        validate_retry_attempts: u32,
        validate_retry_delay: Duration,
    ) -> Result<Self> {
        let docs = Arc::new(DashMap::new());
        let metrics = Metrics::new(docs.clone());
        if backend_url.is_none() {
            tracing::warn!(
                "Y_SWEET_BACKEND_URL is not set. All access-validated requests will be denied."
            );
        }
        if backend_url.is_some() && server_token.is_none() {
            tracing::warn!(
                "Y_SWEET_SERVER_TOKEN is not set. Calls to the backend's validate endpoint will be unauthenticated."
            );
        }
        Ok(Self {
            docs,
            doc_worker_tracker: TaskTracker::new(),
            store: store.map(Arc::new),
            checkpoint_freq,
            authenticator,
            url_prefix,
            path_prefix: path_prefix
                .map(normalize_path_prefix)
                .filter(|p| !p.is_empty()),
            cancellation_token,
            doc_gc,
            max_body_size,
            skip_gc,
            metrics,
            backend_url,
            server_token,
            http_client: reqwest::Client::new(),
            validate_poll_every,
            validate_retry_attempts,
            validate_retry_delay,
            // moka's default TinyLFU can refuse a new insert when full, so the ticket we hand out
            // would not exist. LRU always stores it and evicts the oldest instead.
            tickets: Cache::builder()
                .time_to_live(TICKET_TTL)
                .max_capacity(TICKET_MAX_CAPACITY)
                .eviction_policy(EvictionPolicy::lru())
                .build(),
            ws_grant_key: None,
            seen_grants: Cache::builder()
                .time_to_live(GRANT_MEMORY)
                .eviction_policy(EvictionPolicy::lru())
                .build(),
            revoked_sids: Cache::builder()
                .time_to_live(GRANT_MEMORY)
                .eviction_policy(EvictionPolicy::lru())
                .build(),
            sessions: DashMap::new(),
            next_conn_id: Default::default(),
            started_ms: current_time_epoch_millis(),
        })
    }

    /// With a key, every socket must use a ticket that carries a socket key.
    pub fn with_ws_encryption(mut self, ws_grant_key: Option<WsGrantKey>) -> Self {
        self.ws_grant_key = ws_grant_key;
        self
    }

    fn socket_crypto(&self, grant: Option<Grant>) -> Result<SocketCrypto, AppError> {
        if self.ws_grant_key.is_none() {
            return Ok(SocketCrypto::Plain);
        }
        match grant {
            Some(g) if !self.revoked_sids.contains_key(&g.sid) => Ok(SocketCrypto::Encrypted(g)),
            Some(_) => Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("Session revoked"),
            )),
            None => Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("WebSocket encryption requires a ticket with a socket key"),
            )),
        }
    }

    /// Checks a wrapped socket key from the backend and marks it used.
    async fn accept_grant(
        &self,
        key: &WsGrantKey,
        w: &str,
        doc_id: &str,
    ) -> Result<Grant, AppError> {
        let bad = |e: anyhow::Error| AppError(StatusCode::BAD_REQUEST, e);
        let grant = key.unwrap_grant(w).map_err(bad)?;
        if grant.doc != doc_id {
            return Err(bad(anyhow!("wsKey is for another doc")));
        }
        if grant.exp <= current_time_epoch_millis() {
            return Err(bad(anyhow!("wsKey expired")));
        }
        if grant.exp.saturating_sub(GRANT_LIFETIME_MS) < self.started_ms {
            return Err(bad(anyhow!("wsKey minted before this server started")));
        }
        if self.revoked_sids.contains_key(&grant.sid) {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("Session revoked"),
            ));
        }
        let hash: [u8; 32] = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, w.as_bytes())
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes");
        if !self.seen_grants.entry(hash).or_insert(()).await.is_fresh() {
            return Err(bad(anyhow!("wsKey already used")));
        }
        Ok(grant)
    }

    async fn close_sessions(&self, sids: &[String]) {
        for sid in sids {
            self.revoked_sids.insert(sid.clone(), ()).await;
            if let Some((_, conns)) = self.sessions.remove(sid) {
                conns.iter().for_each(|(_, cancel)| cancel.cancel());
            }
        }
    }

    /// Calls the Xyne backend to check whether `user_id` currently has the
    /// given `authorization` level of access to `doc_id` — full (edit) or
    /// read-only — so a user downgraded from editor to viewer gets caught
    /// here even though they still technically have *some* access. Fails
    /// closed (denies) if the backend is unconfigured, unreachable, or
    /// returns a non-2xx response.
    async fn validate_user_access(
        &self,
        doc_id: &str,
        user_id: &str,
        authorization: &Authorization,
    ) -> bool {
        let Some(backend_url) = &self.backend_url else {
            return false;
        };
        let url = format!("{}/api/ysweet/validate", backend_url.trim_end_matches('/'));
        let mut req = self.http_client.post(&url).json(&serde_json::json!({
            "docId": doc_id,
            "userId": user_id,
            "authorization": authorization,
        }));
        if let Some(token) = &self.server_token {
            req = req.bearer_auth(token);
        }
        match req.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                tracing::error!(?e, doc_id = %doc_id, user_id = %user_id, "Failed to reach backend for access validation");
                false
            }
        }
    }

    /// Like `validate_user_access`, but retries transient failures (network
    /// errors, backend hiccups) up to `VALIDATE_RETRY_ATTEMPTS` times before
    /// treating the check as a real denial. Used by the periodic mid-session
    /// poll, where a brief backend blip shouldn't kick an otherwise-valid user.
    async fn validate_user_access_with_retry(
        &self,
        doc_id: &str,
        user_id: &str,
        authorization: &Authorization,
    ) -> bool {
        for attempt in 1..=self.validate_retry_attempts {
            if self
                .validate_user_access(doc_id, user_id, authorization)
                .await
            {
                return true;
            }
            if attempt < self.validate_retry_attempts {
                tokio::time::sleep(self.validate_retry_delay).await;
            }
        }
        false
    }

    /// Like `validate_user_access`, but used for the connect-time check
    /// (WS upgrade, as-update, etc). Retries on a fixed backoff schedule to
    /// ride out read-replica lag right after a canvas is created or a
    /// participant is added, since that check only gets one shot before the
    /// connection is refused.
    async fn validate_user_access_with_connect_retry(
        &self,
        doc_id: &str,
        user_id: &str,
        authorization: &Authorization,
    ) -> bool {
        if self
            .validate_user_access(doc_id, user_id, authorization)
            .await
        {
            return true;
        }
        for delay in CONNECT_VALIDATE_RETRY_DELAYS {
            tokio::time::sleep(delay).await;
            if self
                .validate_user_access(doc_id, user_id, authorization)
                .await
            {
                return true;
            }
        }
        false
    }

    pub async fn doc_exists(&self, doc_id: &str) -> bool {
        if self.docs.contains_key(doc_id) {
            return true;
        }
        if let Some(store) = &self.store {
            store
                .exists(&format!("{}/data.ysweet", doc_id))
                .await
                .unwrap_or_default()
        } else {
            false
        }
    }

    pub async fn create_doc(&self) -> Result<String> {
        let doc_id = nanoid::nanoid!();
        self.load_doc(&doc_id).await?;
        tracing::info!(doc_id=%doc_id, "Created doc");
        Ok(doc_id)
    }

    pub async fn load_doc(&self, doc_id: &str) -> Result<()> {
        let (send, recv) = channel(1024);

        let dwskv = DocWithSyncKv::new(
            doc_id,
            self.store.clone(),
            move || {
                send.try_send(()).unwrap();
            },
            self.skip_gc,
        )
        .await?;

        dwskv
            .sync_kv()
            .persist()
            .await
            .map_err(|e| anyhow!("Error persisting: {:?}", e))?;

        {
            let sync_kv = dwskv.sync_kv();
            let checkpoint_freq = self.checkpoint_freq;
            let doc_id = doc_id.to_string();
            let cancellation_token = self.cancellation_token.clone();

            let metrics = self.metrics.clone();

            // Spawn a task to save the document to the store when it changes.
            self.doc_worker_tracker.spawn(
                Self::doc_persistence_worker(
                    recv,
                    sync_kv,
                    checkpoint_freq,
                    doc_id.clone(),
                    cancellation_token.clone(),
                    metrics.clone(),
                )
                .instrument(span!(Level::INFO, "save_loop", doc_id=%doc_id)),
            );

            if self.doc_gc {
                self.doc_worker_tracker.spawn(
                    Self::doc_gc_worker(
                        self.docs.clone(),
                        doc_id.clone(),
                        checkpoint_freq,
                        cancellation_token,
                        metrics,
                    )
                    .instrument(span!(Level::INFO, "gc_loop", doc_id=%doc_id)),
                );
            }
        }

        self.docs.insert(doc_id.to_string(), dwskv);
        Ok(())
    }

    async fn doc_gc_worker(
        docs: Arc<DashMap<String, DocWithSyncKv>>,
        doc_id: String,
        checkpoint_freq: Duration,
        cancellation_token: CancellationToken,
        metrics: Metrics,
    ) {
        let mut checkpoints_without_refs = 0;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(checkpoint_freq) => {
                    if let Some(doc) = docs.get(&doc_id) {
                        let awareness = Arc::downgrade(&doc.awareness());
                        if awareness.strong_count() > 1 {
                            checkpoints_without_refs = 0;
                            tracing::debug!("doc is still alive - it has {} references", awareness.strong_count());
                        } else {
                            checkpoints_without_refs += 1;
                            tracing::info!("doc has only one reference, candidate for GC. checkpoints_without_refs: {}", checkpoints_without_refs);
                        }
                    } else {
                        break;
                    }

                    if checkpoints_without_refs >= 2 {
                        tracing::info!("GCing doc");
                        if let Some(doc) = docs.get(&doc_id) {
                            doc.sync_kv().shutdown();
                        }

                        docs.remove(&doc_id);
                        metrics.documents_gc.add(1, &[]);
                        break;
                    }
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            };
        }
        tracing::info!("Exiting gc_loop");
    }

    async fn doc_persistence_worker(
        mut recv: Receiver<()>,
        sync_kv: Arc<SyncKv>,
        checkpoint_freq: Duration,
        doc_id: String,
        cancellation_token: CancellationToken,
        metrics: Metrics,
    ) {
        let mut last_save = std::time::Instant::now();

        loop {
            let is_done = tokio::select! {
                v = recv.recv() => v.is_none(),
                _ = cancellation_token.cancelled() => true,
                _ = tokio::time::sleep(checkpoint_freq) => {
                    sync_kv.is_shutdown()
                }
            };

            tracing::info!("Received signal. done: {}", is_done);
            let now = std::time::Instant::now();
            if !is_done && now - last_save < checkpoint_freq {
                let sleep = tokio::time::sleep(checkpoint_freq - (now - last_save));
                tokio::pin!(sleep);
                tracing::info!("Throttling.");

                loop {
                    tokio::select! {
                        _ = &mut sleep => {
                            break;
                        }
                        v = recv.recv() => {
                            tracing::info!("Received dirty while throttling.");
                            if v.is_none() {
                                break;
                            }
                        }
                        _ = cancellation_token.cancelled() => {
                            tracing::info!("Received cancellation while throttling.");
                            break;
                        }

                    }
                    tracing::info!("Done throttling.");
                }
            }
            tracing::info!("Persisting.");
            let persist_start = std::time::Instant::now();
            if let Err(e) = sync_kv.persist().await {
                tracing::error!(doc_id = %doc_id, ?e, "Error persisting.");
                metrics.persistence_errors.add(1, &[]);
            } else {
                let elapsed_ms = persist_start.elapsed().as_secs_f64() * 1000.0;
                metrics.persistence_latency_ms.record(elapsed_ms, &[]);
                metrics.persistence_ops.add(1, &[]);
                tracing::info!("Done persisting.");
            }
            last_save = std::time::Instant::now();

            if is_done {
                break;
            }
        }
        tracing::info!("Terminating loop for {}", doc_id);
    }

    pub async fn get_or_create_doc(
        &self,
        doc_id: &str,
    ) -> Result<MappedRef<'_, String, DocWithSyncKv, DocWithSyncKv>> {
        if !self.docs.contains_key(doc_id) {
            tracing::info!(doc_id=%doc_id, "Loading doc");
            self.load_doc(doc_id).await?;
            self.metrics.documents_loaded.add(1, &[]);
        }

        Ok(self
            .docs
            .get(doc_id)
            .ok_or_else(|| anyhow!("Failed to get-or-create doc"))?
            .map(|d| d))
    }

    pub fn check_auth(
        &self,
        auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    ) -> Result<(), AppError> {
        if let Some(auth) = &self.authenticator {
            if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
                if let Ok(()) =
                    auth.verify_server_token(bearer.token(), current_time_epoch_millis())
                {
                    return Ok(());
                }
            }
            Err((StatusCode::UNAUTHORIZED, anyhow!("Unauthorized.")))?
        } else {
            Ok(())
        }
    }

    pub async fn redact_error_middleware(req: Request, next: Next) -> impl IntoResponse {
        let resp = next.run(req).await;
        if resp.status().is_server_error() || resp.status().is_client_error() {
            // If we should redact errors, copy over only the status code and
            // not the response body.
            return resp.status().into_response();
        }
        resp
    }

    pub fn routes(self: &Arc<Self>) -> Router {
        let protected = Router::new()
            .route("/doc/ws/:doc_id", get(handle_socket_upgrade_deprecated))
            .route("/doc/:doc_id/as-update", get(get_doc_as_update_deprecated))
            .route("/doc/:doc_id/update", post(update_doc_deprecated))
            .route("/d/:doc_id/as-update", get(get_doc_as_update))
            .route("/d/:doc_id/update", post(update_doc))
            .route(
                "/d/:doc_id/ws/:doc_id2",
                get(handle_socket_upgrade_full_path),
            )
            .route_layer(middleware::from_fn_with_state(
                self.clone(),
                validate_user_middleware,
            ));

        Router::new()
            .route("/ready", get(ready))
            .route("/check_store", post(check_store))
            .route("/check_store", get(check_store_deprecated))
            .route("/doc/new", post(new_doc))
            .route("/doc/:doc_id/auth", post(auth_doc))
            .route("/internal/close-sessions", post(close_sessions))
            .merge(protected)
            .with_state(self.clone())
    }

    pub fn single_doc_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ws/:doc_id", get(handle_socket_upgrade_single))
            .route("/as-update", get(get_doc_as_update_single))
            .route("/update", post(update_doc_single))
            .with_state(self.clone())
    }

    async fn serve_internal(
        self: Arc<Self>,
        listener: TcpListener,
        redact_errors: bool,
        routes: Router,
    ) -> Result<()> {
        let token = self.cancellation_token.clone();

        let mut app = if let Some(max_body_size) = self.max_body_size {
            routes.layer(DefaultBodyLimit::max(max_body_size))
        } else {
            routes
        };

        app = if redact_errors {
            app
        } else {
            app.layer(middleware::from_fn(Self::redact_error_middleware))
        };

        if let Some(path_prefix) = &self.path_prefix {
            app = app.clone().nest(path_prefix, app);
        }

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await?;

        self.doc_worker_tracker.close();
        self.doc_worker_tracker.wait().await;

        Ok(())
    }

    pub async fn serve(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    pub async fn serve_doc(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.single_doc_routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    fn verify_doc_token(
        &self,
        token: Option<&str>,
        doc: &str,
    ) -> Result<(Authorization, Option<String>), AppError> {
        if let Some(authenticator) = &self.authenticator {
            if let Some(token) = token {
                let claims = authenticator
                    .verify_doc_token(token, doc, current_time_epoch_millis())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
                Ok((claims.authorization, claims.user_id))
            } else {
                Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
            }
        } else {
            Ok((Authorization::Full, None))
        }
    }

    async fn issue_ticket(
        &self,
        doc_id: &str,
        user_id: String,
        authorization: Authorization,
        grant: Option<Grant>,
    ) -> Result<String> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)?;
        let ticket = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        self.tickets
            .insert(
                ticket.clone(),
                Ticket {
                    doc_id: doc_id.to_string(),
                    user_id,
                    authorization,
                    expires_at: std::time::Instant::now() + TICKET_TTL,
                    grant,
                },
            )
            .await;
        Ok(ticket)
    }

    /// Resolves a signed token or a single-use ticket. Tickets are only valid for WebSocket upgrades.
    async fn verify_token_or_ticket(
        &self,
        token: &str,
        doc_id: &str,
        websocket: bool,
    ) -> Result<(Authorization, Option<String>, Option<Grant>), AppError> {
        if !token.starts_with(TICKET_PREFIX) {
            // In both modes: a socket needs a ticket, a signed token is for the backend's HTTP calls.
            if websocket {
                return Err(AppError(
                    StatusCode::UNAUTHORIZED,
                    anyhow!("WebSocket connections need a ticket"),
                ));
            }
            let (authorization, user_id) = self.verify_doc_token(Some(token), doc_id)?;
            return Ok((authorization, user_id, None));
        }
        if !websocket {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("Tickets are only valid for WebSocket connections"),
            ));
        }
        match self.tickets.remove(token).await {
            Some(t) if t.doc_id == doc_id && std::time::Instant::now() < t.expires_at => {
                Ok((t.authorization, Some(t.user_id), t.grant))
            }
            _ => Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("Invalid or used ticket"),
            )),
        }
    }

    fn get_single_doc_id(&self) -> Result<String, AppError> {
        self.docs
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, anyhow!("No document found")))
    }
}

#[derive(Deserialize)]
struct HandlerParams {
    token: Option<String>,
}

async fn get_doc_as_update(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    // All authorization types allow reading the document.
    let token = get_token_from_header(auth_header);
    let _ = server_state.verify_doc_token(token.as_deref(), &doc_id)?;

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let update = dwskv.as_update();
    tracing::debug!("update: {:?}", update);
    Ok(update.into_response())
}

async fn get_doc_as_update_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/as-update is deprecated; call /doc/:doc_id/auth instead and then call as-update on the returned base URL.");
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/update is deprecated; call /doc/:doc_id/auth instead and then call update on the returned base URL.");
    update_doc(Path(doc_id), State(server_state), auth_header, body).await
}

async fn get_doc_as_update_single(
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    let token = get_token_from_header(auth_header);
    let (authorization, _user_id) = server_state.verify_doc_token(token.as_deref(), &doc_id)?;
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn update_doc_inner(
    doc_id: String,
    server_state: Arc<Server>,
    authorization: Authorization,
    body: Bytes,
) -> Result<Response, AppError> {
    if !matches!(authorization, Authorization::Full) {
        return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Unauthorized.")));
    }

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let start = std::time::Instant::now();
    if let Err(err) = dwskv.apply_update(&body) {
        tracing::error!(doc_id = %doc_id, ?err, "Failed to apply update");
        return Err(AppError(StatusCode::INTERNAL_SERVER_ERROR, err));
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    server_state.metrics.http_latency_ms.record(elapsed_ms, &[]);
    server_state.metrics.http_updates.add(1, &[]);

    Ok(StatusCode::OK.into_response())
}

async fn update_doc_single(
    State(server_state): State<Arc<Server>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization.
    let authorization = get_authorization_from_plane_header(headers)?;
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn handle_socket_upgrade(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    authorization: Authorization,
    user_id: Option<String>,
    crypto: SocketCrypto,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    // Read-only clients may open a stored doc that is not loaded yet, but never create one.
    if !matches!(authorization, Authorization::Full) && !server_state.doc_exists(&doc_id).await {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Doc {} not found", doc_id),
        ));
    }

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let awareness = dwskv.awareness();
    let cancellation_token = server_state.cancellation_token.clone();
    let metrics = server_state.metrics.clone();
    let server_state_for_socket = server_state.clone();

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            awareness,
            authorization,
            user_id,
            cancellation_token,
            metrics,
            doc_id,
            server_state_for_socket,
            crypto,
        )
    }))
}

async fn handle_socket_upgrade_deprecated(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    tracing::warn!(
        "/doc/ws/:doc_id is deprecated; call /doc/:doc_id/auth instead and use the returned URL."
    );
    // This route takes no ticket, and signed tokens no longer open sockets.
    if server_state.authenticator.is_some() {
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("WebSocket connections need a ticket"),
        ));
    }
    let (authorization, user_id) =
        server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
    let crypto = server_state.socket_crypto(None)?;
    handle_socket_upgrade(
        ws,
        Path(doc_id),
        authorization,
        user_id,
        crypto,
        State(server_state),
    )
    .await
}

async fn handle_socket_upgrade_full_path(
    ws: WebSocketUpgrade,
    Path((doc_id, doc_id2)): Path<(String, String)>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
    identity: Option<Extension<VerifiedIdentity>>,
) -> Result<Response, AppError> {
    if doc_id != doc_id2 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            anyhow!("For Yjs compatibility, the doc_id appears twice in the URL. It must be the same in both places, but we got {} and {}.", doc_id, doc_id2),
        ));
    }
    // A ticket is gone once the middleware consumes it, so reuse the middleware's result.
    let (authorization, user_id, grant) = match identity {
        Some(Extension(VerifiedIdentity(authorization, user_id, grant))) => {
            (authorization, user_id, grant)
        }
        None => {
            let (authorization, user_id) =
                server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
            (authorization, user_id, None)
        }
    };
    let crypto = server_state.socket_crypto(grant)?;
    handle_socket_upgrade(
        ws,
        Path(doc_id),
        authorization,
        user_id,
        crypto,
        State(server_state),
    )
    .await
}

async fn handle_socket_upgrade_single(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    headers: HeaderMap,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    let single_doc_id = server_state.get_single_doc_id()?;
    if doc_id != single_doc_id {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Document not found"),
        ));
    }

    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization. Plane mode carries no userId claim,
    // so the periodic mid-session poll never runs for these connections.
    let authorization = get_authorization_from_plane_header(headers)?;
    let crypto = server_state.socket_crypto(None)?;
    handle_socket_upgrade(
        ws,
        Path(single_doc_id),
        authorization,
        None,
        crypto,
        State(server_state),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_socket(
    socket: WebSocket,
    awareness: Arc<RwLock<Awareness>>,
    authorization: Authorization,
    user_id: Option<String>,
    cancellation_token: CancellationToken,
    metrics: Metrics,
    doc_id: String,
    server_state: Arc<Server>,
    crypto: SocketCrypto,
) {
    let conn_cancel = CancellationToken::new();
    let (mut sealer, mut opener, mut session) = (None::<FrameCipher>, None::<FrameCipher>, None);
    if let SocketCrypto::Encrypted(grant) = crypto {
        sealer =
            Some(FrameCipher::new(&grant.key, ws_crypto::SERVER_TO_CLIENT).expect("32-byte key"));
        opener =
            Some(FrameCipher::new(&grant.key, ws_crypto::CLIENT_TO_SERVER).expect("32-byte key"));
        let conn_id = server_state
            .next_conn_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        server_state
            .sessions
            .entry(grant.sid.clone())
            .or_default()
            .push((conn_id, conn_cancel.clone()));
        // A revoke between the upgrade check and the insert above would otherwise miss this socket.
        if server_state.revoked_sids.contains_key(&grant.sid) {
            conn_cancel.cancel();
        }
        session = Some((grant.sid, conn_id));
    }

    metrics.active_connections.add(1, &[]);
    let (mut sink, mut stream) = socket.split();
    let (send, mut recv) = channel::<Vec<u8>>(1024);

    let last_pong = Arc::new(RwLock::new(tokio::time::Instant::now()));
    let last_pong_clone = last_pong.clone();
    let pong_metrics = metrics.clone();
    let pong_doc_id = doc_id.clone();
    let conn_cancel_ping = conn_cancel.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_ping_sent: Option<tokio::time::Instant> = None;

        loop {
            tokio::select! {
                msg = recv.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    let msg = match &mut sealer {
                        Some(sealer) => sealer.seal(&msg),
                        None => msg,
                    };
                    let _ = sink.send(Message::Binary(msg)).await;
                }
                _ = ticker.tick() => {
                    let pong_overdue = last_pong_clone.read().expect("Failed to get read lock on last_pong").elapsed() > PONG_TIMEOUT;
                    if pong_overdue && last_ping_sent.is_some_and(|t| t.elapsed() < PONG_TIMEOUT) {
                        tracing::info!(doc_id = %pong_doc_id, "Pong timeout, closing connection");
                        pong_metrics.pong_timeouts.add(1, &[]);
                        let _ = sink.send(Message::Close(None)).await;
                        conn_cancel_ping.cancel();
                        break;
                    }
                    if sink.send(Message::Ping(vec![])).await.is_ok() {
                        last_ping_sent = Some(tokio::time::Instant::now());
                    } else {
                        conn_cancel_ping.cancel();
                        break;
                    }
                }
            }
        }
    });

    // Periodically re-checks with the Xyne backend that this connection's
    // user still has access, so a mid-session permission revocation closes
    // the connection instead of leaving it open until the client reconnects.
    // Only runs when the token carried a userId (i.e. a signing key is
    // configured) — see validate_user_middleware for why that's optional.
    if let Some(user_id) = user_id {
        let server_state_poll = server_state.clone();
        let doc_id_poll = doc_id.clone();
        let conn_cancel_poll = conn_cancel.clone();
        let authorization_poll = authorization.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(server_state_poll.validate_poll_every);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick fires immediately; skip it since access was
            // already checked once by validate_user_middleware at connect time.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if !server_state_poll.validate_user_access_with_retry(&doc_id_poll, &user_id, &authorization_poll).await {
                            tracing::info!(doc_id = %doc_id_poll, user_id = %user_id, "Access revoked mid-session; closing connection");
                            conn_cancel_poll.cancel();
                            break;
                        }
                    }
                    _ = conn_cancel_poll.cancelled() => {
                        break;
                    }
                }
            }
        });
    }

    let connection = DocConnection::new(awareness, authorization, move |bytes| {
        if let Err(e) = send.try_send(bytes.to_vec()) {
            tracing::warn!(?e, "Error sending message");
        }
    });

    loop {
        tokio::select! {
            msg = stream.next() => {
                let Some(msg) = msg else {
                    break;
                };
                let msg = match msg {
                    Ok(Message::Binary(bytes)) => bytes,
                    Ok(Message::Close(_)) => break,
                    Ok(Message::Pong(_)) => {
                        *last_pong.write().expect("Failed to get write lock on last_pong") = tokio::time::Instant::now();
                        continue;
                    }
                    Err(_e) => {
                        tracing::warn!(doc_id = %doc_id, "WebSocket stream error");
                        metrics.websocket_failures.add(1, &[]);
                        break;
                    }
                    _ if opener.is_some() => {
                        tracing::warn!(doc_id = %doc_id, "Non-binary frame on an encrypted socket; closing");
                        break;
                    }
                    _ => {
                        tracing::warn!(doc_id = %doc_id, "Received non-binary message");
                        continue;
                    }
                };
                let msg = match &mut opener {
                    Some(opener) => match opener.open(&msg) {
                        Ok(msg) => msg,
                        Err(e) => {
                            tracing::warn!(doc_id = %doc_id, ?e, "WebSocket frame rejected; closing");
                            break;
                        }
                    },
                    None => msg,
                };

                let start = std::time::Instant::now();
                if let Err(e) = connection.send(&msg).await {
                    tracing::warn!(doc_id = %doc_id, ?e, "Error handling message");
                }
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                metrics.sync_latency_ms.record(elapsed_ms, &[]);
                metrics.sync_updates.add(1, &[]);
            }
            _ = cancellation_token.cancelled() => {
                tracing::debug!(doc_id = %doc_id, "Closing doc connection due to server cancel...");
                break;
            }
            _ = conn_cancel.cancelled() => {
                tracing::debug!(doc_id = %doc_id, "Closing doc connection: pong timeout, access lost or session closed");
                break;
            }
        }
    }

    if let Some((sid, conn_id)) = session {
        server_state.sessions.remove_if_mut(&sid, |_, conns| {
            conns.retain(|(id, _)| *id != conn_id);
            conns.is_empty()
        });
    }
    metrics.active_connections.add(-1, &[]);
}

async fn check_store(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    server_state.check_auth(auth_header)?;

    if server_state.store.is_none() {
        return Ok(Json(json!({"ok": false, "error": "No store set."})));
    };

    // The check_store endpoint for the native server is kind of moot, since
    // the server will not start if store is not ok.
    Ok(Json(json!({"ok": true})))
}

async fn check_store_deprecated(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    tracing::warn!(
        "GET check_store is deprecated, use POST check_store with an empty body instead."
    );
    check_store(auth_header, State(server_state)).await
}

/// Always returns a 200 OK response, as long as we are listening.
async fn ready() -> Result<Json<Value>, AppError> {
    Ok(Json(json!({"ok": true})))
}

async fn new_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
    Json(body): Json<DocCreationRequest>,
) -> Result<Json<NewDocResponse>, AppError> {
    server_state.check_auth(auth_header)?;

    let doc_id = if let Some(doc_id) = body.doc_id {
        if !validate_doc_name(doc_id.as_str()) {
            Err((StatusCode::BAD_REQUEST, anyhow!("Invalid document name")))?
        }

        server_state
            .get_or_create_doc(doc_id.as_str())
            .await
            .map_err(|e| {
                tracing::error!(?e, "Failed to create doc");
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            })?;

        doc_id
    } else {
        server_state.create_doc().await.map_err(|d| {
            tracing::error!(?d, "Failed to create doc");
            (StatusCode::INTERNAL_SERVER_ERROR, d)
        })?
    };

    Ok(Json(NewDocResponse { doc_id }))
}

async fn auth_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    TypedHeader(host): TypedHeader<headers::Host>,
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    body: Option<Json<AuthDocRequest>>,
) -> Result<Json<ClientToken>, AppError> {
    server_state.check_auth(auth_header)?;

    let Json(AuthDocRequest {
        authorization,
        user_id,
        valid_for_seconds,
        ticket,
        ws_key,
    }) = body.unwrap_or_default();

    let Some(user_id) = user_id else {
        Err((StatusCode::FORBIDDEN, anyhow!("userId is required")))?
    };

    if !server_state.doc_exists(&doc_id).await {
        Err((StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)))?;
    }

    let valid_for_seconds = valid_for_seconds.unwrap_or(DEFAULT_EXPIRATION_SECONDS);
    let expiration_time =
        ExpirationTimeEpochMillis(current_time_epoch_millis() + valid_for_seconds * 1000);

    // With encryption off, wsKey is ignored and the ticket opens a plain socket.
    let grant = match (&server_state.ws_grant_key, ws_key, ticket) {
        (Some(key), Some(w), true) => Some(server_state.accept_grant(key, &w, &doc_id).await?),
        // The socket would be refused at the upgrade, so refuse the ticket now.
        (Some(_), None, true) => Err((StatusCode::CONFLICT, anyhow!("wsKey is required")))?,
        _ => None,
    };
    let ws_encrypted = grant.is_some() && server_state.authenticator.is_some();

    let token = match &server_state.authenticator {
        None => None,
        Some(_) if ticket => Some(
            server_state
                .issue_ticket(&doc_id, user_id, authorization, grant)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?,
        ),
        Some(auth) => {
            Some(auth.gen_doc_token(&doc_id, Some(user_id), authorization, expiration_time))
        }
    };

    let url = if let Some(url_prefix) = &server_state.url_prefix {
        let mut url_prefix = url_prefix.clone();
        let scheme = if url_prefix.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        url_prefix.set_scheme(scheme).unwrap();
        let mut url_str = url_prefix.to_string();
        if !url_str.ends_with('/') {
            url_str.push('/');
        }
        // TODO: nothing in y-sweet or xyne-spaces reads `?docId=` (added in aba7029). Check the
        // ingress, LB and log rules, then remove it here, below and in the three URL tests.
        format!("{url_str}d/{doc_id}/ws?docId={doc_id}")
    } else {
        format!("ws://{host}/d/{doc_id}/ws?docId={doc_id}")
    };

    let base_url = if let Some(url_prefix) = &server_state.url_prefix {
        let mut url_prefix = url_prefix.to_string();
        if !url_prefix.ends_with('/') {
            url_prefix = format!("{url_prefix}/");
        }

        format!("{url_prefix}d/{doc_id}")
    } else {
        format!("http://{host}/d/{doc_id}")
    };

    Ok(Json(ClientToken {
        url,
        base_url: Some(base_url),
        doc_id,
        token,
        authorization,
        ws_encrypted,
    }))
}

#[derive(Deserialize)]
struct CloseSessionsRequest {
    sids: Vec<String>,
}

/// Closes every encrypted socket of these auth sessions and refuses their unused tickets.
/// Plain sockets carry no sid, so they stay open.
async fn close_sessions(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
    Json(body): Json<CloseSessionsRequest>,
) -> Result<StatusCode, AppError> {
    server_state.check_auth(auth_header)?;
    server_state.close_sessions(&body.sids).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Runs in front of `as-update`, `update`, and the WebSocket-upgrade routes.
/// Resolves the request's token to a userId (via `token_identities`, set at
/// `/doc/:doc_id/auth` time) and asks the Xyne backend whether that user
/// still has access to this doc. Rejects with 403 if there's no token, no
/// associated userId, or the backend denies access.
async fn validate_user_middleware(
    State(server_state): State<Arc<Server>>,
    Path(params): Path<HashMap<String, String>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if server_state.authenticator.is_none() {
        return Ok(next.run(req).await);
    }

    let doc_id = params
        .get("doc_id")
        .cloned()
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, anyhow!("Missing doc_id")))?;

    let token = extract_request_token(&req)
        .ok_or_else(|| AppError(StatusCode::FORBIDDEN, anyhow!("Missing token")))?;

    // Only `/d/:doc_id/ws/:doc_id2` has a second doc id.
    let websocket = params.contains_key("doc_id2");
    let (authorization, user_id, grant) = server_state
        .verify_token_or_ticket(&token, &doc_id, websocket)
        .await?;
    req.extensions_mut()
        .insert(VerifiedIdentity(authorization, user_id.clone(), grant));

    let Some(user_id) = user_id else {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            anyhow!("Token has no associated userId"),
        ));
    };

    if !server_state
        .validate_user_access_with_connect_retry(&doc_id, &user_id, &authorization)
        .await
    {
        return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Access denied")));
    }

    Ok(next.run(req).await)
}

fn extract_request_token(req: &Request) -> Option<String> {
    if let Some(query) = req.uri().query() {
        if let Some((_, v)) =
            url::form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == "token")
        {
            return Some(v.into_owned());
        }
    }
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn get_token_from_header(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Option<String> {
    if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
        Some(bearer.token().to_string())
    } else {
        None
    }
}

#[derive(Deserialize)]
struct PlaneVerifiedUserData {
    authorization: Authorization,
}

fn get_authorization_from_plane_header(headers: HeaderMap) -> Result<Authorization, AppError> {
    if let Some(token) = headers.get(HeaderName::from_static(PLANE_VERIFIED_USER_DATA_HEADER)) {
        let token_str = token.to_str().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let user_data: PlaneVerifiedUserData =
            serde_json::from_str(token_str).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        Ok(user_data.authorization)
    } else {
        Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use y_sweet_core::api_types::Authorization;

    #[tokio::test]
    async fn test_auth_doc() {
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: Some("u1".to_string()),
                valid_for_seconds: None,
                ticket: false,
                ws_key: None,
            })),
        )
        .await
        .unwrap();

        let expected_url = format!("ws://localhost/d/{doc_id}/ws?docId={doc_id}");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
        assert!(!token.ws_encrypted);
    }

    #[tokio::test]
    async fn test_auth_doc_with_prefix() {
        let prefix: Url = "https://foo.bar".parse().unwrap();
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            Some(prefix),
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                user_id: Some("u1".to_string()),
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let expected_url = format!("wss://foo.bar/d/{doc_id}/ws?docId={doc_id}");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    #[tokio::test]
    async fn test_auth_doc_with_prefix_and_path() {
        let prefix: Url = "https://foo.bar/my-prefix".parse().unwrap();
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            Some(prefix),
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                user_id: Some("u1".to_string()),
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let expected_url = format!("wss://foo.bar/my-prefix/d/{doc_id}/ws?docId={doc_id}");
        assert_eq!(token.url, expected_url);
        let expected_base_url = format!("https://foo.bar/my-prefix/d/{doc_id}");
        assert_eq!(token.base_url, Some(expected_base_url));
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    #[test]
    fn test_normalize_path_prefix() {
        assert_eq!(normalize_path_prefix("/ysweet".to_string()), "/ysweet");
        assert_eq!(normalize_path_prefix("ysweet".to_string()), "/ysweet");
        assert_eq!(normalize_path_prefix("/ysweet/".to_string()), "/ysweet");
        assert_eq!(normalize_path_prefix("  /ysweet/  ".to_string()), "/ysweet");
        assert_eq!(normalize_path_prefix("/a/b/c".to_string()), "/a/b/c");
        assert_eq!(normalize_path_prefix("".to_string()), "");
        assert_eq!(normalize_path_prefix("/".to_string()), "");
    }

    #[tokio::test]
    async fn test_empty_path_prefix_is_none() {
        for p in ["", "/", "   "] {
            let server = Server::new(
                None,
                Duration::from_secs(60),
                None,
                None,
                Some(p.to_string()),
                CancellationToken::new(),
                true,
                None,
                false,
                None,
                None,
                DEFAULT_VALIDATE_POLL_EVERY,
                DEFAULT_VALIDATE_RETRY_ATTEMPTS,
                DEFAULT_VALIDATE_RETRY_DELAY,
            )
            .await
            .unwrap();
            assert_eq!(server.path_prefix, None, "prefix {p:?} should be None");
        }
    }

    #[tokio::test]
    async fn test_path_prefix_normalized_on_server() {
        let server = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            Some("ysweet/".to_string()),
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();
        assert_eq!(server.path_prefix.as_deref(), Some("/ysweet"));
    }

    async fn ticket_server() -> (Arc<Server>, String) {
        let server = Server::new(
            None,
            Duration::from_secs(60),
            Some(Authenticator::gen_key().unwrap()),
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();
        let doc_id = server.create_doc().await.unwrap();
        (Arc::new(server), doc_id)
    }

    async fn request_token(server: &Arc<Server>, doc_id: &str, ticket: bool) -> String {
        auth_request(server, doc_id, ticket, None)
            .await
            .unwrap()
            .0
            .token
            .unwrap()
    }

    async fn auth_request(
        server: &Arc<Server>,
        doc_id: &str,
        ticket: bool,
        ws_key: Option<String>,
    ) -> Result<Json<ClientToken>, AppError> {
        let server_token = server.authenticator.as_ref().unwrap().server_token();
        auth_doc(
            Some(TypedHeader(
                headers::Authorization::bearer(&server_token).unwrap(),
            )),
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(server.clone()),
            Path(doc_id.to_string()),
            Some(Json(AuthDocRequest {
                authorization: Authorization::ReadOnly,
                user_id: Some("u1".to_string()),
                valid_for_seconds: None,
                ticket,
                ws_key,
            })),
        )
        .await
    }

    #[tokio::test]
    async fn test_ticket_is_single_use() {
        let (server, doc_id) = ticket_server().await;
        let ticket = request_token(&server, &doc_id, true).await;
        assert!(ticket.starts_with(TICKET_PREFIX));

        let (authorization, user_id, _) = server
            .verify_token_or_ticket(&ticket, &doc_id, true)
            .await
            .unwrap();
        assert!(authorization == Authorization::ReadOnly);
        assert_eq!(user_id.as_deref(), Some("u1"));

        let err = server
            .verify_token_or_ticket(&ticket, &doc_id, true)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_ticket_rejected() {
        let (server, doc_id) = ticket_server().await;
        let ticket = request_token(&server, &doc_id, true).await;
        let mut entry = server.tickets.get(&ticket).await.unwrap();
        entry.expires_at = std::time::Instant::now() - Duration::from_millis(1);
        server.tickets.insert(ticket.clone(), entry).await;

        let err = server
            .verify_token_or_ticket(&ticket, &doc_id, true)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ticket_doc_mismatch_rejected() {
        let (server, doc_id) = ticket_server().await;
        let ticket = request_token(&server, &doc_id, true).await;
        let err = server
            .verify_token_or_ticket(&ticket, "other-doc", true)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ticket_rejected_outside_websocket() {
        let (server, doc_id) = ticket_server().await;
        let ticket = request_token(&server, &doc_id, true).await;
        let err = server
            .verify_token_or_ticket(&ticket, &doc_id, false)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_signed_token_http_only() {
        let (server, doc_id) = ticket_server().await;
        let token = request_token(&server, &doc_id, false).await;
        assert!(!token.starts_with(TICKET_PREFIX));
        for _ in 0..2 {
            let (_, user_id, _) = server
                .verify_token_or_ticket(&token, &doc_id, false)
                .await
                .unwrap();
            assert_eq!(user_id.as_deref(), Some("u1"));
        }
        let Err(err) = server.verify_token_or_ticket(&token, &doc_id, true).await else {
            panic!("a signed token opened a socket");
        };
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    async fn ws_server() -> String {
        let server = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            None,
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap();
        let doc_id = server.create_doc().await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener, false));
        format!("ws://{addr}/d/{doc_id}/ws/{doc_id}")
    }

    type Client = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    async fn connect(url: &str) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
        tokio_tungstenite::connect_async(url)
            .await
            .map(|(ws, _)| ws)
    }

    async fn next_binary(ws: &mut Client) -> Option<Vec<u8>> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .ok()??
            {
                Ok(WsMessage::Binary(b)) => return Some(b),
                Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
                _ => return None,
            }
        }
    }

    /// True if the server closes the socket within 5 s, skipping any data frames when `skip_data`.
    async fn closes(ws: &mut Client, skip_data: bool) -> bool {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                Err(_) => return false,
                Ok(Some(Ok(WsMessage::Binary(_)))) if !skip_data => return false,
                Ok(Some(Ok(WsMessage::Binary(_) | WsMessage::Ping(_) | WsMessage::Pong(_)))) => {}
                Ok(_) => return true,
            }
        }
    }

    const SYNC_STEP_1_EMPTY: [u8; 4] = [0, 0, 1, 0];

    #[tokio::test]
    async fn test_ws_plain_mode_unchanged() {
        let url = ws_server().await;
        let mut ws = connect(&url).await.unwrap();
        assert_eq!(next_binary(&mut ws).await.unwrap()[..2], [0, 0]);
        ws.send(WsMessage::Binary(SYNC_STEP_1_EMPTY.to_vec()))
            .await
            .unwrap();
        let mut saw_step_2 = false;
        while let Some(frame) = next_binary(&mut ws).await {
            if frame[..2] == [0, 1] {
                saw_step_2 = true;
                break;
            }
        }
        assert!(saw_step_2);
    }

    use base64::engine::general_purpose::STANDARD;
    use ws_crypto::{CLIENT_TO_SERVER, SERVER_TO_CLIENT};

    const SOCKET_KEY: [u8; 32] = [9; 32];

    /// A wsKey as the encryption service mints it.
    fn grant(doc_id: &str, sid: &str, exp_in_ms: i64) -> String {
        let exp = current_time_epoch_millis() as i64 + exp_in_ms;
        let json = format!(
            r#"{{"k":"{}","doc":"{doc_id}","sid":"{sid}","exp":{exp}}}"#,
            STANDARD.encode(SOCKET_KEY)
        );
        ws_crypto::test::wrap_grant(&json)
    }

    /// A y-sweet with auth, WS encryption and a backend that allows every validate call.
    async fn encrypted_server() -> (Arc<Server>, String, String) {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_url = format!("http://{}", backend.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/api/ysweet/validate",
            axum::routing::post(|| async { Json(json!({ "ok": true })) }),
        );
        tokio::spawn(async move { axum::serve(backend, app).await });

        let server = Server::new(
            None,
            Duration::from_secs(60),
            Some(Authenticator::gen_key().unwrap()),
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
            Some(backend_url),
            None,
            DEFAULT_VALIDATE_POLL_EVERY,
            DEFAULT_VALIDATE_RETRY_ATTEMPTS,
            DEFAULT_VALIDATE_RETRY_DELAY,
        )
        .await
        .unwrap()
        .with_ws_encryption(Some(
            WsGrantKey::from_base64(ws_crypto::test::private_key()).unwrap(),
        ));
        let doc_id = server.create_doc().await.unwrap();
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/d/{doc_id}/ws/{doc_id}",
            listener.local_addr().unwrap()
        );
        let routes = server.routes();
        tokio::spawn(server.clone().serve_internal(listener, false, routes));
        (server, doc_id, url)
    }

    async fn encrypted_ticket(server: &Arc<Server>, doc_id: &str, sid: &str) -> String {
        let token = auth_request(server, doc_id, true, Some(grant(doc_id, sid, 30_000)))
            .await
            .unwrap()
            .0;
        assert!(token.ws_encrypted);
        token.token.unwrap()
    }

    #[tokio::test]
    async fn test_ws_encrypted_round_trip() {
        let (server, doc_id, url) = encrypted_server().await;
        let ticket = encrypted_ticket(&server, &doc_id, "s1").await;
        let mut ws = connect(&format!("{url}?token={ticket}")).await.unwrap();
        let mut seal = FrameCipher::new(&SOCKET_KEY, CLIENT_TO_SERVER).unwrap();
        let mut open = FrameCipher::new(&SOCKET_KEY, SERVER_TO_CLIENT).unwrap();

        let first = next_binary(&mut ws).await.unwrap();
        assert_eq!(open.open(&first).unwrap()[..2], [0, 0]);
        ws.send(WsMessage::Binary(seal.seal(&SYNC_STEP_1_EMPTY)))
            .await
            .unwrap();
        let mut saw_step_2 = false;
        while let Some(frame) = next_binary(&mut ws).await {
            if open.open(&frame).unwrap()[..2] == [0, 1] {
                saw_step_2 = true;
                break;
            }
        }
        assert!(saw_step_2);

        // A plaintext frame closes the socket.
        ws.send(WsMessage::Binary(SYNC_STEP_1_EMPTY.to_vec()))
            .await
            .unwrap();
        assert!(closes(&mut ws, true).await);
    }

    #[tokio::test]
    async fn test_bad_grants_rejected() {
        let (server, doc_id, _) = encrypted_server().await;
        let other_doc = server.create_doc().await.unwrap();
        for w in [
            grant(&other_doc, "s1", 30_000),
            grant(&doc_id, "s1", -1),
            "not base64!".to_string(),
        ] {
            let res = auth_request(&server, &doc_id, true, Some(w)).await;
            assert!(matches!(res, Err(AppError(StatusCode::BAD_REQUEST, _))));
        }

        // One socket key never serves two tickets: their nonces would repeat.
        let w = grant(&doc_id, "s1", 30_000);
        assert!(auth_request(&server, &doc_id, true, Some(w.clone()))
            .await
            .is_ok());
        let res = auth_request(&server, &doc_id, true, Some(w)).await;
        assert!(matches!(res, Err(AppError(StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn test_close_sessions() {
        let (server, doc_id, url) = encrypted_server().await;
        let ticket = encrypted_ticket(&server, &doc_id, "s1").await;
        let unused = encrypted_ticket(&server, &doc_id, "s1").await;
        let other = encrypted_ticket(&server, &doc_id, "s2").await;
        let mut ws = connect(&format!("{url}?token={ticket}")).await.unwrap();
        let mut kept = connect(&format!("{url}?token={other}")).await.unwrap();
        assert!(next_binary(&mut ws).await.is_some());
        assert!(next_binary(&mut kept).await.is_some());

        server.close_sessions(&["s1".to_string()]).await;
        assert!(closes(&mut ws, true).await);
        assert!(connect(&format!("{url}?token={unused}")).await.is_err());
        let res = auth_request(&server, &doc_id, true, Some(grant(&doc_id, "s1", 30_000))).await;
        assert!(matches!(res, Err(AppError(StatusCode::UNAUTHORIZED, _))));
        assert!(!closes(&mut kept, true).await);
    }

    #[tokio::test]
    async fn test_close_sessions_route_needs_server_token() {
        let (_server, _doc_id, url) = encrypted_server().await;
        let base = url.replace("ws://", "http://");
        let route = format!(
            "{}/internal/close-sessions",
            &base[..base.find("/d/").unwrap()]
        );
        for bearer in [None, Some("wrong")] {
            let mut req = reqwest::Client::new()
                .post(&route)
                .json(&serde_json::json!({ "sids": ["s1"] }));
            if let Some(b) = bearer {
                req = req.bearer_auth(b);
            }
            assert_eq!(
                req.send().await.unwrap().status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn test_grant_minted_before_start_rejected() {
        let (server, doc_id, _url) = encrypted_server().await;
        let res = auth_request(&server, &doc_id, true, Some(grant(&doc_id, "s1", 1_000))).await;
        assert!(matches!(res, Err(AppError(StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn test_encrypted_mode_rejects_credentials_without_socket_key() {
        let (server, doc_id, url) = encrypted_server().await;
        let res = auth_request(&server, &doc_id, true, None).await;
        assert!(matches!(res, Err(AppError(StatusCode::CONFLICT, _))));
        let token = request_token(&server, &doc_id, false).await;
        assert!(connect(&format!("{url}?token={token}")).await.is_err());
    }

    #[tokio::test]
    async fn test_plain_mode_ignores_ws_key() {
        let (server, doc_id) = ticket_server().await;
        let token = auth_request(&server, &doc_id, true, Some(grant(&doc_id, "s1", 30_000)))
            .await
            .unwrap()
            .0;
        assert!(!token.ws_encrypted);
        let (_, _, grant) = server
            .verify_token_or_ticket(&token.token.unwrap(), &doc_id, true)
            .await
            .unwrap();
        assert!(grant.is_none());
    }
}
