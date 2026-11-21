//! Web server (`vulnizard serve`): HTML UI + read-only REST API.
//!
//! Everything is embedded in the binary: pages are compiled `maud` templates,
//! the stylesheet is included at build time, and the database is the same
//! SQLite file as the CLI (one short-lived connection per request).

mod admin;
mod api;
mod charts;
mod inventory;
mod mfa;
mod notifications;
mod oidc;
mod pages;
mod product;
mod projects;
mod scim;
mod views;

use anyhow::Result;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{self, HeaderValue};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::auth;
use crate::config::Config;
use crate::db::{Account, Database};

pub const SESSION_COOKIE: &str = "vz_session";
pub const SESSION_TTL_SECS: i64 = 14 * 24 * 3600;
/// SSO sessions are shorter: rights changed at the identity provider (group
/// removal, deprovisioning) only apply at the next sign-in.
pub const SSO_SESSION_TTL_SECS: i64 = 12 * 3600;

pub struct AppState {
    pub db_path: PathBuf,
    pub config: Config,
    /// Wakes the scheduler for an immediate sync cycle
    pub sync_trigger: Mutex<Sender<crate::scheduler::SyncOrder>>,
    /// Sources requested for a sync and not started yet
    pub sync_queue: crate::scheduler::SyncQueue,
    pub login_guard: auth::LoginGuard,
    /// Cached metadata of the SSO providers
    pub oidc_discovery: Mutex<std::collections::HashMap<String, oidc::Discovery>>,
    /// After a failed metadata fetch, no new attempt before this instant
    pub oidc_retry_after: Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

pub type St = State<Arc<AppState>>;

impl AppState {
    pub fn db(&self) -> Result<Database, AppError> {
        Ok(Database::connect(&self.db_path)?)
    }

    /// Cookies get the Secure flag when asked, and always when the public
    /// URL is https.
    /// Configuration file overlaid with the settings saved in the admin UI
    pub fn effective_config(&self, db: &Database) -> Result<Config, AppError> {
        Ok(crate::settings::effective(&self.config, db)?)
    }

    pub fn secure_cookies(&self) -> bool {
        self.config.web.secure_cookies || self.config.web.base_url.starts_with("https://")
    }
}

/// Runs blocking work (SQLite, Argon2) without stalling the async workers.
pub fn blocking<T>(f: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(f)
}

// ==========================================
// Errors
// ==========================================

pub enum AppError {
    NotFound,
    Forbidden,
    /// Not logged in (HTML): redirect to the login page
    Login,
    /// Not authenticated (API)
    Unauthorized,
    /// Invalid user input, message shown to the user
    Bad(String),
    /// Login throttling or password-hashing queue full
    TooMany,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        use crate::db::watchlist::{TooGeneric, UserFacing};
        if e.is::<crate::db::Busy>() {
            AppError::TooMany
        } else if e.is::<TooGeneric>() || e.is::<UserFacing>() {
            AppError::Bad(e.to_string())
        } else {
            AppError::Internal(e)
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl AppError {
    /// For database helpers whose errors are user-facing validation messages
    pub fn bad(e: anyhow::Error) -> Self {
        match e.downcast_ref::<rusqlite::Error>() {
            Some(_) => AppError::Internal(e),
            None => AppError::Bad(e.to_string()),
        }
    }

    fn status_message(&self) -> (StatusCode, String) {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".into()),
            AppError::Login | AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Authentication required".into())
            }
            AppError::Bad(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::TooMany => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts, try again later".into(),
            ),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if matches!(self, AppError::Login) {
            return Redirect::to("/login").into_response();
        }
        let (status, message) = self.status_message();
        (status, views::error_page(status.as_u16(), &message)).into_response()
    }
}

/// JSON flavour of [`AppError`] for the API
pub struct ApiError(AppError);

impl<E: Into<AppError>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.0.status_message();
        let body = Json(serde_json::json!({ "error": message }));
        if status == StatusCode::UNAUTHORIZED {
            (status, [(header::WWW_AUTHENTICATE, "Basic realm=\"vulnizard\"")], body).into_response()
        } else {
            (status, body).into_response()
        }
    }
}

// ==========================================
// Authentication extractors
// ==========================================

pub fn session_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == SESSION_COOKIE)
        .map(|(_, v)| v.to_string())
}

/// Account resolved once per request by the `page_context` middleware
#[derive(Clone)]
struct ResolvedSession(Option<Account>);

fn lookup_session(parts: &Parts, state: &AppState) -> Result<Option<Account>, AppError> {
    let Some(token) = session_token(parts) else {
        return Ok(None);
    };
    blocking(|| Ok(state.db()?.get_session_account(&auth::hash_token(&token))?))
}

fn session_account(parts: &Parts, state: &AppState) -> Result<Option<Account>, AppError> {
    match parts.extensions.get::<ResolvedSession>() {
        Some(resolved) => Ok(resolved.0.clone()),
        None => lookup_session(parts, state),
    }
}

/// Optional web session
pub struct MaybeUser(pub Option<Account>);

impl FromRequestParts<Arc<AppState>> for MaybeUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, AppError> {
        Ok(MaybeUser(session_account(parts, state)?))
    }
}

/// Required web session (redirects to /login otherwise)
pub struct User(pub Account);

impl FromRequestParts<Arc<AppState>> for User {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, AppError> {
        session_account(parts, state)?.map(User).ok_or(AppError::Login)
    }
}

/// Network address of the client, for throttling. Behind a reverse proxy the
/// connection comes from the proxy: when the peer is on this machine or is a
/// proxy named in `web.trusted_proxies`, the last `X-Forwarded-For` entry (the
/// one the proxy appended) is used instead. Any other client cannot choose
/// its address this way. IPv6 clients are told apart by their /64, which is
/// what one subscriber usually holds.
fn client_address(parts: &Parts, trusted_proxies: &[String]) -> String {
    use std::net::{IpAddr, SocketAddr};
    let peer = parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>().map(|info| info.0.ip());
    let unmapped = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    let behind_proxy = match peer.map(unmapped) {
        // No peer address: not served from a socket (tests)
        None => true,
        Some(ip) => ip.is_loopback() || trusted_proxies.iter().any(|p| p.parse::<IpAddr>().is_ok_and(|p| p == ip)),
    };
    let forwarded = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|last| last.trim().parse::<IpAddr>().ok());
    let address = match (behind_proxy, forwarded, peer) {
        (true, Some(ip), _) => ip,
        (_, _, Some(ip)) => ip,
        _ => return "unknown".to_string(),
    };
    match unmapped(address) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Counts a sign-in started by a client (SSO, passkey). Starting one needs
/// no account and stores a row: one client may only start so many.
pub(crate) fn count_start(state: &AppState, client: &str) -> Result<(), AppError> {
    let key = auth::ThrottleKey::start(client);
    if state.login_guard.is_locked_at(&key, auth::MAX_STARTS) {
        return Err(AppError::TooMany);
    }
    state.login_guard.record(&key, false);
    Ok(())
}

/// Network address of the client (see `client_address`)
pub struct ClientAddr(pub String);

impl FromRequestParts<Arc<AppState>> for ClientAddr {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, AppError> {
        Ok(ClientAddr(client_address(parts, &state.config.web.trusted_proxies)))
    }
}

/// API authentication: `Authorization: Bearer <token>` or HTTP Basic
pub struct ApiUser(pub Account);

impl FromRequestParts<Arc<AppState>> for ApiUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, ApiError> {
        use base64::Engine;

        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let account = blocking(|| -> Result<Option<Account>, AppError> {
            let db = state.db()?;
            if let Some(token) = value.strip_prefix("Bearer ") {
                return Ok(db.get_token_account(&auth::hash_token(token.trim()))?);
            }
            if let Some(encoded) = value.strip_prefix("Basic ") {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok());
                if let Some((username, password)) = decoded.as_deref().and_then(|d| d.split_once(':')) {
                    // A password alone is not enough once a second factor is set or required: use a token
                    let from = pages::Attempt::Client(client_address(parts, &state.config.web.trusted_proxies));
                    return Ok(match pages::check_credentials(state, &db, username, password, &from)? {
                        Some(account) if db.has_second_factor(account.id)? || db.mfa_required(account.id)? => None,
                        account => account,
                    });
                }
            }
            Ok(None)
        })?;
        account.map(ApiUser).ok_or(ApiError(AppError::Unauthorized))
    }
}

// ==========================================
// Middlewares
// ==========================================

/// CSRF protection for the cookie-authenticated UI: state-changing requests
/// must come from our own origin (in addition to the SameSite=Lax cookie).
async fn csrf_guard(req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let headers = req.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    let same_origin = match (host, source) {
        (Some(host), Some(source)) => source
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(""))
            .is_some_and(|authority| authority.eq_ignore_ascii_case(host)),
        _ => false,
    };
    if same_origin {
        next.run(req).await
    } else {
        AppError::Forbidden.into_response()
    }
}

/// Resolves the session once and prepares what the page chrome shows on
/// every page (sync status, the user's projects for the project selector).
async fn page_context(State(state): St, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let prepared = blocking(|| -> Result<(Option<Account>, views::PageContext), AppError> {
        let account = lookup_session(&parts, &state)?;
        let db = state.db()?;
        let (last_sync, sync_running) = db.sync_status()?;
        let projects = match &account {
            Some(a) => db.list_user_projects(a.id)?.into_iter().map(|p| (p.org, p.name)).collect(),
            None => Vec::new(),
        };
        Ok((
            account,
            views::PageContext {
                last_sync,
                sync_running,
                projects,
                path,
            },
        ))
    });
    match prepared {
        Ok((account, context)) => {
            parts.extensions.insert(ResolvedSession(account));
            views::PAGE.scope(context, next.run(Request::from_parts(parts, body))).await
        }
        Err(e) => e.into_response(),
    }
}

/// Requests served at the same time. Database work blocks a thread per
/// request: without a bound, a burst of slow requests grows threads and
/// memory until the machine gives up. Beyond it, the answer is "busy".
const MAX_IN_FLIGHT: usize = 128;
/// Largest request body accepted (the extractors' own limit is 2 MiB)
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024 + 64 * 1024;
/// Time a client has to send its request body
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The body is read first, under a time limit and without holding a slot: a
/// client that sends its request slowly, or never finishes it, waits alone
/// and does not keep others out. Only then is a slot taken for the work.
async fn limit_in_flight(req: Request, next: Next) -> Response {
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_IN_FLIGHT);
    let (parts, body) = req.into_parts();
    let body = match tokio::time::timeout(BODY_TIMEOUT, axum::body::to_bytes(body, MAX_BODY_BYTES)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return (StatusCode::PAYLOAD_TOO_LARGE, "The request is too large.").into_response(),
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "The request took too long to arrive.").into_response(),
    };
    match SLOTS.try_acquire() {
        Ok(_slot) => next.run(Request::from_parts(parts, axum::body::Body::from(body))).await,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
            "The server is busy, try again in a moment.",
        )
            .into_response(),
    }
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // Scripts: only the two same-origin files of the browser notifications
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Pages show private data: no cache keeps them (static files set their own lifetime)
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    resp
}

// ==========================================
// Router
// ==========================================

/// MCP over HTTP (streamable HTTP transport, JSON responses): one JSON-RPC
/// message per POST, answered on behalf of the owner of the API token.
/// Disabled until an administrator turns it on.
async fn mcp_http(State(state): St, ApiUser(user): ApiUser, headers: axum::http::HeaderMap, body: String) -> Response {
    // Browsers send an Origin: only the public URL of this instance is accepted.
    // (Comparing it with the Host header would not stop DNS rebinding, where
    // both carry the attacker's name.)
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let ours = url::Url::parse(&state.config.web.base_url).ok().map(|u| u.origin().ascii_serialization());
        if ours.as_deref() != Some(origin.trim_end_matches('/')) {
            return ApiError(AppError::Forbidden).into_response();
        }
    }
    let answer = blocking(|| -> Result<Option<serde_json::Value>, AppError> {
        let db = state.db()?;
        let settings = crate::settings::mcp(&db)?;
        if !settings.http_enabled {
            return Err(AppError::NotFound);
        }
        let user_id = user.id;
        // A synchronization asked through MCP is queued like one asked in the UI
        let trigger = |source: Option<String>| {
            let (request, sources) = match source {
                Some(source) => (crate::scheduler::SyncRequest::Source(source.clone()), vec![source]),
                None => (
                    crate::scheduler::SyncRequest::All,
                    state.effective_config(&db).map(|c| c.sync.sources).unwrap_or_default(),
                ),
            };
            let order = crate::scheduler::SyncOrder { request, by: Some(user_id) };
            let sent = state.sync_trigger.lock().map(|tx| tx.send(order).is_ok()).unwrap_or(false);
            if sent {
                let mut queued = state.sync_queue.lock().unwrap_or_else(|e| e.into_inner());
                for source in sources {
                    if !queued.contains(&source) {
                        queued.push(source);
                    }
                }
            }
            sent
        };
        let server = crate::mcp::Mcp {
            db: &db,
            caller: crate::mcp::Caller::User(user),
            allow_write: settings.allow_write,
            request_sync: Some(&trigger),
            inventory: state.config.inventory.enabled,
        };
        Ok(server.handle(&body))
    });
    match answer {
        Ok(Some(message)) => Json(message).into_response(),
        // Notifications have no response
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        Err(e) => ApiError(e).into_response(),
    }
}

/// Former project URL
async fn project_redirect(axum::extract::Path((org, project)): axum::extract::Path<(String, String)>) -> Redirect {
    Redirect::to(&views::product_url(Some((&org, &project)), "overview"))
}

pub fn router(state: Arc<AppState>) -> Router {
    let ui = Router::new()
        // My products
        .route("/", get(|| async { Redirect::to("/product") }))
        .route("/product", get(product::product_all))
        .route("/product/{org}/{project}", get(product::product_project))
        .route("/projects", get(projects::projects).post(projects::project_create_any))
        .route("/orgs", get(pages::orgs).post(pages::org_create))
        .route("/orgs/{org}", get(pages::org_detail))
        .route("/orgs/{org}/delete", post(pages::org_delete))
        .route("/orgs/{org}/members", post(pages::member_add))
        .route("/orgs/{org}/members/{user_id}/delete", post(pages::member_remove))
        .route("/orgs/{org}/projects", post(projects::project_create))
        .route("/orgs/{org}/projects/{project}", get(project_redirect))
        .route("/orgs/{org}/projects/{project}/delete", post(projects::project_delete))
        .route(
            "/orgs/{org}/projects/{project}/watchlist/{entry_id}",
            post(projects::watchlist_status),
        )
        .route("/orgs/{org}/projects/{project}/applications", post(projects::application_add))
        .route(
            "/orgs/{org}/projects/{project}/applications/{app_id}/version",
            post(projects::application_version),
        )
        .route(
            "/orgs/{org}/projects/{project}/applications/{app_id}/delete",
            post(projects::application_delete),
        )
        .route("/orgs/{org}/projects/{project}/members", post(projects::project_member_set))
        .route(
            "/orgs/{org}/projects/{project}/members/{user_id}/delete",
            post(projects::project_member_remove),
        )
        .route("/orgs/{org}/projects/{project}/notifications", post(notifications::rule_create))
        .route(
            "/orgs/{org}/projects/{project}/notifications/{id}/delete",
            post(notifications::rule_delete),
        )
        .route(
            "/orgs/{org}/projects/{project}/notifications/{id}/toggle",
            post(notifications::rule_toggle),
        )
        .route("/orgs/{org}/projects/{project}/inventory/sources", post(inventory::source_create))
        .route(
            "/orgs/{org}/projects/{project}/inventory/sources/{id}/delete",
            post(inventory::source_delete),
        )
        .route(
            "/orgs/{org}/projects/{project}/inventory/sources/{id}/run",
            post(inventory::source_run),
        )
        .route("/orgs/{org}/projects/{project}/inventory/choose", post(inventory::choose))
        .route(
            "/orgs/{org}/projects/{project}/destinations",
            post(notifications::project_destination_create),
        )
        .route(
            "/orgs/{org}/projects/{project}/destinations/{id}/delete",
            post(notifications::project_destination_delete),
        )
        // Browser notifications
        .route("/push/key", get(notifications::push_key))
        .route("/push/subscribe", post(notifications::push_subscribe))
        .route("/push/unsubscribe", post(notifications::push_unsubscribe))
        .route("/push/inbox", get(notifications::push_inbox))
        .route("/static/push.js", get(notifications::push_script))
        .route("/sw.js", get(notifications::service_worker))
        .route("/orgs/{org}/projects/{project}/reports/{day}", get(projects::report_detail))
        .route("/subscriptions", post(pages::subscription_update))
        // Reference database
        .route("/cve", get(pages::cve_list))
        .route("/cve/{id}", get(pages::cve_detail))
        .route("/cve/{id}/tags", post(pages::tag_add))
        .route("/cve/{id}/tags/delete", post(pages::tag_remove))
        .route("/vendors", get(pages::vendors))
        .route("/vendors/{vendor}", get(pages::vendor_detail))
        .route("/weaknesses", get(pages::weaknesses))
        // Accounts
        .route("/login", get(pages::login_form).post(pages::login))
        .route("/register", get(pages::register_form).post(pages::register))
        .route("/logout", post(pages::logout))
        .route("/auth/oidc/{provider}/login", get(oidc::login))
        .route("/auth/oidc/{provider}/callback", get(oidc::callback))
        .route("/login/mfa", get(mfa::second_step_form).post(mfa::second_step))
        .route("/login/mfa/passkey/start", post(mfa::passkey_login_start))
        .route("/login/mfa/passkey/finish", post(mfa::passkey_login_finish))
        .route("/settings", get(pages::settings))
        .route("/settings/mfa", get(mfa::manage))
        .route("/settings/mfa/totp", post(mfa::totp_begin))
        .route("/settings/mfa/totp/confirm", post(mfa::totp_confirm))
        .route("/settings/mfa/totp/delete", post(mfa::totp_delete))
        .route("/settings/mfa/recovery", post(mfa::recovery_regenerate))
        .route("/settings/mfa/passkeys/start", post(mfa::passkey_register_start))
        .route("/settings/mfa/passkeys/finish", post(mfa::passkey_register_finish))
        .route("/settings/mfa/passkeys/{id}/delete", post(mfa::passkey_delete))
        .route("/static/mfa.js", get(mfa::script))
        .route("/static/filter.js", get(pages::filter_script))
        .route("/login/passkey/start", post(mfa::passwordless_start))
        .route("/login/passkey/finish", post(mfa::passwordless_finish))
        .route("/orgs/{org}/mfa", post(mfa::org_requirement))
        .route("/orgs/{org}/leave", post(mfa::org_leave))
        .route("/admin/mfa", post(admin::mfa_requirement))
        .route("/admin/security", get(admin::security_log))
        .route("/settings/password", post(pages::password_change))
        .route("/settings/tokens", post(pages::token_create))
        .route("/settings/tokens/{id}/delete", post(pages::token_delete))
        // Administration
        .route("/admin", get(admin::admin))
        .route("/sync", post(admin::sync_now))
        .route("/admin/users", get(admin::users).post(admin::user_create))
        .route("/admin/users/password", post(admin::user_password))
        .route("/admin/users/bulk", post(admin::users_bulk))
        .route("/admin/users/{id}", get(admin::user_detail).post(admin::user_action))
        .route("/admin/users/{id}/assign", post(admin::user_assign))
        .route("/admin/sources", get(admin::sources).post(admin::sources_settings))
        .route("/admin/sources/{source}", post(admin::source_action))
        .route("/admin/notifications", get(notifications::admin))
        .route("/admin/notifications/delivery", post(notifications::admin_delivery))
        .route("/admin/notifications/destinations", post(notifications::admin_destination_create))
        .route(
            "/admin/notifications/destinations/{id}",
            post(notifications::admin_destination_action),
        )
        .route("/admin/notifications/{id}", post(notifications::admin_rule_action))
        .route("/admin/mcp", get(admin::mcp).post(admin::mcp_save))
        .route("/admin/sso", get(admin::sso).post(admin::sso_save))
        .route("/admin/sso/scim/tokens", post(admin::scim_token_create))
        .route("/admin/sso/scim/tokens/{id}/delete", post(admin::scim_token_delete))
        .route("/admin/sso/scim/groups/{id}/roles", post(admin::scim_group_role_set))
        .route(
            "/admin/sso/scim/groups/{id}/roles/{role_id}/delete",
            post(admin::scim_group_role_remove),
        )
        .route("/admin/sso/{slug}", post(admin::sso_action))
        .route("/static/app.css", get(pages::stylesheet))
        .route("/static/logo.svg", get(pages::logo))
        .route("/favicon.ico", get(pages::logo))
        .fallback(|| async { AppError::NotFound })
        .layer(middleware::from_fn_with_state(state.clone(), mfa::gate))
        .layer(middleware::from_fn_with_state(state.clone(), page_context))
        .layer(middleware::from_fn(csrf_guard));

    let api = Router::new()
        .route("/inventory", post(inventory::api_ingest))
        .route("/cve", get(api::cve_list))
        .route("/cve/{id}", get(api::cve_detail))
        .route("/vendors", get(api::vendors))
        .route("/vendors/{vendor}/products", get(api::products))
        .route("/weaknesses", get(api::weaknesses))
        .route("/organizations", get(api::organizations))
        .route("/organizations/{org}/projects", get(api::projects))
        .route("/organizations/{org}/projects/{project}", get(api::project))
        .route("/organizations/{org}/projects/{project}/reports", get(api::reports))
        .route("/organizations/{org}/projects/{project}/reports/{day}", get(api::report))
        .fallback(|| async { ApiError(AppError::NotFound) });

    Router::new()
        .nest("/api", api)
        .nest("/scim/v2", scim::router())
        .route("/mcp", post(mcp_http))
        .merge(ui)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(limit_in_flight))
        .with_state(state)
}

/// Runs the server until interrupted
pub fn serve(db_path: PathBuf, config: Config) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let sync_queue = crate::scheduler::SyncQueue::default();
    crate::scheduler::spawn(db_path.clone(), config.clone(), rx, sync_queue.clone());

    let bind = config.web.bind.clone();
    let base_url_is_https = config.web.base_url.starts_with("https://");
    let state = Arc::new(AppState {
        db_path,
        config,
        sync_trigger: Mutex::new(tx),
        sync_queue,
        login_guard: auth::LoginGuard::default(),
            oidc_discovery: Mutex::new(Default::default()),
            oidc_retry_after: Mutex::new(Default::default()),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        tracing::info!("listening on http://{}", listener.local_addr()?);
        if !base_url_is_https && !listener.local_addr()?.ip().is_loopback() {
            tracing::warn!(
                "listening beyond this machine without HTTPS: put a reverse proxy with HTTPS in front \
                 and set web.base_url to its https URL (session cookies are sent in clear otherwise)"
            );
        }
        axum::serve(listener, router(state).into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tempfile::TempDir;
    use tower::ServiceExt;

    struct TestApp {
        state: Arc<AppState>,
        router: Router,
        _dir: TempDir,
        db_path: PathBuf,
        sync_rx: std::sync::mpsc::Receiver<crate::scheduler::SyncOrder>,
    }

    fn open_registration() -> Config {
        let mut config = Config::default();
        config.web.allow_registration = true;
        config
    }

    /// The inventory is a preview, closed by default
    fn with_inventory() -> Config {
        let mut config = open_registration();
        config.inventory.enabled = true;
        config
    }

    fn app(config: Config) -> TestApp {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::open(&db_path).unwrap();
        let mut cve = crate::models::Cve::new("CVE-2024-4242".into());
        cve.description = Some("Test <script>alert(1)</script> vulnerability".into());
        cve.cvss_v3_score = Some(9.8);
        db.upsert_cve(&cve).unwrap();
        drop(db);

        let (tx, sync_rx) = std::sync::mpsc::channel();
        let state = Arc::new(AppState {
            db_path: db_path.clone(),
            config,
            sync_trigger: Mutex::new(tx),
            sync_queue: Default::default(),
            login_guard: auth::LoginGuard::default(),
            oidc_discovery: Mutex::new(Default::default()),
            oidc_retry_after: Mutex::new(Default::default()),
        });
        TestApp {
            state: state.clone(),
            router: router(state),
            _dir: dir,
            db_path,
            sync_rx,
        }
    }

    struct Reply {
        status: StatusCode,
        location: Option<String>,
        cookie: Option<String>,
        /// Every cookie set by the response (`name=value`)
        cookies: Vec<String>,
        cache: Option<String>,
        body: String,
    }

    impl TestApp {
        async fn send(&self, req: HttpRequest<Body>) -> Reply {
            let resp = self.router.clone().oneshot(req).await.unwrap();
            let header = |name: header::HeaderName| {
                resp.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from)
            };
            let cookies: Vec<String> = resp
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|c| c.split(';').next().unwrap_or("").to_string())
                .collect();
            let (status, location, cookie, cache) = (
                resp.status(),
                header(header::LOCATION),
                header(header::SET_COOKIE).map(|c| c.split(';').next().unwrap().to_string()),
                header(header::CACHE_CONTROL),
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            Reply {
                status,
                location,
                cookie,
                cookies,
                cache,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            }
        }

        async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
            let mut req = HttpRequest::get(path).header(header::HOST, "localhost");
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            self.send(req.body(Body::empty()).unwrap()).await
        }

        async fn post(&self, path: &str, cookie: Option<&str>, form: &str) -> Reply {
            let mut req = HttpRequest::post(path)
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            self.send(req.body(Body::from(form.to_string())).unwrap()).await
        }

        /// Same as `post`, from a client at this address (as a reverse proxy reports it)
        async fn post_from(&self, address: &str, path: &str, cookie: Option<&str>, form: &str) -> Reply {
            let mut req = HttpRequest::post(path)
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "http://localhost")
                .header("x-forwarded-for", address)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            self.send(req.body(Body::from(form.to_string())).unwrap()).await
        }

        async fn api(&self, path: &str, authorization: Option<&str>) -> Reply {
            let mut req = HttpRequest::get(path).header(header::HOST, "localhost");
            if let Some(a) = authorization {
                req = req.header(header::AUTHORIZATION, a);
            }
            self.send(req.body(Body::empty()).unwrap()).await
        }

        /// Forgets the wrong codes of an account (what the passing of time does)
        fn unlock_second_step(&self, username: &str) {
            let db = Database::connect(&self.db_path).unwrap();
            let id = db.get_credentials(username).unwrap().unwrap().0.id;
            self.state.login_guard.record(&auth::ThrottleKey::second_step(id), true);
        }

        async fn register(&self, username: &str) -> String {
            let reply = self
                .post("/register", None, &format!("username={username}&password=a-long-password"))
                .await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
            reply.cookie.expect("session cookie")
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn browsing_requires_login_and_escapes() {
        let app = app(open_registration());
        // The CVE reference pages now require a session: anonymous visitors are sent to the login form.
        for path in ["/cve", "/cve/cve-2024-4242", "/vendors", "/weaknesses"] {
            let r = app.get(path, None).await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{path}");
            assert_eq!(r.location.as_deref(), Some("/login"), "{path}");
        }
        // Static assets and the login page stay public.
        assert_eq!(app.get("/static/app.css", None).await.status, StatusCode::OK);
        assert_eq!(app.get("/login", None).await.status, StatusCode::OK);

        // Signed in, the pages render and escape stored content.
        let alice = app.register("alice").await;
        let list = app.get("/cve", Some(&alice)).await;
        assert_eq!(list.status, StatusCode::OK);
        assert!(list.body.contains("CVE-2024-4242"));
        assert!(!list.body.contains("<script>alert"));

        let detail = app.get("/cve/cve-2024-4242", Some(&alice)).await;
        assert_eq!(detail.status, StatusCode::OK);
        assert!(detail.body.contains("&lt;script&gt;"));
        assert!(detail.body.contains("New CVE"));

        assert_eq!(app.get("/cve/CVE-1999-0000", Some(&alice)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/nope", Some(&alice)).await.status, StatusCode::NOT_FOUND);

        // A keyword needs three characters; a catch-all application name is refused
        let short = app.get("/cve?search=ab", Some(&alice)).await;
        assert_eq!(short.status, StatusCode::BAD_REQUEST);
        assert!(short.body.contains("at least 3 characters"));
        assert_eq!(app.get("/cve?search=abc", Some(&alice)).await.status, StatusCode::OK);
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        let wildcard = app.post("/orgs/acme/projects/infra/applications", Some(&alice), "name=%25&version=&vendor=").await;
        assert_eq!(wildcard.status, StatusCode::BAD_REQUEST, "{}", wildcard.body);

        // Private pages still redirect to the login form.
        let orgs = app.get("/orgs", None).await;
        assert_eq!(orgs.status, StatusCode::SEE_OTHER);
        assert_eq!(orgs.location.as_deref(), Some("/login"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cross_origin_posts_are_rejected() {
        let app = app(open_registration());
        let cookie = app.register("alice").await;
        for origin in [None, Some("http://evil.example"), Some("http://localhost.evil.example")] {
            let mut req = HttpRequest::post("/orgs")
                .header(header::HOST, "localhost")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(o) = origin {
                req = req.header(header::ORIGIN, o);
            }
            let reply = app.send(req.body(Body::from("name=acme")).unwrap()).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "origin {origin:?}");
        }
        assert!(!app.get("/orgs", Some(&cookie)).await.body.contains("acme"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_project_workflow_and_tenant_isolation() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        let bob = app.register("bob").await;

        // First account is admin, second is not
        assert_eq!(app.get("/admin", Some(&alice)).await.status, StatusCode::OK);
        assert_eq!(app.get("/admin", Some(&bob)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.get("/admin/users", Some(&bob)).await.status, StatusCode::FORBIDDEN);

        // Home is the products overview: login for anonymous users, onboarding when empty
        assert_eq!(app.get("/", None).await.location.as_deref(), Some("/product"));
        assert_eq!(app.get("/product", None).await.location.as_deref(), Some("/login"));
        assert!(app.get("/product", Some(&bob)).await.body.contains("Nothing is monitored yet"));

        // Organization + project (created from the projects page)
        let created = app.post("/orgs", Some(&alice), "name=acme").await;
        assert_eq!(created.location.as_deref(), Some("/orgs/acme"));
        let project = app.post("/projects", Some(&alice), "org=acme&name=infra&description=Prod").await;
        assert_eq!(project.location.as_deref(), Some("/product/acme/infra?view=applications"));
        for scope in ["/product", "/product/acme/infra"] {
            for view in ["", "?view=review", "?view=review&show=handled", "?view=applications", "?view=subscriptions",
                         "?view=evolution", "?view=evolution&days=365&at=2026-01-01", "?view=evolution&at=garbage",
                         "?view=audit", "?view=audit&decision=all", "?view=settings", "?view=bogus"] {
                let page = app.get(&format!("{scope}{view}"), Some(&alice)).await;
                assert_eq!(page.status, StatusCode::OK, "{scope}{view}");
            }
        }
        // The former project URL still works
        assert_eq!(
            app.get("/orgs/acme/projects/infra", Some(&alice)).await.location.as_deref(),
            Some("/product/acme/infra")
        );
        assert!(app.get("/projects", Some(&alice)).await.body.contains("infra"));

        // Bob cannot see or alter Alice's organization
        assert_eq!(app.get("/orgs/acme", Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/product/acme/infra", Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert!(!app.get("/product?view=applications", Some(&bob)).await.body.contains("infra"));
        assert_eq!(
            app.post("/orgs/acme/projects", Some(&bob), "name=evil").await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.post("/projects", Some(&bob), "org=acme&name=evil").await.status,
            StatusCode::NOT_FOUND
        );
        let db = Database::connect(&app.db_path).unwrap();
        let project_id = db.find_project("acme", "infra").unwrap().unwrap();
        let sub = format!("project_id={project_id}&vendor=Apache&product=&action=subscribe&back=project");
        assert_eq!(app.post("/subscriptions", Some(&bob), &sub).await.status, StatusCode::FORBIDDEN);
        let subscribed = app.post("/subscriptions", Some(&alice), &sub).await;
        assert_eq!(subscribed.location.as_deref(), Some("/product/acme/infra?view=subscriptions"));
        assert_eq!(db.list_subscriptions(project_id).unwrap()[0].vendor, "apache");

        // Notifications: private targets are refused, events are multi-valued
        let base = "/orgs/acme/projects/infra/notifications";
        let refused = app
            .post(base, Some(&alice), "name=local&kind=webhook&target=http%3A%2F%2F127.0.0.1%2Fhook")
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        let ok = app
            .post(
                base,
                Some(&alice),
                "name=mail&kind=email&target=sec%40example.org&smtp_host=smtp.example.org&smtp_port=587\
                 &smtp_from=v%40example.org&events=created&events=kev&events=bogus&min_cvss=7",
            )
            .await;
        assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
        let notifications = db.list_notifications(project_id).unwrap();
        assert_eq!(notifications[0].events, ["created", "kev"]);
        assert_eq!(notifications[0].min_cvss, Some(7.0));

        // Logout invalidates the session server-side
        app.post("/logout", Some(&bob), "").await;
        assert_eq!(app.get("/orgs", Some(&bob)).await.status, StatusCode::SEE_OTHER);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn roles_limit_what_members_can_do() {
        let app = app(open_registration());
        let owner = app.register("owner").await;
        let editor = app.register("editor").await;
        let viewer = app.register("viewer").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        app.post("/projects", Some(&owner), "org=acme&name=infra").await;
        for (name, role) in [("editor", "editor"), ("viewer", "viewer")] {
            let added = app
                .post("/orgs/acme/members", Some(&owner), &format!("username={name}&role={role}"))
                .await;
            assert_eq!(added.status, StatusCode::SEE_OTHER);
        }
        // The legacy role name is refused
        let legacy = app.post("/orgs/acme/members", Some(&owner), "username=viewer&role=member").await;
        assert_eq!(legacy.status, StatusCode::BAD_REQUEST);

        // A tracked application matching the seeded CVE (no version: always affected)
        let base = "/orgs/acme/projects/infra";
        let db = Database::connect(&app.db_path).unwrap();
        let mut cve = crate::models::Cve::new("CVE-2024-4343".into());
        cve.description = Some("Widget flaw".into());
        cve.cvss_v3_score = Some(9.1);
        cve.affected_products.push(crate::models::AffectedProduct {
            vendor: Some("acme".into()),
            product: Some("widget".into()),
            version: Some("*".into()),
            version_start: None,
            version_end: None,
            cpe: Some("cpe".into()),
        });
        db.upsert_cve(&cve).unwrap();

        let app_form = "name=widget&version=1.0&vendor=acme";
        assert_eq!(app.post(&format!("{base}/applications"), Some(&viewer), app_form).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("{base}/applications"), Some(&editor), app_form).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&format!("{base}/applications"), Some(&editor), app_form).await.status, StatusCode::BAD_REQUEST);
        let project_id = db.find_project("acme", "infra").unwrap().unwrap();
        let entry = db.project_triage(project_id, false).unwrap()[0].entry_id;
        let app_id = db.list_applications(project_id).unwrap()[0].id.unwrap();

        // Everyone sees the entry; the dashboard lists it with actions only for those who can triage
        for page in ["/product/acme/infra", "/product", "/product?view=review"] {
            let viewer_page = app.get(page, Some(&viewer)).await;
            assert!(viewer_page.body.contains("CVE-2024-4343"), "{page}");
            assert!(!viewer_page.body.contains(&format!("/watchlist/{entry}")), "{page}");
            assert!(app.get(page, Some(&editor)).await.body.contains(&format!("/watchlist/{entry}")), "{page}");
        }
        // The overview draws its charts without any inline style or script
        let overview = app.get("/product", Some(&editor)).await.body;
        assert!(overview.contains("<svg") && overview.contains("stroke-p0"));
        // No inline style or script: the only script is the external one of the live filters
        assert!(!overview.contains("style=") && overview.replace("<script src=\"/static/filter.js\" defer></script>", "").matches("<script").count() == 0);

        // Triage: viewer refused, editor allowed, entry scoped to its project
        let triage = format!("{base}/watchlist/{entry}");
        assert_eq!(app.post(&triage, Some(&viewer), "status=treated").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&triage, Some(&editor), "status=bogus").await.status, StatusCode::BAD_REQUEST);
        // Accepting a risk needs a justification; the decision is attributed in the audit view
        assert_eq!(app.post(&triage, Some(&editor), "status=accepted").await.status, StatusCode::BAD_REQUEST);
        let done = app
            .post(&triage, Some(&editor), "status=accepted&comment=behind+VPN&back=%2Fproduct%3Fview%3Dreview")
            .await;
        assert_eq!(done.location.as_deref(), Some("/product?view=review"));
        assert!(db.project_triage(project_id, false).unwrap().is_empty());
        let audit = app.get("/product/acme/infra?view=audit", Some(&viewer)).await.body;
        assert!(audit.contains("behind VPN") && audit.contains("<strong>editor</strong>"));
        assert!(app.get("/product?view=evolution", Some(&viewer)).await.body.contains("behind VPN"));
        // The return page is never an external URL
        let evil = app
            .post(&triage, Some(&editor), "status=untreated&back=https%3A%2F%2Fevil.example%2F")
            .await;
        assert_eq!(evil.location.as_deref(), Some("/product/acme/infra?view=review"));
        let evil = app.post(&triage, Some(&editor), "status=treated&back=%2F%2Fevil.example").await;
        assert_eq!(evil.location.as_deref(), Some("/product/acme/infra?view=review"));
        app.post("/projects", Some(&owner), "org=acme&name=other").await;
        let foreign = format!("/orgs/acme/projects/other/watchlist/{entry}");
        assert_eq!(app.post(&foreign, Some(&editor), "status=accepted&comment=x").await.status, StatusCode::NOT_FOUND);
        assert_eq!(
            app.post(&format!("/orgs/acme/projects/other/applications/{app_id}/delete"), Some(&editor), "").await.status,
            StatusCode::NOT_FOUND
        );

        // Version update and removal need the editor role
        let version = format!("{base}/applications/{app_id}/version");
        assert_eq!(app.post(&version, Some(&viewer), "version=2.0").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&version, Some(&editor), "version=2.0").await.status, StatusCode::SEE_OTHER);
        assert_eq!(db.list_applications(project_id).unwrap()[0].version.as_deref(), Some("2.0"));

        // Editors manage projects but neither members nor the organization
        let sub = format!("project_id={project_id}&vendor=acme&product=widget&action=subscribe");
        assert_eq!(app.post("/subscriptions", Some(&viewer), &sub).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/subscriptions", Some(&editor), &sub).await.status, StatusCode::SEE_OTHER);
        assert_eq!(
            app.post("/orgs/acme/members", Some(&editor), "username=viewer&role=owner").await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(app.post("/orgs/acme/delete", Some(&editor), "name=acme").await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            app.post(&format!("{base}/notifications"), Some(&viewer), "name=m&kind=email&target=a%40example.org").await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(app.post(&format!("{base}/delete"), Some(&viewer), "name=infra").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/projects", Some(&viewer), "org=acme&name=nope").await.status, StatusCode::FORBIDDEN);
        // Deleting a project is for owners, and never erases who decided what
        assert_eq!(app.post(&format!("{base}/delete"), Some(&editor), "name=infra").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("{base}/delete"), Some(&owner), "name=infra").await.status, StatusCode::SEE_OTHER);
        let audit = app.get("/product?view=audit&decision=all", Some(&viewer)).await.body;
        assert!(audit.contains("behind VPN") && audit.contains("(deleted)"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn administrators_manage_users() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        let user = app.register("user").await;
        let db = Database::connect(&app.db_path).unwrap();
        let user_id = db.get_credentials("user").unwrap().unwrap().0.id;
        let admin_id = db.get_credentials("root").unwrap().unwrap().0.id;

        // Non-administrators cannot reach any user-management action
        for (path, form) in [
            ("/admin/users", "username=mallory&password=a-long-password&admin=1".to_string()),
            (&*format!("/admin/users/{admin_id}"), "action=disable".to_string()),
            ("/admin/users/password", format!("user_id={admin_id}&password=a-long-password")),
        ] {
            assert_eq!(app.post(path, Some(&user), &form).await.status, StatusCode::FORBIDDEN, "{path}");
        }

        // Create, with validation
        let created = app.post("/admin/users", Some(&admin), "username=carol&password=a-long-password").await;
        assert_eq!(created.status, StatusCode::SEE_OTHER);
        assert!(!db.get_credentials("carol").unwrap().unwrap().0.is_admin);
        assert_eq!(
            app.post("/admin/users", Some(&admin), "username=carol&password=a-long-password").await.status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.post("/admin/users", Some(&admin), "username=dave&password=short").await.status,
            StatusCode::BAD_REQUEST
        );
        let listing = app.get("/admin/users", Some(&admin)).await;
        assert!(listing.body.contains("carol") && listing.body.contains("(you)"));

        // Disabling closes the session and blocks login; enabling restores it
        let action = format!("/admin/users/{user_id}");
        assert_eq!(app.post(&action, Some(&admin), "action=disable").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/projects", Some(&user)).await.status, StatusCode::SEE_OTHER);
        let login = app.post("/login", None, "username=user&password=a-long-password").await;
        assert_eq!(login.status, StatusCode::UNAUTHORIZED);
        app.post(&action, Some(&admin), "action=enable").await;
        let login = app.post("/login", None, "username=user&password=a-long-password").await;
        assert_eq!(login.status, StatusCode::SEE_OTHER);

        // Password reset by an administrator
        let reset = app
            .post("/admin/users/password", Some(&admin), &format!("user_id={user_id}&password=a-brand-new-password"))
            .await;
        assert_eq!(reset.status, StatusCode::SEE_OTHER);
        let old = app.post("/login", None, "username=user&password=a-long-password").await;
        assert_eq!(old.status, StatusCode::UNAUTHORIZED);
        let new = app.post("/login", None, "username=user&password=a-brand-new-password").await;
        assert_eq!(new.status, StatusCode::SEE_OTHER);

        // Promotion takes effect; an administrator cannot lock themselves out
        app.post(&action, Some(&admin), "action=grant_admin").await;
        assert_eq!(app.get("/admin/users", new.cookie.as_deref()).await.status, StatusCode::SEE_OTHER); // session closed
        let relog = app.post("/login", None, "username=user&password=a-brand-new-password").await;
        assert_eq!(app.get("/admin/users", relog.cookie.as_deref()).await.status, StatusCode::OK);
        let own = format!("/admin/users/{admin_id}");
        assert_eq!(app.post(&own, Some(&admin), "action=disable").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&own, Some(&admin), "action=revoke_admin").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&action, Some(&admin), "action=bogus").await.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_and_registration_rules() {
        // Registration is closed by default, even for the first account
        let closed = app(Config::default());
        let refused = closed.post("/register", None, "username=eve&password=a-long-password").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(Database::connect(&closed.db_path).unwrap().count_accounts().unwrap(), 0);

        let app = app(open_registration());
        let alice = app.register("alice").await;

        let bad = app.post("/login", None, "username=alice&password=wrong-password").await;
        assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
        assert!(bad.cookie.is_none());
        let good = app.post("/login", None, "username=alice&password=a-long-password").await;
        assert_eq!(good.status, StatusCode::SEE_OTHER);
        assert!(good.cookie.is_some());

        // Names of the automatic actors of the audit trail cannot be registered
        for reserved in ["system", "CLI", "unknown"] {
            let r = app.post("/register", None, &format!("username={reserved}&password=a-long-password")).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{reserved}");
        }

        // Short passwords are refused
        let short = app
            .post("/settings/password", Some(&alice), "current=a-long-password&new=short")
            .await;
        assert_eq!(short.status, StatusCode::BAD_REQUEST);

        // Repeated failures lock the account for the client that failed, even with the right password
        let bob = app.register("bob").await;
        let attacker = "203.0.113.7";
        for _ in 0..10 {
            let r = app.post_from(attacker, "/login", None, "username=bob&password=wrong-password").await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        }
        let locked = app.post_from(attacker, "/login", None, "username=bob&password=a-long-password").await;
        assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
        // Other accounts are unaffected
        let other = app.post_from(attacker, "/login", None, "username=alice&password=a-long-password").await;
        assert_eq!(other.status, StatusCode::SEE_OTHER);
        // Bob himself, from his own address, is not locked out by someone else's failures
        let own = app.post_from("198.51.100.4", "/login", None, "username=BOB&password=a-long-password").await;
        assert_eq!(own.status, StatusCode::SEE_OTHER);
        // Nor is his API access with his password, nor a password change from his session
        use base64::Engine;
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("bob:a-long-password"));
        assert_eq!(app.api("/api/cve", Some(&basic)).await.status, StatusCode::OK);
        for _ in 0..10 {
            app.post_from(attacker, "/login", None, "username=bob&password=wrong-password").await;
        }
        let changed = app.post("/settings/password", Some(&bob), "current=a-long-password&new=another-long-password").await;
        assert_eq!(changed.status, StatusCode::SEE_OTHER);

        // Many addresses together are still bounded: the account locks for everyone
        app.register("carol").await;
        // (all but the last failure are recorded directly: each real one costs a password hash)
        for _ in 1..crate::auth::MAX_ACCOUNT_FAILURES {
            app.state.login_guard.record(&crate::auth::ThrottleKey::account("carol"), false);
        }
        let last = app.post_from("203.0.113.200", "/login", None, "username=carol&password=wrong-password").await;
        assert_eq!(last.status, StatusCode::UNAUTHORIZED);
        let exhausted = app.post_from("198.51.100.9", "/login", None, "username=carol&password=a-long-password").await;
        assert_eq!(exhausted.status, StatusCode::TOO_MANY_REQUESTS);

        // A browser that signed in before is known: the lock others put on the account does not apply to it
        app.register("dave").await;
        let signed_in = app.post_from("198.51.100.20", "/login", None, "username=dave&password=a-long-password").await;
        let device = signed_in.cookies.iter().find(|c| c.starts_with("vulnizard_device=")).cloned().expect("device cookie");
        for _ in 0..crate::auth::MAX_ACCOUNT_FAILURES {
            app.state.login_guard.record(&crate::auth::ThrottleKey::account("dave"), false);
        }
        let stranger = app.post_from("198.51.100.21", "/login", None, "username=dave&password=a-long-password").await;
        assert_eq!(stranger.status, StatusCode::TOO_MANY_REQUESTS);
        let owner = app.post_from("198.51.100.22", "/login", Some(&device), "username=dave&password=a-long-password").await;
        assert_eq!(owner.status, StatusCode::SEE_OTHER);
        // The mark is bound to its account and cannot be made up
        let forged = "vulnizard_device=1.1700000000.0000000000000000000000000000000000000000000000000000000000000000";
        for cookie in [forged, device.replace("vulnizard_device=", "vulnizard_device=9").as_str()] {
            let r = app.post_from("198.51.100.23", "/login", Some(cookie), "username=dave&password=a-long-password").await;
            assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        }
        // It still needs the right password, and counts its own mistakes
        for _ in 0..10 {
            let r = app.post_from("198.51.100.22", "/login", Some(&device), "username=dave&password=wrong-password").await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        }
        let worn = app.post_from("198.51.100.22", "/login", Some(&device), "username=dave&password=a-long-password").await;
        assert_eq!(worn.status, StatusCode::TOO_MANY_REQUESTS);

        // Starting sign-ins without an account is counted per client
        for _ in 0..crate::auth::MAX_STARTS {
            let started = app.post_from("198.51.100.30", "/login/passkey/start", None, "").await;
            assert_ne!(started.status, StatusCode::TOO_MANY_REQUESTS);
        }
        assert_eq!(app.post_from("198.51.100.30", "/login/passkey/start", None, "").await.status, StatusCode::TOO_MANY_REQUESTS);
        assert_ne!(app.post_from("198.51.100.31", "/login/passkey/start", None, "").await.status, StatusCode::TOO_MANY_REQUESTS);

        // A name shaped like an internal counter is just a name: it locks nothing else
        let db = Database::connect(&app.db_path).unwrap();
        let alice_id = db.get_credentials("alice").unwrap().unwrap().0.id;
        for _ in 0..12 {
            app.post_from(attacker, "/login", None, &format!("username=mfa%3A{alice_id}&password=x")).await;
        }
        assert!(!app.state.login_guard.is_locked(&crate::auth::ThrottleKey::second_step(alice_id)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn password_change_revokes_tokens_and_sessions() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        let page = app.post("/settings/tokens", Some(&alice), "name=ci&password=a-long-password").await;
        let token = page.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
        let bearer = format!("Bearer {token}");
        assert_eq!(app.api("/api/organizations", Some(&bearer)).await.status, StatusCode::OK);

        let changed = app
            .post("/settings/password", Some(&alice), "current=a-long-password&new=another-long-password")
            .await;
        assert_eq!(changed.status, StatusCode::SEE_OTHER);
        assert_eq!(app.api("/api/organizations", Some(&bearer)).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.get("/orgs", Some(&alice)).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/orgs", changed.cookie.as_deref()).await.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_authentication() {
        use base64::Engine;

        let app = app(open_registration());
        let alice = app.register("alice").await;

        let anonymous = app.api("/api/cve", None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        // A web session is not an API credential
        assert_eq!(app.get("/api/cve", Some(&alice)).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.api("/api/cve", Some("Bearer nope")).await.status, StatusCode::UNAUTHORIZED);

        // A session alone does not mint a token: the password is asked again
        for form in ["name=ci", "name=ci&password=wrong-password"] {
            let refused = app.post("/settings/tokens", Some(&alice), form).await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST);
            assert!(!refused.body.contains("class=\"token\""));
        }
        // Pages are never kept by a cache; static files set their own lifetime
        assert_eq!(app.get("/settings", Some(&alice)).await.cache.as_deref(), Some("no-store"));
        assert_eq!(app.api("/api/cve", Some("Bearer nope")).await.cache.as_deref(), Some("no-store"));
        assert!(app.get("/static/app.css", None).await.cache.unwrap().contains("max-age"));

        let page = app.post("/settings/tokens", Some(&alice), "name=ci&password=a-long-password").await;
        let token = page
            .body
            .split("<code class=\"token\">")
            .nth(1)
            .and_then(|s| s.split('<').next())
            .expect("token shown once")
            .to_string();
        let bearer = format!("Bearer {token}");

        let list = app.api("/api/cve?cvss=critical", Some(&bearer)).await;
        assert_eq!(list.status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&list.body).unwrap();
        assert_eq!(json[0]["cve_id"], "CVE-2024-4242");

        let detail = app.api("/api/cve/CVE-2024-4242", Some(&bearer)).await;
        let json: serde_json::Value = serde_json::from_str(&detail.body).unwrap();
        assert_eq!(json["changes"][0]["events"][0]["type"], "created");

        assert_eq!(app.api("/api/cve/CVE-1999-1", Some(&bearer)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api("/api/organizations/nope/projects", Some(&bearer)).await.status, StatusCode::NOT_FOUND);

        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:a-long-password")
        );
        assert_eq!(app.api("/api/organizations", Some(&basic)).await.status, StatusCode::OK);
        let wrong = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:wrong-password")
        );
        assert_eq!(app.api("/api/organizations", Some(&wrong)).await.status, StatusCode::UNAUTHORIZED);
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_status_is_in_the_header_and_admins_can_start_a_sync() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        let user = app.register("user").await;

        let page = app.get("/product", Some(&admin)).await.body;
        assert!(page.contains("Database never synced"));
        assert!(page.contains("action=\"/sync\""));
        // The two sides of the navigation are both present, the selector defaults to all projects
        assert!(page.contains("My products") && page.contains("CVE database") && page.contains("All projects"));
        let user_page = app.get("/cve", Some(&user)).await.body;
        assert!(user_page.contains("Database never synced") && !user_page.contains("action=\"/sync\""));
        // The reference pages require a session now
        let anonymous = app.get("/cve", None).await;
        assert_eq!(anonymous.location.as_deref(), Some("/login"));

        let db = Database::connect(&app.db_path).unwrap();
        let id = db.start_sync("nvd").unwrap();
        assert!(app.get("/cve", Some(&user)).await.body.contains("sync in progress"));
        db.complete_sync(id, 1, 0).unwrap();
        assert!(app.get("/cve", Some(&user)).await.body.contains("Database synced just now"));

        assert_eq!(app.post("/sync", Some(&user), "back=%2Fproduct").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/sync", None, "back=%2Fproduct").await.status, StatusCode::SEE_OTHER); // to /login
        let started = app.post("/sync", Some(&admin), "back=%2Fproduct%3Fview%3Daudit").await;
        assert_eq!(started.location.as_deref(), Some("/product?view=audit"));
        for evil in ["https%3A%2F%2Fevil.example", "%2F%2Fevil.example", "evil"] {
            let r = app.post("/sync", Some(&admin), &format!("back={evil}")).await;
            assert_eq!(r.location.as_deref(), Some("/admin"), "{evil}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn administrators_manage_sources_and_notifications() {
        use crate::scheduler::SyncRequest;

        let app = app(open_registration());
        let admin = app.register("root").await;
        let user = app.register("user").await;
        let db = Database::connect(&app.db_path).unwrap();

        // Admin pages and actions are closed to other users
        for page in ["/admin/sources", "/admin/notifications", "/admin/mcp"] {
            assert_eq!(app.get(page, Some(&user)).await.status, StatusCode::FORBIDDEN, "{page}");
            assert_eq!(app.get(page, Some(&admin)).await.status, StatusCode::OK, "{page}");
        }
        for (path, form) in [
            ("/admin/sources", "interval=5"),
            ("/admin/sources/osv", "action=enable"),
            ("/admin/notifications/delivery", "allow_private=1"),
            ("/admin/notifications/destinations", "owner=instance&kind=ntfy&name=x&url=https%3A%2F%2F8.8.8.8%2Fx"),
            ("/admin/notifications/destinations/1", "action=delete"),
            ("/admin/notifications/1", "action=delete"),
            ("/admin/mcp", "http_enabled=1&allow_write=1"),
        ] {
            assert_eq!(app.post(path, Some(&user), form).await.status, StatusCode::FORBIDDEN, "{path}");
        }

        // Sources: enable, disable, sync one, settings
        assert_eq!(app.post("/admin/sources/osv", Some(&admin), "action=enable").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/admin/sources/epss", Some(&admin), "action=disable").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/admin/sources/bogus", Some(&admin), "action=enable").await.status, StatusCode::NOT_FOUND);
        let effective = crate::settings::effective(&Config::default(), &db).unwrap();
        assert_eq!(effective.sync.sources, ["nvd", "cisa_kev", "vulnrichment", "osv"]);
        // The source of the inventory is closed with it
        assert_eq!(app.post("/admin/sources/distros", Some(&admin), "action=sync").await.status, StatusCode::NOT_FOUND);
        assert!(app.get("/admin/sources", Some(&admin)).await.body.contains("Not in this release"));
        let requested = app.post("/admin/sources/osv", Some(&admin), "action=sync").await;
        assert_eq!(requested.status, StatusCode::SEE_OTHER);
        let order = app.sync_rx.try_recv().unwrap();
        assert_eq!(order.request, SyncRequest::Source("osv".into()));
        // The request remembers who asked, to tell them when it is over
        assert!(order.by.is_some());
        // The request is visible at once: confirmation, "waiting" state, auto-refresh, button disabled
        let flash = requested.cookie.expect("confirmation");
        let page = app.get("/admin/sources", Some(&format!("{admin}; {flash}"))).await.body;
        assert!(page.contains("Synchronization of osv requested"));
        assert!(page.contains("waiting to start") && page.contains("http-equiv=\"refresh\""));
        // Once running, then finished, the state follows and the page stops refreshing
        let run = db.start_sync("osv").unwrap();
        assert!(app.get("/admin/sources", Some(&admin)).await.body.contains("synchronizing…"));
        db.complete_sync(run, 3, 0).unwrap();
        app.post("/sync", Some(&admin), "back=%2Fadmin").await;
        assert_eq!(app.sync_rx.try_recv().unwrap().request, SyncRequest::All);

        let saved = app.post("/admin/sources", Some(&admin), "interval=15&nvd_api_key=secret-key-1").await;
        assert_eq!(saved.status, StatusCode::SEE_OTHER);
        let effective = crate::settings::effective(&Config::default(), &db).unwrap();
        assert_eq!((effective.web.sync_interval_minutes, effective.nvd.api_key.as_deref()), (15, Some("secret-key-1")));
        // The key is never shown back; an empty field keeps it, the checkbox removes it
        assert!(!app.get("/admin/sources", Some(&admin)).await.body.contains("secret-key-1"));
        app.post("/admin/sources", Some(&admin), "interval=15&nvd_api_key=").await;
        assert!(crate::settings::effective(&Config::default(), &db).unwrap().nvd.api_key.is_some());
        app.post("/admin/sources", Some(&admin), "interval=15&clear_nvd_api_key=1").await;
        assert!(crate::settings::effective(&Config::default(), &db).unwrap().nvd.api_key.is_none());
        assert_eq!(app.post("/admin/sources", Some(&admin), "interval=999999").await.status, StatusCode::BAD_REQUEST);

        // Notifications: the private-address setting changes what projects may target
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        app.post("/projects", Some(&admin), "org=acme&name=web").await;
        let infra = db.find_project("acme", "infra").unwrap().unwrap();
        let web = db.find_project("acme", "web").unwrap().unwrap();
        let create = "/orgs/acme/projects/infra/destinations";
        let ntfy = "kind=ntfy&name=phone&url=http%3A%2F%2F127.0.0.1%3A9%2Fvulns&notify=1";
        assert_eq!(app.post(create, Some(&admin), ntfy).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/admin/notifications/delivery", Some(&admin), "allow_private=1").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(create, Some(&admin), ntfy).await.status, StatusCode::SEE_OTHER);
        // The destination belongs to its project: usable there, not in the other project
        let phone = db.list_project_destinations(infra).unwrap()[0].id;
        assert_eq!(db.list_notifications(infra).unwrap().len(), 1);
        assert!(db.list_project_destinations(web).unwrap().is_empty());
        let foreign = format!("destination_id={phone}");
        assert_eq!(app.post("/orgs/acme/projects/web/notifications", Some(&admin), &foreign).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            app.post(&format!("/orgs/acme/projects/web/destinations/{phone}/delete"), Some(&admin), "").await.status,
            StatusCode::NOT_FOUND
        );

        // The form of a destination only shows once its type is chosen; SMTP only for email
        let settings = app.get("/product/acme/infra?view=settings", Some(&admin)).await.body;
        assert!(!settings.contains("name=\"smtp_host\"") && settings.contains("new=email"));
        let email_form = app.get("/product/acme/infra?view=settings&new=email", Some(&admin)).await.body;
        assert!(email_form.contains("name=\"smtp_host\"") && email_form.contains("name=\"to\""));
        let ntfy_form = app.get("/product/acme/infra?view=settings&new=ntfy", Some(&admin)).await.body;
        assert!(!ntfy_form.contains("name=\"smtp_host\"") && ntfy_form.contains("name=\"url\""));

        // An email destination carries its own SMTP server; the password is never shown
        let mail = "kind=email&name=mail&to=sec%40example.org&smtp_host=smtp.example.org&smtp_port=587\
                    &smtp_username=bot&smtp_password=smtp-secret&smtp_from=Vulnizard+%3Cv%40example.org%3E";
        assert_eq!(app.post("/orgs/acme/projects/web/destinations", Some(&admin), mail).await.status, StatusCode::SEE_OTHER);
        assert_eq!(
            app.post("/orgs/acme/projects/web/destinations", Some(&admin), "kind=email&name=nosmtp&to=a%40example.org").await.status,
            StatusCode::BAD_REQUEST
        );
        let stored = &db.list_project_destinations(web).unwrap()[0];
        assert_eq!(stored.config["smtp"]["password"], "smtp-secret");
        for page in ["/product/acme/web?view=settings", "/admin/notifications", "/admin/notifications?tab=destinations"] {
            let body = app.get(page, Some(&admin)).await.body;
            assert!(!body.contains("smtp-secret"), "{page}");
        }

        // Administration: rules per project, every destination, instance destinations
        let rules = app.get("/admin/notifications", Some(&admin)).await.body;
        assert!(rules.contains("phone") && rules.contains("infra"));
        let destinations = app.get("/admin/notifications?tab=destinations", Some(&admin)).await.body;
        assert!(destinations.contains("phone") && destinations.contains("sec@example.org (via smtp.example.org)"));
        assert!(!destinations.contains("name=\"owner\""));
        assert!(app.get("/admin/notifications?tab=destinations&new=ntfy", Some(&admin)).await.body.contains("name=\"owner\""));
        let ops = "owner=instance&kind=ntfy&name=ops&url=http%3A%2F%2F127.0.0.1%3A9%2Fops&system_events=1";
        assert_eq!(app.post("/admin/notifications/destinations", Some(&admin), ops).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/admin/notifications/destinations", Some(&user), ops).await.status, StatusCode::FORBIDDEN);
        // An instance destination is usable by every project and receives instance events
        let ops_id = db.list_system_destinations().unwrap()[0].id;
        assert!(db.list_project_destinations(web).unwrap().iter().any(|d| d.id == ops_id));
        let org_scoped = "owner=organization%3Aacme&kind=ntfy&name=team&url=http%3A%2F%2F127.0.0.1%3A9%2Fteam&system_events=1";
        app.post("/admin/notifications/destinations", Some(&admin), org_scoped).await;
        assert_eq!(db.list_system_destinations().unwrap().len(), 1); // organization destinations never get instance events

        // The target of a shared destination is its owner's secret: a project using it never sees it
        let attach = format!("destination_id={ops_id}");
        assert_eq!(app.post("/orgs/acme/projects/web/notifications", Some(&admin), &attach).await.status, StatusCode::SEE_OTHER);
        let web_settings = app.get("/product/acme/web?view=settings", Some(&admin)).await.body;
        assert!(web_settings.contains("ops") && web_settings.contains("managed elsewhere"));
        assert!(!web_settings.contains("127.0.0.1:9/ops") && !web_settings.contains("127.0.0.1:9/team"));
        // The project's own destination shows its target to those who manage the project
        assert!(app.get("/product/acme/infra?view=settings", Some(&admin)).await.body.contains("127.0.0.1:9/vulns"));

        // A test send reports the failure (nothing listens on that port) instead of crashing
        let id = db.list_notifications(infra).unwrap()[0].id;
        let action = format!("/admin/notifications/{id}");
        let tested = app.post(&action, Some(&admin), "action=test").await;
        assert_eq!(tested.status, StatusCode::SEE_OTHER);
        // The outcome comes back in a one-time cookie, never in the URL
        assert_eq!(tested.location.as_deref(), Some("/admin/notifications"));
        let flash = tested.cookie.expect("flash cookie");
        assert!(flash.starts_with("vz_flash=") && flash.contains("failed"));
        let shown = app.get("/admin/notifications", Some(&format!("{admin}; {flash}"))).await;
        assert!(shown.body.contains("failed") && shown.cookie.as_deref() == Some("vz_flash="));
        let crafted = app.get("/admin/notifications?msg=Your+session+expired", Some(&admin)).await;
        assert!(!crafted.body.contains("class=\"card notice\""));
        assert!(shown.body.contains("class=\"card notice\""));
        let dest_test = app.post(&format!("/admin/notifications/destinations/{ops_id}"), Some(&admin), "action=test").await;
        assert!(dest_test.cookie.unwrap().contains("failed"));

        assert_eq!(app.post(&action, Some(&admin), "action=toggle").await.status, StatusCode::SEE_OTHER);
        assert!(!db.list_notifications(infra).unwrap()[0].enabled);
        assert_eq!(app.post(&action, Some(&admin), "action=delete").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&action, Some(&admin), "action=delete").await.status, StatusCode::NOT_FOUND);
        // Stopping a rule keeps the destination; deleting the destination removes its rules
        assert!(db.get_destination(phone).unwrap().is_some());
        app.post("/orgs/acme/projects/infra/notifications", Some(&admin), &format!("destination_id={phone}&events=kev")).await;
        assert_eq!(db.list_notifications(infra).unwrap()[0].events, ["kev"]);
        let deleted = app.post(&format!("/orgs/acme/projects/infra/destinations/{phone}/delete"), Some(&admin), "").await;
        assert_eq!(deleted.status, StatusCode::SEE_OTHER);
        assert!(db.list_notifications(infra).unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn browser_notifications_are_per_user() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        let bob = app.register("bob").await;
        let json = |path: &'static str, cookie: Option<String>, body: serde_json::Value| {
            let app = &app;
            async move {
                let mut req = HttpRequest::post(path)
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(c) = cookie {
                    req = req.header(header::COOKIE, c);
                }
                app.send(req.body(Body::from(body.to_string())).unwrap()).await
            }
        };

        // The page offers the feature with same-origin scripts only
        let settings = app.get("/settings", Some(&alice)).await;
        assert!(settings.body.contains("id=\"push-box\"") && settings.body.contains("src=\"/static/push.js\""));
        assert!(!settings.body.contains("<script>"));
        for (path, needle) in [("/static/push.js", "pushManager"), ("/sw.js", "showNotification")] {
            let script = app.get(path, None).await;
            assert_eq!(script.status, StatusCode::OK);
            assert!(script.body.contains(needle));
        }
        let key = app.get("/push/key", Some(&alice)).await;
        assert!(serde_json::from_str::<serde_json::Value>(&key.body).unwrap()["key"].as_str().unwrap().len() > 80);
        assert_eq!(app.get("/push/key", None).await.status, StatusCode::SEE_OTHER);

        // Subscribing needs a session and a public https push service
        let good = serde_json::json!({ "endpoint": "https://8.8.8.8/push/abc", "label": "laptop" });
        assert_eq!(json("/push/subscribe", None, good.clone()).await.status, StatusCode::SEE_OTHER);
        for bad in ["http://8.8.8.8/push", "https://127.0.0.1/push", "https://10.0.0.1/x", "nonsense"] {
            let r = json("/push/subscribe", Some(alice.clone()), serde_json::json!({ "endpoint": bad })).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
        }
        assert_eq!(json("/push/subscribe", Some(alice.clone()), good.clone()).await.status, StatusCode::OK);
        let db = Database::connect(&app.db_path).unwrap();
        let alice_id = db.get_credentials("alice").unwrap().unwrap().0.id;
        assert_eq!(db.list_push_subscriptions(alice_id).unwrap().len(), 1);
        assert!(app.get("/settings", Some(&alice)).await.body.contains("laptop"));

        // The inbox is read once, by its owner only; signed out, it is empty
        db.push_enqueue(alice_id, "Synchronization finished", "nvd: 3 added", "/admin/sources").unwrap();
        assert_eq!(app.get("/push/inbox", None).await.body, "[]");
        assert_eq!(app.get("/push/inbox", Some(&bob)).await.body, "[]");
        let inbox = app.get("/push/inbox", Some(&alice)).await.body;
        assert!(inbox.contains("Synchronization finished"));
        assert_eq!(app.get("/push/inbox", Some(&alice)).await.body, "[]");

        assert_eq!(json("/push/unsubscribe", Some(alice.clone()), good).await.status, StatusCode::OK);
        assert!(db.list_push_subscriptions(alice_id).unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rights_exist_at_instance_organization_and_project_level() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        app.post("/projects", Some(&admin), "org=acme&name=web").await;
        let db = Database::connect(&app.db_path).unwrap();

        // The creation form only shows on demand, and can give a first right
        let listing = app.get("/admin/users", Some(&admin)).await.body;
        assert!(!listing.contains("Initial password") && listing.contains("/admin/users?new=1"));
        assert!(app.get("/admin/users?new=1", Some(&admin)).await.body.contains("Initial password"));
        let created = app
            .post(
                "/admin/users",
                Some(&admin),
                "username=dev&password=a-long-password&scope=project%3Aacme%2Finfra&role=editor",
            )
            .await;
        assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
        let dev_id = db.get_credentials("dev").unwrap().unwrap().0.id;
        assert_eq!(created.location.as_deref(), Some(&*format!("/admin/users/{dev_id}")));
        // An unknown scope creates nothing
        let bad = app
            .post("/admin/users", Some(&admin), "username=ghost&password=a-long-password&scope=project%3Anope%2Fnope&role=editor")
            .await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST);
        assert!(db.get_credentials("ghost").unwrap().is_none());

        let login = app.post("/login", None, "username=dev&password=a-long-password").await;
        let dev = login.cookie.unwrap();

        // A project right: that project only — neither the other project, nor the
        // organization, nor the list of its projects, nor project creation
        assert_eq!(app.get("/product/acme/infra", Some(&dev)).await.status, StatusCode::OK);
        assert_eq!(app.get("/product/acme/web", Some(&dev)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/orgs/acme", Some(&dev)).await.status, StatusCode::NOT_FOUND);
        let projects = app.get("/projects", Some(&dev)).await.body;
        assert!(projects.contains("infra") && !projects.contains(">web<"));
        assert!(!app.get("/product", Some(&dev)).await.body.contains("/product/acme/web"));
        assert_eq!(app.post("/projects", Some(&dev), "org=acme&name=mine").await.status, StatusCode::NOT_FOUND);
        // It manages its own project (editor), not the members of it
        let add = app.post("/orgs/acme/projects/infra/applications", Some(&dev), "name=widget&version=1").await;
        assert_eq!(add.status, StatusCode::SEE_OTHER);
        assert_eq!(
            app.post("/orgs/acme/projects/web/applications", Some(&dev), "name=widget&version=1").await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.post("/orgs/acme/projects/infra/members", Some(&dev), "username=dev&role=owner").await.status,
            StatusCode::FORBIDDEN
        );
        // The API follows the same scope
        let page = app.post("/settings/tokens", Some(&dev), "name=t&password=a-long-password").await;
        let token = page.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
        let bearer = format!("Bearer {token}");
        assert_eq!(app.api("/api/organizations/acme/projects/infra", Some(&bearer)).await.status, StatusCode::OK);
        assert_eq!(app.api("/api/organizations/acme/projects/web", Some(&bearer)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api("/api/organizations/acme/projects", Some(&bearer)).await.status, StatusCode::NOT_FOUND);

        // A project owner gives access to their project only
        let assign = format!("/admin/users/{dev_id}/assign");
        app.post(&assign, Some(&admin), "scope=project%3Aacme%2Finfra&role=owner").await;
        app.post("/admin/users", Some(&admin), "username=mate&password=a-long-password").await;
        let given = app.post("/orgs/acme/projects/infra/members", Some(&dev), "username=mate&role=viewer").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER);
        let mate_id = db.get_credentials("mate").unwrap().unwrap().0.id;
        let infra = db.find_project("acme", "infra").unwrap().unwrap();
        let web = db.find_project("acme", "web").unwrap().unwrap();
        assert_eq!(db.project_role(mate_id, infra).unwrap(), Some(crate::rbac::Role::Viewer));
        assert_eq!(db.project_role(mate_id, web).unwrap(), None);

        // Bulk: a right at organization level for several users at once
        let bulk = format!("ids={dev_id}&ids={mate_id}&ids=99999&action=assign&scope=organization%3Aacme&role=viewer");
        let applied = app.post("/admin/users/bulk", Some(&admin), &bulk).await;
        assert_eq!(applied.status, StatusCode::SEE_OTHER);
        assert!(applied.cookie.unwrap().contains("Applied%20to%202%20of%203"));
        assert_eq!(db.project_role(mate_id, web).unwrap(), Some(crate::rbac::Role::Viewer));
        // The higher project role still wins on infra
        assert_eq!(db.project_role(dev_id, infra).unwrap(), Some(crate::rbac::Role::Owner));
        assert_eq!(app.get("/product/acme/web", Some(&dev)).await.status, StatusCode::OK);
        // Bulk status change skips the caller's own account
        let admin_id = db.get_credentials("root").unwrap().unwrap().0.id;
        let disable = format!("ids={admin_id}&ids={mate_id}&action=disable");
        let applied = app.post("/admin/users/bulk", Some(&admin), &disable).await;
        assert!(applied.cookie.unwrap().contains("Applied%20to%201%20of%202"));
        assert_eq!(app.get("/admin/users", Some(&admin)).await.status, StatusCode::OK);
        assert_eq!(app.post("/admin/users/bulk", Some(&admin), "action=disable").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/admin/users/bulk", Some(&dev), &bulk).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&assign, Some(&dev), "scope=instance&role=owner").await.status, StatusCode::FORBIDDEN);

        // Instance level: every organization; removing a right takes it away
        app.post(&assign, Some(&admin), "scope=instance&role=viewer").await;
        assert_eq!(app.get("/orgs/default", Some(&dev)).await.status, StatusCode::OK);
        for scope in ["instance", "organization%3Aacme", "project%3Aacme%2Finfra"] {
            app.post(&assign, Some(&admin), &format!("scope={scope}&role=none")).await;
        }
        assert_eq!(app.get("/product/acme/infra", Some(&dev)).await.status, StatusCode::NOT_FOUND);
        assert!(db.user_assignments(dev_id).unwrap().is_empty());
        let detail = app.get(&format!("/admin/users/{dev_id}"), Some(&admin)).await.body;
        assert!(detail.contains("this user sees no project"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scim_provisions_users_and_groups_inside_the_token_scope() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        app.post("/projects", Some(&admin), "org=acme&name=web").await;
        let db = Database::connect(&app.db_path).unwrap();
        let infra = db.find_project("acme", "infra").unwrap().unwrap();
        let web = db.find_project("acme", "web").unwrap().unwrap();

        // Tokens are created by an administrator and shown once
        let token_of = |scope: &'static str| {
            let (app, admin) = (&app, admin.clone());
            async move {
                let page = app.post("/admin/sso/scim/tokens", Some(&admin), &format!("name=idp&scope={scope}")).await;
                assert_eq!(page.status, StatusCode::OK, "{}", page.body);
                let token = page.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
                format!("Bearer {token}")
            }
        };
        let project_token = token_of("project%3Aacme%2Finfra").await;
        let other_token = token_of("project%3Aacme%2Fweb").await;
        assert!(!app.get("/admin/sso?tab=scim", Some(&admin)).await.body.contains(project_token.trim_start_matches("Bearer ")));

        let scim = |method: &'static str, path: String, auth: Option<String>, body: Option<serde_json::Value>| {
            let app = &app;
            async move {
                let mut req = HttpRequest::builder().method(method).uri(format!("/scim/v2{path}")).header(header::HOST, "localhost");
                if let Some(auth) = auth {
                    req = req.header(header::AUTHORIZATION, auth);
                }
                let body = match body {
                    Some(b) => {
                        req = req.header(header::CONTENT_TYPE, "application/scim+json");
                        Body::from(b.to_string())
                    }
                    None => Body::empty(),
                };
                let reply = app.send(req.body(body).unwrap()).await;
                let json: serde_json::Value = serde_json::from_str(&reply.body).unwrap_or(serde_json::Value::Null);
                (reply.status, json)
            }
        };
        let t = || Some(project_token.clone());

        // Authentication
        let (status, error) = scim("GET", "/Users".into(), None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error");
        assert_eq!(scim("GET", "/Users".into(), Some("Bearer nope".into()), None).await.0, StatusCode::UNAUTHORIZED);
        // An API token of a user is not a SCIM token
        let page = app.post("/settings/tokens", Some(&admin), "name=api&password=a-long-password").await;
        let api = page.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
        assert_eq!(scim("GET", "/Users".into(), Some(format!("Bearer {api}")), None).await.0, StatusCode::UNAUTHORIZED);

        // Discovery
        let (status, config) = scim("GET", "/ServiceProviderConfig".into(), t(), None).await;
        assert_eq!((status, config["patch"]["supported"].as_bool(), config["bulk"]["supported"].as_bool()), (StatusCode::OK, Some(true), Some(false)));
        assert_eq!(scim("GET", "/ResourceTypes".into(), t(), None).await.1["totalResults"], 2);
        assert_eq!(scim("GET", "/Schemas".into(), t(), None).await.1["totalResults"], 2);
        let (_, schema) = scim("GET", "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User".into(), t(), None).await;
        assert_eq!(schema["name"], "User");

        // Create: userName is kept verbatim, a local username is derived
        let new_user = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "Jane.Doe@corp.example", "externalId": "ext-1", "active": true,
            "name": { "givenName": "Jane", "familyName": "Doe" },
            "emails": [{ "value": "other@corp.example" }, { "value": "jane.doe@corp.example", "primary": true }],
        });
        let (status, created) = scim("POST", "/Users".into(), t(), Some(new_user.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["userName"], "Jane.Doe@corp.example");
        assert_eq!(created["displayName"], "jane.doe.p2");
        assert_eq!(created["emails"][0]["value"], "jane.doe@corp.example");
        assert_eq!(created["meta"]["resourceType"], "User");
        assert_eq!(scim("POST", "/Users".into(), t(), Some(new_user)).await.0, StatusCode::CONFLICT);
        assert_eq!(scim("POST", "/Users".into(), t(), Some(serde_json::json!({ "active": true }))).await.0, StatusCode::BAD_REQUEST);

        // The account belongs to the project of the token: no right can be given elsewhere
        let user_id: i64 = id.parse().unwrap();
        assert_eq!(db.user_origin(user_id).unwrap(), crate::db::Scope::Project(infra));
        let assign = format!("/admin/users/{user_id}/assign");
        assert_eq!(app.post(&assign, Some(&admin), "scope=project%3Aacme%2Fweb&role=viewer").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&assign, Some(&admin), "scope=instance&role=viewer").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&format!("/admin/users/{user_id}"), Some(&admin), "action=grant_admin").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&assign, Some(&admin), "scope=project%3Aacme%2Finfra&role=viewer").await.status, StatusCode::SEE_OTHER);
        assert_eq!(
            app.post("/orgs/acme/projects/web/members", Some(&admin), "username=jane.doe.p2&role=viewer").await.status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(db.project_role(user_id, web).unwrap(), None);

        // Filters and pagination
        let filter = |f: &str| format!("/Users?filter={}", views::enc(f));
        let (_, found) = scim("GET", filter(r#"userName eq "jane.doe@corp.example""#), t(), None).await;
        assert_eq!((found["totalResults"].as_i64(), found["Resources"][0]["id"].as_str()), (Some(1), Some(id.as_str())));
        assert_eq!(scim("GET", filter(r#"userName eq "nobody""#), t(), None).await.1["totalResults"], 0);
        assert_eq!(scim("GET", filter(r#"externalId eq "ext-1" and active eq true"#), t(), None).await.1["totalResults"], 1);
        assert_eq!(scim("GET", filter(r#"userName eq "a" or userName eq "b""#), t(), None).await.0, StatusCode::BAD_REQUEST);
        let (_, page) = scim("GET", "/Users?startIndex=2&count=10".into(), t(), None).await;
        assert_eq!((page["totalResults"].as_i64(), page["itemsPerPage"].as_i64(), page["startIndex"].as_i64()), (Some(1), Some(0), Some(2)));

        // Another token does not see it
        assert_eq!(scim("GET", format!("/Users/{id}"), Some(other_token.clone()), None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(scim("GET", "/Users".into(), Some(other_token.clone()), None).await.1["totalResults"], 0);
        assert_eq!(scim("DELETE", format!("/Users/{id}"), Some(other_token.clone()), None).await.0, StatusCode::NOT_FOUND);

        // PATCH as sent by common providers: string boolean, path forms
        let patch = |ops: serde_json::Value| serde_json::json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": ops });
        let (status, patched) = scim("PATCH", format!("/Users/{id}"), t(), Some(patch(serde_json::json!([
            { "op": "Replace", "path": "active", "value": "False" },
            { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "jd@corp.example" },
            { "op": "add", "path": "name.givenName", "value": "J" },
        ])))).await;
        assert_eq!(status, StatusCode::OK, "{patched}");
        assert_eq!((patched["active"].as_bool(), patched["emails"][0]["value"].as_str()), (Some(false), Some("jd@corp.example")));
        assert!(db.list_accounts().unwrap().iter().any(|a| a.id == user_id && a.disabled));
        let (_, patched) = scim("PATCH", format!("/Users/{id}"), t(), Some(patch(serde_json::json!([
            { "op": "replace", "value": { "active": true, "externalId": "ext-2" } },
            { "op": "remove", "path": "emails" },
        ])))).await;
        assert_eq!((patched["active"].as_bool(), patched["externalId"].as_str(), patched.get("emails")), (Some(true), Some("ext-2"), None));
        assert_eq!(
            scim("PATCH", format!("/Users/{id}"), t(), Some(patch(serde_json::json!([{ "op": "remove", "path": "userName" }])))).await.0,
            StatusCode::BAD_REQUEST
        );
        // PUT replaces: absent attributes are cleared
        let (status, replaced) = scim("PUT", format!("/Users/{id}"), t(), Some(serde_json::json!({ "userName": "jane@corp.example" }))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!((replaced["userName"].as_str(), replaced.get("externalId"), replaced["displayName"].as_str()), (Some("jane@corp.example"), None, Some("jane.doe.p2")));

        // Groups: members by id, rights given by an administrator inside the group's scope
        let (status, group) = scim("POST", "/Groups".into(), t(), Some(serde_json::json!({
            "displayName": "Operators", "members": [{ "value": id }],
        }))).await;
        assert_eq!(status, StatusCode::CREATED, "{group}");
        let group_id = group["id"].as_str().unwrap().to_string();
        assert_eq!(group["members"][0]["display"], "jane.doe.p2");
        assert_eq!(scim("POST", "/Groups".into(), t(), Some(serde_json::json!({ "displayName": "Operators" }))).await.0, StatusCode::CONFLICT);
        assert_eq!(
            scim("POST", "/Groups".into(), t(), Some(serde_json::json!({ "displayName": "Ghosts", "members": [{ "value": "99999" }] }))).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(scim("GET", "/Groups".into(), t(), None).await.1["totalResults"], 1);
        let (_, user) = scim("GET", format!("/Users/{id}"), t(), None).await;
        assert_eq!(user["groups"][0]["display"], "Operators");
        let (_, mine) = scim("GET", format!("/Groups?filter={}", views::enc(&format!("members eq \"{id}\""))), t(), None).await;
        assert_eq!(mine["totalResults"], 1);

        app.post(&assign, Some(&admin), "scope=project%3Aacme%2Finfra&role=none").await;
        assert_eq!(db.project_role(user_id, infra).unwrap(), None);
        let roles = format!("/admin/sso/scim/groups/{group_id}/roles");
        assert_eq!(app.post(&roles, Some(&admin), "scope=project%3Aacme%2Fweb&role=owner").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&roles, Some(&admin), "scope=instance&role=owner").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&roles, Some(&admin), "scope=project%3Aacme%2Finfra&role=editor").await.status, StatusCode::SEE_OTHER);
        assert_eq!(db.project_role(user_id, infra).unwrap(), Some(crate::rbac::Role::Editor));
        assert!(app.get("/admin/sso?tab=scim", Some(&admin)).await.body.contains("Operators"));

        // Membership changes take effect at once
        let (status, _) = scim("PATCH", format!("/Groups/{group_id}"), t(), Some(patch(serde_json::json!([
            { "op": "remove", "path": format!("members[value eq \"{id}\"]") },
        ])))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(db.project_role(user_id, infra).unwrap(), None);
        scim("PATCH", format!("/Groups/{group_id}"), t(), Some(patch(serde_json::json!([
            { "op": "add", "path": "members", "value": [{ "value": id }] },
            { "op": "replace", "path": "displayName", "value": "Ops" },
        ])))).await;
        assert_eq!(db.project_role(user_id, infra).unwrap(), Some(crate::rbac::Role::Editor));
        assert_eq!(scim("GET", format!("/Groups/{group_id}"), t(), None).await.1["displayName"], "Ops");
        let (_, replaced) = scim("PUT", format!("/Groups/{group_id}"), t(), Some(serde_json::json!({ "displayName": "Ops", "members": [] }))).await;
        assert_eq!(replaced["members"].as_array().map(Vec::len), Some(0));
        assert_eq!(db.project_role(user_id, infra).unwrap(), None);

        // Deprovisioning: gone for SCIM, disabled and kept for administrators
        assert_eq!(scim("DELETE", format!("/Users/{id}"), t(), None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(scim("GET", format!("/Users/{id}"), t(), None).await.0, StatusCode::NOT_FOUND);
        assert!(db.list_accounts().unwrap().iter().any(|a| a.id == user_id && a.disabled));
        assert_eq!(scim("DELETE", format!("/Groups/{group_id}"), t(), None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(scim("GET", format!("/Groups/{group_id}"), t(), None).await.0, StatusCode::NOT_FOUND);

        // Non-administrators cannot manage tokens or group rights
        let user = app.register("user").await;
        assert_eq!(app.post("/admin/sso/scim/tokens", Some(&user), "name=x&scope=instance").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&roles, Some(&user), "scope=instance&role=owner").await.status, StatusCode::FORBIDDEN);
        // A revoked token stops working
        let token_id = db.list_scim_tokens().unwrap()[0].id;
        app.post(&format!("/admin/sso/scim/tokens/{token_id}/delete"), Some(&admin), "").await;
        assert_eq!(scim("GET", "/Users".into(), t(), None).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inventory_is_delivered_then_chosen_from_a_checklist() {
        let app = app(with_inventory());
        let admin = app.register("root").await;
        let viewer = app.register("viewer").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        app.post("/orgs/acme/members", Some(&admin), "username=viewer&role=viewer").await;
        let db = Database::connect(&app.db_path).unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        let base = "/orgs/acme/projects/infra/inventory";
        let view = "/product/acme/infra?view=applications";

        // The source forms only show when a type is chosen, and the Git one says what is read
        let page = app.get(view, Some(&admin)).await.body;
        assert!(page.contains("Inventory sources") && !page.contains("name=\"repository\""));
        let git_form = app.get(&format!("{view}&new=git"), Some(&admin)).await.body;
        assert!(git_form.contains("name=\"repository\"") && git_form.contains("never clones the repository"));
        assert!(git_form.contains("read-only"));
        assert!(app.get(&format!("{view}&new=push"), Some(&admin)).await.body.contains("deliver the inventory of this source"));

        // A viewer cannot create a source
        assert_eq!(app.post(&format!("{base}/sources"), Some(&viewer), "kind=push&name=ci").await.status, StatusCode::FORBIDDEN);
        let created = app.post(&format!("{base}/sources"), Some(&admin), "kind=push&name=ci").await;
        assert_eq!(created.status, StatusCode::OK, "{}", created.body);
        let token = created.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
        assert!(!app.get(view, Some(&admin)).await.body.contains(&token));

        let push = |auth: Option<String>, body: String| {
            let app = &app;
            async move {
                let mut req = HttpRequest::post("/api/inventory").header(header::HOST, "localhost").header(header::CONTENT_TYPE, "application/json");
                if let Some(auth) = auth {
                    req = req.header(header::AUTHORIZATION, auth);
                }
                app.send(req.body(Body::from(body)).unwrap()).await
            }
        };
        let bearer = || Some(format!("Bearer {token}"));
        let inventory = serde_json::json!({ "components": [
            { "name": "libfoo", "version": "1.0" },
            { "name": "nginx", "version": "1.30.6", "vendor": "f5" },
            { "name": "custom-daemon", "version": "0.1", "exposed": true },
        ]})
        .to_string();

        // Only the token of a push source delivers; a user's API token does not
        assert_eq!(push(None, inventory.clone()).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(push(Some("Bearer nope".into()), inventory.clone()).await.status, StatusCode::UNAUTHORIZED);
        let api_page = app.post("/settings/tokens", Some(&admin), "name=api&password=a-long-password").await;
        let api = api_page.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string();
        assert_eq!(push(Some(format!("Bearer {api}")), inventory.clone()).await.status, StatusCode::UNAUTHORIZED);
        // And it only delivers: it is not an API credential
        assert_eq!(app.api("/api/cve", bearer().as_deref()).await.status, StatusCode::UNAUTHORIZED);

        // A project rule receives the announcement of new probable services in the browser inbox
        app.post("/orgs/acme/projects/infra/destinations", Some(&admin), "kind=browser&name=browsers&notify=1").await;
        let delivered = push(bearer(), inventory.clone()).await;
        assert_eq!(delivered.status, StatusCode::OK, "{}", delivered.body);
        let outcome: serde_json::Value = serde_json::from_str(&delivered.body).unwrap();
        assert_eq!((outcome["added"].as_i64(), outcome["new_probable_services"].as_array().map(Vec::len)), (Some(3), Some(2)));
        let inbox = app.get("/push/inbox", Some(&viewer)).await.body;
        assert!(inbox.contains("2 new probable service(s)") && inbox.contains("nginx 1.30.6"));
        // Delivering the same list again announces nothing
        push(bearer(), inventory.clone()).await;
        assert_eq!(app.get("/push/inbox", Some(&viewer)).await.body, "[]");
        assert_eq!(push(bearer(), "not json".into()).await.status, StatusCode::BAD_REQUEST);

        // The checklist ranks exposed components and known services first
        let page = app.get(view, Some(&admin)).await.body;
        let position = |name: &str| page.find(&format!("<strong>{name}</strong>")).unwrap_or(usize::MAX);
        assert!(position("custom-daemon") < position("nginx") && position("nginx") < position("libfoo"));
        assert!(page.contains("probable service") && page.contains("To choose (3)"));

        // Ticking components makes them tracked applications; viewers cannot
        let candidates = db.list_candidates(project).unwrap();
        let id = |name: &str| candidates.iter().find(|c| c.name == name).unwrap().id;
        let choose = format!("ids={}&ids={}&action=monitor", id("nginx"), id("custom-daemon"));
        assert_eq!(app.post(&format!("{base}/choose"), Some(&viewer), &choose).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("{base}/choose"), Some(&admin), "action=monitor").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&format!("{base}/choose"), Some(&admin), &choose).await.status, StatusCode::SEE_OTHER);
        let apps = db.list_applications(project).unwrap();
        assert_eq!(apps.len(), 2);
        assert!(apps.iter().any(|a| a.name == "nginx" && a.version.as_deref() == Some("1.30.6") && a.vendor.as_deref() == Some("f5")));
        app.post(&format!("{base}/choose"), Some(&admin), &format!("ids={}&action=ignore", id("libfoo"))).await;
        assert!(app.get(&format!("{view}&show=ignored"), Some(&admin)).await.body.contains("<strong>libfoo</strong>"));

        // The next delivery is followed: upgrade, and removal of what disappeared
        let next = serde_json::json!([{ "name": "nginx", "version": "1.31.0", "vendor": "f5" }]).to_string();
        let outcome: serde_json::Value = serde_json::from_str(&push(bearer(), next).await.body).unwrap();
        assert_eq!((outcome["updated"].as_i64(), outcome["removed"].as_i64()), (Some(1), Some(2)));
        let apps = db.list_applications(project).unwrap();
        assert_eq!((apps.len(), apps[0].version.as_deref()), (1, Some("1.31.0")));

        // A Git source is validated, and its token is never shown again
        let bad = app.post(&format!("{base}/sources"), Some(&admin), "kind=git&name=repo&provider=forgejo&repository=https%3A%2F%2F8.8.8.8%2Fme%2Fnixos&branch=main&path=..%2Fsecrets").await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST);
        let git = app
            .post(
                &format!("{base}/sources"),
                Some(&admin),
                "kind=git&name=repo&provider=forgejo&repository=https%3A%2F%2F127.0.0.1%3A9%2Fme%2Fnixos&branch=main&path=inventory%2Fio.json&token=git-secret",
            )
            .await;
        assert_eq!(git.status, StatusCode::OK);
        // The one file read is shown; the reading failed (private address refused) and says so
        assert!(git.body.contains("https://127.0.0.1:9/me/nixos/raw/branch/main/inventory/io.json"));
        // A token is never sent in clear
        let clear = "kind=git&name=clear&provider=forgejo&repository=http%3A%2F%2Fgit.example.org%2Fme%2Fnixos&branch=main&path=inv.json&token=t";
        assert_eq!(app.post(&format!("{base}/sources"), Some(&admin), clear).await.status, StatusCode::BAD_REQUEST);
        // An empty delivery is refused rather than removing everything
        assert_eq!(push(bearer(), "[]".into()).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(db.list_applications(project).unwrap().len(), 1);
        // A project editor cannot point a mail destination at the server itself or at odd ports
        for smtp in ["smtp_host=127.0.0.1&smtp_port=25", "smtp_host=localhost&smtp_port=587", "smtp_host=smtp.example.org&smtp_port=6379"] {
            let body = format!("kind=email&name=m&to=a%40example.org&{smtp}&smtp_from=v%40example.org");
            assert_eq!(app.post("/orgs/acme/projects/infra/destinations", Some(&admin), &body).await.status, StatusCode::BAD_REQUEST, "{smtp}");
        }
        assert!(git.body.contains("The first reading failed"));
        let listing = app.get(view, Some(&admin)).await.body;
        assert!(listing.contains("failed") && !listing.contains("git-secret"));
        let source_id = db.list_inventory_sources(project).unwrap().iter().find(|s| s.kind == "git").unwrap().id;
        assert_eq!(app.post(&format!("{base}/sources/{source_id}/run"), Some(&viewer), "").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("{base}/sources/{source_id}/run"), Some(&admin), "").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&format!("{base}/sources/{source_id}/delete"), Some(&admin), "").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&format!("{base}/sources/{source_id}/delete"), Some(&admin), "").await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inventory_is_greyed_out_unless_enabled() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        let base = "/orgs/acme/projects/infra/inventory";

        // Shown as coming, with nothing to act on
        let page = app.get("/product/acme/infra?view=applications&new=push", Some(&admin)).await.body;
        assert!(page.contains("Not in this release") && page.contains("disabled"));
        assert!(!page.contains(&format!("{base}/sources")) && !page.contains("name=\"auto_monitor\""));

        // Every entry point is closed, whatever the rights
        for (path, form) in [
            (format!("{base}/sources"), "kind=push&name=ci"),
            (format!("{base}/sources/1/delete"), ""),
            (format!("{base}/sources/1/run"), ""),
            (format!("{base}/choose"), "ids=1&action=monitor"),
        ] {
            assert_eq!(app.post(&path, Some(&admin), form).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        let req = HttpRequest::post("/api/inventory")
            .header(header::HOST, "localhost")
            .header(header::AUTHORIZATION, "Bearer anything")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(app.send(req).await.status, StatusCode::NOT_FOUND);
        let db = Database::connect(&app.db_path).unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        assert!(db.list_inventory_sources(project).unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identical_machines_are_triaged_once_per_group() {
        let app = app(with_inventory());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        let db = Database::connect(&app.db_path).unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        db.replace_distro_advisories(
            "Debian",
            &[crate::db::DistroAdvisory {
                ecosystem: "Debian:12".into(),
                package: "openssh".into(),
                cve_id: "CVE-2024-6387".into(),
                introduced: "0".into(),
                fixed: Some("1:9.2p1-2+deb12u3".into()),
                urgency: None,
                details: Some("Race condition in sshd".into()),
                published: None,
            }],
        )
        .unwrap();
        let view = "/product/acme/infra?view=applications";
        // The form explains groups and offers to monitor everything
        let form = app.get(&format!("{view}&new=push"), Some(&admin)).await.body;
        assert!(form.contains("name=\"group\"") && form.contains("name=\"auto_monitor\"") && form.contains("triaged together"));

        // Two web servers in the same group, each with its own token
        let mut tokens = Vec::new();
        for name in ["web-01", "web-02"] {
            let created = app
                .post("/orgs/acme/projects/infra/inventory/sources", Some(&admin), &format!("kind=push&name={name}&group=web&auto_monitor=1"))
                .await;
            assert_eq!(created.status, StatusCode::OK, "{}", created.body);
            tokens.push(created.body.split("<code class=\"token\">").nth(1).and_then(|s| s.split('<').next()).unwrap().to_string());
        }
        let deliver = |token: String, version: &'static str| {
            let app = &app;
            async move {
                // What `vulnizard-collector` sends for `type = "dpkg"`
                let body = serde_json::json!({ "components": [
                    { "name": "openssh", "version": version, "ecosystem": "Debian:12" },
                    { "name": "bash", "version": "5.2.15-2", "ecosystem": "Debian:12" },
                ]})
                .to_string();
                let req = HttpRequest::post("/api/inventory")
                    .header(header::HOST, "localhost")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap();
                app.send(req).await
            }
        };
        for token in &tokens {
            assert_eq!(deliver(token.clone(), "1:9.2p1-2+deb12u2").await.status, StatusCode::OK);
        }
        // One application per package for the group, one CVE to decide — not one per machine
        let apps = db.list_applications(project).unwrap();
        assert_eq!(apps.len(), 2);
        assert!(apps.iter().all(|a| a.group == "web"));
        let review = app.get("/product/acme/infra?view=review", Some(&admin)).await.body;
        assert_eq!(review.matches("CVE-2024-6387</a>").count(), 1);
        assert!(review.contains(">web</span>"));
        let page = app.get(view, Some(&admin)).await.body;
        assert!(page.contains("2 sources") && page.contains(">web</span>"));
        // Packages reported by a source follow the source: no manual version field or removal
        assert!(!page.contains("/applications/") || !page.contains("name=\"version\" value=\"1:9.2p1"));

        // One machine is patched: the CVE stays open for the other one
        deliver(tokens[0].clone(), "1:9.2p1-2+deb12u3").await;
        assert_eq!(db.list_applications(project).unwrap().iter().filter(|a| a.name == "openssh").count(), 2);
        assert_eq!(db.project_triage(project, false).unwrap().len(), 1);
        // Both patched: nothing left to review, the old version is gone
        deliver(tokens[1].clone(), "1:9.2p1-2+deb12u3").await;
        assert!(db.project_triage(project, false).unwrap().is_empty());
        let versions: Vec<Option<String>> =
            db.list_applications(project).unwrap().into_iter().filter(|a| a.name == "openssh").map(|a| a.version).collect();
        assert_eq!(versions, [Some("1:9.2p1-2+deb12u3".to_string())]);
        // The audit keeps what happened to the old version
        let audit = app.get("/product/acme/infra?view=audit&decision=all", Some(&admin)).await.body;
        assert!(audit.contains("CVE-2024-6387"));
    }

    // ---------- SSO against a mock identity provider ----------

    #[derive(Clone)]
    struct MockIdp {
        issuer: String,
        /// (subject, username, groups, nonce to put in the ID token)
        identity: Arc<Mutex<(String, String, Vec<String>, String)>>,
    }

    async fn mock_idp() -> MockIdp {
        use axum::extract::Form;
        use base64::Engine;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idp = MockIdp {
            issuer: format!("http://{}", listener.local_addr().unwrap()),
            identity: Arc::new(Mutex::new(("sub-1".into(), "jdoe".into(), vec!["admins".into()], String::new()))),
        };
        let (meta, token, userinfo) = (idp.clone(), idp.clone(), idp.clone());
        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    Json(serde_json::json!({
                        "issuer": meta.issuer,
                        "authorization_endpoint": format!("{}/authorize", meta.issuer),
                        "token_endpoint": format!("{}/token", meta.issuer),
                        "userinfo_endpoint": format!("{}/userinfo", meta.issuer),
                    }))
                }),
            )
            .route(
                "/token",
                post(move |Form(form): Form<std::collections::HashMap<String, String>>| async move {
                    let valid = form.get("code").map(String::as_str) == Some("good-code")
                        && form.get("client_secret").map(String::as_str) == Some("s3cret")
                        && form.get("grant_type").map(String::as_str) == Some("authorization_code")
                        && form.get("code_verifier").is_some_and(|v| v.len() >= 43);
                    if !valid {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_grant" })));
                    }
                    let (sub, _, _, nonce) = token.identity.lock().unwrap().clone();
                    let enc = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
                    let id_token = format!(
                        "{}.{}.signature",
                        enc(serde_json::json!({ "alg": "RS256" })),
                        enc(serde_json::json!({
                            "iss": token.issuer, "aud": "vulnizard", "sub": sub, "nonce": nonce,
                            "exp": chrono::Utc::now().timestamp() + 300,
                        }))
                    );
                    (StatusCode::OK, Json(serde_json::json!({ "id_token": id_token, "access_token": "at", "token_type": "Bearer" })))
                }),
            )
            .route(
                "/userinfo",
                get(move || async move {
                    let (sub, username, groups, _) = userinfo.identity.lock().unwrap().clone();
                    Json(serde_json::json!({
                        "sub": sub, "preferred_username": username, "groups": groups,
                        "email": format!("{username}@example.org"),
                        "email_verified": !username.starts_with("unverified"),
                    }))
                }),
            );
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        idp
    }

    fn sso_config(idp: &MockIdp) -> Config {
        let mut config = Config::default();
        config.web.base_url = "http://localhost".into();
        config.oidc = Some(crate::config::OidcConfig {
            issuer: idp.issuer.clone(),
            client_id: "vulnizard".into(),
            client_secret: "s3cret".into(),
            name: "Mock".into(),
            scopes: "openid profile email groups".into(),
            auto_create: true,
            link_existing_accounts: false,
            admin_group: Some("admins".into()),
            allowed_domains: vec![],
        });
        config
    }

    /// Starts a login: returns (state, state cookie) and gives the nonce to the mock
    async fn sso_begin(app: &TestApp, idp: &MockIdp) -> (String, String) {
        let start = app.get("/auth/oidc/config/login", None).await;
        assert_eq!(start.status, StatusCode::SEE_OTHER);
        let location = url::Url::parse(start.location.as_deref().unwrap()).unwrap();
        assert!(location.as_str().starts_with(&format!("{}/authorize?", idp.issuer)));
        let param = |name: &str| {
            location
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        assert_eq!(param("redirect_uri"), "http://localhost/auth/oidc/config/callback");
        assert_eq!(param("code_challenge_method"), "S256");
        assert_eq!(param("client_id"), "vulnizard");
        assert!(param("code_challenge").len() >= 43);
        idp.identity.lock().unwrap().3 = param("nonce");
        (param("state"), start.cookie.expect("state cookie"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sso_login_creates_and_reuses_accounts() {
        let idp = mock_idp().await;
        let app = app(sso_config(&idp));
        assert!(app.get("/login", None).await.body.contains("Log in with Mock"));

        // First login creates the account; the group makes it administrator
        let (state, cookie) = sso_begin(&app, &idp).await;
        let callback = format!("/auth/oidc/config/callback?code=good-code&state={state}");
        let done = app.get(&callback, Some(&cookie)).await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        assert_eq!(done.location.as_deref(), Some("/"));
        let session = done.cookie.expect("session cookie");
        assert!(session.starts_with("vz_session="));
        assert_eq!(app.get("/admin/users", Some(&session)).await.status, StatusCode::OK);
        let db = Database::connect(&app.db_path).unwrap();
        let accounts = db.list_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].username == "jdoe" && accounts[0].sso && !accounts[0].has_password && accounts[0].is_admin);

        // The state is single-use
        assert_eq!(app.get(&callback, Some(&cookie)).await.status, StatusCode::BAD_REQUEST);

        // Second login reuses the account; leaving the group removes admin
        // (kept here because jdoe is the last administrator)
        idp.identity.lock().unwrap().2 = vec![];
        let (state, cookie) = sso_begin(&app, &idp).await;
        let again = app.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(again.status, StatusCode::SEE_OTHER);
        assert_eq!(db.list_accounts().unwrap().len(), 1);
        assert!(db.list_accounts().unwrap()[0].is_admin);

        // A disabled account cannot sign in through SSO either
        db.create_account("root", None, "h", true).unwrap();
        db.set_disabled(accounts[0].id, true).unwrap();
        let (state, cookie) = sso_begin(&app, &idp).await;
        let refused = app.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("disabled"));
        assert!(refused.cookie.as_deref().is_some_and(|c| !c.starts_with("vz_session=")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sso_rejects_forged_or_mismatched_responses() {
        let idp = mock_idp().await;
        let app = app(sso_config(&idp));
        let db = Database::connect(&app.db_path).unwrap();
        let no_session = |r: &Reply| r.status == StatusCode::BAD_REQUEST && !r.cookie.as_deref().is_some_and(|c| c.starts_with("vz_session="));

        // State not bound to this browser (no cookie / another cookie)
        let (state, cookie) = sso_begin(&app, &idp).await;
        let path = format!("/auth/oidc/config/callback?code=good-code&state={state}");
        assert!(no_session(&app.get(&path, None).await));
        assert!(no_session(&app.get(&path, Some("vz_oidc=other")).await));
        // Unknown state, provider error, missing code
        assert!(no_session(&app.get("/auth/oidc/config/callback?code=good-code&state=forged", Some("vz_oidc=forged")).await));
        assert!(no_session(&app.get("/auth/oidc/config/callback?error=access_denied", Some(&cookie)).await));
        assert!(no_session(&app.get(&format!("/auth/oidc/config/callback?state={state}"), Some(&cookie)).await));
        // Wrong authorization code
        assert!(no_session(&app.get(&format!("/auth/oidc/config/callback?code=bad&state={state}"), Some(&cookie)).await));

        // ID token carrying another nonce (replayed token)
        let (state, cookie) = sso_begin(&app, &idp).await;
        idp.identity.lock().unwrap().3 = "another-nonce".into();
        assert!(no_session(&app.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await));
        assert_eq!(db.count_accounts().unwrap(), 0);

        // A local account with the same username is never taken over
        db.create_account("jdoe", None, "h", true).unwrap();
        let (state, cookie) = sso_begin(&app, &idp).await;
        let taken = app.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert!(no_session(&taken));
        assert!(taken.body.contains("already exists"));
        assert!(!db.list_accounts().unwrap()[0].sso);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sso_can_link_existing_accounts_when_enabled_and_is_absent_otherwise() {
        let idp = mock_idp().await;
        let mut config = sso_config(&idp);
        config.oidc.as_mut().unwrap().link_existing_accounts = true;
        config.oidc.as_mut().unwrap().admin_group = None;
        let app = app(config);
        let db = Database::connect(&app.db_path).unwrap();
        let id = db.create_account("jdoe", None, "h", false).unwrap();
        let (state, cookie) = sso_begin(&app, &idp).await;
        let done = app.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        let accounts = db.list_accounts().unwrap();
        assert_eq!((accounts.len(), accounts[0].id, accounts[0].sso, accounts[0].is_admin), (1, id, true, false));

        // Without [oidc] the routes do not exist and the button is hidden
        let plain = super::tests::app(Config::default());
        assert_eq!(plain.get("/auth/oidc/config/login", None).await.status, StatusCode::NOT_FOUND);
        assert!(!plain.get("/login", None).await.body.contains("Log in with"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn administrators_add_their_own_sso_providers() {
        let idp = mock_idp().await;
        let mut config = open_registration();
        config.web.base_url = "http://localhost".into();
        let app = app(config);
        let admin = app.register("root").await;
        let user = app.register("user").await;
        let issuer = views::enc(&idp.issuer);
        let form = |slug: &str, extra: &str| {
            format!("name=Corp+SSO&slug={slug}&issuer={issuer}&client_id=vulnizard&client_secret=s3cret&scopes=openid+email&auto_create=1{extra}")
        };

        // Only administrators manage providers
        assert_eq!(app.get("/admin/sso", Some(&user)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/admin/sso", Some(&user), &form("corp", "")).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/admin/sso/corp", Some(&user), "action=delete").await.status, StatusCode::FORBIDDEN);

        // Validation
        for (bad, why) in [
            (form("config", ""), "reserved identifier"),
            (form("bad slug", ""), "invalid identifier"),
            (form("corp", "").replace(&issuer, "http%3A%2F%2Fid.example.org"), "plain http issuer"),
            (form("corp", "").replace("scopes=openid+email", "scopes=email"), "missing openid scope"),
            (form("corp", "").replace("client_secret=s3cret", "client_secret="), "missing secret"),
            (form("google", "").replace(&issuer, "https%3A%2F%2Faccounts.google.com"), "public provider without domains"),
            (form("gitlab", "&link_existing=1&allowed_domains=example.org").replace(&issuer, "https%3A%2F%2Fgitlab.com"), "linking on a public provider"),
        ] {
            assert_eq!(app.post("/admin/sso", Some(&admin), &bad).await.status, StatusCode::BAD_REQUEST, "{why}");
        }
        // Google is accepted with a domain restriction
        let google = form("google", "&allowed_domains=example.org").replace(&issuer, "https%3A%2F%2Faccounts.google.com");
        assert_eq!(app.post("/admin/sso", Some(&admin), &google).await.status, StatusCode::SEE_OTHER);

        // Two providers on the same mock, one restricted to another domain
        assert_eq!(app.post("/admin/sso", Some(&admin), &form("corp", "")).await.status, StatusCode::SEE_OTHER);
        let restricted = form("partner", "&allowed_domains=partner.example");
        assert_eq!(app.post("/admin/sso", Some(&admin), &restricted).await.status, StatusCode::SEE_OTHER);
        let listing = app.get("/admin/sso", Some(&admin)).await.body;
        assert!(listing.contains("http://localhost/auth/oidc/corp/callback"));
        assert!(!listing.contains("s3cret"));
        let login = app.get("/login", None).await.body;
        assert!(login.contains("/auth/oidc/corp/login") && login.contains("/auth/oidc/google/login"));

        // Sign-in through a provider added from the UI
        let begin = |slug: &'static str| {
            let (app, idp) = (&app, &idp);
            async move {
                let start = app.get(&format!("/auth/oidc/{slug}/login"), None).await;
                assert_eq!(start.status, StatusCode::SEE_OTHER);
                let location = url::Url::parse(start.location.as_deref().unwrap()).unwrap();
                let param = |name: &str| location.query_pairs().find(|(k, _)| k == name).unwrap().1.into_owned();
                assert_eq!(param("redirect_uri"), format!("http://localhost/auth/oidc/{slug}/callback"));
                idp.identity.lock().unwrap().3 = param("nonce");
                (param("state"), start.cookie.unwrap())
            }
        };
        let (state, cookie) = begin("corp").await;
        let done = app.get(&format!("/auth/oidc/corp/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        let db = Database::connect(&app.db_path).unwrap();
        assert!(db.list_accounts().unwrap().iter().any(|a| a.username == "jdoe" && a.sso && !a.is_admin));

        // A login started with one provider cannot be completed at another
        let (state, cookie) = begin("corp").await;
        let mixed = app.get(&format!("/auth/oidc/partner/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(mixed.status, StatusCode::BAD_REQUEST);

        // Domain restriction: jdoe@example.org is refused by the partner provider
        *idp.identity.lock().unwrap() = ("sub-2".into(), "newcomer".into(), vec![], String::new());
        let (state, cookie) = begin("partner").await;
        let refused = app.get(&format!("/auth/oidc/partner/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("not allowed"));
        assert!(!db.list_accounts().unwrap().iter().any(|a| a.username == "newcomer"));

        // Editing keeps the secret when left empty; a disabled or deleted provider disappears
        let edit = form("corp", "").replace("client_secret=s3cret", "client_secret=").replace("Corp+SSO", "Renamed");
        assert_eq!(app.post("/admin/sso", Some(&admin), &edit).await.status, StatusCode::SEE_OTHER);
        assert_eq!(db.get_sso_provider("corp").unwrap().unwrap().client_secret, "s3cret");
        assert!(app.get("/login", None).await.body.contains("Log in with Renamed"));
        assert_eq!(app.post("/admin/sso/corp", Some(&admin), "action=disable").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/auth/oidc/corp/login", None).await.status, StatusCode::NOT_FOUND);
        assert!(!app.get("/login", None).await.body.contains("/auth/oidc/corp/login"));
        assert_eq!(app.post("/admin/sso/partner", Some(&admin), "action=delete").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/admin/sso/partner", Some(&admin), "action=delete").await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/auth/oidc/partner/login", None).await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_project_provider_only_gives_access_to_its_project() {
        let idp = mock_idp().await;
        let mut config = open_registration();
        config.web.base_url = "http://localhost".into();
        let app = app(config);
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;
        app.post("/projects", Some(&admin), "org=acme&name=web").await;
        let db = Database::connect(&app.db_path).unwrap();
        let infra = db.find_project("acme", "infra").unwrap().unwrap();

        // The provider form only shows when adding; the provider belongs to one project
        let page = app.get("/admin/sso", Some(&admin)).await.body;
        assert!(!page.contains("name=\"client_secret\"") && page.contains("/admin/sso?new=1"));
        assert!(app.get("/admin/sso?new=1", Some(&admin)).await.body.contains("name=\"client_secret\""));
        let form = format!(
            "name=Infra+SSO&slug=infra-sso&issuer={}&client_id=vulnizard&client_secret=s3cret&scopes=openid+email\
             &auto_create=1&scope=project%3Aacme%2Finfra&default_role=editor&admin_group=admins",
            views::enc(&idp.issuer)
        );
        assert_eq!(app.post("/admin/sso", Some(&admin), &form).await.status, StatusCode::SEE_OTHER);
        let provider = db.get_sso_provider("infra-sso").unwrap().unwrap();
        assert_eq!(provider.scope, crate::db::Scope::Project(infra));
        // A project provider never designates administrators
        assert_eq!(provider.admin_group, None);

        let sign_in = |slug: &'static str| {
            let (app, idp) = (&app, &idp);
            async move {
                let start = app.get(&format!("/auth/oidc/{slug}/login"), None).await;
                let location = url::Url::parse(start.location.as_deref().unwrap()).unwrap();
                let param = |name: &str| location.query_pairs().find(|(k, _)| k == name).unwrap().1.into_owned();
                idp.identity.lock().unwrap().3 = param("nonce");
                let state = param("state");
                app.get(&format!("/auth/oidc/{slug}/callback?code=good-code&state={state}"), start.cookie.as_deref()).await
            }
        };

        // First sign-in: an account of the project, with the default role there and nowhere else
        // (the mock says the user is in "admins": ignored for a project provider)
        let done = sign_in("infra-sso").await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        let session = done.cookie.unwrap();
        let account = db.list_accounts().unwrap().into_iter().find(|a| a.username == "jdoe").unwrap();
        assert!(!account.is_admin);
        assert_eq!(db.user_origin(account.id).unwrap(), crate::db::Scope::Project(infra));
        assert_eq!(db.project_role(account.id, infra).unwrap(), Some(crate::rbac::Role::Editor));
        assert_eq!(app.get("/product/acme/infra", Some(&session)).await.status, StatusCode::OK);
        assert_eq!(app.get("/product/acme/web", Some(&session)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/admin", Some(&session)).await.status, StatusCode::FORBIDDEN);
        // No right outside the project can ever be given to it
        let assign = format!("/admin/users/{}/assign", account.id);
        assert_eq!(app.post(&assign, Some(&admin), "scope=organization%3Aacme&role=viewer").await.status, StatusCode::BAD_REQUEST);

        // An account provisioned by SCIM for the project is recognised at its first sign-in
        *idp.identity.lock().unwrap() = ("sub-9".into(), "pre.provisioned".into(), vec![], String::new());
        let provisioned = db
            .scim_create_user(crate::db::Scope::Project(infra), "pre.provisioned@example.org", None, None, true)
            .unwrap();
        let done = sign_in("infra-sso").await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        let accounts = db.list_accounts().unwrap();
        assert!(accounts.iter().any(|a| a.id == provisioned && a.sso));
        assert_eq!(accounts.iter().filter(|a| a.username.starts_with("pre")).count(), 1);

        // An instance provider cannot sign in an account that belongs to a project... and
        // a project account cannot use the provider of another project
        let other = form.replace("infra-sso", "web-sso").replace("project%3Aacme%2Finfra", "project%3Aacme%2Fweb");
        assert_eq!(app.post("/admin/sso", Some(&admin), &other).await.status, StatusCode::SEE_OTHER);
        *idp.identity.lock().unwrap() = ("sub-1".into(), "jdoe".into(), vec![], String::new());
        let refused = sign_in("web-sso").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("cannot sign in with this provider"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_administrators_use_the_instance_mail_server() {
        let mut config = open_registration();
        config.smtp = Some(crate::config::SmtpConfig {
            host: "smtp.example.org".into(),
            port: 587,
            username: None,
            password: None,
            from: "Vulnizard <vulnizard@example.org>".into(),
        });
        let app = app(config);
        let admin = app.register("root").await;
        let owner = app.register("owner").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        app.post("/projects", Some(&owner), "org=acme&name=infra").await;

        // A project destination needs its own SMTP server
        let without_server = "kind=email&name=team&to=team%40example.org&notify=1";
        let refused = app.post("/orgs/acme/projects/infra/destinations", Some(&owner), without_server).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("only an administrator"));
        let db = Database::connect(&app.db_path).unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        assert!(db.list_project_destinations(project).unwrap().is_empty());
        let form = app.get("/product/acme/infra?view=settings&new=email", Some(&owner)).await.body;
        assert!(form.contains("name=\"smtp_host\"") && !form.contains("Leave the server empty"));

        // An instance destination, created by an administrator, may use it
        let ops = "owner=instance&kind=email&name=ops&to=ops%40example.org";
        assert_eq!(app.post("/admin/notifications/destinations", Some(&owner), ops).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/admin/notifications/destinations", Some(&admin), ops).await.status, StatusCode::SEE_OTHER);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mcp_over_http_only_answers_its_own_origin() {
        let app = app(open_registration()); // public URL: http://127.0.0.1:8000
        let admin = app.register("root").await;
        assert_eq!(app.post("/admin/mcp", Some(&admin), "http_enabled=1").await.status, StatusCode::SEE_OTHER);
        let token = tokens_of(&app.post("/settings/tokens", Some(&admin), "name=mcp&password=a-long-password").await.body).remove(0);
        let call = |origin: Option<&'static str>, host: &'static str| {
            let (app, token) = (&app, token.clone());
            async move {
                let mut req = HttpRequest::post("/mcp")
                    .header(header::HOST, host)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(origin) = origin {
                    req = req.header(header::ORIGIN, origin);
                }
                app.send(req.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)).unwrap()).await.status
            }
        };
        // A program sends no Origin; a browser page of this instance sends its own
        assert_eq!(call(None, "127.0.0.1:8000").await, StatusCode::OK);
        assert_eq!(call(Some("http://127.0.0.1:8000"), "127.0.0.1:8000").await, StatusCode::OK);
        // Another site is refused, even when its name is also what the Host header says (DNS rebinding)
        assert_eq!(call(Some("http://evil.example"), "127.0.0.1:8000").await, StatusCode::FORBIDDEN);
        assert_eq!(call(Some("http://evil.example"), "evil.example").await, StatusCode::FORBIDDEN);
    }

    // ---------- two-step sign-in ----------

    /// Every page declares the icon of the site
    async fn cves_icon(app: &TestApp) -> bool {
        app.get("/login", None).await.body.contains("rel=\"icon\"")
    }

    /// Text of the n-th `<code class="token">` of a page
    fn tokens_of(body: &str) -> Vec<String> {
        body.split("<code class=\"token\">").skip(1).filter_map(|s| s.split('<').next()).map(String::from).collect()
    }

    /// Sets up the authenticator app of a signed-in account; returns (secret, recovery codes)
    async fn enrol_totp(app: &TestApp, session: &str) -> (String, Vec<String>) {
        let setup = app.post("/settings/mfa/totp", Some(session), "password=a-long-password").await;
        assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
        let secret = tokens_of(&setup.body).remove(0);
        let code = crate::mfa::code_at(&secret, crate::mfa::current_step()).unwrap();
        let done = app.post("/settings/mfa/totp/confirm", Some(session), &format!("code={code}")).await;
        assert_eq!(done.status, StatusCode::OK, "{}", done.body);
        (secret, tokens_of(&done.body))
    }

    /// Last step the server accepted for this account (does not depend on the clock of the test)
    fn last_step(app: &TestApp, username: &str) -> u64 {
        let db = Database::connect(&app.db_path).unwrap();
        let id = db.get_credentials(username).unwrap().unwrap().0.id;
        db.totp(id).unwrap().unwrap().2
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_step_sign_in_with_an_authenticator_app() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        assert!(app.get("/settings", Some(&alice)).await.body.contains("Not enabled"));

        // Setting it up needs the password, then a valid code
        assert_eq!(app.post("/settings/mfa/totp", Some(&alice), "password=wrong-password").await.status, StatusCode::BAD_REQUEST);
        let setup = app.post("/settings/mfa/totp", Some(&alice), "password=a-long-password").await;
        assert!(setup.body.contains("<svg") && setup.body.contains("Key:"));
        assert_eq!(app.post("/settings/mfa/totp/confirm", Some(&alice), "code=000000").await.status, StatusCode::BAD_REQUEST);
        assert!(app.get("/settings", Some(&alice)).await.body.contains("Not enabled"));
        let (secret, recovery) = enrol_totp(&app, &alice).await;
        assert_eq!(recovery.len(), crate::mfa::RECOVERY_CODES);
        assert!(app.get("/settings", Some(&alice)).await.body.contains("authenticator app"));
        // The secret and the codes are shown once
        let manage = app.get("/settings/mfa", Some(&alice)).await.body;
        assert!(!manage.contains(&secret) && !manage.contains(&recovery[0]));

        // The password alone no longer opens a session
        let login = || app.post("/login", None, "username=alice&password=a-long-password");
        let step = login().await;
        assert_eq!(step.location.as_deref(), Some("/login/mfa"));
        let pending = step.cookie.unwrap();
        assert!(pending.starts_with("vulnizard_mfa="));
        assert_eq!(app.get("/settings", Some(&pending)).await.location.as_deref(), Some("/login"));
        assert!(app.get("/login/mfa", Some(&pending)).await.body.contains("authenticator app"));
        assert_eq!(app.get("/login/mfa", None).await.location.as_deref(), Some("/login"));

        // Wrong code, then the code already used to enrol, then a fresh one
        assert_eq!(app.post("/login/mfa", Some(&pending), "code=000000").await.status, StatusCode::UNAUTHORIZED);
        let used = crate::mfa::code_at(&secret, last_step(&app, "alice")).unwrap();
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={used}")).await.status, StatusCode::UNAUTHORIZED);
        let opened = app.post("/login/mfa", Some(&pending), &format!("code={}", crate::mfa::code_at(&secret, last_step(&app, "alice") + 1).unwrap())).await;
        assert_eq!(opened.location.as_deref(), Some("/"));
        let session = opened.cookie.unwrap();
        assert!(session.starts_with(&format!("{SESSION_COOKIE}=")));
        assert_eq!(app.get("/settings", Some(&session)).await.status, StatusCode::OK);
        // The pending check served once
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", recovery[0])).await.location.as_deref(), Some("/login"));

        // A recovery code works once, however it is typed
        let pending = login().await.cookie.unwrap();
        let typed = recovery[1].to_uppercase().replace('-', "+");
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={typed}")).await.location.as_deref(), Some("/"));
        let pending = login().await.cookie.unwrap();
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", recovery[1])).await.status, StatusCode::UNAUTHORIZED);
        assert!(app.get("/settings/mfa", Some(&session)).await.body.contains("9 unused code"));

        // Too many wrong answers: back to the password
        let pending = login().await.cookie.unwrap();
        for _ in 1..crate::db::MAX_MFA_ATTEMPTS {
            assert_eq!(app.post("/login/mfa", Some(&pending), "code=111111").await.status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(app.post("/login/mfa", Some(&pending), "code=111111").await.location.as_deref(), Some("/login"));
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", recovery[2])).await.location.as_deref(), Some("/login"));

        // Wrong codes add up across sign-ins: the right password does not reset the count
        let pending = login().await.cookie.unwrap();
        for _ in 0..4 {
            assert_eq!(app.post("/login/mfa", Some(&pending), "code=222222").await.status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", recovery[2])).await.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(login().await.status, StatusCode::TOO_MANY_REQUESTS);
        app.unlock_second_step("alice");

        // The API takes a token, no longer the password
        use base64::Engine;
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("alice:a-long-password"));
        assert_eq!(app.api("/api/cve", Some(&basic)).await.status, StatusCode::UNAUTHORIZED);
        let token = tokens_of(&app.post("/settings/tokens", Some(&session), "name=ci&password=a-long-password").await.body).remove(0);
        assert_eq!(app.api("/api/cve", Some(&format!("Bearer {token}"))).await.status, StatusCode::OK);

        // New recovery codes cancel the previous ones
        let fresh = tokens_of(&app.post("/settings/mfa/recovery", Some(&session), "password=a-long-password").await.body);
        assert_eq!(fresh.len(), crate::mfa::RECOVERY_CODES);
        let pending = login().await.cookie.unwrap();
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", recovery[3])).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.post("/login/mfa", Some(&pending), &format!("code={}", fresh[0])).await.location.as_deref(), Some("/"));

        // Removing it needs the password; the password alone works again
        assert_eq!(app.post("/settings/mfa/totp/delete", Some(&session), "password=nope-nope-nope").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/settings/mfa/totp/delete", Some(&session), "password=a-long-password").await.status, StatusCode::SEE_OTHER);

        // Everything that happened to the second factor is on record, for the account itself
        let db = Database::connect(&app.db_path).unwrap();
        let id = db.get_credentials("alice").unwrap().unwrap().0.id;
        let mut trail: Vec<String> = db.list_security_events(Some(id), 100).unwrap().into_iter().map(|e| e.event).collect();
        trail.reverse();
        assert_eq!(
            trail,
            [
                "totp_enabled", "recovery_codes_generated", "recovery_code_used", "second_step_locked",
                "recovery_codes_generated", "recovery_code_used", "totp_removed"
            ]
        );
        let activity = app.get("/settings/mfa", Some(&session)).await.body;
        assert!(activity.contains("Authenticator app removed") && activity.contains("Signed in with a recovery code"));
        assert_eq!(login().await.location.as_deref(), Some("/"));
        assert_eq!(app.api("/api/cve", Some(&basic)).await.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_required_second_factor_holds_the_account_to_its_enrolment() {
        let app = app(open_registration());
        let root = app.register("root").await;
        let bob = app.register("bob").await;
        let db = Database::connect(&app.db_path).unwrap();
        let bob_id = db.get_credentials("bob").unwrap().unwrap().0.id;

        // Only an administrator sets the requirement of the instance
        assert_eq!(app.post("/admin/mfa", Some(&bob), "required=1").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/admin/mfa", Some(&root), "required=1").await.status, StatusCode::SEE_OTHER);

        // Everyone, the administrator included, is held to the enrolment
        for session in [&root, &bob] {
            assert_eq!(app.get("/product", Some(session)).await.location.as_deref(), Some("/settings/mfa"));
            assert_eq!(app.get("/settings", Some(session)).await.location.as_deref(), Some("/settings/mfa"));
            assert_eq!(app.post("/settings/tokens", Some(session), "name=x").await.status, StatusCode::FORBIDDEN);
            assert!(app.get("/settings/mfa", Some(session)).await.body.contains("A second factor is required"));
        }
        assert_eq!(app.post("/orgs", Some(&root), "name=acme").await.status, StatusCode::FORBIDDEN);
        // The password alone no longer opens the API either
        use base64::Engine;
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("bob:a-long-password"));
        assert_eq!(app.api("/api/cve", Some(&basic)).await.status, StatusCode::UNAUTHORIZED);

        // Once enrolled everything opens, and the last factor cannot be removed
        enrol_totp(&app, &bob).await;
        assert_eq!(app.get("/settings", Some(&bob)).await.status, StatusCode::OK);
        let removal = app.post("/settings/mfa/totp/delete", Some(&bob), "password=a-long-password").await;
        assert_eq!(removal.status, StatusCode::BAD_REQUEST);
        assert!(db.has_second_factor(bob_id).unwrap());

        // Lost device: an administrator resets it; the sessions close and the account enrols again
        enrol_totp(&app, &root).await;
        let detail = app.get(&format!("/admin/users/{bob_id}"), Some(&root)).await.body;
        assert!(detail.contains("authenticator app") && detail.contains("reset_mfa"));
        assert_eq!(app.post(&format!("/admin/users/{bob_id}"), Some(&bob), "action=reset_mfa").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("/admin/users/{bob_id}"), Some(&root), "action=reset_mfa").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/settings", Some(&bob)).await.location.as_deref(), Some("/login"));
        let again = app.post("/login", None, "username=bob&password=a-long-password").await;
        assert_eq!(again.location.as_deref(), Some("/"));
        let bob = again.cookie.unwrap();
        assert_eq!(app.get("/product", Some(&bob)).await.location.as_deref(), Some("/settings/mfa"));
        assert!(app.get(&format!("/admin/users/{bob_id}"), Some(&root)).await.body.contains("required, not set up"));

        // Requirement of one organization: only those who have a role in it
        assert_eq!(app.post("/admin/mfa", Some(&root), "").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/settings", Some(&bob)).await.status, StatusCode::OK);
        let carol = app.register("carol").await;
        app.post("/orgs", Some(&root), "name=acme").await;
        app.post("/orgs/acme/members", Some(&root), "username=bob&role=viewer").await;
        assert_eq!(app.post("/orgs/acme/mfa", Some(&bob), "required=1").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/orgs/acme/mfa", Some(&root), "required=1").await.status, StatusCode::SEE_OTHER);
        assert!(app.get("/orgs/acme", Some(&root)).await.body.contains("checked"));

        // The organization is closed to bob (no factor) and only that: the rest of his account works
        assert_eq!(app.get("/orgs/acme", Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.get("/product", Some(&bob)).await.status, StatusCode::OK);
        assert_eq!(app.get("/settings", Some(&bob)).await.status, StatusCode::OK);
        let listed = app.get("/orgs", Some(&bob)).await.body;
        assert!(listed.contains("closed: requires two-step sign-in") && listed.contains("/orgs/acme/leave"));
        assert!(app.get("/settings/mfa", Some(&bob)).await.body.contains("Closed until you set up a second factor"));
        // Someone without a factor cannot turn the requirement on (they would lock themselves out)
        app.post("/orgs", Some(&carol), "name=carols").await;
        let refused = app.post("/orgs/carols/mfa", Some(&carol), "required=1").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        // Added without being asked, bob can leave; the only owner cannot
        assert_eq!(app.post("/orgs/acme/leave", Some(&bob), "").await.status, StatusCode::SEE_OTHER);
        assert!(!app.get("/orgs", Some(&bob)).await.body.contains("acme"));
        assert_eq!(app.post("/orgs/carols/leave", Some(&carol), "").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/orgs/acme/leave", Some(&carol), "").await.status, StatusCode::NOT_FOUND);

        // The administrators read who did what; nobody else
        assert_eq!(app.get("/admin/security", Some(&carol)).await.status, StatusCode::FORBIDDEN);
        let log = app.get("/admin/security", Some(&root)).await.body;
        for needle in ["Two-step sign-in reset", "instance: required", "instance: not required", "organization acme: required", "Authenticator app set up"] {
            assert!(log.contains(needle), "{needle}");
        }
        let filtered = app.get("/admin/security?q=reset", Some(&root)).await.body;
        assert!(filtered.contains("Two-step sign-in reset") && !filtered.contains("Authenticator app set up"));
        assert!(app.get(&format!("/admin/users/{bob_id}"), Some(&root)).await.body.contains("Two-step sign-in reset"));
        // Saving the same requirement again records nothing
        app.post("/orgs/acme/mfa", Some(&root), "required=1").await;
        assert_eq!(db.list_security_events(None, 100).unwrap().iter().filter(|e| e.event == "mfa_requirement").count(), 3);
        assert_eq!(app.get("/settings", Some(&carol)).await.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_step_sign_in_with_a_passkey() {
        use webauthn_authenticator_rs::softpasskey::SoftPasskey;
        use webauthn_authenticator_rs::WebauthnAuthenticator;
        use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

        // Passkeys need a host name; the default address is an IP
        let plain = app(open_registration());
        let someone = plain.register("someone").await;
        assert!(plain.get("/settings/mfa", Some(&someone)).await.body.contains("Passkeys are not available"));

        let mut config = open_registration();
        config.web.base_url = "http://localhost".into();
        let app = app(config);
        let origin = Url::parse("http://localhost").unwrap();
        let alice = app.register("alice").await;
        assert!(app.get("/settings/mfa", Some(&alice)).await.body.contains("id=\"passkey-register\""));
        assert!(app.get("/static/mfa.js", None).await.body.contains("navigator.credentials"));
        // Live filters: the script is on every page and the forms carry what it refreshes
        assert!(app.get("/static/filter.js", None).await.body.contains("form.filters"));
        assert!(app.get("/static/logo.svg", None).await.body.starts_with("<svg"));
        assert!(cves_icon(&app).await);
        let cves = app.get("/cve", Some(&alice)).await.body;
        assert!(cves.contains("src=\"/static/filter.js\"") && cves.contains("class=\"filters\""));

        let json = |path: &'static str, cookie: String, body: String| {
            let app = &app;
            async move {
                let req = HttpRequest::post(path)
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(Body::from(body))
                    .unwrap();
                app.send(req).await
            }
        };

        // Registration needs the password and a name
        let start = |password: &'static str, name: &'static str| {
            json("/settings/mfa/passkeys/start", alice.clone(), serde_json::json!({ "password": password, "name": name }).to_string())
        };
        let refused = start("wrong-password", "laptop").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("\"error\""));
        assert_eq!(start("a-long-password", " ").await.status, StatusCode::BAD_REQUEST);
        let options = start("a-long-password", "laptop").await;
        assert_eq!(options.status, StatusCode::OK, "{}", options.body);
        let challenge: CreationChallengeResponse = serde_json::from_str(&options.body).unwrap();
        let mut authenticator = SoftPasskey::new(true);
        let credential = authenticator.do_registration(origin.clone(), challenge).unwrap();
        let credential = serde_json::to_string(&credential).unwrap();
        let registered = credential.clone();
        let finished = json("/settings/mfa/passkeys/finish", alice.clone(), credential.clone()).await;
        assert_eq!(finished.status, StatusCode::OK, "{}", finished.body);
        // The registration served once
        assert_eq!(json("/settings/mfa/passkeys/finish", alice.clone(), credential).await.status, StatusCode::BAD_REQUEST);
        let manage = app.get("/settings/mfa", Some(&alice)).await.body;
        assert!(manage.contains("laptop") && manage.contains("You have no recovery code"));

        // Sign-in: password, then the passkey
        let step = app.post("/login", None, "username=alice&password=a-long-password").await;
        assert_eq!(step.location.as_deref(), Some("/login/mfa"));
        let pending = step.cookie.unwrap();
        assert!(app.get("/login/mfa", Some(&pending)).await.body.contains("id=\"passkey-login\""));
        let options = json("/login/mfa/passkey/start", pending.clone(), "{}".into()).await;
        assert_eq!(options.status, StatusCode::OK, "{}", options.body);
        let challenge: RequestChallengeResponse = serde_json::from_str(&options.body).unwrap();
        let assertion = serde_json::to_string(&authenticator.do_authentication(origin.clone(), challenge).unwrap()).unwrap();
        let opened = json("/login/mfa/passkey/finish", pending.clone(), assertion.clone()).await;
        assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
        let session = opened.cookie.unwrap();
        assert!(session.starts_with(&format!("{SESSION_COOKIE}=")));
        assert_eq!(app.get("/settings", Some(&session)).await.status, StatusCode::OK);
        assert!(!app.get("/settings/mfa", Some(&session)).await.body.contains("<td>never</td>"));
        // The same answer does not open a second session
        assert_eq!(json("/login/mfa/passkey/finish", pending.clone(), assertion.clone()).await.status, StatusCode::UNAUTHORIZED);

        // An answer to another challenge is refused
        let pending = app.post("/login", None, "username=alice&password=a-long-password").await.cookie.unwrap();
        assert_eq!(json("/login/mfa/passkey/start", pending.clone(), "{}".into()).await.status, StatusCode::OK);
        assert_eq!(json("/login/mfa/passkey/finish", pending.clone(), assertion).await.status, StatusCode::UNAUTHORIZED);
        // Without a pending check there is nothing to start
        assert_eq!(json("/login/mfa/passkey/start", alice.clone(), "{}".into()).await.status, StatusCode::UNAUTHORIZED);

        // The passkey alone signs in: the authenticator says which account it is
        assert!(app.get("/login", None).await.body.contains("id=\"passkey-signin\""));
        assert!(!plain.get("/login", None).await.body.contains("passkey-signin"));
        let anonymous = |path: &'static str, cookie: Option<String>, body: String| {
            let app = &app;
            async move {
                let mut req = HttpRequest::post(path)
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(cookie) = cookie {
                    req = req.header(header::COOKIE, cookie);
                }
                app.send(req.body(Body::from(body)).unwrap()).await
            }
        };
        // The software authenticator keeps no list of accounts: the test plays that part of a
        // real one, which finds the credential by itself and returns the account identifier.
        let db = Database::connect(&app.db_path).unwrap();
        let user_id = db.get_credentials("alice").unwrap().unwrap().0.id;
        let handle = |user_id: i64| {
            use base64::Engine;
            let uuid = uuid::Uuid::parse_str(&db.mfa_handle(user_id).unwrap()).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uuid.as_bytes())
        };
        let credential_id = serde_json::from_str::<serde_json::Value>(&registered).unwrap()["id"].clone();
        let mut answers = Vec::new();
        for _ in 0..2 {
            let options = anonymous("/login/passkey/start", None, "{}".into()).await;
            assert_eq!(options.status, StatusCode::OK, "{}", options.body);
            let mut challenge: serde_json::Value = serde_json::from_str(&options.body).unwrap();
            assert_eq!(challenge["publicKey"]["allowCredentials"], serde_json::json!([]));
            assert_eq!(challenge["publicKey"]["userVerification"], "required");
            challenge["publicKey"]["allowCredentials"] = serde_json::json!([{ "type": "public-key", "id": credential_id }]);
            let challenge: RequestChallengeResponse = serde_json::from_value(challenge).unwrap();
            let assertion = serde_json::to_value(authenticator.do_authentication(origin.clone(), challenge).unwrap()).unwrap();
            answers.push((options.cookie.unwrap(), assertion));
        }
        let finish = |cookie: Option<String>, mut assertion: serde_json::Value, account: i64| {
            assertion["response"]["userHandle"] = serde_json::json!(handle(account));
            anonymous("/login/passkey/finish", cookie, assertion.to_string())
        };
        let (cookie, assertion) = answers.remove(0);
        // Without the cookie of the challenge nothing opens
        assert_eq!(finish(None, assertion.clone(), user_id).await.status, StatusCode::BAD_REQUEST);
        let opened = finish(Some(cookie.clone()), assertion.clone(), user_id).await;
        assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
        let direct = opened.cookie.unwrap();
        assert!(direct.starts_with(&format!("{SESSION_COOKIE}=")));
        assert_eq!(app.get("/settings", Some(&direct)).await.status, StatusCode::OK);
        // The challenge served once
        assert_eq!(finish(Some(cookie), assertion, user_id).await.status, StatusCode::BAD_REQUEST);
        // A passkey does not open the account of someone else
        let mallory = app.register("mallory").await;
        let _ = mallory;
        let mallory_id = db.get_credentials("mallory").unwrap().unwrap().0.id;
        let (cookie, assertion) = answers.remove(0);
        assert_eq!(finish(Some(cookie), assertion, mallory_id).await.status, StatusCode::UNAUTHORIZED);

        // Removing the passkey needs the password
        let id = db.mfa_status(user_id).unwrap().passkeys[0].id;
        let path = format!("/settings/mfa/passkeys/{id}/delete");
        assert_eq!(app.post(&path, Some(&session), "password=wrong-password").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post(&path, Some(&session), "password=a-long-password").await.status, StatusCode::SEE_OTHER);
        assert!(!db.has_second_factor(user_id).unwrap());
    }
}
