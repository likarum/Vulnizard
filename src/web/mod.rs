//! Web server (`vulnizard serve`): HTML UI + read-only REST API.
//!
//! Everything is embedded in the binary: pages are compiled `maud` templates,
//! the stylesheet is included at build time, and the database is the same
//! SQLite file as the CLI (one short-lived connection per request).

mod admin;
mod api;
mod charts;
mod deadlines;
mod inventory;
mod invitations;
mod mfa;
mod notifications;
mod oidc;
mod pages;
mod product;
mod projects;
mod scim;
mod setup;
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

    /// Asks the scheduler for a synchronization of one source, or of every
    /// enabled one. Sources already waiting, running, or started less than
    /// `web.min_manual_sync_minutes` ago are set aside: asking again and again
    /// does not hammer the upstream services or pile up cycles. Returns the
    /// sources that will be synchronized, or why none will.
    pub fn request_sync(&self, db: &Database, source: Option<String>, by: i64) -> Result<Vec<String>, String> {
        use crate::scheduler::{SyncOrder, SyncRequest};
        let config = crate::settings::effective(&self.config, db).map_err(|e| e.to_string())?;
        let all = source.is_none();
        let wanted = match source {
            Some(source) => vec![source],
            None => config.sync.sources.clone(),
        };
        let minutes = config.web.min_manual_sync_minutes;
        let recent = db.recently_synced_sources(minutes).map_err(|e| e.to_string())?;
        let mut queued = self.sync_queue.lock().unwrap_or_else(|e| e.into_inner());
        let accepted: Vec<String> = wanted.iter().filter(|s| !queued.contains(s) && !recent.contains(s)).cloned().collect();
        if accepted.is_empty() {
            return Err(if minutes > 0 {
                format!("already waiting, running, or synchronized less than {minutes} minutes ago")
            } else {
                "already waiting or running".to_string()
            });
        }
        let request = match (all && accepted.len() == wanted.len(), accepted.as_slice()) {
            (true, _) => SyncRequest::All,
            (false, [one]) if !all => SyncRequest::Source(one.clone()),
            _ => SyncRequest::Sources(accepted.clone()),
        };
        let sent = self.sync_trigger.lock().map(|tx| tx.send(SyncOrder { request, by: Some(by) }).is_ok()).unwrap_or(false);
        if !sent {
            return Err("the scheduler is not running".to_string());
        }
        queued.extend(accepted.iter().cloned());
        Ok(accepted)
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
            // A token first: it is the way meant for programs, and the only
            // one left once the account has a second factor
            let mut response = (status, body).into_response();
            for challenge in ["Bearer realm=\"vulnizard\"", "Basic realm=\"vulnizard\""] {
                response.headers_mut().append(header::WWW_AUTHENTICATE, header::HeaderValue::from_static(challenge));
            }
            response
        } else {
            (status, body).into_response()
        }
    }
}

// ==========================================
// Authentication extractors
// ==========================================

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub fn session_token(parts: &Parts) -> Option<String> {
    cookie_value(parts, SESSION_COOKIE)
}

/// Organization asked for by the menu of the products bar. What the browser
/// sends is only a wish: it is kept when it names an organization the account
/// sees a project of, and several are seen; anything else, unknown or not
/// visible alike, is no filter at all.
fn chosen_org(parts: &Parts, projects: &[(String, String)]) -> Option<String> {
    let asked = cookie_value(parts, views::ORG_COOKIE)?;
    let asked = percent_encoding::percent_decode_str(&asked).decode_utf8().ok()?;
    let several = projects.iter().any(|(org, _)| Some(org) != projects.first().map(|(first, _)| first));
    (several && projects.iter().any(|(org, _)| *org == asked)).then(|| asked.into_owned())
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
        let account = account.ok_or(ApiError(AppError::Unauthorized))?;
        // An account confined to the Overview reaches its figures and nothing else
        let route = parts.extensions.get::<axum::extract::MatchedPath>().map(|p| p.as_str().to_string());
        if !route.as_deref().is_some_and(|route| CONFINED_API.contains(&route)) {
            let confined = blocking(|| -> Result<bool, AppError> { Ok(state.db()?.summary_only(account.id)?) })?;
            if confined {
                return Err(ApiError(AppError::Forbidden));
            }
        }
        Ok(ApiUser(account))
    }
}

// ==========================================
// Accounts confined to the Overview
// ==========================================

/// Everything the web UI answers to an account confined to the Overview
/// (`Database::summary_only`: every role it holds is executive): method and
/// route, as the router names them. Any other route is refused before its
/// handler runs, whatever it is asked about: the answer tells nothing.
///
/// A route added to the router is refused to these accounts until it is
/// listed here (`an_executive_reaches_its_overview_and_nothing_else`).
pub(crate) const CONFINED_ROUTES: &[(&str, &str)] = &[
    // The Overview of what it holds, and the organization filter of its bar
    ("GET", "/"),
    ("GET", "/product"),
    ("GET", "/product/{org}/{project}"),
    ("POST", "/org-filter"),
    // Its own settings: password, two-step sign-in, tokens, invitations
    ("GET", "/settings"),
    ("POST", "/settings/password"),
    ("POST", "/settings/tokens"),
    ("POST", "/settings/tokens/{id}/delete"),
    ("GET", "/settings/mfa"),
    ("POST", "/settings/mfa/totp"),
    ("POST", "/settings/mfa/totp/confirm"),
    ("POST", "/settings/mfa/totp/delete"),
    ("POST", "/settings/mfa/recovery"),
    ("POST", "/settings/mfa/passkeys/start"),
    ("POST", "/settings/mfa/passkeys/finish"),
    ("POST", "/settings/mfa/passkeys/{id}/delete"),
    ("POST", "/invitations/{id}/accept"),
    ("POST", "/invitations/{id}/decline"),
    // Signing out, and in: these answer the same to everyone
    ("POST", "/logout"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/register"),
    ("POST", "/register"),
    ("GET", "/setup"),
    ("POST", "/setup"),
    ("GET", "/auth/oidc/{provider}/login"),
    ("GET", "/auth/oidc/{provider}/callback"),
    ("GET", "/login/mfa"),
    ("POST", "/login/mfa"),
    ("POST", "/login/mfa/passkey/start"),
    ("POST", "/login/mfa/passkey/finish"),
    ("POST", "/login/passkey/start"),
    ("POST", "/login/passkey/finish"),
    // Files of the page itself
    ("GET", "/static/app.css"),
    ("GET", "/static/logo.svg"),
    ("GET", "/static/logo.png"),
    ("GET", "/static/mfa.js"),
    ("GET", "/static/filter.js"),
    ("GET", "/static/theme.js"),
    ("GET", "/favicon.ico"),
];

/// What the REST API answers to such an account: its figures and the names
/// of the projects they are about. `/mcp` is in, the tools being narrowed by
/// the server itself (`mcp::CONFINED_TOOLS`).
pub(crate) const CONFINED_API: &[&str] = &[
    "/api/summary",
    "/api/summary/projects",
    "/api/organizations/{org}/projects/{project}/summary",
    "/mcp",
];

/// Refuses whatever is not in `CONFINED_ROUTES` to an account confined to
/// the Overview, with the answer a missing permission gets. Each handler and
/// each query still checks the rights on its own: this is what holds for the
/// routes that never looked at a project (reference database, organizations
/// to create, administration).
async fn confined_gate(State(state): St, req: Request, next: Next) -> Response {
    let method = if *req.method() == Method::HEAD { "GET" } else { req.method().as_str() };
    let open = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .is_some_and(|route| CONFINED_ROUTES.contains(&(method, route.as_str())));
    if open {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let confined = blocking(|| -> Result<bool, AppError> {
        match session_account(&parts, &state)? {
            Some(account) => Ok(state.db()?.summary_only(account.id)?),
            None => Ok(false),
        }
    });
    match confined {
        Ok(false) => next.run(Request::from_parts(parts, body)).await,
        Ok(true) => AppError::Forbidden.into_response(),
        Err(e) => e.into_response(),
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
        // The menus name what the account holds a role on, executive included
        let held = match &account {
            Some(a) => db.held_projects(a.id)?,
            None => Vec::new(),
        };
        let figures_only: Vec<(String, String)> =
            held.iter().filter(|p| !p.can_view()).map(|p| (p.org.clone(), p.name.clone())).collect();
        let projects: Vec<(String, String)> = held.into_iter().map(|p| (p.org, p.name)).collect();
        let confined = match &account {
            Some(a) => db.summary_only(a.id)?,
            None => false,
        };
        let org = chosen_org(&parts, &projects);
        let invitations = match &account {
            Some(a) => db.received_invitations(a.id)?.len(),
            None => 0,
        };
        Ok((
            account,
            views::PageContext {
                last_sync,
                sync_running,
                projects,
                figures_only,
                confined,
                org,
                path,
                invitations,
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
            // Scripts are same-origin files only; connect-src is for their fetch (filter.js, mfa.js)
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
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
        // A synchronization asked through MCP goes through the same gate as one asked in the UI
        let trigger = |source: Option<String>| state.request_sync(&db, source, user_id);
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
        .route("/org-filter", post(product::org_filter))
        .route("/projects", get(projects::projects).post(projects::project_create_any))
        .route("/orgs", get(pages::orgs).post(pages::org_create))
        .route("/orgs/{org}", get(pages::org_detail))
        .route("/orgs/{org}/delete", post(pages::org_delete))
        .route("/orgs/{org}/members", post(pages::member_add))
        .route("/orgs/{org}/members/{user_id}/delete", post(pages::member_remove))
        .route("/orgs/{org}/invitations/{id}/cancel", post(invitations::org_cancel))
        .route("/orgs/{org}/projects/{project}/invitations/{id}/cancel", post(invitations::project_cancel))
        .route("/invitations/{id}/accept", post(invitations::accept))
        .route("/invitations/{id}/decline", post(invitations::decline))
        .route("/orgs/{org}/projects", post(projects::project_create))
        .route("/orgs/{org}/projects/{project}", get(project_redirect))
        .route("/orgs/{org}/projects/{project}/delete", post(projects::project_delete))
        .route(
            "/orgs/{org}/projects/{project}/watchlist/{entry_id}",
            post(projects::watchlist_status),
        )
        .route("/applications", post(projects::application_add_any))
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
        .route("/orgs/{org}/projects/{project}/notifications", post(notifications::project_notifications_save))
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
        .route("/setup", get(setup::form).post(setup::submit))
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
        .route("/static/theme.js", get(pages::theme_script))
        .route("/login/passkey/start", post(mfa::passwordless_start))
        .route("/login/passkey/finish", post(mfa::passwordless_finish))
        .route("/orgs/{org}/mfa", post(mfa::org_requirement))
        .route("/orgs/{org}/leave", post(mfa::org_leave))
        .route("/admin/mfa", post(admin::mfa_requirement))
        .route("/admin/security", get(admin::security_log))
        .route("/admin/security/export", get(admin::security_log_export))
        .route("/orgs/{org}/audit/export", get(pages::org_audit_export))
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
            get(notifications::admin_destination).post(notifications::admin_destination_action),
        )
        .route("/admin/notifications/{id}", post(notifications::admin_project_test))
        .route("/admin/mcp", get(admin::mcp).post(admin::mcp_save))
        .route("/admin/deadlines", get(deadlines::admin).post(deadlines::admin_save))
        .route("/orgs/{org}/deadlines", post(deadlines::org_save))
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
        .route("/static/logo.png", get(pages::logo_png))
        .route("/favicon.ico", get(pages::logo))
        .fallback(|| async { AppError::NotFound })
        .layer(middleware::from_fn_with_state(state.clone(), confined_gate))
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
        .route("/security-log", get(api::security_log))
        .route("/organizations/{org}/audit", get(api::audit_log))
        .route("/organizations", get(api::organizations))
        .route("/organizations/{org}/projects", get(api::projects))
        .route("/organizations/{org}/projects/{project}", get(api::project))
        .route("/organizations/{org}/projects/{project}/watchlist", get(api::watchlist))
        .route("/organizations/{org}/projects/{project}/summary", get(api::project_summary))
        .route("/summary", get(api::summary))
        .route("/summary/projects", get(api::summary_projects))
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
        setup::announce(&state);
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
        cve.nuclei_template = Some("http/cves/2024/CVE-2024-4242.yaml".into());
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
        csp: Option<String>,
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
            let (status, location, cookie, cache, csp) = (
                resp.status(),
                header(header::LOCATION),
                header(header::SET_COOKIE).map(|c| c.split(';').next().unwrap().to_string()),
                header(header::CACHE_CONTROL),
                header(header::CONTENT_SECURITY_POLICY),
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            Reply {
                status,
                location,
                cookie,
                cookies,
                cache,
                csp,
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

        /// Accepts every invitation waiting for an account: what follows a
        /// name typed in a member form, when the tests are about something else
        fn accept_invitations(&self, username: &str) {
            let db = Database::connect(&self.db_path).unwrap();
            let id = db.get_credentials(username).unwrap().unwrap().0.id;
            let waiting = db.received_invitations(id).unwrap();
            assert!(!waiting.is_empty(), "no invitation waiting for {username}");
            for invitation in waiting {
                assert!(db.accept_invitation(id, invitation.id).unwrap().is_some());
            }
        }

        /// The setup code of an instance without accounts
        fn setup_code(&self) -> Option<String> {
            Database::connect(&self.db_path).unwrap().setup_code().unwrap()
        }

        /// Creates an account: the first through the setup page, the others by registration
        async fn register(&self, username: &str) -> String {
            let reply = match self.setup_code() {
                Some(code) => {
                    let form = format!("code={code}&username={username}&password=a-long-password&confirm=a-long-password");
                    self.post("/setup", None, &form).await
                }
                None => self.post("/register", None, &format!("username={username}&password=a-long-password")).await,
            };
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
        // Static assets stay public; without any account, signing in leads to the setup page
        assert_eq!(app.get("/static/app.css", None).await.status, StatusCode::OK);
        assert_eq!(app.get("/login", None).await.location.as_deref(), Some("/setup"));
        assert_eq!(app.get("/setup", None).await.status, StatusCode::OK);

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
        // A detection template is shown as such, with a link to it, and is not an exploit
        assert!(detail.body.contains("https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4242.yaml"));
        assert!(detail.body.contains("Detection") && !detail.body.contains("public exploit"));
        // CVEs by source: the page names the sources of a CVE, and the list narrows to one
        assert!(detail.body.contains("href=\"/cve?source=nuclei\"") && !detail.body.contains("/cve?source=metasploit"));
        assert!(app.get("/cve?source=nuclei", Some(&alice)).await.body.contains("CVE-2024-4242"));
        assert!(!app.get("/cve?source=metasploit", Some(&alice)).await.body.contains("CVE-2024-4242"));
        assert_eq!(app.get("/cve?source=bogus", Some(&alice)).await.status, StatusCode::BAD_REQUEST);

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
            for view in ["", "?view=vulnerabilities", "?view=vulnerabilities&show=handled", "?view=applications", "?view=subscriptions",
                         "?view=history", "?view=history&days=365&at=2026-01-01", "?view=history&at=garbage",
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

        // Notifications: private targets are refused; what a destination sends is saved from the table
        let base = "/orgs/acme/projects/infra";
        let refused = app
            .post(&format!("{base}/destinations"), Some(&alice), "name=local&kind=webhook&url=http%3A%2F%2F127.0.0.1%2Fhook")
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        let ok = app
            .post(
                &format!("{base}/destinations"),
                Some(&alice),
                "name=mail&kind=email&to=sec%40example.org&smtp_host=smtp.example.org&smtp_port=587&smtp_from=v%40example.org",
            )
            .await;
        assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
        let mail = db.list_project_destinations(project_id).unwrap()[0].id;
        let table = format!("id={mail}&enabled_{mail}=1&events_{mail}=created&events_{mail}=kev&events_{mail}=bogus&min_cvss_{mail}=7");
        assert_eq!(app.post(&format!("{base}/notifications"), Some(&alice), &table).await.status, StatusCode::SEE_OTHER);
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
            app.accept_invitations(name);
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
            ..Default::default()
        });
        db.upsert_cve(&cve).unwrap();

        let app_form = "name=widget&version=1.0&vendor=acme";
        assert_eq!(app.post(&format!("{base}/applications"), Some(&viewer), app_form).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post(&format!("{base}/applications"), Some(&editor), app_form).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&format!("{base}/applications"), Some(&editor), app_form).await.status, StatusCode::BAD_REQUEST);
        let project_id = db.find_project("acme", "infra").unwrap().unwrap();
        let entry = db.project_triage(project_id, false).unwrap()[0].entry_id;
        let app_id = db.list_applications(project_id).unwrap()[0].id.unwrap();

        // Everyone sees the entry; the list shows it with actions only for those who can triage
        for page in ["/product/acme/infra?view=vulnerabilities", "/product?view=vulnerabilities"] {
            let viewer_page = app.get(page, Some(&viewer)).await;
            assert!(viewer_page.body.contains("CVE-2024-4343"), "{page}");
            assert!(!viewer_page.body.contains(&format!("/watchlist/{entry}")), "{page}");
            assert!(app.get(page, Some(&editor)).await.body.contains(&format!("/watchlist/{entry}")), "{page}");
        }
        // The overview counts it, and names neither the CVE nor a decision to take
        for page in ["/product/acme/infra", "/product"] {
            let figures = app.get(page, Some(&editor)).await.body;
            assert!(figures.contains(&open_figure(page, 1)) && !figures.contains("CVE-2024-4343") && !figures.contains("/watchlist/"), "{page}");
        }
        // The history draws its charts without any inline style or script
        let overview = app.get("/product?view=history", Some(&editor)).await.body;
        assert!(overview.contains("<svg") && overview.contains("stroke-p0"));
        // No inline style or script: the only scripts are the external ones of the theme and of the live filters
        let without_files = overview
            .replace("<script src=\"/static/theme.js\"></script>", "")
            .replace("<script src=\"/static/filter.js\" defer></script>", "");
        assert!(!overview.contains("style=") && without_files.matches("<script").count() == 0);

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
        assert!(app.get("/product?view=history", Some(&viewer)).await.body.contains("behind VPN"));
        // The return page is never an external URL
        let evil = app
            .post(&triage, Some(&editor), "status=untreated&back=https%3A%2F%2Fevil.example%2F")
            .await;
        assert_eq!(evil.location.as_deref(), Some("/product/acme/infra?view=vulnerabilities"));
        let evil = app.post(&triage, Some(&editor), "status=treated&back=%2F%2Fevil.example").await;
        assert_eq!(evil.location.as_deref(), Some("/product/acme/infra?view=vulnerabilities"));
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
    async fn the_first_administrator_takes_the_setup_code() {
        // Registration is open here: even so, the first account is not for whoever comes first
        let app = app(open_registration());
        let db = Database::connect(&app.db_path).unwrap();
        let code = app.setup_code().unwrap();
        let good = |code: &str| format!("code={code}&username=root&password=a-long-password&confirm=a-long-password");

        let page = app.get("/setup", None).await;
        assert!(page.status == StatusCode::OK && page.body.contains("Setup code") && !page.body.contains(&code));
        assert_eq!(app.get("/register", None).await.location.as_deref(), Some("/setup"));
        assert_eq!(app.post("/register", None, "username=eve&password=a-long-password").await.status, StatusCode::BAD_REQUEST);

        // Without the code nothing is created, and nothing else is told
        let wrong = app.post("/setup", None, "code=AAAAA-AAAAA-AAAAA-AAAAA&username=x&password=short&confirm=other").await;
        assert!(wrong.status == StatusCode::UNAUTHORIZED && wrong.body.contains("Wrong setup code") && wrong.cookie.is_none());
        // With it, the usual rules on the account apply
        let mismatch = app.post("/setup", None, &format!("code={code}&username=root&password=a-long-password&confirm=another-password")).await;
        assert!(mismatch.status == StatusCode::BAD_REQUEST && mismatch.body.contains("passwords differ"));
        let short = app.post("/setup", None, &format!("code={code}&username=root&password=short&confirm=short")).await;
        assert_eq!(short.status, StatusCode::BAD_REQUEST);
        assert_eq!(db.count_accounts().unwrap(), 0);

        // A restart of the server gives a new code: one read in an old log opens nothing
        setup::announce(&app.state);
        let old = code;
        let code = app.setup_code().unwrap();
        assert_ne!(old, code);
        assert_eq!(app.post("/setup", None, &good(&old)).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(db.count_accounts().unwrap(), 0);

        // Guessing is cut short, for the address that guesses only
        for _ in 0..auth::MAX_FAILURES {
            app.post_from("203.0.113.9", "/setup", None, &good("AAAAA-AAAAA-AAAAA-AAAAB")).await;
        }
        assert_eq!(app.post_from("203.0.113.9", "/setup", None, &good(&code)).await.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(db.count_accounts().unwrap(), 0);

        // The code, typed loosely, creates the administrator and signs them in
        let done = app.post("/setup", None, &good(&code.to_lowercase().replace('-', ""))).await;
        assert_eq!((done.status, done.location.as_deref()), (StatusCode::SEE_OTHER, Some("/")));
        let root = done.cookie.expect("session cookie");
        let account = db.get_credentials("root").unwrap().unwrap().0;
        assert!(account.is_admin);
        // No page of the setup outlives it
        assert_eq!(app.get("/welcome", Some(&root)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.list_security_events(Some(account.id), 10).unwrap()[0].event, "instance_set_up");

        // Closed for good: the page is gone, the code is dead, a second try creates nothing
        assert_eq!(app.setup_code(), None);
        assert_eq!(app.get("/setup", None).await.location.as_deref(), Some("/login"));
        let replay = app.post("/setup", None, &format!("code={code}&username=mallory&password=a-long-password&confirm=a-long-password")).await;
        assert_eq!(replay.status, StatusCode::NOT_FOUND);
        assert_eq!(db.count_accounts().unwrap(), 1);
        assert_eq!(app.get("/login", None).await.status, StatusCode::OK);
        // Later accounts register as before, without administration rights
        app.register("bob").await;
        assert!(!db.get_credentials("bob").unwrap().unwrap().0.is_admin);

        // The session given by the setup is an ordinary administrator session, and the
        // password chosen there is the one that signs in afterwards
        assert_eq!(app.get("/admin", Some(&root)).await.status, StatusCode::OK);
        assert_eq!(app.post("/logout", Some(&root), "").await.location.as_deref(), Some("/login"));
        assert_eq!(app.get("/admin", Some(&root)).await.location.as_deref(), Some("/login"));
        assert_eq!(app.post("/login", None, "username=root&password=another-password").await.status, StatusCode::UNAUTHORIZED);
        let signed_in = app.post("/login", None, "username=root&password=a-long-password").await;
        assert_eq!(signed_in.location.as_deref(), Some("/"));
        assert_eq!(app.get("/admin", Some(&signed_in.cookie.unwrap())).await.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_place_a_password_is_chosen_applies_the_same_rules() {
        let app = app(open_registration());
        let db = Database::connect(&app.db_path).unwrap();
        let code = app.setup_code().unwrap();
        // Fourteen characters; common words; the alphabet; the username with little around
        let refused = ["short-pass-001", "passwordpassword1", "abcdefghijklmnopq", "qwertyuiopasdfgh"];

        // Setup
        for password in refused.iter().chain(["rootroot-2024-x"].iter()) {
            let reply = app.post("/setup", None, &format!("code={code}&username=rootroot&password={password}&confirm={password}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "setup accepted {password}");
            assert!(reply.body.contains("at least 15") || reply.body.contains("easy to guess"), "{password}");
        }
        assert_eq!(db.count_accounts().unwrap(), 0);
        assert!(app.get("/setup", None).await.body.contains("At least 15 characters"));
        let admin = app.register("root").await;

        // Registration
        for password in refused.iter().chain(["mallory-mallory1"].iter()) {
            let reply = app.post("/register", None, &format!("username=mallory&password={password}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "registration accepted {password}");
        }
        assert!(db.get_credentials("mallory").unwrap().is_none());

        // Change of one's own password: the current one stays in place when the new one is refused
        for password in refused.iter().chain(["root-root-root-1"].iter()) {
            let reply = app.post("/settings/password", Some(&admin), &format!("current=a-long-password&new={password}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "change accepted {password}");
        }
        assert_eq!(app.post("/login", None, "username=root&password=a-long-password").await.location.as_deref(), Some("/"));

        // An administrator creating an account, or resetting a password
        for password in refused.iter().chain(["carol-carol-2024"].iter()) {
            let reply = app.post("/admin/users", Some(&admin), &format!("username=carol&password={password}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "creation accepted {password}");
        }
        assert!(db.get_credentials("carol").unwrap().is_none());
        assert_eq!(app.post("/admin/users", Some(&admin), "username=carol&password=a-long-password").await.status, StatusCode::SEE_OTHER);
        let carol = db.get_credentials("carol").unwrap().unwrap().0.id;
        for password in refused.iter().chain(["carol-carol-2024"].iter()) {
            let reply = app.post("/admin/users/password", Some(&admin), &format!("user_id={carol}&password={password}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "reset accepted {password}");
        }
        assert_eq!(app.post("/login", None, "username=carol&password=a-long-password").await.location.as_deref(), Some("/"));

        // A password chosen under the old rule (ten characters) still signs in: the rule
        // applies when a password is chosen, not when it is used
        db.create_account("oldtimer", None, &auth::hash_password("ten-chars!").unwrap(), false).unwrap();
        assert_eq!(app.post("/login", None, "username=oldtimer&password=ten-chars!").await.location.as_deref(), Some("/"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_setup_refuses_what_a_sign_in_would_refuse() {
        let app = app(Config::default());
        let db = Database::connect(&app.db_path).unwrap();
        let code = app.setup_code().unwrap();
        let form = |username: &str, extra: &str| format!("code={code}&username={username}&password=a-long-password&confirm=a-long-password{extra}");

        // Nothing answers without an account: no page, no API
        for path in ["/product", "/cve", "/admin", "/settings"] {
            assert_eq!(app.get(path, None).await.location.as_deref(), Some("/login"), "{path}");
        }
        assert_eq!(app.api("/api/cve", None).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.api("/api/cve", Some(&format!("Bearer {code}"))).await.status, StatusCode::UNAUTHORIZED);
        // The setup code is not a password: it signs nobody in
        assert_eq!(app.post("/login", None, &format!("username=root&password={code}")).await.status, StatusCode::UNAUTHORIZED);

        // A form posted from another site is refused, even with the right code
        for origin in [None, Some("http://evil.example")] {
            let mut req = HttpRequest::post("/setup")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(o) = origin {
                req = req.header(header::ORIGIN, o);
            }
            let reply = app.send(req.body(Body::from(form("root", ""))).unwrap()).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "origin {origin:?}");
        }
        // Names and addresses follow the rules of every account
        assert!(auth::is_reserved_username("default"));
        for (username, extra) in [("default", ""), ("ab", ""), ("ro ot", ""), ("root", "&email=not-an-address")] {
            let reply = app.post("/setup", None, &form(&username.replace(' ', "+"), extra)).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{username} {extra}");
            assert!(reply.cookie.is_none());
        }
        let too_long = format!("code={code}&username=root&password={0}&confirm={0}", "x".repeat(auth::MAX_PASSWORD_LEN + 1));
        assert_eq!(app.post("/setup", None, &too_long).await.status, StatusCode::BAD_REQUEST);
        // A missing field is a bad request, not an account
        assert!(app.post("/setup", None, &format!("code={code}&username=root")).await.status.is_client_error());
        assert_eq!(db.count_accounts().unwrap(), 0);
        // None of this used up the code or the attempts of the address
        assert_eq!(app.setup_code().as_deref(), Some(code.as_str()));
        assert_eq!(app.post("/setup", None, &form("root", "&email=root%40example.org")).await.location.as_deref(), Some("/"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_setup_closes_however_the_first_account_comes() {
        // From the command line: the page never opens, and a code read before is dead
        let app_cli = app(open_registration());
        let code = app_cli.setup_code().unwrap();
        let db = Database::connect(&app_cli.db_path).unwrap();
        let admin = db.create_account("root", None, &auth::hash_password("a-long-password").unwrap(), true).unwrap();
        let form = format!("code={code}&username=mallory&password=a-long-password&confirm=a-long-password");
        assert_eq!(app_cli.setup_code(), None);
        assert_eq!(app_cli.get("/setup", None).await.location.as_deref(), Some("/login"));
        assert_eq!(app_cli.get("/login", None).await.status, StatusCode::OK);
        assert_eq!(app_cli.post("/setup", None, &form).await.status, StatusCode::NOT_FOUND);
        // The last administrator cannot be disabled, and a disabled account is still an
        // account: the setup does not come back that way
        assert!(db.set_disabled(admin, true).is_err());
        let other = db.create_account("other", None, "h", true).unwrap();
        db.set_disabled(admin, true).unwrap();
        db.set_disabled(other, true).unwrap_err();
        assert_eq!(app_cli.post("/login", None, "username=root&password=a-long-password").await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app_cli.post("/setup", None, &form).await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.count_accounts().unwrap(), 2);

        // With single sign-on declared, the sign-in page stays (accounts come from there);
        // the setup is still there for who has the code, until the first account exists
        let idp = mock_idp().await;
        let app_sso = app(sso_config(&idp));
        let code = app_sso.setup_code().unwrap();
        let form = format!("code={code}&username=mallory&password=a-long-password&confirm=a-long-password");
        let login = app_sso.get("/login", None).await;
        assert!(login.status == StatusCode::OK && login.body.contains("Log in with Mock"));
        assert_eq!(app_sso.get("/setup", None).await.status, StatusCode::OK);
        let (state, cookie) = sso_begin(&app_sso, &idp).await;
        let done = app_sso.get(&format!("/auth/oidc/config/callback?code=good-code&state={state}"), Some(&cookie)).await;
        assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
        assert_eq!(app_sso.setup_code(), None);
        assert_eq!(app_sso.post("/setup", None, &form).await.status, StatusCode::NOT_FOUND);
        let db = Database::connect(&app_sso.db_path).unwrap();
        assert_eq!(db.list_accounts().unwrap().len(), 1);
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
        assert!(app.get("/static/app.css", None).await.cache.as_deref() == Some("no-cache"));

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
        db.complete_sync(id, 1, 0, 0).unwrap();
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
            ("/admin/notifications/destinations/1", "action=save&enabled=1"),
            ("/admin/notifications/1", "action=test&project=1"),
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
        // The page says how often each source downloads and what, and that "Sync now" does not wait
        let sources = app.get("/admin/sources", Some(&admin)).await.body;
        for shown in ["At every cycle: only the CVEs changed", "At most every 12 h: only the advisories changed", "At most every 24 h: the whole file of scores", "At most every 6 h", "downloads at once, without waiting"] {
            assert!(sources.contains(shown), "{shown}");
        }
        // It says so in a bubble opened by a small "i", reachable from the keyboard, without script
        assert!(sources.contains("<span class=\"info\" tabindex=\"0\"><span class=\"i\" aria-hidden=\"true\">i</span><span class=\"bubble\" role=\"note\">At every cycle"));
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
        db.complete_sync(run, 3, 0, 0).unwrap();
        // Asking again for a source that is waiting or just ran is not repeated, and says why
        let again = app.post("/admin/sources/osv", Some(&admin), "action=sync").await;
        let flash = again.cookie.expect("explanation");
        assert!(flash.contains("not%20requested") && flash.contains("less%20than%205%20minutes"), "{flash}");
        assert!(app.sync_rx.try_recv().is_err());
        // "Sync now" leaves out what just ran and asks for the rest; a second click asks for nothing
        app.post("/sync", Some(&admin), "back=%2Fadmin").await;
        assert_eq!(
            app.sync_rx.try_recv().unwrap().request,
            SyncRequest::Sources(vec!["nvd".into(), "cisa_kev".into(), "vulnrichment".into()])
        );
        let second = app.post("/sync", Some(&admin), "back=%2Fadmin").await;
        assert_eq!(second.location.as_deref(), Some("/admin"));
        assert!(app.sync_rx.try_recv().is_err());

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
        let ntfy = "kind=ntfy&name=phone&url=http%3A%2F%2F127.0.0.1%3A9%2Fvulns";
        assert_eq!(app.post(create, Some(&admin), ntfy).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/admin/notifications/delivery", Some(&admin), "allow_private=1").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(create, Some(&admin), ntfy).await.status, StatusCode::SEE_OTHER);
        // The destination belongs to its project: it notifies that one, not the other, and starts with every event
        let phone = db.list_project_destinations(infra).unwrap()[0].id;
        assert_eq!(db.list_notifications(infra).unwrap().len(), 1);
        assert_eq!(db.get_destination(phone).unwrap().unwrap().events, crate::db::all_events());
        assert!(db.list_notifications(web).unwrap().is_empty());
        let foreign = format!("id={phone}&events_{phone}=kev");
        assert_eq!(app.post("/orgs/acme/projects/web/notifications", Some(&admin), &foreign).await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.get_destination(phone).unwrap().unwrap().events, crate::db::all_events());
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
        let gear = format!("/admin/notifications/destinations/{}", stored.id);
        for page in ["/product/acme/web?view=settings", "/admin/notifications", "/admin/notifications?tab=destinations", gear.as_str()] {
            let body = app.get(page, Some(&admin)).await.body;
            assert!(!body.contains("smtp-secret"), "{page}");
        }

        // Administration: what notifies each project, every destination, instance destinations
        let rules = app.get("/admin/notifications", Some(&admin)).await.body;
        assert!(rules.contains("phone") && rules.contains("infra"));
        let destinations = app.get("/admin/notifications?tab=destinations", Some(&admin)).await.body;
        assert!(destinations.contains("phone") && destinations.contains("sec@example.org (via smtp.example.org)"));
        assert!(!destinations.contains("name=\"owner\""));
        assert!(app.get("/admin/notifications?tab=destinations&new=ntfy", Some(&admin)).await.body.contains("name=\"owner\""));
        let ops = "owner=instance&kind=ntfy&name=ops&url=http%3A%2F%2F127.0.0.1%3A9%2Fops&system_events=1";
        assert_eq!(app.post("/admin/notifications/destinations", Some(&admin), ops).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/admin/notifications/destinations", Some(&user), ops).await.status, StatusCode::FORBIDDEN);
        // An instance destination receives the notifications of every project by itself, and instance events
        let ops_id = db.list_system_destinations().unwrap()[0].id;
        assert!(db.list_notifications(web).unwrap().iter().any(|n| n.id == ops_id));
        assert!(db.list_notifications(infra).unwrap().iter().any(|n| n.id == ops_id));
        let org_scoped = "owner=organization%3Aacme&kind=ntfy&name=team&url=http%3A%2F%2F127.0.0.1%3A9%2Fteam&system_events=1";
        app.post("/admin/notifications/destinations", Some(&admin), org_scoped).await;
        assert_eq!(db.list_system_destinations().unwrap().len(), 1); // organization destinations never get instance events

        // A destination managed elsewhere is its owner's: the project page shows neither its name nor its target,
        // and cannot change it
        let web_settings = app.get("/product/acme/web?view=settings", Some(&admin)).await.body;
        assert!(web_settings.contains("Destinations of the organization or of the whole instance, if there are any, also receive"));
        assert!(!web_settings.contains("ops") && !web_settings.contains("team"), "{web_settings}");
        assert!(!web_settings.contains("127.0.0.1:9/ops") && !web_settings.contains("127.0.0.1:9/team"));
        let not_ours = format!("id={ops_id}&events_{ops_id}=kev");
        assert_eq!(app.post("/orgs/acme/projects/web/notifications", Some(&admin), &not_ours).await.status, StatusCode::NOT_FOUND);
        assert_eq!(
            app.post(&format!("/orgs/acme/projects/web/destinations/{ops_id}/delete"), Some(&admin), "").await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(db.get_destination(ops_id).unwrap().unwrap().events, crate::db::all_events());
        // The project's own destination shows which service it sends to, to those who manage the
        // project; the rest of its address is a secret and stays out of the page
        let settings = app.get("/product/acme/infra?view=settings", Some(&admin)).await.body;
        assert!(settings.contains("http://127.0.0.1/…") && !settings.contains("127.0.0.1:9/vulns"), "{settings}");

        // A test send reports the failure (nothing listens on that port) instead of crashing
        let action = format!("/admin/notifications/{phone}");
        let tested = app.post(&action, Some(&admin), &format!("action=test&project={infra}")).await;
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
        // The test of a project only goes through a destination that receives its notifications
        assert_eq!(app.post(&action, Some(&admin), &format!("action=test&project={web}")).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.post(&action, Some(&admin), "action=test&project=nope").await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.post(&action, Some(&admin), &format!("action=delete&project={infra}")).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            app.post(&format!("/admin/notifications/{ops_id}"), Some(&admin), &format!("action=test&project={web}")).await.status,
            StatusCode::SEE_OTHER
        );

        // Deleting the destination stops it
        let deleted = app.post(&format!("/orgs/acme/projects/infra/destinations/{phone}/delete"), Some(&admin), "").await;
        assert_eq!(deleted.status, StatusCode::SEE_OTHER);
        assert!(db.list_notifications(infra).unwrap().iter().all(|n| n.scope != "project"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_destination_tells_what_it_covers_and_what_it_sends() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        let user = app.register("user").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        for project in ["infra", "web"] {
            app.post("/projects", Some(&admin), &format!("org=acme&name={project}")).await;
        }
        for form in [
            "owner=instance&kind=ntfy&name=Everyone&url=https%3A%2F%2F8.8.8.8%2Feveryone&system_events=1",
            "owner=organization%3Aacme&kind=ntfy&name=Team&url=https%3A%2F%2F8.8.8.8%2Fteam",
            "owner=project%3Aacme%2Finfra&kind=ntfy&name=Solo&url=https%3A%2F%2F8.8.8.8%2Fsolo",
        ] {
            assert_eq!(app.post("/admin/notifications/destinations", Some(&admin), form).await.status, StatusCode::SEE_OTHER);
        }
        let db = Database::connect(&app.db_path).unwrap();
        let id_of = |name: &str| db.list_all_destinations().unwrap().into_iter().find(|d| d.name == name).unwrap().id;
        let (everyone, team, solo) = (id_of("Everyone"), id_of("Team"), id_of("Solo"));
        let list = "/admin/notifications?tab=destinations";
        let row = |page: &str, name: &str| page.split("<tr>").find(|r| r.contains(&format!("<td>{name}</td>"))).unwrap().to_string();

        // Nobody picked anything, and nobody has to: each row says what it covers and what it sends
        let page = app.get(list, Some(&admin)).await.body;
        assert!(page.contains("Covers<span") && page.contains("<th>Sends</th>"));
        let row_everyone = row(&page, "Everyone");
        assert!(row_everyone.contains("<td>all projects</td><td>every event<div class=\"muted\">and instance events (sync finished)</div></td>"), "{row_everyone}");
        assert!(row(&page, "Team").contains("<td>projects of organization acme</td><td>every event</td>"));
        assert!(row(&page, "Solo").contains("<td>project acme / infra</td><td>every event</td>"));
        // The address of a topic or of a webhook is a secret: the pages name the service, not the rest
        assert!(page.contains("<td>https://8.8.8.8/…</td>"), "{}", row_everyone);
        for secret in ["8.8.8.8/everyone", "8.8.8.8/team", "8.8.8.8/solo"] {
            assert!(!page.contains(secret), "{secret}");
            assert!(!app.get(&format!("/admin/notifications/destinations/{everyone}"), Some(&admin)).await.body.contains(secret));
            assert!(!app.get("/product/acme/infra?view=settings", Some(&admin)).await.body.contains(secret));
        }
        // What the former model said is no longer true, and no longer said
        for gone in ["no project yet", "until a project picks it", "Offered to", "Used by", "It sends nothing"] {
            assert!(!page.contains(gone), "{gone}");
        }
        // The gear of a row: a link with a name for those who do not see the glyph
        let gear = format!("/admin/notifications/destinations/{everyone}");
        assert!(row_everyone.contains(&format!(
            "<a class=\"btn gear\" href=\"{gear}\" title=\"Configure what it sends\" aria-label=\"Configure Everyone\"><span aria-hidden=\"true\">\u{2699}\u{fe0e}</span></a>"
        )), "{row_everyone}");

        // Its page: everything checked on a new destination, no minimum CVSS
        let config = app.get(&gear, Some(&admin)).await;
        assert_eq!(config.status, StatusCode::OK);
        assert!(config.body.contains("Destination “Everyone”") && config.body.contains("receives the notifications of all projects."));
        assert!(config.body.contains("<input type=\"checkbox\" name=\"enabled\" value=\"1\" checked>"));
        for (kind, _) in crate::changes::EVENT_TYPES {
            assert!(config.body.contains(&format!("<input type=\"checkbox\" name=\"events\" value=\"{kind}\" checked>")), "{kind}");
        }
        assert_eq!(config.body.matches("name=\"events\"").count(), crate::changes::EVENT_TYPES.len());
        assert!(config.body.contains("<input type=\"number\" name=\"min_cvss\" min=\"0\" max=\"10\" step=\"0.1\" value=\"\">"));
        assert!(config.body.contains("<input type=\"checkbox\" name=\"system_events\" value=\"1\" checked>"));
        // Instance events are only offered to a destination of the instance
        let team_page = app.get(&format!("/admin/notifications/destinations/{team}"), Some(&admin)).await.body;
        assert!(team_page.contains("projects of organization acme") && !team_page.contains("name=\"system_events\""));
        // Closed to anyone but an administrator, and to nobody without a session
        assert_eq!(app.get(&gear, Some(&user)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.get(&gear, None).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&gear, None, "action=save").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post(&gear, Some(&user), "action=save").await.status, StatusCode::FORBIDDEN);
        assert_eq!(db.get_destination(everyone).unwrap().unwrap().events, crate::db::all_events());
        assert_eq!(app.get("/admin/notifications/destinations/99999", Some(&admin)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.post("/admin/notifications/destinations/99999", Some(&admin), "action=save").await.status, StatusCode::NOT_FOUND);

        // Saving: what is checked is what it sends
        let saved = app.post(&gear, Some(&admin), "action=save&enabled=1&events=kev&events=created&events=bogus&min_cvss=7.5").await;
        assert_eq!(saved.location.as_deref(), Some(list));
        let d = db.get_destination(everyone).unwrap().unwrap();
        assert_eq!((d.events.clone(), d.min_cvss, d.enabled, d.system_events), (vec!["created".to_string(), "kev".to_string()], Some(7.5), true, false));
        let config = app.get(&gear, Some(&admin)).await.body;
        assert!(config.contains("name=\"events\" value=\"kev\" checked>") && config.contains("name=\"events\" value=\"metrics\">"));
        assert!(config.contains("name=\"min_cvss\" min=\"0\" max=\"10\" step=\"0.1\" value=\"7.5\">"));
        let page = app.get(list, Some(&admin)).await.body;
        assert!(row(&page, "Everyone").contains("<td>New CVE, CISA KEV, CVSS 7.5 and above</td>"), "{page}");
        assert_eq!(app.post(&gear, Some(&admin), "action=save&enabled=1&min_cvss=11").await.status, StatusCode::BAD_REQUEST);
        // Nothing checked, or disabled: it sends nothing, and the list says why
        app.post(&gear, Some(&admin), "action=save&enabled=1").await;
        assert!(row(&app.get(list, Some(&admin)).await.body, "Everyone").contains("nothing: no event checked"));
        app.post(&gear, Some(&admin), "action=save&enabled=1&system_events=1").await;
        assert!(row(&app.get(list, Some(&admin)).await.body, "Everyone").contains("only instance events (sync finished)"));
        app.post(&format!("/admin/notifications/destinations/{team}"), Some(&admin), "action=save&events=kev&system_events=1").await;
        let team_now = db.get_destination(team).unwrap().unwrap();
        assert_eq!((team_now.enabled, team_now.system_events), (false, false));
        assert!(row(&app.get(list, Some(&admin)).await.body, "Team").contains("nothing: disabled"));

        // Per project: every destination receiving its notifications, its own or not
        let per_project = app.get("/admin/notifications", Some(&admin)).await.body;
        let lines = |project: &str| per_project.split("<tr>").filter(|r| r.contains(&format!("title=\"{project}\""))).count();
        assert_eq!((lines("infra"), lines("web")), (3, 2));
        assert!(per_project.contains(&format!("<a href=\"/admin/notifications/destinations/{solo}\">Solo</a>")));
        assert!(per_project.contains("<td>the instance</td>") && per_project.contains("<td>its organization</td>") && per_project.contains("<td>the project</td>"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_project_sets_what_its_own_destinations_send_in_one_table() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        for project in ["infra", "web"] {
            app.post("/projects", Some(&admin), &format!("org=acme&name={project}")).await;
        }
        let mut cookies = std::collections::HashMap::new();
        for (name, role) in [("editor", "editor"), ("viewer", "viewer"), ("stranger", "")] {
            cookies.insert(name, app.register(name).await);
            if !role.is_empty() {
                app.post("/orgs/acme/members", Some(&admin), &format!("username={name}&role={role}")).await;
                app.accept_invitations(name);
            }
        }
        let (editor, viewer, stranger) = (&cookies["editor"], &cookies["viewer"], &cookies["stranger"]);
        let db = Database::connect(&app.db_path).unwrap();
        let infra = db.find_project("acme", "infra").unwrap().unwrap();
        let base = "/orgs/acme/projects/infra";
        let page = "/product/acme/infra?view=settings";

        // Destinations of the instance and of the organization exist: the project page never names them
        app.post("/admin/notifications/destinations", Some(&admin), "owner=instance&kind=ntfy&name=Everyone&url=https%3A%2F%2F8.8.8.8%2Fsecret-topic").await;
        app.post("/admin/notifications/destinations", Some(&admin), "owner=organization%3Aacme&kind=ntfy&name=Teamwide&url=https%3A%2F%2F8.8.8.8%2Forg-topic").await;
        let empty = app.get(page, Some(editor)).await.body;
        assert!(empty.contains("This project has no destination of its own yet.") && !empty.contains("Save notifications"));

        // Three destinations of the project, each starting with every event checked
        for name in ["alpha", "bravo", "charlie"] {
            let form = format!("kind=ntfy&name={name}&url=https%3A%2F%2F8.8.8.8%2F{name}");
            assert_eq!(app.post(&format!("{base}/destinations"), Some(editor), &form).await.status, StatusCode::SEE_OTHER);
        }
        let ids: Vec<i64> = db.list_project_destinations(infra).unwrap().iter().map(|d| d.id).collect();
        let (alpha, bravo, charlie) = (ids[0], ids[1], ids[2]);
        let section = |body: &str| body.split("<h2>Notifications</h2>").nth(1).unwrap().split("<h2>Members</h2>").next().unwrap().to_string();
        let shown = section(&app.get(page, Some(editor)).await.body);
        // One table: a row per destination, a checkbox column per event type, a minimum CVSS, one Save
        assert_eq!(shown.matches("<table").count(), 1);
        assert_eq!(shown.split("<tbody>").nth(1).unwrap().split("</tbody>").next().unwrap().matches("<tr>").count(), 3);
        for (kind, label) in crate::changes::EVENT_TYPES {
            assert!(shown.contains(&format!("<th class=\"up\" title=\"{label}\">")), "{label}");
            for id in &ids {
                assert!(shown.contains(&format!("<input type=\"checkbox\" name=\"events_{id}\" value=\"{kind}\" checked aria-label=")), "{kind} {id}");
            }
        }
        assert!(shown.contains(&format!("<input type=\"number\" name=\"min_cvss_{alpha}\" min=\"0\" max=\"10\" step=\"0.1\" value=\"\" aria-label=\"Minimum CVSS: alpha\">")));
        assert_eq!(shown.matches("Save notifications").count(), 1);
        assert!(shown.contains("A destination with no event checked sends nothing for this project."));
        assert!(!shown.contains("none checked = all") && !shown.contains("Destinations of this project") && !shown.contains("Notify a destination"));
        // Delete posts its own form: Enter in a field of the table saves, it never deletes
        assert!(shown.contains(&format!("<button class=\"small danger\" type=\"submit\" form=\"delete-destination-{bravo}\">Delete</button>")));
        assert!(shown.contains(&format!("<form id=\"delete-destination-{bravo}\" method=\"post\" action=\"{base}/destinations/{bravo}/delete\"></form>")));
        // Works without JavaScript: nothing in the section but plain forms
        assert!(!shown.contains("<script") && shown.contains(&format!("<form method=\"post\" action=\"{base}/notifications\">")));
        // Managed elsewhere: neither a name nor a target, for anyone
        for who in [&admin, editor, viewer] {
            let body = app.get(page, Some(who)).await.body;
            for secret in ["Everyone", "Teamwide", "secret-topic", "org-topic"] {
                assert!(!body.contains(secret), "{secret}");
            }
            assert!(body.contains("They are managed by their administrators, not here."));
        }

        // Uncheck, check and set a minimum: the form comes back as it was sent
        let form = format!(
            "id={alpha}&enabled_{alpha}=1&events_{alpha}=kev&events_{alpha}=created&min_cvss_{alpha}=7.5\
             &id={bravo}&events_{bravo}=metrics&min_cvss_{bravo}=\
             &id={charlie}&enabled_{charlie}=1&min_cvss_{charlie}=0"
        );
        let saved = app.post(&format!("{base}/notifications"), Some(editor), &form).await;
        assert_eq!(saved.location.as_deref(), Some(page));
        let settings = |id: i64| {
            let d = db.get_destination(id).unwrap().unwrap();
            (d.events, d.min_cvss, d.enabled)
        };
        assert_eq!(settings(alpha), (vec!["created".to_string(), "kev".to_string()], Some(7.5), true));
        assert_eq!(settings(bravo), (vec!["metrics".to_string()], None, false));
        assert_eq!(settings(charlie), (vec![], Some(0.0), true));
        let shown = app.get(page, Some(editor)).await.body;
        let checked = |id: i64, kind: &str| shown.contains(&format!("name=\"events_{id}\" value=\"{kind}\" checked"));
        assert!(checked(alpha, "kev") && checked(alpha, "created") && !checked(alpha, "metrics") && !checked(alpha, "service"));
        assert!(checked(bravo, "metrics") && !checked(bravo, "kev") && !checked(charlie, "kev"));
        assert!(shown.contains(&format!("name=\"enabled_{alpha}\" value=\"1\" checked")) && !shown.contains(&format!("name=\"enabled_{bravo}\" value=\"1\" checked")));
        assert!(shown.contains(&format!("name=\"min_cvss_{alpha}\" min=\"0\" max=\"10\" step=\"0.1\" value=\"7.5\"")));
        // A row left out of the form is left as it is; a bad value changes nothing at all
        assert_eq!(app.post(&format!("{base}/notifications"), Some(editor), &format!("id={charlie}&events_{charlie}=kev")).await.status, StatusCode::SEE_OTHER);
        assert_eq!(settings(alpha).0, ["created", "kev"]);
        let bad = format!("id={alpha}&events_{alpha}=metrics&id={bravo}&min_cvss_{bravo}=12");
        assert_eq!(app.post(&format!("{base}/notifications"), Some(editor), &bad).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(settings(alpha).0, ["created", "kev"]);

        // Rights: a session, the right to manage the project, and a destination of this very project
        let change = format!("id={alpha}&events_{alpha}=service");
        let table = format!("{base}/notifications");
        let delete = format!("{base}/destinations/{alpha}/delete");
        let create = format!("{base}/destinations");
        let new = "kind=ntfy&name=delta&url=https%3A%2F%2F8.8.8.8%2Fdelta";
        for (path, body) in [(table.as_str(), change.as_str()), (delete.as_str(), ""), (create.as_str(), new)] {
            let anonymous = app.post(path, None, body).await;
            assert_eq!(anonymous.status, StatusCode::SEE_OTHER, "{path}");
            assert!(anonymous.location.as_deref().is_some_and(|l| l.starts_with("/login")), "{path}");
            assert_eq!(app.post(path, Some(viewer), body).await.status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(app.post(path, Some(stranger), body).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(app.get(page, None).await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get(page, Some(stranger)).await.status, StatusCode::NOT_FOUND);
        // A viewer sees the table, cannot change it, and does not see the targets
        let read_only = app.get(page, Some(viewer)).await.body;
        assert!(read_only.contains("alpha") && !read_only.contains("8.8.8.8") && !read_only.contains("Save notifications"));
        assert!(!read_only.contains("name=\"id\"") && !read_only.contains(">Delete</button>") && !read_only.contains("new=ntfy"));
        assert!(read_only.contains(&format!("name=\"events_{alpha}\" value=\"kev\" checked disabled")));
        // The id of a destination of another project, of the organization or of the instance: not found, nothing changed
        let others: Vec<i64> = db.list_all_destinations().unwrap().iter().filter(|d| d.scope != "project").map(|d| d.id).collect();
        assert_eq!(others.len(), 2);
        for id in others.iter().copied().chain([alpha, 99999]) {
            let foreign = format!("id={id}&min_cvss_{id}=9");
            assert_eq!(app.post("/orgs/acme/projects/web/notifications", Some(editor), &foreign).await.status, StatusCode::NOT_FOUND, "{id}");
            assert_eq!(app.post(&format!("/orgs/acme/projects/web/destinations/{id}/delete"), Some(editor), "").await.status, StatusCode::NOT_FOUND, "{id}");
        }
        assert_eq!(app.post(&table, Some(editor), "id=abc").await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.list_all_destinations().unwrap().len(), 5);
        assert_eq!(settings(alpha), (vec!["created".to_string(), "kev".to_string()], Some(7.5), true));
        assert!(others.iter().all(|id| settings(*id) == (crate::db::all_events(), None, true)));

        // Delete per row
        assert_eq!(app.post(&delete, Some(editor), "").await.status, StatusCode::SEE_OTHER);
        assert!(db.get_destination(alpha).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn browser_notifications_are_gone() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.post("/orgs", Some(&admin), "name=acme").await;
        app.post("/projects", Some(&admin), "org=acme&name=infra").await;

        // Their addresses answer like any address that never existed, signed in or not
        let unknown = |cookie: Option<String>, post: bool| {
            let app = &app;
            async move {
                let r = if post { app.post("/no/such/page", cookie.as_deref(), "").await } else { app.get("/no/such/page", cookie.as_deref()).await };
                (r.status, r.location, r.body)
            }
        };
        for cookie in [Some(admin.clone()), None] {
            for path in ["/push/key", "/push/inbox", "/static/push.js", "/sw.js"] {
                let r = app.get(path, cookie.as_deref()).await;
                assert_eq!((r.status, r.location, r.body), unknown(cookie.clone(), false).await, "GET {path}");
            }
            for path in ["/push/subscribe", "/push/unsubscribe"] {
                let r = app.post(path, cookie.as_deref(), "").await;
                assert_eq!((r.status, r.location, r.body), unknown(cookie.clone(), true).await, "POST {path}");
            }
        }
        assert_eq!(app.get("/sw.js", Some(&admin)).await.status, StatusCode::NOT_FOUND);

        // No page offers them or loads their script
        let pages = [
            "/settings",
            "/admin/notifications",
            "/admin/notifications?tab=destinations",
            "/admin/notifications?tab=destinations&new=browser",
            "/admin/notifications?tab=destinations&enable=1",
            "/product/acme/infra?view=settings",
            "/product/acme/infra?view=settings&new=browser",
        ];
        for path in pages {
            let page = app.get(path, Some(&admin)).await;
            assert_eq!(page.status, StatusCode::OK, "{path}");
            let body = page.body.to_lowercase();
            // (the address asked for is repeated by the filter of a list: only what is offered counts)
            for gone in ["browser notification", "new destination", "name=\"kind\"", "push", "sw.js", "serviceworker"] {
                assert!(!body.contains(gone), "{path}: {gone}");
            }
        }

        // And such a destination can no longer be created, by the administration or by a project
        for (path, form) in [
            ("/admin/notifications/destinations", "owner=instance&kind=browser&name=Browsers"),
            ("/orgs/acme/projects/infra/destinations", "kind=browser&name=Browsers"),
        ] {
            assert_eq!(app.post(path, Some(&admin), form).await.status, StatusCode::BAD_REQUEST, "{path}");
        }
        let db = Database::connect(&app.db_path).unwrap();
        assert!(db.list_all_destinations().unwrap().is_empty());
        assert!(db.create_destination("instance", None, "Browsers", "browser", &serde_json::json!({}), false).is_err());
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
        app.accept_invitations("mate");
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
            // An invitation says nothing of the account it names; this one can never be accepted
            app.post("/orgs/acme/projects/web/members", Some(&admin), "username=jane.doe.p2&role=viewer").await.status,
            StatusCode::SEE_OTHER
        );
        assert!(db.received_invitations(user_id).unwrap().is_empty());
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
        app.accept_invitations("viewer");
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

        // A destination of the project receives the announcement of new probable services
        let received = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hook = format!("http://{}/hook", listener.local_addr().unwrap());
        let sink = received.clone();
        let receiver = Router::new().route(
            "/hook",
            post(move |Json(body): Json<serde_json::Value>| async move {
                sink.lock().unwrap().push(body);
            }),
        );
        tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });
        app.post("/admin/notifications/delivery", Some(&admin), "allow_private=1").await;
        let form = format!("kind=webhook&name=hook&url={}", percent_encoding::utf8_percent_encode(&hook, percent_encoding::NON_ALPHANUMERIC));
        assert_eq!(app.post("/orgs/acme/projects/infra/destinations", Some(&admin), &form).await.status, StatusCode::SEE_OTHER);
        let delivered = push(bearer(), inventory.clone()).await;
        assert_eq!(delivered.status, StatusCode::OK, "{}", delivered.body);
        let outcome: serde_json::Value = serde_json::from_str(&delivered.body).unwrap();
        assert_eq!((outcome["added"].as_i64(), outcome["new_probable_services"].as_array().map(Vec::len)), (Some(3), Some(2)));
        let announced = received.lock().unwrap().clone();
        assert_eq!(announced.len(), 1, "{announced:?}");
        assert_eq!((announced[0]["event"].as_str(), announced[0]["title"].as_str()), (Some("service"), Some("acme/infra: 2 new probable service(s)")));
        assert!(announced[0]["message"].as_str().unwrap().contains("nginx 1.30.6"));
        // Delivering the same list again announces nothing
        push(bearer(), inventory.clone()).await;
        assert_eq!(received.lock().unwrap().len(), 1);
        app.post("/admin/notifications/delivery", Some(&admin), "").await;
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
        let review = app.get("/product/acme/infra?view=vulnerabilities", Some(&admin)).await.body;
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
    async fn adding_a_member_is_an_invitation_that_tells_nothing_of_the_name() {
        let app = app(open_registration());
        let root = app.register("root").await;
        let bob = app.register("bob").await;
        let viewer = app.register("viewer").await;
        let stranger = app.register("stranger").await;
        app.register("gone").await;
        app.post("/orgs", Some(&root), "name=acme").await;
        app.post("/projects", Some(&root), "org=acme&name=infra").await;
        let db = Database::connect(&app.db_path).unwrap();
        let id = |name: &str| db.list_accounts().unwrap().into_iter().find(|a| a.username == name).unwrap().id;
        let (org, infra) = (db.get_org("acme", id("root")).unwrap().unwrap().id, db.find_project("acme", "infra").unwrap().unwrap());
        db.set_org_member(org, id("viewer"), crate::rbac::Role::Viewer).unwrap();
        db.set_disabled(id("gone"), true).unwrap();
        let (org_form, project_form) = ("/orgs/acme/members", "/orgs/acme/projects/infra/members");
        let (org_page, project_page) = ("/orgs/acme", "/product/acme/infra?view=settings");
        let answer = |r: &Reply| (r.status, r.location.clone(), r.body.clone(), r.cookies.clone());
        let cancel_link = regex::Regex::new(r"/invitations/(\d+)/cancel").unwrap();

        // An account, a name nobody bears and a disabled account: one answer, to the letter,
        // and a row that only differs by the name typed
        for (form, page) in [(org_form, org_page), (project_form, project_page)] {
            let mut answers = Vec::new();
            for name in ["bob", "ghost", "gone"] {
                let reply = app.post(form, Some(&root), &format!("username=+{name}+&role=viewer")).await;
                assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
                let shown = app.get(reply.location.as_deref().unwrap(), Some(&root)).await;
                assert_eq!(shown.status, StatusCode::OK);
                assert!(shown.body.contains("Invitation recorded.") && shown.body.contains("nothing here tells whether the name is one of an account"));
                let row = shown.body.split("<tr>").find(|row| row.starts_with(&format!("<td>{name}</td>"))).expect("the row of the name").to_string();
                let row = cancel_link.replace(row.split("</tr>").next().unwrap(), "/invitations/N/cancel").replace(name, "NAME");
                assert!(row.contains("<td data-label=\"Invited by\">root</td>") && row.contains(">Cancel</button>"), "{row}");
                answers.push((answer(&reply), row));
            }
            let location = answers[0].0.1.clone().unwrap();
            assert!(location.starts_with(page) && location.ends_with("notice=invited#invitations"), "{location}");
            assert!(answers.iter().all(|a| *a == answers[0]), "{form}");
            // The words only show after an invitation, and the list is sized like every other
            let plain = app.get(page, Some(&root)).await.body;
            assert!(!plain.contains("Invitation recorded.") && plain.contains("Pending invitations"));
            assert!(plain.contains("<table class=\"list fit\"><colgroup><col><col class=\"kind\"><col class=\"who\"><col class=\"day\"><col class=\"day\"><col class=\"act\"></colgroup>"));
        }
        // A name that could not be a username is refused on its spelling, a role that is none on its name
        for name in ["bob%40example.org", "a+b", ""] {
            assert_eq!(app.post(org_form, Some(&root), &format!("username={name}&role=viewer")).await.status, StatusCode::BAD_REQUEST);
        }
        assert_eq!(app.post(project_form, Some(&root), "username=bob&role=admin").await.status, StatusCode::BAD_REQUEST);

        // Nothing is granted
        assert_eq!(app.get(org_page, Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.project_role(id("bob"), infra).unwrap(), None);
        assert!(db.list_members(org).unwrap().iter().all(|m| m.username != "bob"));

        // Managing members is what gives the form, the list and the cancellation
        let pending = db.pending_invitations(crate::db::Scope::Organization(org)).unwrap();
        let on_project = db.pending_invitations(crate::db::Scope::Project(infra)).unwrap();
        let (ghost_org, ghost_project) = (pending[1].id, on_project[1].id);
        assert_eq!((pending[1].name.as_str(), on_project[1].name.as_str()), ("ghost", "ghost"));
        for (who, refused) in [(&viewer, StatusCode::FORBIDDEN), (&stranger, StatusCode::NOT_FOUND)] {
            assert_eq!(app.post(org_form, Some(who), "username=bob&role=viewer").await.status, refused);
            assert_eq!(app.post(project_form, Some(who), "username=bob&role=viewer").await.status, refused);
            assert_eq!(app.post(&format!("/orgs/acme/invitations/{ghost_org}/cancel"), Some(who), "").await.status, refused);
            assert_eq!(app.post(&format!("/orgs/acme/projects/infra/invitations/{ghost_project}/cancel"), Some(who), "").await.status, refused);
        }
        for page in [org_page, project_page] {
            let seen = app.get(page, Some(&viewer)).await;
            assert_eq!(seen.status, StatusCode::OK);
            assert!(!seen.body.contains("Pending invitations") && !seen.body.contains("ghost") && !seen.body.contains("/invitations/"), "{page}");
        }
        assert_eq!(db.pending_invitations(crate::db::Scope::Organization(org)).unwrap().len(), 3);

        // Without a session: the sign-in page; from another site: refused
        for path in [
            "/invitations/1/accept".to_string(), "/invitations/1/decline".to_string(),
            format!("/orgs/acme/invitations/{ghost_org}/cancel"), format!("/orgs/acme/projects/infra/invitations/{ghost_project}/cancel"),
            org_form.to_string(), project_form.to_string(),
        ] {
            assert_eq!(app.post(&path, None, "username=bob&role=viewer").await.location.as_deref(), Some("/login"), "{path}");
            for session in [None, Some(root.as_str()), Some(bob.as_str())] {
                let mut foreign = HttpRequest::post(path.as_str())
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://elsewhere.example")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                if let Some(cookie) = session {
                    foreign = foreign.header(header::COOKIE, cookie);
                }
                assert_eq!(app.send(foreign.body(Body::from("username=bob&role=owner")).unwrap()).await.status, StatusCode::FORBIDDEN, "{path}");
            }
        }
        assert_eq!(db.pending_invitations(crate::db::Scope::Organization(org)).unwrap().len(), 3);

        // The invited account is told in the header of every page, and answers in its settings
        let home = app.get("/projects", Some(&bob)).await.body;
        assert!(home.contains("<a class=\"invited\" href=\"/settings#invitations\"") && home.contains(">2 invitations</a>"));
        let settings = app.get("/settings", Some(&bob)).await.body;
        assert!(settings.contains("<table class=\"list fit\"><colgroup><col><col class=\"kind\"><col class=\"who\"><col class=\"day\"><col class=\"actions\"></colgroup>"));
        assert!(settings.contains("<td>organization acme</td>") && settings.contains("<td>project acme / infra</td>"));
        assert!(settings.contains("<td data-label=\"Invited by\">root</td>") && settings.contains("<td data-label=\"Role\">viewer</td>"));
        let mine = db.received_invitations(id("bob")).unwrap();
        let (to_org, to_project) = (mine[0].id, mine[1].id);
        for other in [&root, &viewer, &stranger] {
            let page = app.get("/settings", Some(other)).await.body;
            assert!(!page.contains("class=\"invited\"") && !page.contains("id=\"invitations\"") && !page.contains("/accept"));
        }

        // An account created afterwards with an invited name neither sees the invitation nor takes it,
        // and an invitation of someone else answers like one that does not exist
        let ghost = app.register("ghost").await;
        let page = app.get("/settings", Some(&ghost)).await.body;
        assert!(!page.contains("class=\"invited\"") && !page.contains("id=\"invitations\"") && !page.contains("acme"));
        let unknown = app.post("/invitations/99999/accept", Some(&ghost), "").await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
        for (who, invitation) in [(&ghost, ghost_org), (&ghost, ghost_project), (&ghost, to_org), (&stranger, to_project), (&root, to_org)] {
            for action in ["accept", "decline"] {
                let reply = app.post(&format!("/invitations/{invitation}/{action}"), Some(who), "").await;
                assert_eq!(answer(&reply), answer(&unknown), "{invitation} {action}");
            }
        }
        assert_eq!(app.get(org_page, Some(&ghost)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(db.project_role(id("ghost"), infra).unwrap(), None);
        assert_eq!(db.received_invitations(id("bob")).unwrap().len(), 2);

        // Declining removes the invitation; accepting gives exactly the role offered, where it was offered
        let declined = app.post(&format!("/invitations/{to_org}/decline"), Some(&bob), "").await;
        assert_eq!((declined.status, declined.location.as_deref()), (StatusCode::SEE_OTHER, Some("/settings")));
        assert_eq!(app.get(org_page, Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert!(!app.get(org_page, Some(&root)).await.body.contains("<td>bob</td>"));
        let accepted = app.post(&format!("/invitations/{to_project}/accept"), Some(&bob), "").await;
        assert_eq!((accepted.status, accepted.location.as_deref()), (StatusCode::SEE_OTHER, Some("/product/acme/infra")));
        assert_eq!(db.project_role(id("bob"), infra).unwrap(), Some(crate::rbac::Role::Viewer));
        assert_eq!(app.get("/product/acme/infra", Some(&bob)).await.status, StatusCode::OK);
        assert_eq!(app.get(org_page, Some(&bob)).await.status, StatusCode::NOT_FOUND);
        assert!(!app.get("/projects", Some(&bob)).await.body.contains("class=\"invited\""));
        assert_eq!(answer(&app.post(&format!("/invitations/{to_project}/accept"), Some(&bob), "").await), answer(&unknown));
        // Now a member the list shows: its name changes its role at once, as before
        let changed = app.post(project_form, Some(&root), "username=Bob&role=editor").await;
        assert_eq!(changed.location.as_deref(), Some(project_page));
        assert_eq!(db.project_role(id("bob"), infra).unwrap(), Some(crate::rbac::Role::Editor));

        // Cancelling: at the level the invitation was made, by who manages its members
        assert_eq!(app.post(&format!("/orgs/acme/invitations/{ghost_project}/cancel"), Some(&root), "").await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.post(&format!("/orgs/acme/projects/infra/invitations/{ghost_org}/cancel"), Some(&root), "").await.status, StatusCode::NOT_FOUND);
        let cancelled = app.post(&format!("/orgs/acme/invitations/{ghost_org}/cancel"), Some(&root), "").await;
        assert_eq!((cancelled.status, cancelled.location.as_deref()), (StatusCode::SEE_OTHER, Some("/orgs/acme#invitations")));
        let cancelled = app.post(&format!("/orgs/acme/projects/infra/invitations/{ghost_project}/cancel"), Some(&root), "").await;
        assert_eq!(cancelled.location.as_deref(), Some("/product/acme/infra?view=settings#invitations"));
        assert!(!app.get(org_page, Some(&root)).await.body.contains("<td>ghost</td>"));
        assert!(!app.get(project_page, Some(&root)).await.body.contains("<td>ghost</td>"));

        // Expiry: after fourteen days the invitation is nowhere, and cannot be accepted
        app.post(org_form, Some(&root), "username=stranger&role=editor").await;
        let waiting = db.received_invitations(id("stranger")).unwrap()[0].id;
        db.conn().execute("UPDATE invitations SET expires_at = datetime('now', '-1 minute') WHERE id = ?1", [waiting]).unwrap();
        assert!(!app.get("/settings", Some(&stranger)).await.body.contains("id=\"invitations\""));
        assert!(!app.get(org_page, Some(&root)).await.body.contains("<td>stranger</td>"));
        assert_eq!(answer(&app.post(&format!("/invitations/{waiting}/accept"), Some(&stranger), "").await), answer(&unknown));
        assert_eq!(app.get(org_page, Some(&stranger)).await.status, StatusCode::NOT_FOUND);

        // Whoever invited is demoted, or disabled, before the answer: the invitation is void
        let second = app.register("second").await;
        db.set_org_member(org, id("second"), crate::rbac::Role::Owner).unwrap();
        for void in ["demoted", "disabled"] {
            assert_eq!(app.post(org_form, Some(&second), "username=stranger&role=owner").await.status, StatusCode::SEE_OTHER, "{void}");
            let waiting = db.received_invitations(id("stranger")).unwrap()[0].id;
            assert!(app.get("/settings", Some(&stranger)).await.body.contains("<td data-label=\"Invited by\">second</td>"));
            match void {
                "demoted" => db.set_org_member(org, id("second"), crate::rbac::Role::Editor).unwrap(),
                _ => db.set_disabled(id("second"), true).unwrap(),
            }
            assert!(!app.get("/settings", Some(&stranger)).await.body.contains("id=\"invitations\""), "{void}");
            assert!(!app.get(org_page, Some(&root)).await.body.contains("<td>stranger</td>"), "{void}");
            assert_eq!(answer(&app.post(&format!("/invitations/{waiting}/accept"), Some(&stranger), "").await), answer(&unknown), "{void}");
            assert_eq!(app.get(org_page, Some(&stranger)).await.status, StatusCode::NOT_FOUND, "{void}");
            db.set_org_member(org, id("second"), crate::rbac::Role::Owner).unwrap();
        }

        // The cap: the same refusal for an account and for a name nobody bears
        let taken = db.pending_invitations(crate::db::Scope::Project(infra)).unwrap().len() as i64;
        for i in taken..crate::db::MAX_PENDING_INVITATIONS {
            db.invite(crate::db::Scope::Project(infra), &format!("name-{i}"), crate::rbac::Role::Viewer, &crate::db::Actor::user(id("root"), "root")).unwrap();
        }
        let full = app.post(project_form, Some(&root), "username=stranger&role=viewer").await;
        assert_eq!(full.status, StatusCode::BAD_REQUEST);
        assert!(full.body.contains("Too many pending invitations"));
        assert_eq!(answer(&app.post(project_form, Some(&root), "username=nobody-at-all&role=viewer").await), answer(&full));
        assert!(db.received_invitations(id("stranger")).unwrap().is_empty());

        // Everything is on the security trail; what is recorded when a name is typed names the level, not an account
        let trail = db.list_security_events(None, 500).unwrap();
        for event in ["invitation_sent", "invitation_accepted", "invitation_declined", "invitation_cancelled"] {
            assert!(trail.iter().any(|e| e.event == event), "{event}");
        }
        assert!(trail.iter().filter(|e| e.event == "invitation_sent").all(|e| e.username.is_empty()));
        assert!(trail.iter().any(|e| e.event == "invitation_accepted" && e.username == "bob" && e.detail.as_deref() == Some("project acme / infra as viewer, invited by root")));
    }

    /// Every route declared in the routers, as (path, public). Read from the
    /// source, so that a route added tomorrow is swept without anyone
    /// remembering to list it here.
    fn declared_routes() -> Vec<String> {
        let marker = concat!(".rou", "te(");
        let paths = |source: &str, prefix: &str| -> Vec<String> {
            let source = source.split("#[cfg(test)]").next().unwrap();
            source
                .split(marker)
                .skip(1)
                .filter_map(|rest| {
                    let start = rest.find('"')? + 1;
                    let end = start + rest[start..].find('"')?;
                    Some(format!("{prefix}{}", &rest[start..end]))
                })
                .collect()
        };
        let web = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let (ui, rest) = web.split_once("let api = Router::new()").expect("the API router");
        let (api, top) = rest.split_once(".nest(\"/api\", api)").expect("the top router");
        let mut routes = paths(ui, "");
        routes.extend(paths(api, "/api"));
        routes.extend(paths(top, ""));
        routes.extend(paths(include_str!("scim.rs"), "/scim/v2"));
        routes
    }

    /// What answers without signing in: signing in itself, and static files
    const PUBLIC_ROUTES: [&str; 18] = [
        "/login",
        "/register",
        "/setup",
        "/logout",
        "/login/mfa",
        "/login/mfa/passkey/start",
        "/login/mfa/passkey/finish",
        "/login/passkey/start",
        "/login/passkey/finish",
        "/auth/oidc/{provider}/login",
        "/auth/oidc/{provider}/callback",
        "/static/app.css",
        "/static/logo.svg",
        "/static/logo.png",
        "/static/mfa.js",
        "/static/filter.js",
        "/static/theme.js",
        "/favicon.ico",
    ];

    #[tokio::test(flavor = "multi_thread")]
    async fn nothing_answers_without_authentication() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        // MCP over HTTP is switched on, so that it is the authentication that is tested
        assert_eq!(app.post("/admin/mcp", Some(&admin), "http_enabled=1").await.status, StatusCode::SEE_OTHER);
        let token = tokens_of(&app.post("/settings/tokens", Some(&admin), "name=t&password=a-long-password").await.body).remove(0);

        let routes = declared_routes();
        assert!(routes.len() >= 110, "only {} routes found: the source is no longer read correctly", routes.len());
        for expected in ["/cve", "/admin/users", "/api/cve", "/api/security-log", "/mcp", "/scim/v2/Users", "/setup"] {
            assert!(routes.iter().any(|r| r == expected), "{expected} is not among the routes found");
        }
        for public in PUBLIC_ROUTES {
            assert!(routes.iter().any(|r| r == public), "{public} is listed as public but is not a route");
        }

        // Who presents nothing, and who presents something that is not valid
        let forged_session = format!("{SESSION_COOKIE}={}", "a".repeat(64));
        let callers: [(&str, Option<(header::HeaderName, String)>); 5] = [
            ("nothing", None),
            ("a forged session", Some((header::COOKIE, forged_session))),
            ("a forged token", Some((header::AUTHORIZATION, format!("Bearer {}", "b".repeat(64))))),
            ("a truncated real token", Some((header::AUTHORIZATION, format!("Bearer {}", &token[..token.len() - 1])))),
            ("basic credentials that are wrong", Some((header::AUTHORIZATION, "Basic cm9vdDp3cm9uZw==".to_string()))),
        ];
        let mut swept = 0;
        let mut answered: Vec<String> = Vec::new();
        for route in routes.iter().filter(|r| !PUBLIC_ROUTES.contains(&r.as_str())) {
            let path: String = {
                // Path parameters get a plausible value
                let mut out = String::new();
                let mut inside = false;
                for c in route.chars() {
                    match c {
                        '{' => {
                            inside = true;
                            out.push('1');
                        }
                        '}' => inside = false,
                        _ if !inside => out.push(c),
                        _ => {}
                    }
                }
                out
            };
            let json = route.starts_with("/api") || route.starts_with("/scim") || route == "/mcp";
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                for (who, credential) in &callers {
                    let mut req = HttpRequest::builder()
                        .method(method)
                        .uri(&path)
                        .header(header::HOST, "localhost")
                        // Its own origin: what is tested is the authentication, not the origin check
                        .header(header::ORIGIN, "http://localhost");
                    if let Some((name, value)) = credential {
                        req = req.header(name, value);
                    }
                    let body = if method == "GET" {
                        Body::empty()
                    } else if json {
                        req = req.header(header::CONTENT_TYPE, "application/json");
                        Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","schemas":[],"userName":"x"}"#)
                    } else {
                        req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                        Body::from("name=x&username=x&password=a-long-password&status=accepted&required=1")
                    };
                    let reply = app.send(req.body(body).unwrap()).await;
                    let is_refusal = |r: &Reply| match r.status {
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => true,
                        // Too many wrong credentials from one address
                        StatusCode::TOO_MANY_REQUESTS => true,
                        StatusCode::SEE_OTHER => r.location.as_deref() == Some("/login"),
                        _ => false,
                    };
                    let mut refused = is_refusal(&reply);
                    // An old address may move to the new one before being refused there
                    if !refused && reply.status == StatusCode::SEE_OTHER && reply.body.is_empty() {
                        if let Some(next) = reply.location.as_deref().filter(|l| l.starts_with('/')) {
                            let mut follow = HttpRequest::get(next).header(header::HOST, "localhost");
                            if let Some((name, value)) = credential {
                                follow = follow.header(name, value);
                            }
                            refused = is_refusal(&app.send(follow.body(Body::empty()).unwrap()).await);
                        }
                    }
                    if !refused {
                        answered.push(format!(
                            "{method} {path} with {who}: {} {:?} — {}",
                            reply.status,
                            reply.location,
                            reply.body.chars().take(120).collect::<String>()
                        ));
                    }
                    // A refusal carries no session
                    assert!(!reply.cookies.iter().any(|c| c.starts_with(&format!("{SESSION_COOKIE}=")) && c.len() > SESSION_COOKIE.len() + 1), "{method} {path}");
                    swept += 1;
                }
            }
        }
        assert!(answered.is_empty(), "{} requests were answered without authentication:\n{}", answered.len(), answered.join("\n"));
        assert!(swept > 2000, "{swept}");

        // The same requests, signed, do answer: the sweep above did not pass by accident
        assert_eq!(app.api("/api/cve", Some(&format!("Bearer {token}"))).await.status, StatusCode::OK);
        assert_eq!(app.get("/cve", Some(&admin)).await.status, StatusCode::OK);
        let mcp = |authorization: Option<String>| {
            let app = &app;
            async move {
                let mut req = HttpRequest::post("/mcp").header(header::HOST, "127.0.0.1:8000").header(header::CONTENT_TYPE, "application/json");
                if let Some(a) = authorization {
                    req = req.header(header::AUTHORIZATION, a);
                }
                app.send(req.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"database_status","arguments":{}}}"#)).unwrap()).await
            }
        };
        let signed = mcp(Some(format!("Bearer {token}"))).await;
        assert!(signed.status == StatusCode::OK && signed.body.contains("result"), "{}", signed.body);
        for unsigned in [mcp(None).await, mcp(Some("Bearer nope".into())).await] {
            assert_eq!(unsigned.status, StatusCode::UNAUTHORIZED);
            assert!(!unsigned.body.contains("result") && !unsigned.body.contains("cves"));
        }
        // A token that was deleted, and the token of a disabled account, stop working at once
        let other = app.register("bob").await;
        let bob_token = tokens_of(&app.post("/settings/tokens", Some(&other), "name=t&password=a-long-password").await.body).remove(0);
        assert_eq!(mcp(Some(format!("Bearer {bob_token}"))).await.status, StatusCode::OK);
        let db = Database::connect(&app.db_path).unwrap();
        db.set_disabled(db.get_credentials("bob").unwrap().unwrap().0.id, true).unwrap();
        assert_eq!(mcp(Some(format!("Bearer {bob_token}"))).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.api("/api/cve", Some(&format!("Bearer {bob_token}"))).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.get("/cve", Some(&other)).await.location.as_deref(), Some("/login"));
    }

    #[test]
    fn a_refused_api_call_asks_for_a_token_first() {
        let response = ApiError(AppError::Unauthorized).into_response();
        let challenges: Vec<_> = response.headers().get_all(header::WWW_AUTHENTICATE).iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert_eq!(challenges, ["Bearer realm=\"vulnizard\"", "Basic realm=\"vulnizard\""]);
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
                "instance_set_up", "totp_enabled", "recovery_codes_generated", "recovery_code_used", "second_step_locked",
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
        app.accept_invitations("bob");
        assert_eq!(app.post("/orgs/acme/mfa", Some(&bob), "required=1").await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/orgs/acme/mfa", Some(&root), "required=1").await.status, StatusCode::SEE_OTHER);
        assert!(app.get("/orgs/acme", Some(&root)).await.body.contains("checked"));

        // Bob, a member without a factor, is held to setting one up: nothing else answers, as when
        // the instance requires it. Carol, who is not a member, is not concerned.
        for path in ["/orgs/acme", "/product", "/settings", "/orgs"] {
            assert_eq!(app.get(path, Some(&bob)).await.location.as_deref(), Some("/settings/mfa"), "{path}");
        }
        assert_eq!(app.post("/orgs/acme/leave", Some(&bob), "").await.status, StatusCode::FORBIDDEN);
        let enrol = app.get("/settings/mfa", Some(&bob)).await.body;
        assert!(enrol.contains("A second factor is required for your account.") && enrol.contains("Required by: acme."));
        assert_eq!(app.get("/product", Some(&carol)).await.status, StatusCode::OK);
        assert!(app.get(&format!("/admin/users/{bob_id}"), Some(&root)).await.body.contains("required, not set up"));
        // The requirement lifted, the account works again
        // Someone without a factor cannot turn the requirement on (they would lock themselves out)
        app.post("/orgs", Some(&carol), "name=carols").await;
        let refused = app.post("/orgs/carols/mfa", Some(&carol), "required=1").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/orgs/acme/mfa", Some(&root), "").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/product", Some(&bob)).await.status, StatusCode::OK);
        // Bob can leave; the only owner cannot
        assert_eq!(app.post("/orgs/acme/leave", Some(&bob), "").await.status, StatusCode::SEE_OTHER);
        assert!(!app.get("/orgs", Some(&bob)).await.body.contains("acme"));
        assert_eq!(app.post("/orgs/carols/leave", Some(&carol), "").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/orgs/acme/leave", Some(&carol), "").await.status, StatusCode::NOT_FOUND);

        // The security log exports signed, for administrators only, and the export verifies
        assert_eq!(app.get("/admin/security/export?format=json", Some(&carol)).await.status, StatusCode::FORBIDDEN);
        let page = app.get("/admin/security", Some(&root)).await.body;
        assert!(page.contains("Chain intact") && page.contains("/admin/security/export?format=json"));
        let exported = app.get("/admin/security/export?format=json", Some(&root)).await;
        assert_eq!(exported.status, StatusCode::OK);
        let export: crate::trail::Export = serde_json::from_str(&exported.body).unwrap();
        let verified = crate::trail::verify(&export, Some(&db.log_key_fingerprint().unwrap())).unwrap();
        assert!(verified.count >= 4 && verified.scope == "instance");
        let csv = app.get("/admin/security/export?format=csv", Some(&root)).await.body;
        assert!(csv.starts_with("id,at,actor_id,actor,") && csv.lines().count() == verified.count + 1);
        assert_eq!(app.get("/admin/security/export?format=xml", Some(&root)).await.status, StatusCode::BAD_REQUEST);
        // Same content through the API, with an administrator's token only
        let root_token = tokens_of(&app.post("/settings/tokens", Some(&root), "name=audit&password=a-long-password").await.body).remove(0);
        let api = app.api("/api/security-log", Some(&format!("Bearer {root_token}"))).await;
        let api_export: crate::trail::Export = serde_json::from_str(&api.body).unwrap();
        assert_eq!(api_export.head, crate::trail::verify(&api_export, None).unwrap().head);
        let carol_token = tokens_of(&app.post("/settings/tokens", Some(&carol), "name=x&password=a-long-password").await.body).remove(0);
        assert_eq!(app.api("/api/security-log", Some(&format!("Bearer {carol_token}"))).await.status, StatusCode::FORBIDDEN);
        // The audit of an organization exports for its members, not for others
        assert!(app.get("/orgs/acme", Some(&root)).await.body.contains("/orgs/acme/audit/export?format=json"));
        let audit = app.get("/orgs/acme/audit/export?format=json", Some(&root)).await;
        let audit: crate::trail::Export = serde_json::from_str(&audit.body).unwrap();
        assert_eq!(crate::trail::verify(&audit, None).unwrap().scope, "organization:acme");
        assert_eq!(app.get("/orgs/acme/audit/export?format=json", Some(&carol)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api("/api/organizations/acme/audit", Some(&format!("Bearer {carol_token}"))).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api("/api/organizations/acme/audit", Some(&format!("Bearer {root_token}"))).await.status, StatusCode::OK);

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
        app.post("/orgs/acme/mfa", Some(&root), "").await;
        assert_eq!(db.list_security_events(None, 100).unwrap().iter().filter(|e| e.event == "mfa_requirement").count(), 4);
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
        let png = app.router.clone().oneshot(HttpRequest::get("/static/logo.png").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(png.headers().get(header::CONTENT_TYPE).unwrap(), "image/png");
        let png = axum::body::to_bytes(png.into_body(), 1 << 20).await.unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n") && png.len() > 5_000);
        // The stylesheet has a layout for narrow screens, and pages tell phones not to zoom out
        assert!(app.get("/static/app.css", None).await.body.contains("@media (max-width: 760px)"));
        assert!(app.get("/login", None).await.body.contains("name=\"viewport\" content=\"width=device-width"));
        // Signed out, a page shows nothing of the instance: no menus, no sync state, no version
        let login = app.get("/login", None).await.body;
        for hidden in ["CVE database", "/vendors", "/weaknesses", "Database synced", "Sync now", "never synced", env!("CARGO_PKG_VERSION")] {
            assert!(!login.contains(hidden), "the login page shows '{hidden}'");
        }
        assert!(login.contains("footer") && login.contains("DISCLAIMER.md"));
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

    // ---------- remediation deadlines ----------

    #[tokio::test(flavor = "multi_thread")]
    async fn deadlines_are_set_by_administrators_and_replaced_by_organization_owners() {
        let app = app(open_registration());
        let root = app.register("root").await;
        let owner = app.register("owner").await;
        let editor = app.register("editor").await;
        let viewer = app.register("viewer").await;
        let stranger = app.register("stranger").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        for (name, role) in [("editor", "editor"), ("viewer", "viewer")] {
            assert_eq!(app.post("/orgs/acme/members", Some(&owner), &format!("username={name}&role={role}")).await.status, StatusCode::SEE_OTHER);
            app.accept_invitations(name);
        }
        let db = Database::connect(&app.db_path).unwrap();
        let acme = db.get_org("acme", db.get_credentials("owner").unwrap().unwrap().0.id).unwrap().unwrap().id;
        let all = "critical=3&high=20&medium=60&low=120&kev=10";

        // The instance: administrators only, and nobody without a session
        for (who, session) in [("owner", &owner), ("viewer", &viewer), ("stranger", &stranger)] {
            assert_eq!(app.get("/admin/deadlines", Some(session)).await.status, StatusCode::FORBIDDEN, "{who}");
            assert_eq!(app.post("/admin/deadlines", Some(session), all).await.status, StatusCode::FORBIDDEN, "{who}");
        }
        for anonymous in [app.get("/admin/deadlines", None).await, app.post("/admin/deadlines", None, all).await, app.post("/orgs/acme/deadlines", None, "critical=1").await] {
            assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
            assert!(anonymous.location.as_deref().is_some_and(|to| to.starts_with("/login")), "{:?}", anonymous.location);
        }
        assert_eq!(db.instance_delays().unwrap(), crate::deadlines::Delays::default());
        let page = app.get("/admin/deadlines", Some(&root)).await;
        assert_eq!(page.status, StatusCode::OK);
        for (field, days) in [("critical", 7), ("high", 30), ("medium", 90), ("low", 180), ("kev", 14)] {
            assert!(page.body.contains(&format!("<input type=\"number\" name=\"{field}\" value=\"{days}\" min=\"1\" max=\"3650\" step=\"1\" required>")), "{field}");
        }
        assert!(page.body.contains("<a href=\"/admin/deadlines\" class=\"active\">Deadlines</a>"), "{}", page.body);
        // Whole numbers of days from 1 to 3650, all five of them
        for bad in ["critical=0&high=20&medium=60&low=120&kev=10", "critical=3&high=3651&medium=60&low=120&kev=10", "critical=3&high=20&medium=soon&low=120&kev=10",
                    "critical=3&high=20&medium=60&low=-5&kev=10", "critical=3&high=20&medium=60&low=120", "critical=3&high=20&medium=60&low=120&kev=1.5"] {
            assert_eq!(app.post("/admin/deadlines", Some(&root), bad).await.status, StatusCode::BAD_REQUEST, "{bad}");
        }
        assert_eq!(db.instance_delays().unwrap(), crate::deadlines::Delays::default());
        let saved = app.post("/admin/deadlines", Some(&root), all).await;
        assert_eq!((saved.status, saved.location.as_deref()), (StatusCode::SEE_OTHER, Some("/admin/deadlines")));
        let instance = crate::deadlines::Delays { critical: 3, high: 20, medium: 60, low: 120, kev: 10 };
        assert_eq!(db.instance_delays().unwrap(), instance);
        assert!(app.get("/admin/deadlines", Some(&root)).await.body.contains("name=\"kev\" value=\"10\""));

        // The organization: its owners. A viewer or an editor is refused, and who has no role in it does not
        // even learn it exists, an administrator of the instance included
        let replace = "critical=1&high=&medium=&low=&kev=40";
        for (who, session, expected) in [
            ("viewer", &viewer, StatusCode::FORBIDDEN), ("editor", &editor, StatusCode::FORBIDDEN),
            ("stranger", &stranger, StatusCode::NOT_FOUND), ("root", &root, StatusCode::NOT_FOUND),
        ] {
            assert_eq!(app.post("/orgs/acme/deadlines", Some(session), replace).await.status, expected, "{who}");
        }
        assert!(db.org_delay_override(acme).unwrap().is_empty());
        for bad in ["critical=0", "kev=3651", "high=many"] {
            assert_eq!(app.post("/orgs/acme/deadlines", Some(&owner), bad).await.status, StatusCode::BAD_REQUEST, "{bad}");
        }
        let saved = app.post("/orgs/acme/deadlines", Some(&owner), replace).await;
        assert_eq!((saved.status, saved.location.as_deref()), (StatusCode::SEE_OTHER, Some("/orgs/acme#deadlines")));
        assert_eq!(db.org_delays(acme).unwrap(), crate::deadlines::Delays { critical: 1, kev: 40, ..instance });
        // The page says what applies and who set it; the form is for the owners only
        let page = app.get("/orgs/acme", Some(&owner)).await.body;
        assert!(page.contains("<tr><td>Critical</td><td>1</td><td>this organization</td></tr>"), "{page}");
        assert!(page.contains("<tr><td>High</td><td>20</td><td><span class=\"muted\">the instance</span></td></tr>"));
        assert!(page.contains("<input type=\"number\" name=\"critical\" value=\"1\" placeholder=\"inherited: 3\" min=\"1\" max=\"3650\" step=\"1\">"));
        assert!(page.contains("<input type=\"number\" name=\"high\" placeholder=\"inherited: 20\" min=\"1\" max=\"3650\" step=\"1\">"));
        let read_only = app.get("/orgs/acme", Some(&viewer)).await.body;
        assert!(read_only.contains("<td>Exploited (CISA KEV)</td><td>40</td>") && !read_only.contains("/orgs/acme/deadlines"));
        // Emptied: the organization follows the instance again
        assert_eq!(app.post("/orgs/acme/deadlines", Some(&owner), "critical=&high=&medium=&low=&kev=").await.status, StatusCode::SEE_OTHER);
        assert_eq!(db.org_delays(acme).unwrap(), instance);

        // Every change is in the security log, with its author
        let logged: Vec<(String, String)> = db.list_security_events(None, 100).unwrap().into_iter()
            .filter(|e| e.event == "remediation_delays").map(|e| (e.actor, e.detail.unwrap_or_default())).collect();
        assert_eq!(logged, [
            ("owner".to_string(), "organization acme: inherited from the instance".to_string()),
            ("owner".to_string(), "organization acme: critical 1, kev 40".to_string()),
            ("root".to_string(), "instance: critical 3, high 20, medium 60, low 120, kev 10".to_string()),
        ]);
        let log = app.get("/admin/security", Some(&root)).await.body;
        assert!(log.contains("Remediation deadlines changed") && log.contains("organization acme: critical 1, kev 40"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_vulnerabilities_view_and_the_api_tell_what_is_due() {
        let app = app(open_registration());
        let owner = app.register("owner").await;
        let stranger = app.register("stranger").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        app.post("/projects", Some(&owner), "org=acme&name=infra").await;
        let db = Database::connect(&app.db_path).unwrap();
        for (id, cvss) in [("CVE-2024-4343", 9.1), ("CVE-2024-4344", 5.0)] {
            let mut cve = crate::models::Cve::new(id.into());
            cve.description = Some("Widget flaw".into());
            cve.cvss_v3_score = Some(cvss);
            cve.affected_products.push(crate::models::AffectedProduct {
                vendor: Some("acme".into()),
                product: Some("widget".into()),
                version: Some("*".into()),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        }
        assert_eq!(app.post("/orgs/acme/projects/infra/applications", Some(&owner), "name=widget&version=1.0&vendor=acme").await.status, StatusCode::SEE_OTHER);
        // Detected ten days ago: the critical one was due after 7 days, the medium one has 80 left
        db.conn().execute("UPDATE watchlist_entries SET created_at = datetime('now', '-10 days')", []).unwrap();
        let today = chrono::Utc::now().date_naive();
        let day = |from_detection: i64| (today + chrono::Duration::days(from_detection - 10)).to_string();
        let late = format!("<td class=\"due late\"><span class=\"tag late\" title=\"Due {}: 7 days after its detection on {}\">overdue by 3 days</span></td>", day(7), day(0));
        let in_time = format!("<td class=\"due\" title=\"Due {}: 90 days after its detection on {}\">in 80 days</td>", day(90), day(0));

        for scope in ["/product", "/product/acme/infra"] {
            let view = format!("{scope}?view=vulnerabilities");
            let page = app.get(&view, Some(&owner)).await.body;
            assert!(page.contains(&late) && page.contains(&in_time), "{scope}: {page}");
            assert!(page.contains(&format!("<a href=\"{view}&amp;show=overdue\">Overdue</a>")), "{scope}");
            // The column sorts: the nearest deadline first, or last
            assert!(page.contains("sort=due&amp;dir=asc"), "{scope}");
            let order = |body: &str| body.find("CVE-2024-4343</a>").unwrap() < body.find("CVE-2024-4344</a>").unwrap();
            assert!(order(&app.get(&format!("{view}&sort=due&dir=asc"), Some(&owner)).await.body), "{scope}");
            assert!(!order(&app.get(&format!("{view}&sort=due&dir=desc"), Some(&owner)).await.body), "{scope}");
            // Only what is overdue
            let overdue = app.get(&format!("{view}&show=overdue"), Some(&owner)).await.body;
            assert!(overdue.contains(&late) && !overdue.contains("CVE-2024-4344"), "{scope}");
            assert!(overdue.contains(&format!("<a href=\"{view}&amp;show=overdue\" class=\"active\">Overdue</a>")), "{scope}");
            // The rule is said under the list, with the delays that apply
            assert!(page.contains("7 days for a critical CVE, 30 for high, 90 for medium, 180 for low") && page.contains("without a score follows the medium delay"), "{scope}");
        }
        // Somebody else's projects are not theirs to list
        assert!(!app.get("/product?view=vulnerabilities&show=overdue", Some(&stranger)).await.body.contains("CVE-2024-4343"));
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities&show=overdue", Some(&stranger)).await.status, StatusCode::NOT_FOUND);

        // REST API: the same answer, for who can read the project
        let token = |session: &str| {
            let (app, session) = (&app, session.to_string());
            async move { format!("Bearer {}", tokens_of(&app.post("/settings/tokens", Some(&session), "name=ci&password=a-long-password").await.body).remove(0)) }
        };
        let (bearer, other) = (token(&owner).await, token(&stranger).await);
        let path = "/api/organizations/acme/projects/infra/watchlist";
        assert_eq!(app.api(path, None).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.get(path, Some(&owner)).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(app.api(path, Some(&other)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api(&format!("{path}?status=bogus"), Some(&bearer)).await.status, StatusCode::BAD_REQUEST);
        let read = |query: &'static str| {
            let (app, bearer) = (&app, bearer.clone());
            async move {
                let reply = app.api(&format!("{path}{query}"), Some(&bearer)).await;
                assert_eq!(reply.status, StatusCode::OK, "{query}: {}", reply.body);
                serde_json::from_str::<serde_json::Value>(&reply.body).unwrap()
            }
        };
        let entry = |list: &serde_json::Value, cve: &str| list["entries"].as_array().unwrap().iter().find(|e| e["entry"]["cve_id"] == cve).cloned().unwrap();
        let list = read("").await;
        assert_eq!(list["total"], 2);
        let critical = entry(&list, "CVE-2024-4343");
        assert_eq!((critical["due_at"].as_str(), critical["days_left"].as_i64(), critical["overdue_days"].as_i64()), (Some(day(7).as_str()), Some(-3), Some(3)));
        let medium = entry(&list, "CVE-2024-4344");
        assert_eq!((medium["due_at"].as_str(), medium["days_left"].as_i64(), medium["overdue_days"].as_i64()), (Some(day(90).as_str()), Some(80), Some(0)));
        let overdue = read("?overdue=1").await;
        assert_eq!((overdue["total"].as_i64(), overdue["entries"][0]["entry"]["cve_id"].as_str()), (Some(1), Some("CVE-2024-4343")));
        assert_eq!(read("?status=untreated&overdue=true").await["total"], 1);

        // The organization gives itself more time: nothing is overdue any more, in the list as in the API
        assert_eq!(app.post("/orgs/acme/deadlines", Some(&owner), "critical=30").await.status, StatusCode::SEE_OTHER);
        let page = app.get("/product?view=vulnerabilities", Some(&owner)).await.body;
        assert!(page.contains("in 20 days") && !page.contains("tag late"), "{page}");
        assert!(app.get("/product/acme/infra?view=vulnerabilities", Some(&owner)).await.body.contains("30 days for a critical CVE"));
        assert_eq!(read("?overdue=1").await["total"], 0);
        assert_eq!(app.post("/orgs/acme/deadlines", Some(&owner), "").await.status, StatusCode::SEE_OTHER);

        // Decided: no longer due, never overdue; the API says how long it took
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        let id = db.project_entries_for_cve(project, "CVE-2024-4343").unwrap()[0].0;
        assert_eq!(app.post(&format!("/orgs/acme/projects/infra/watchlist/{id}"), Some(&owner), "status=treated").await.status, StatusCode::SEE_OTHER);
        assert!(!app.get("/product?view=vulnerabilities&show=overdue", Some(&owner)).await.body.contains("CVE-2024-4343"));
        let closed = entry(&read("?status=treated").await, "CVE-2024-4343");
        assert_eq!(closed["resolved_in_days"], 10);
        assert!(closed.get("due_at").is_none() && closed.get("overdue_days").is_none());
        assert_eq!(read("?overdue=1").await["total"], 0);
    }

    /// The entry of a view in the products menu, as the page writes it
    fn menu_entry(scope: &str, key: &str, label: &str, active: bool) -> String {
        let class = if active { " class=\"active\"" } else { "" };
        format!("<a href=\"{scope}?view={key}\"{class}>{label}</a>")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_vulnerabilities_lists_fit_the_window() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        // Both lists name their columns for the stylesheet; the project column only exists for all projects
        for (scope, project) in [("/product", "<col class=\"project\">"), ("/product/acme/infra", "")] {
            let review = app.get(&format!("{scope}?view=vulnerabilities"), Some(&alice)).await.body;
            assert!(review.contains(&format!("<table class=\"list triage fit\"><colgroup><col class=\"cve\"><col class=\"cvss\"><col class=\"app\">{project}<col class=\"due\"><col class=\"desc\"><col class=\"actions\"></colgroup>")), "{scope}");
            let decided = app.get(&format!("{scope}?view=vulnerabilities&show=handled"), Some(&alice)).await.body;
            assert!(decided.contains(&format!("<table class=\"list fit decided\"><colgroup><col class=\"cve\"><col class=\"cvss\"><col class=\"app\">{project}<col class=\"decision\"><col class=\"actions\"></colgroup>")), "{scope}");
            let columns = if project.is_empty() { 5 } else { 6 };
            assert!(decided.contains(&format!("colspan=\"{columns}\"")) && decided.contains("No decision yet."), "{scope}");
        }
        let css = app.get("/static/app.css", None).await.body;
        assert!(css.contains("table.list.fit { table-layout: fixed; }"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_list_fits_the_window() {
        let app = app(with_inventory());
        let root = app.register("root").await;
        app.post("/orgs", Some(&root), "name=acme").await;
        app.post("/projects", Some(&root), "org=acme&name=infra").await;
        let id = Database::connect(&app.db_path).unwrap().get_credentials("root").unwrap().unwrap().0.id;
        let user = format!("/admin/users/{id}");
        // The widths the stylesheet knows; a column without a name takes what is left
        let sized = ["check", "cve", "cvss", "when", "day", "num", "fig", "flag", "kind", "decision", "due", "name", "app", "who", "project", "wide", "version", "act", "actions", "desc"];
        let table = regex::Regex::new(r#"(?s)<table class="([^"]*)">(.*?)</table>"#).unwrap();
        let column = regex::Regex::new(r#"<col(?: class="([a-z]+)")?>"#).unwrap();
        let pages = [
            "/product", "/product?view=vulnerabilities", "/product?view=vulnerabilities&show=handled", "/product?view=vulnerabilities&show=overdue",
            "/product/acme/infra?view=vulnerabilities&show=overdue", "/admin/deadlines", "/product?view=applications",
            "/product?view=overdue", "/product/acme/infra?view=overdue", "/product/default/default",
            "/product?view=subscriptions", "/product?view=history", "/product?view=audit",
            "/product/acme/infra", "/product/acme/infra?view=vulnerabilities", "/product/acme/infra?view=applications",
            "/product/acme/infra?view=subscriptions", "/product/acme/infra?view=history", "/product/acme/infra?view=audit",
            "/product/acme/infra?view=settings", "/projects", "/orgs", "/orgs/acme", "/cve", "/cve/CVE-2024-4242", "/vendors", "/weaknesses",
            "/settings", "/settings/mfa", "/admin", "/admin/users", user.as_str(), "/admin/sources", "/admin/notifications",
            "/admin/notifications?tab=destinations", "/admin/security", "/admin/mcp", "/admin/sso", "/admin/sso?tab=scim",
        ];
        let (mut lists, mut dense) = (0, 0);
        for path in pages {
            let page = app.get(path, Some(&root)).await;
            assert_eq!(page.status, StatusCode::OK, "{path}");
            for found in table.captures_iter(&page.body) {
                let (classes, inside) = (&found[1], &found[2]);
                lists += 1;
                // Sized by the stylesheet, not by its content: no name or text can make it wider than the page
                assert!(classes.starts_with("list ") && classes.split(' ').any(|c| c == "fit"), "{path}: {classes}");
                let head = inside.split("</thead>").next().unwrap();
                let columns: Vec<&str> = column.captures_iter(head).map(|c| c.get(1).map_or("", |m| m.as_str())).collect();
                assert!(inside.starts_with("<colgroup>") && !columns.is_empty(), "{path}: no column group");
                // One column named per header cell, each name known to the stylesheet, and room left for a text
                assert_eq!(columns.len(), head.matches("<th").count() - 1, "{path}: {columns:?}");
                assert!(columns.iter().all(|c| c.is_empty() || sized.contains(c)), "{path}: {columns:?}");
                assert!(columns.iter().any(|c| c.is_empty() || ["desc", "app"].contains(c)), "{path}: {columns:?}");
                // A cell kept on one line must be one whose column is wide enough: an identifier, a score, a date
                assert!(!inside.contains("class=\"right nowrap\""), "{path}");
                // The widest lists scroll inside their own box, which is all that surrounds them
                if classes.split(' ').any(|c| c == "dense") {
                    dense += 1;
                    let before = &page.body[..found.get(0).unwrap().start()];
                    assert!(before.ends_with("<div class=\"scroll\">"), "{path}");
                }
            }
        }
        assert!(lists >= 34 && dense >= 6, "{lists} lists, {dense} dense");
        // No list of the interface is left to the width of its content
        for source in [
            include_str!("admin.rs"), include_str!("inventory.rs"), include_str!("invitations.rs"), include_str!("mfa.rs"), include_str!("notifications.rs"),
            include_str!("pages.rs"), include_str!("product.rs"), include_str!("projects.rs"), include_str!("views.rs"),
        ] {
            let plain = regex::Regex::new(r"(?m)^\s*table\.list \{").unwrap();
            assert_eq!(plain.find_iter(source).count(), 0);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_vulnerabilities_view_keeps_its_old_address() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        for scope in ["/product", "/product/acme/infra"] {
            let page = app.get(&format!("{scope}?view=vulnerabilities"), Some(&alice)).await.body;
            assert!(page.contains("<title>Vulnerabilities · Vulnizard</title>"), "{scope}");
            assert!(page.contains(&menu_entry(scope, "vulnerabilities", "Vulnerabilities", true)), "{scope}");
            // The menu no longer names the view after its default filter, which is still the first one
            assert!(!page.contains("view=review"), "{scope}");
            assert!(page.contains(&format!("<a href=\"{scope}?view=vulnerabilities\" class=\"active\">To review</a>")), "{scope}");
            assert!(page.contains("Nothing to review."), "{scope}");
            // The address of before the renaming shows the same view, under its new name
            for old in ["?view=review", "?view=review&show=handled"] {
                let former = app.get(&format!("{scope}{old}"), Some(&alice)).await;
                assert_eq!(former.status, StatusCode::OK, "{scope}{old}");
                assert!(former.body.contains("<title>Vulnerabilities · Vulnizard</title>"), "{scope}{old}");
                assert!(former.body.contains(&menu_entry(scope, "vulnerabilities", "Vulnerabilities", true)), "{scope}{old}");
            }
            let decided = app.get(&format!("{scope}?view=review&show=handled"), Some(&alice)).await.body;
            assert!(decided.contains("No decision yet."), "{scope}");
        }
        // Other pages lead to the view under its new name
        assert!(app.get("/product", Some(&alice)).await.body.contains(&menu_entry("/product", "vulnerabilities", "Vulnerabilities", false)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_history_view_says_which_day_it_shows() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        let today = chrono::Utc::now().date_naive();
        let day = |back: i64| (today - chrono::Duration::days(back)).to_string();
        for scope in ["/product", "/product/acme/infra"] {
            let now = app.get(&format!("{scope}?view=history"), Some(&alice)).await.body;
            assert!(now.contains("<title>History · Vulnizard</title>"), "{scope}");
            assert!(now.contains(&menu_entry(scope, "history", "History", true)) && !now.contains("Evolution"), "{scope}");
            // Today: nothing calls it a past state, and there is nowhere to come back from
            assert!(now.contains("You are looking at the current state.") && !now.contains("Past state"), "{scope}");
            assert!(!now.contains("Back to today") && !now.contains("Next day"), "{scope}");
            // A day is chosen in a chart, with the date field, or one step at a time
            assert!(now.contains("Every day of a chart is a link"), "{scope}");
            assert!(now.contains(&format!("<a href=\"{scope}?view=history&amp;days=30&amp;at={}\">", day(3))), "{scope}");
            assert!(now.contains(&format!("<input type=\"date\" name=\"at\" value=\"{today}\" max=\"{today}\" required>")), "{scope}");
            assert!(now.contains(&format!("href=\"{scope}?view=history&amp;days=30&amp;at={}\" title=\"State on {}\">← Previous day</a>", day(1), day(1))), "{scope}");

            // A past day is announced as such, with the way back
            let then = app.get(&format!("{scope}?view=history&days=90&at={}", day(10)), Some(&alice)).await.body;
            assert!(then.contains(&format!("<span class=\"tag warn\">Past state</span> <strong>You are looking at {}.</strong>", day(10))), "{scope}");
            assert!(!then.contains("You are looking at the current state."), "{scope}");
            assert!(then.contains(&format!("<a class=\"button today\" href=\"{scope}?view=history&amp;days=90\">Back to today</a>")), "{scope}");
            assert!(then.contains(&format!("at={}\" title=\"State on {}\">Next day →</a>", day(9), day(9))), "{scope}");
            assert!(then.contains("Nothing was tracked at that date."), "{scope}");
            // A day in the future is today
            let future = app.get(&format!("{scope}?view=history&at=2999-01-01"), Some(&alice)).await.body;
            assert!(future.contains("You are looking at the current state."), "{scope}");

            // The address of before the renaming shows the same view, past day included
            let former = app.get(&format!("{scope}?view=evolution&at={}", day(10)), Some(&alice)).await;
            assert_eq!(former.status, StatusCode::OK, "{scope}");
            assert!(former.body.contains("<title>History · Vulnizard</title>") && former.body.contains("Past state"), "{scope}");
            assert!(former.body.contains(&menu_entry(scope, "history", "History", true)), "{scope}");
        }
        // The overview leads there
        app.post("/orgs/acme/projects/infra/applications", Some(&alice), "name=widget&version=1.0").await;
        let overview = app.get("/product", Some(&alice)).await.body;
        assert!(overview.contains("Charts, and the state of any past day: <a href=\"/product?view=history\">History</a>."));
        assert!(overview.contains("What is late and where: <a href=\"/product?view=overdue\">Overdue</a>."));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_add_button_offers_only_projects_one_may_manage() {
        let app = app(open_registration());
        let owner = app.register("owner").await;
        let carol = app.register("carol").await;
        let reader = app.register("reader").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        for project in ["infra", "shop", "vault"] {
            app.post("/projects", Some(&owner), &format!("org=acme&name={project}")).await;
        }
        // Carol edits one project, reads another and does not know of the third; the reader only reads
        for (project, user, role) in [("infra", "carol", "editor"), ("shop", "carol", "viewer"), ("shop", "reader", "viewer")] {
            let given = app
                .post(&format!("/orgs/acme/projects/{project}/members"), Some(&owner), &format!("username={user}&role={role}"))
                .await;
            assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
            app.accept_invitations(user);
        }
        let db = Database::connect(&app.db_path).unwrap();
        let id = |project: &str| db.find_project("acme", project).unwrap().unwrap();
        let (infra, shop, vault) = (id("infra"), id("shop"), id("vault"));
        let option = |project_id: i64, name: &str| format!("<option value=\"{project_id}\">{name}</option>");

        for view in ["applications", "subscriptions"] {
            // With all projects shown, the form asks for the project instead of sending to the menu
            let all = app.get(&format!("/product?view={view}"), Some(&carol)).await.body;
            assert!(all.contains("<details class=\"add\"><summary><span class=\"plus\" aria-hidden=\"true\">+</span>Add a"), "{view}");
            assert!(all.contains("<select name=\"project_id\" required>") && all.contains(&option(infra, "infra")), "{view}");
            assert!(!all.contains(&option(shop, "shop")) && !all.contains(&option(vault, "vault")), "{view}");
            assert!(!all.contains("Select a project in the menu to add") && !all.contains("Select a project in the menu to subscribe"), "{view}");
            // The button comes before the list it adds to
            assert!(all.find("<details class=\"add\">").unwrap() < all.find("class=\"card notice\"").or(all.find("<table")).unwrap(), "{view}");
            // In a project the form needs no choice; without the right there is no form at all
            let one = app.get(&format!("/product/acme/infra?view={view}"), Some(&carol)).await.body;
            assert!(one.contains("<details class=\"add\">") && !one.contains("<select name=\"project_id\""), "{view}");
            assert!(one.contains(&format!("<input type=\"hidden\" name=\"project_id\" value=\"{infra}\">")), "{view}");
            for page in [format!("/product/acme/shop?view={view}"), format!("/product?view={view}")] {
                let read_only = app.get(&page, Some(&reader)).await.body;
                assert!(!read_only.contains("<details class=\"add\">") && !read_only.contains("name=\"project_id\""), "{page}");
                assert!(read_only.contains("takes the owner or editor role"), "{page}");
            }
        }

        // A forged form does not add to a project one only reads, nor to one that is not one's own
        let application = |project_id: i64| format!("project_id={project_id}&name=widget&version=1.0&back=%2Fproduct%3Fview%3Dapplications");
        let subscription = |project_id: i64| format!("project_id={project_id}&vendor=acme&product=&action=subscribe&back=all");
        for target in [shop, vault, 999_999] {
            assert_eq!(app.post("/applications", Some(&carol), &application(target)).await.status, StatusCode::FORBIDDEN, "{target}");
            assert_eq!(app.post("/subscriptions", Some(&carol), &subscription(target)).await.status, StatusCode::FORBIDDEN, "{target}");
        }
        assert_eq!(app.post("/applications", Some(&reader), &application(shop)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.post("/applications", Some(&carol), "name=widget&version=1.0").await.status, StatusCode::BAD_REQUEST);
        assert_eq!(app.post("/applications", None, &application(infra)).await.location.as_deref(), Some("/login"));
        for project in [shop, vault] {
            assert!(db.list_applications(project).unwrap().is_empty() && db.list_subscriptions(project).unwrap().is_empty());
        }

        // Where she may, the addition is made and she comes back to the page she was on
        let added = app.post("/applications", Some(&carol), &application(infra)).await;
        assert_eq!(added.location.as_deref(), Some("/product?view=applications"), "{}", added.body);
        assert_eq!(db.list_applications(infra).unwrap()[0].name, "widget");
        assert_eq!(app.post("/applications", Some(&carol), &application(infra)).await.status, StatusCode::BAD_REQUEST);
        let subscribed = app.post("/subscriptions", Some(&carol), &subscription(infra)).await;
        assert_eq!(subscribed.location.as_deref(), Some("/product?view=subscriptions"), "{}", subscribed.body);
        assert_eq!(db.list_subscriptions(infra).unwrap()[0].vendor, "acme");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_subscription_list_says_what_a_subscription_is() {
        let app = app(open_registration());
        let alice = app.register("alice").await;
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        let project_id = Database::connect(&app.db_path).unwrap().find_project("acme", "infra").unwrap().unwrap();
        for scope in ["/product", "/product/acme/infra"] {
            let empty = app.get(&format!("{scope}?view=subscriptions"), Some(&alice)).await.body;
            assert!(empty.contains("No subscription yet."), "{scope}");
            // What it follows, what it feeds, and how a tracked application differs
            assert!(empty.contains("follows a vendor, or one product of a vendor, <strong>without a version</strong>"), "{scope}");
            assert!(empty.contains("daily report of the project and is sent to its notifications"), "{scope}");
            assert!(empty.contains("It is not a tracked application."), "{scope}");
            assert!(empty.contains(&format!("<a href=\"{scope}?view=applications\">applications</a>")), "{scope}");
            assert!(empty.contains(&format!("<a href=\"{scope}?view=vulnerabilities\">vulnerabilities</a>")), "{scope}");
            // An empty table under the explanation would say it twice
            assert!(!empty.contains("<table"), "{scope}");
        }
        let sub = format!("project_id={project_id}&vendor=acme&product=&action=subscribe&back=project");
        assert_eq!(app.post("/subscriptions", Some(&alice), &sub).await.location.as_deref(), Some("/product/acme/infra?view=subscriptions"));
        for scope in ["/product", "/product/acme/infra"] {
            let listed = app.get(&format!("{scope}?view=subscriptions"), Some(&alice)).await.body;
            assert!(listed.contains("<table") && !listed.contains("It is not a tracked application."), "{scope}");
            // A filter that matches nothing is not an empty list
            let filtered = app.get(&format!("{scope}?view=subscriptions&q=zzz"), Some(&alice)).await.body;
            assert!(filtered.contains("No subscription matches.") && !filtered.contains("No subscription yet."), "{scope}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_page_offers_the_themes_without_loosening_the_policy() {
        let app = app(open_registration());
        let login = app.get("/setup", None).await;
        let alice = app.register("alice").await;
        let home = app.get("/product", Some(&alice)).await;
        for page in [&login, &home] {
            // The script that applies the choice comes before the body, and is a file
            let head = page.body.split("</head>").next().unwrap();
            assert!(head.contains("<script src=\"/static/theme.js\"></script>"));
            // The menu lists every theme, and the button says both ways
            assert!(page.body.contains("<select data-theme-choice aria-label=\"Color theme\""));
            for (key, label) in views::THEMES {
                assert!(page.body.contains(&format!("<option value=\"{key}\">{label}</option>")), "{key}");
            }
            assert!(page.body.contains("<button class=\"secondary\" type=\"button\" data-mode-toggle"));
            assert!(page.body.contains("☾ Night") && page.body.contains("☀ Day"));
            // Nothing inline: no script body, no handler, no style attribute
            assert_eq!(page.body.matches("<script").count(), 2);
            assert_eq!(page.body.matches("<script src=\"/static/").count(), 2);
            for inline in [" onclick=", " onchange=", " onload=", " style=", "<style", "javascript:"] {
                assert!(!page.body.contains(inline), "{inline}");
            }
            // The policy is the one of before the themes, word for word
            assert_eq!(
                page.csp.as_deref(),
                Some("default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            );
        }
        // The script is served like the others, and holds what the page relies on
        let script = app.get("/static/theme.js", None).await;
        assert_eq!(script.status, StatusCode::OK);
        assert_eq!(script.cache.as_deref(), Some("no-cache"));
        // Kept by the browser, which asks each time whether it is still the one of this release
        for path in ["/static/theme.js", "/static/filter.js", "/static/mfa.js", "/static/app.css"] {
            let first = app.router.clone().oneshot(HttpRequest::get(path).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(first.status(), StatusCode::OK, "{path}");
            let etag = first.headers().get(header::ETAG).expect("an ETag").clone();
            assert!(etag.to_str().unwrap().contains(env!("CARGO_PKG_VERSION")), "{path}");
            let again = app.router.clone().oneshot(HttpRequest::get(path).header(header::IF_NONE_MATCH, etag).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(again.status(), StatusCode::NOT_MODIFIED, "{path}");
            let other = app.router.clone().oneshot(HttpRequest::get(path).header(header::IF_NONE_MATCH, "\"0.0.0-1\"").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(other.status(), StatusCode::OK, "{path}");
        }
        assert!(script.body.contains("prefers-color-scheme: dark") && script.body.contains("localStorage"));
        assert!(script.body.contains("data-theme-choice") && script.body.contains("data-mode-toggle"));
        // Without the script the controls are hidden, and the system setting still picks day or night
        let css = app.get("/static/app.css", None).await.body;
        assert!(css.contains(".theme { display: none;") && css.contains(".js .theme { display: flex; }"));
        assert!(css.contains("@media (prefers-color-scheme: dark) {\n  :root:not([data-mode=\"light\"]) {"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_actions_on_selected_users_are_a_toolbar_above_the_list() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        app.register("dev").await;
        let page = app.get("/admin/users", Some(&admin)).await.body;
        // One form holds the toolbar, then the list it acts on; the former title is gone
        let form = page.split("<form method=\"post\" action=\"/admin/users/bulk\">").nth(1).expect("the bulk form");
        let form = form.split("</form>").next().unwrap();
        let toolbar = form.find("<div class=\"toolbar\" data-selection=\"ids\">").expect("the toolbar");
        assert_eq!(toolbar, 0, "something sits between the form and its toolbar");
        assert!(toolbar < form.find("<table").unwrap());
        assert!(!page.contains("For the selected users"));
        let bar = form.split("<table").next().unwrap();
        for control in ["<select name=\"action\"", "<select name=\"scope\"", "<select name=\"role\"", "<button type=\"submit\">Apply</button>"] {
            assert!(bar.contains(control), "{control}");
        }
        assert_eq!(form.matches("name=\"ids\"").count(), 2);
        // Served usable: the script greys the toolbar out, a browser without it must not be locked out
        assert!(!bar.contains("disabled"));
        let script = app.get("/static/filter.js", None).await.body;
        assert!(script.contains("data-selection") && script.contains("control.disabled = checked === 0"));

        // Without a selection the server refuses, whatever the action, and changes nothing
        let db = Database::connect(&app.db_path).unwrap();
        let dev = db.get_credentials("dev").unwrap().unwrap().0.id;
        for action in ["assign", "enable", "disable", "grant_admin", "revoke_admin", ""] {
            let refused = app.post("/admin/users/bulk", Some(&admin), &format!("action={action}&scope=instance&role=viewer")).await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{action}");
            assert!(refused.body.contains("Select at least one user."), "{action}");
        }
        // Ids that are not numbers are no selection either
        assert_eq!(app.post("/admin/users/bulk", Some(&admin), "action=disable&ids=&ids=x").await.status, StatusCode::BAD_REQUEST);
        let account = db.list_accounts().unwrap().into_iter().find(|a| a.id == dev).unwrap();
        assert!(!account.disabled && !account.is_admin && account.instance_role.is_none());
        // With one, the action applies
        let applied = app.post("/admin/users/bulk", Some(&admin), &format!("action=disable&ids={dev}")).await;
        assert_eq!(applied.status, StatusCode::SEE_OTHER, "{}", applied.body);
        assert!(db.list_accounts().unwrap().into_iter().find(|a| a.id == dev).unwrap().disabled);
    }

    /// Two organizations, each with a project tracking an application a CVE affects
    async fn two_organizations(app: &TestApp) -> (String, String, String) {
        let root = overseer(app).await;
        let alice = app.register("alice").await;
        let bob = app.register("bob").await;
        let db = Database::connect(&app.db_path).unwrap();
        for (id, vendor, product, score) in [("CVE-2024-4343", "acme", "widget", 9.1), ("CVE-2024-4444", "globex", "gadget", 5.0)] {
            let mut cve = crate::models::Cve::new(id.into());
            cve.cvss_v3_score = Some(score);
            cve.affected_products.push(crate::models::AffectedProduct {
                vendor: Some(vendor.into()),
                product: Some(product.into()),
                version: Some("*".into()),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        }
        app.post("/orgs", Some(&alice), "name=acme").await;
        app.post("/projects", Some(&alice), "org=acme&name=infra").await;
        let added = app.post("/orgs/acme/projects/infra/applications", Some(&alice), "name=widget&version=1.0&vendor=acme").await;
        assert_eq!(added.status, StatusCode::SEE_OTHER, "{}", added.body);
        (root, alice, bob)
    }

    /// The administrator, with a role on the whole instance: administering
    /// gives no project by itself, that role gives those of every organization
    async fn overseer(app: &TestApp) -> String {
        let root = app.register("root").await;
        let id = Database::connect(&app.db_path).unwrap().get_credentials("root").unwrap().unwrap().0.id;
        let given = app.post(&format!("/admin/users/{id}/assign"), Some(&root), "scope=instance&role=viewer").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
        root
    }

    async fn second_organization(app: &TestApp, bob: &str) {
        app.post("/orgs", Some(bob), "name=globex").await;
        app.post("/projects", Some(bob), "org=globex&name=shop").await;
        let added = app.post("/orgs/globex/projects/shop/applications", Some(bob), "name=gadget&version=2.0&vendor=globex").await;
        assert_eq!(added.status, StatusCode::SEE_OTHER, "{}", added.body);
    }

    fn org_entry(org: &str, label: &str, active: bool) -> String {
        let class = if active { " class=\"active\"" } else { "" };
        format!("<button type=\"submit\" name=\"org\" value=\"{org}\"{class}>{label}</button>")
    }

    /// The first figure of the overview of a scope, leading to the list it counts
    fn open_figure(scope: &str, count: i64) -> String {
        format!("<div class=\"value\"><a href=\"{scope}?view=vulnerabilities\">{count}</a></div><div class=\"label\">open vulnerabilities</div>")
    }

    fn to_review(count: i64) -> String {
        open_figure("/product", count)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_administrator_narrows_all_projects_to_one_organization() {
        {
            // With a single organization (the one every instance starts with) there is nothing to choose
            let app = app(open_registration());
            let root = overseer(&app).await;
            let single = app.get("/product", Some(&root)).await.body;
            assert!(single.contains("<a href=\"/product/default/default\"") && !single.contains("/org-filter"));
            assert!(!single.contains("Switch organization"));
        }
        let app = app(open_registration());
        let (root, _alice, bob) = two_organizations(&app).await;
        second_organization(&app, &bob).await;

        // The administrator belongs to neither and sees both: the menu is a plain form, next to the project menu
        let all = app.get("/product?view=applications", Some(&root)).await.body;
        let menu = all.split("<details class=\"menu org\">").nth(1).expect("the organization menu");
        let (menu, after) = menu.split_once("</details>").unwrap();
        assert!(after.starts_with("<details class=\"menu\"><summary title=\"Switch project\">All projects<span class=\"muted\"> (*)</span>"));
        assert!(menu.starts_with("<summary title=\"Switch organization\">All organizations</summary><form method=\"post\" action=\"/org-filter\">"));
        assert!(menu.contains("<input type=\"hidden\" name=\"back\" value=\"/product?view=applications\">"));
        for entry in [org_entry("", "All organizations", true), org_entry("acme", "acme", false), org_entry("default", "default", false), org_entry("globex", "globex", false)] {
            assert!(menu.contains(&entry), "{entry}");
        }
        // Nothing in it needs a script
        assert!(!menu.contains("<script") && !menu.contains("onclick") && !menu.contains("onchange"));
        assert!(app.get("/static/app.css", None).await.body.contains("details.menu li button {"));
        // From another page the choice comes back to that page
        assert!(app.get("/cve", Some(&root)).await.body.contains("<input type=\"hidden\" name=\"back\" value=\"/cve\">"));
        assert!(app.get("/product/acme/infra?view=audit", Some(&root)).await.body.contains("name=\"back\" value=\"/product?view=audit\">"));

        // Everything is listed before a choice
        let project_link = |org: &str, project: &str, view: &str| format!("<a href=\"/product/{org}/{project}?view={view}\"");
        assert!(all.contains("widget") && all.contains("gadget"));
        assert!(all.contains(&project_link("acme", "infra", "applications")) && all.contains(&project_link("globex", "shop", "applications")));
        let vulnerabilities = app.get("/product?view=vulnerabilities", Some(&root)).await.body;
        assert!(vulnerabilities.contains("CVE-2024-4343") && vulnerabilities.contains("CVE-2024-4444"));
        assert!(app.get("/product", Some(&root)).await.body.contains(&to_review(2)));

        // Choosing one sets a cookie the scripts cannot read, and comes back to the page
        let chosen = app.post("/org-filter", Some(&root), "org=acme&back=%2Fproduct%3Fview%3Dapplications").await;
        assert_eq!(chosen.status, StatusCode::SEE_OTHER, "{}", chosen.body);
        assert_eq!(chosen.location.as_deref(), Some("/product?view=applications"));
        assert_eq!(chosen.cookie.as_deref(), Some("vz_org=acme"));
        let acme = format!("{root}; vz_org=acme");

        // The project menu and every list of "all projects" keep that organization only
        for view in ["overview", "vulnerabilities", "overdue", "applications", "subscriptions", "history", "audit"] {
            let page = app.get(&format!("/product?view={view}"), Some(&acme)).await;
            assert_eq!(page.status, StatusCode::OK, "{view}");
            let body = page.body;
            assert!(body.contains("<summary title=\"Switch organization\">acme</summary>"), "{view}");
            assert!(body.contains(&org_entry("acme", "acme", true)) && body.contains(&org_entry("globex", "globex", false)), "{view}");
            assert!(body.contains("<summary title=\"Switch project\">All projects<span class=\"muted\"> of acme</span>"), "{view}");
            assert!(body.contains("All projects of acme (*)</a>") && body.contains("<h1>All projects of acme "), "{view}");
            assert!(body.contains(&project_link("acme", "infra", view).replace("?view=overview", "")), "{view}");
            // The other organization is only named as an entry of the menu
            let rest = body.replace(&org_entry("globex", "globex", false), "");
            assert!(!rest.contains("globex") && !rest.contains("shop") && !rest.contains("gadget") && !rest.contains("CVE-2024-4444"), "{view}");
        }
        let vulnerabilities = app.get("/product?view=vulnerabilities", Some(&acme)).await.body;
        assert!(vulnerabilities.contains("CVE-2024-4343"));
        let applications = app.get("/product?view=applications", Some(&acme)).await.body;
        assert!(applications.contains("widget"));
        // The figures are those of that organization: its critical CVE, not the medium one of the other
        let by_severity = |body: &str, severity: &str| body.contains(&format!("<a href=\"/product?view=vulnerabilities&amp;severity={severity}\">1</a>"));
        let overview = app.get("/product", Some(&acme)).await.body;
        assert!(overview.contains(&to_review(1)) && by_severity(&overview, "critical") && !by_severity(&overview, "medium"));
        assert!(app.get("/product?view=history", Some(&acme)).await.body.contains("<div class=\"value\">1</div><div class=\"label\">to review</div>"));
        let globex = format!("{root}; vz_org=globex");
        let other = app.get("/product", Some(&globex)).await.body;
        assert!(other.contains(&to_review(1)) && by_severity(&other, "medium") && !by_severity(&other, "critical"));
        let everything = app.get("/product", Some(&root)).await.body;
        assert!(by_severity(&everything, "critical") && by_severity(&everything, "medium"));
        // So is what is overdue: the critical one is late once detected ten days ago, the medium one is not
        Database::connect(&app.db_path).unwrap().conn().execute("UPDATE watchlist_events SET at = datetime('now', '-10 days')", []).unwrap();
        let late = "<a href=\"/product?view=vulnerabilities&amp;show=overdue\">1</a></div><div class=\"label\">overdue on their remediation deadline</div>";
        assert!(app.get("/product", Some(&acme)).await.body.contains(late) && app.get("/product", Some(&root)).await.body.contains(late));
        assert!(app.get("/product", Some(&globex)).await.body.contains("<div class=\"value\">0</div><div class=\"label\">overdue on their remediation deadline</div>"));
        assert!(app.get("/product?view=overdue", Some(&acme)).await.body.contains("app=widget\">widget</a>"));
        assert!(app.get("/product?view=overdue", Some(&globex)).await.body.contains("Nothing is overdue."));

        // It narrows lists and is no access rule: a project of the other organization still opens
        let direct = app.get("/product/globex/shop?view=applications", Some(&acme)).await;
        assert_eq!(direct.status, StatusCode::OK);
        assert!(direct.body.contains("gadget") && direct.body.contains("<summary title=\"Switch project\">shop</summary>"));

        // "All organizations" forgets the choice, and everything is back
        let cleared = app.post("/org-filter", Some(&acme), "org=&back=%2Fproduct").await;
        assert_eq!((cleared.status, cleared.location.as_deref(), cleared.cookie.as_deref()), (StatusCode::SEE_OTHER, Some("/product"), Some("vz_org=")));
        for cookie in [root.clone(), format!("{root}; vz_org=")] {
            let body = app.get("/product?view=vulnerabilities", Some(&cookie)).await.body;
            assert!(body.contains("CVE-2024-4343") && body.contains("CVE-2024-4444") && !body.contains("All projects of"));
            assert!(app.get("/product", Some(&cookie)).await.body.contains(&to_review(2)));
        }

        // A forged value is no filter, and is never written back in the page
        for forged in ["nowhere", "%3Cb%3E", "ACME", "acme%00", "%FF", "acme; vz_org=nowhere"] {
            let cookie = format!("{root}; vz_org={forged}");
            let body = app.get("/product?view=applications", Some(&cookie)).await.body;
            if forged.starts_with("acme;") {
                // The first value sent is the one read
                assert!(body.contains("All projects of acme") && !body.contains("nowhere"));
            } else {
                assert_eq!(body, all, "{forged}");
            }
        }

        // The cookie is the session's kind: kept from scripts, sent on navigation, Secure over https
        assert_eq!(org_cookie(open_registration()).await, format!("vz_org=globex; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"));
        let mut https = open_registration();
        https.web.base_url = "https://vulnizard.example".into();
        assert_eq!(org_cookie(https).await, format!("vz_org=globex; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}; Secure"));
    }

    /// The cookie as the server writes it when an organization is chosen
    async fn org_cookie(config: Config) -> String {
        let app = app(config);
        let (root, _, bob) = two_organizations(&app).await;
        second_organization(&app, &bob).await;
        let request = HttpRequest::post("/org-filter")
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://localhost")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, root)
            .body(Body::from("org=globex&back=%2F%2Fevil.example%2F"))
            .unwrap();
        let response = app.router.clone().oneshot(request).await.unwrap();
        // Only a page of this site is come back to
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/product");
        response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_organization_filter_shows_nothing_more_than_one_already_sees() {
        let app = app(open_registration());
        let (_root, alice, bob) = two_organizations(&app).await;
        second_organization(&app, &bob).await;

        // A member of one organization has no menu, and learns nothing by asking for another:
        // an organization that exists and one that does not get the very same pages
        for view in ["overview", "vulnerabilities", "overdue", "applications", "subscriptions", "history", "audit"] {
            let path = format!("/product?view={view}");
            let plain = app.get(&path, Some(&alice)).await.body;
            assert!(!plain.contains("Switch organization") && !plain.contains("/org-filter") && !plain.contains("globex"), "{view}");
            assert!(!plain.contains("gadget") && !plain.contains("CVE-2024-4444"), "{view}");
            for asked in ["globex", "nowhere", "acme"] {
                let body = app.get(&path, Some(&format!("{alice}; vz_org={asked}"))).await.body;
                assert_eq!(body, plain, "{view} {asked}");
            }
        }
        let existing = app.post("/org-filter", Some(&alice), "org=globex&back=%2Fproduct").await;
        let unknown = app.post("/org-filter", Some(&alice), "org=nowhere&back=%2Fproduct").await;
        for reply in [&existing, &unknown] {
            assert_eq!((reply.status, reply.location.as_deref()), (StatusCode::SEE_OTHER, Some("/product")));
            assert_eq!(reply.cookies, vec!["vz_org=".to_string()]);
            assert_eq!(reply.body, "");
        }
        // Nor does a project of the other organization open
        assert_eq!(app.get("/product/globex/shop", Some(&format!("{alice}; vz_org=globex"))).await.status, StatusCode::NOT_FOUND);

        // Who is given a project elsewhere sees two organizations, and gets the menu without being an administrator
        let given = app.post("/orgs/globex/projects/shop/members", Some(&bob), "username=alice&role=viewer").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
        app.accept_invitations("alice");
        let both = app.get("/product?view=applications", Some(&alice)).await.body;
        assert!(both.contains(&org_entry("acme", "acme", false)) && both.contains(&org_entry("globex", "globex", false)));
        assert!(both.contains("widget") && both.contains("gadget"));
        let narrowed = app.get("/product?view=applications", Some(&format!("{alice}; vz_org=globex"))).await.body;
        assert!(narrowed.contains("gadget") && !narrowed.contains("widget") && narrowed.contains("All projects of globex"));
        // The right is lost: the choice kept by the browser stops counting at once
        let project = Database::connect(&app.db_path).unwrap().find_project("globex", "shop").unwrap().unwrap();
        let alice_id = Database::connect(&app.db_path).unwrap().get_credentials("alice").unwrap().unwrap().0.id;
        let removed = app.post(&format!("/orgs/globex/projects/shop/members/{alice_id}/delete"), Some(&bob), "").await;
        assert_eq!(removed.status, StatusCode::SEE_OTHER, "{} {project}", removed.body);
        let after = app.get("/product?view=applications", Some(&format!("{alice}; vz_org=globex"))).await.body;
        assert!(after.contains("widget") && !after.contains("gadget") && !after.contains("globex"));

        // The choice is a form sent from our own pages by a signed-in user: nothing else changes it
        assert_eq!(app.post("/org-filter", None, "org=acme").await.location.as_deref(), Some("/login"));
        assert_eq!(app.get("/org-filter?org=acme", Some(&alice)).await.status, StatusCode::METHOD_NOT_ALLOWED);
        let foreign = HttpRequest::post("/org-filter")
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "http://evil.example")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, alice.as_str())
            .body(Body::from("org=acme"))
            .unwrap();
        let foreign = app.send(foreign).await;
        assert_eq!(foreign.status, StatusCode::FORBIDDEN);
        assert!(foreign.cookies.is_empty());
    }

    /// A project with two applications and six CVEs: five on `widget` detected 20 days ago (one
    /// of each severity, the medium one known exploited, one without a score), one critical on
    /// `gadget` detected 10 days ago. Three entries are overdue, by 13, 6 and 3 days; the high
    /// one was closed today, 20 days after its detection. Returns (owner, viewer, stranger).
    async fn late_project(app: &TestApp) -> (String, String, String) {
        let owner = app.register("owner").await;
        let viewer = app.register("viewer").await;
        let stranger = app.register("stranger").await;
        app.post("/orgs", Some(&owner), "name=acme").await;
        app.post("/projects", Some(&owner), "org=acme&name=infra").await;
        assert_eq!(app.post("/orgs/acme/members", Some(&owner), "username=viewer&role=viewer").await.status, StatusCode::SEE_OTHER);
        app.accept_invitations("viewer");
        let db = Database::connect(&app.db_path).unwrap();
        for (id, product, cvss, kev) in [
            ("CVE-2024-5001", "widget", Some(9.1), false),
            ("CVE-2024-5002", "widget", Some(8.0), false),
            ("CVE-2024-5003", "widget", Some(5.0), true),
            ("CVE-2024-5004", "widget", Some(2.0), false),
            ("CVE-2024-5005", "widget", None, false),
            ("CVE-2024-5006", "gadget", Some(9.5), false),
        ] {
            let mut cve = crate::models::Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.cvss_v3_score = cvss;
            cve.kev_known_exploited = kev;
            cve.affected_products.push(crate::models::AffectedProduct {
                vendor: Some("acme".into()),
                product: Some(product.into()),
                version: Some("*".into()),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        }
        for form in ["name=widget&version=1.0&vendor=acme", "name=gadget&version=2.0&vendor=acme"] {
            assert_eq!(app.post("/orgs/acme/projects/infra/applications", Some(&owner), form).await.status, StatusCode::SEE_OTHER);
        }
        db.conn()
            .execute_batch(
                "UPDATE watchlist_entries SET created_at = datetime('now', '-20 days');
                 UPDATE watchlist_events SET at = datetime('now', '-20 days');
                 UPDATE watchlist_entries SET created_at = datetime('now', '-10 days') WHERE cve_id = 'CVE-2024-5006';
                 UPDATE watchlist_events SET at = datetime('now', '-10 days') WHERE cve_id = 'CVE-2024-5006';",
            )
            .unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        let high = db.project_entries_for_cve(project, "CVE-2024-5002").unwrap()[0].0;
        assert_eq!(app.post(&format!("/orgs/acme/projects/infra/watchlist/{high}"), Some(&owner), "status=treated").await.status, StatusCode::SEE_OTHER);
        (owner, viewer, stranger)
    }

    /// The cells following the name of a row of a table of figures, up to the end of the row
    fn figures_row(body: &str, name: &str) -> String {
        let after = body.split(&format!("{name}</span></td>")).nth(1).unwrap_or_else(|| panic!("no row {name}"));
        after.split("</tr>").next().unwrap().to_string()
    }

    const NO_DATA: &str = "<span class=\"nodata\" title=\"Nothing to measure\">—</span>";

    #[tokio::test(flavor = "multi_thread")]
    async fn the_overview_shows_the_executive_figures_and_history_keeps_the_rest() {
        let app = app(open_registration());
        let (owner, viewer, stranger) = late_project(&app).await;
        let db = Database::connect(&app.db_path).unwrap();
        let today = chrono::Utc::now().date_naive();
        let day = |back: i64| (today - chrono::Duration::days(back)).to_string();
        let days = |n: &str| format!("{n}<span class=\"unit\"> days</span>");

        for scope in ["/product", "/product/acme/infra"] {
            for reader in [&owner, &viewer] {
                let page = app.get(scope, Some(reader)).await;
                assert_eq!(page.status, StatusCode::OK, "{scope}");
                let body = page.body;
                let list = format!("{scope}?view=vulnerabilities");
                // What is open and what is overdue, each leading to the list that shows it
                assert!(body.contains(&format!("<div class=\"tile\"><div class=\"value\"><a href=\"{list}\">5</a></div><div class=\"label\">open vulnerabilities</div></div>")), "{scope}: {body}");
                assert!(body.contains(&format!("<div class=\"tile alert\"><div class=\"value\"><a href=\"{list}&amp;show=overdue\">3</a></div><div class=\"label\">overdue on their remediation deadline</div></div>")), "{scope}");
                // How late, and how long a decision takes: figures with their unit
                assert!(body.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">average lateness of the overdue ones</div>", days("7.3"))), "{scope}");
                assert!(body.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">worst lateness</div>", days("13"))), "{scope}");
                assert!(body.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">average time to resolve, last 90 days</div>", days("20"))), "{scope}");
                // By severity: counts linked to their list, a dash where nothing was decided
                let narrowed = |count: i64, narrowing: &str| format!("<td><a href=\"{list}{narrowing}\">{count}</a></td>");
                assert_eq!(
                    figures_row(&body, "Critical"),
                    format!("{}{}<td>{NO_DATA}</td><td>0</td>", narrowed(2, "&amp;severity=critical"), narrowed(2, "&amp;show=overdue&amp;severity=critical")),
                    "{scope}"
                );
                assert_eq!(figures_row(&body, "High"), format!("<td>0</td><td>0</td><td>{}</td><td>1</td>", days("20")), "{scope}");
                assert_eq!(
                    figures_row(&body, "Medium"),
                    format!("{}{}<td>{NO_DATA}</td><td>0</td>", narrowed(1, "&amp;severity=medium"), narrowed(1, "&amp;show=overdue&amp;severity=medium")),
                    "{scope}"
                );
                assert_eq!(figures_row(&body, "Low"), format!("{}<td>0</td><td>{NO_DATA}</td><td>0</td>", narrowed(1, "&amp;severity=low")), "{scope}");
                assert_eq!(figures_row(&body, "No score"), format!("{}<td>0</td><td>{NO_DATA}</td><td>0</td>", narrowed(1, "&amp;severity=none")), "{scope}");
                assert!(
                    body.contains(&format!(
                        "<tr class=\"total\"><td>All</td>{}{}<td>{}</td><td>1</td></tr>",
                        narrowed(5, ""),
                        narrowed(3, "&amp;show=overdue"),
                        days("20")
                    )),
                    "{scope}"
                );
                // The period is said and chosen without a script; so is what "resolved" means
                assert!(body.contains(&format!("<a href=\"{scope}\" class=\"active\">90 days</a>")) && body.contains(&format!("<a href=\"{scope}?period=30\">30 days</a>")), "{scope}");
                assert!(body.contains(&format!("<a href=\"{scope}?period=365\">365 days</a>")), "{scope}");
                assert!(body.contains("<strong>Resolved</strong> means decided: closed, not applicable or risk accepted."), "{scope}");
                assert!(body.contains(&format!("during the last 90 days ({} to {today}, UTC)", day(89))), "{scope}");
                // Figures only: no chart, no list of CVEs, no decision button, no change of a subscription
                for gone in ["class=\"chart", "<polyline", "<circle", "CVE-2024", "/watchlist/", "list triage", "To review first", "Latest changes", "What changed", "widget", "gadget"] {
                    assert!(!body.contains(gone), "{scope}: {gone}");
                }
                assert!(!body.contains("style="), "{scope}");
            }
        }

        // What left the overview is in the History view: the charts follow the day shown
        let history = app.get("/product/acme/infra?view=history", Some(&viewer)).await.body;
        for kept in ["To review, by severity", "All tracked CVEs, by status", "To review, by application", "class=\"chart donut\"", "Changes on subscribed products"] {
            assert!(history.contains(kept), "{kept}");
        }
        assert!(history.contains("<div class=\"tile alert\"><div class=\"value\">1</div><div class=\"label\">to review and known exploited (KEV)</div></div>"));
        assert!(history.contains("<div class=\"value\">0</div><div class=\"label\">risks accepted</div>"));
        let all = app.get("/product?view=history", Some(&viewer)).await.body;
        for kept in ["To review, by project", "colored by project", "All tracked CVEs, by project and status", "stroke-p0", "Changes on subscribed products"] {
            assert!(all.contains(kept), "{kept}");
        }
        // The new chart: to review per day and per severity, the accepted risks apart, and their figures in a table
        for scope in ["/product", "/product/acme/infra"] {
            let now = app.get(&format!("{scope}?view=history"), Some(&owner)).await.body;
            assert!(now.contains("CVEs to review, by severity") && now.contains("the severity is the one each CVE has today"), "{scope}");
            assert!(now.contains("aria-label=\"CVEs to review per day, by severity\"") && now.contains("aria-label=\"accepted risks per day\""), "{scope}");
            for color in ["sev-critical", "sev-medium", "sev-low", "sev-none"] {
                assert!(now.contains(&format!("rx=\"1.5\" class=\"fill-{color}\"></rect>")), "{scope} {color}");
            }
            assert!(now.contains("<h3 class=\"next\">Accepted risks <small>— 0 on "), "{scope}");
            assert!(now.contains("<details class=\"daily\"><summary>The figures of these two charts, day by day</summary><table class=\"list fit\"><colgroup><col><col class=\"fig\">"), "{scope}");
            assert!(now.contains("<th>Day</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>No score</th><th>To review</th><th>Accepted</th>"), "{scope}");
            let row = |back: i64, figures: [i64; 7]| format!("<tr><td>{}</td>{}</tr>", day(back), figures.map(|n| format!("<td>{n}</td>")).concat());
            // Today, the day before (the high one still open), before the second application, before anything
            assert!(now.contains(&row(0, [2, 0, 1, 1, 1, 5, 0])), "{scope}");
            assert!(now.contains(&row(1, [2, 1, 1, 1, 1, 6, 0])), "{scope}");
            assert!(now.contains(&row(15, [1, 1, 1, 1, 1, 5, 0])), "{scope}");
            assert!(now.contains(&row(21, [0, 0, 0, 0, 0, 0, 0])), "{scope}");
            // The window of the view is the one of the chart
            assert!(!now.contains(&format!("<tr><td>{}</td>", day(30))), "{scope}");
            assert!(app.get(&format!("{scope}?view=history&days=90"), Some(&owner)).await.body.contains(&row(30, [0, 0, 0, 0, 0, 0, 0])), "{scope}");
        }
        // On a past day the charts moved here count that day: five entries, all on the first application
        let then = app.get(&format!("/product/acme/infra?view=history&at={}", day(15)), Some(&owner)).await.body;
        assert!(then.contains("aria-label=\"to review: 5\"") && then.contains("<title>widget · to review: 5</title>") && !then.contains("<title>gadget"), "{then}");

        // A decision older than the period no longer counts in it: a dash, never a zero
        db.conn()
            .execute_batch(
                "UPDATE watchlist_events SET at = datetime('now', '-65 days') WHERE cve_id = 'CVE-2024-5002' AND kind = 'detected';
                 UPDATE watchlist_events SET at = datetime('now', '-45 days') WHERE cve_id = 'CVE-2024-5002' AND kind = 'status';",
            )
            .unwrap();
        let month = app.get("/product/acme/infra?period=30", Some(&owner)).await.body;
        assert!(month.contains(&format!("<div class=\"value\">{NO_DATA}</div><div class=\"label\">average time to resolve, last 30 days</div>")), "{month}");
        assert!(month.contains("<a href=\"/product/acme/infra?period=30\" class=\"active\">30 days</a>") && month.contains("<th>Resolved in 30 days</th>"));
        assert_eq!(figures_row(&month, "High"), format!("<td>0</td><td>0</td><td>{NO_DATA}</td><td>0</td>"));
        assert!(month.contains("<a href=\"/product/acme/infra?view=vulnerabilities\">5</a>"));
        for (asked, label) in [("90", "90 days"), ("365", "365 days"), ("7", "90 days"), ("", "90 days")] {
            let page = app.get(&format!("/product/acme/infra?period={asked}"), Some(&owner)).await.body;
            assert!(page.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">average time to resolve, last {label}</div>", days("20"))), "{asked}");
        }

        // A project with nothing to count: zeros that lead nowhere, and dashes
        app.post("/projects", Some(&owner), "org=acme&name=quiet").await;
        assert_eq!(app.post("/orgs/acme/projects/quiet/applications", Some(&owner), "name=harmless&version=1.0").await.status, StatusCode::SEE_OTHER);
        let quiet = app.get("/product/acme/quiet", Some(&owner)).await.body;
        assert!(quiet.contains("<div class=\"tile\"><div class=\"value\">0</div><div class=\"label\">open vulnerabilities</div></div>"));
        assert!(quiet.contains("<div class=\"tile\"><div class=\"value\">0</div><div class=\"label\">overdue on their remediation deadline</div></div>"));
        for label in ["average lateness of the overdue ones", "worst lateness", "average time to resolve, last 90 days"] {
            assert!(quiet.contains(&format!("<div class=\"value\">{NO_DATA}</div><div class=\"label\">{label}</div>")), "{label}");
        }
        assert_eq!(quiet.matches("class=\"nodata\"").count(), 3 + 6);
        assert!(!quiet.contains("0<span class=\"unit\">") && !quiet.contains("view=vulnerabilities&amp;"));
        // Nothing monitored at all: the first steps, as before
        app.post("/projects", Some(&owner), "org=acme&name=blank").await;
        assert!(app.get("/product/acme/blank", Some(&owner)).await.body.contains("This project does not monitor anything yet."));

        // Nothing for who is not signed in, nor for who is not a member
        for path in ["/product", "/product/acme/infra", "/product/acme/infra?period=30", "/product?view=overdue", "/product/acme/infra?view=overdue"] {
            assert_eq!(app.get(path, None).await.location.as_deref(), Some("/login"), "{path}");
        }
        for path in ["/product/acme/infra", "/product/acme/infra?period=30", "/product/acme/infra?view=overdue", "/product/acme/infra?view=history"] {
            assert_eq!(app.get(path, Some(&stranger)).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        let outside = app.get("/product", Some(&stranger)).await.body;
        assert!(outside.contains("Nothing is monitored yet") && !outside.contains("open vulnerabilities"));

        // REST API: the same figures and nothing else, for who can read the project
        let token = |session: &str| {
            let (app, session) = (&app, session.to_string());
            async move { format!("Bearer {}", tokens_of(&app.post("/settings/tokens", Some(&session), "name=ci&password=a-long-password").await.body).remove(0)) }
        };
        let (bearer, reader, other) = (token(&owner).await, token(&viewer).await, token(&stranger).await);
        let one = "/api/organizations/acme/projects/infra/summary";
        for path in ["/api/summary", one] {
            assert_eq!(app.api(path, None).await.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(app.get(path, Some(&owner)).await.status, StatusCode::UNAUTHORIZED, "{path}");
            for bad in ["0", "366", "ten", "-1"] {
                assert_eq!(app.api(&format!("{path}?days={bad}"), Some(&bearer)).await.status, StatusCode::BAD_REQUEST, "{path} {bad}");
            }
        }
        assert_eq!(app.api(one, Some(&other)).await.status, StatusCode::NOT_FOUND);
        let read = |path: String, bearer: String| {
            let app = &app;
            async move {
                let reply = app.api(&path, Some(&bearer)).await;
                assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
                // Figures only: no CVE, no application, no project
                for leaked in ["CVE-", "widget", "gadget", "infra", "acme"] {
                    assert!(!reply.body.contains(leaked), "{path}: {leaked}");
                }
                serde_json::from_str::<serde_json::Value>(&reply.body).unwrap()
            }
        };
        let expected = serde_json::json!({
            "as_of": today.to_string(),
            "open": { "total": 5, "critical": 2, "high": 0, "medium": 1, "low": 1, "none": 1 },
            "overdue": { "total": 3, "critical": 2, "high": 0, "medium": 1, "low": 0, "none": 0 },
            "overdue_days": { "avg": 7.3, "max": 13 },
            "period_days": 90,
            "resolved": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "none": 0 },
            "resolved_avg_days": { "total": 20.0, "critical": null, "high": 20.0, "medium": null, "low": null, "none": null },
        });
        for path in [one, "/api/summary", "/api/summary?org=acme", "/api/summary?days=90"] {
            for who in [&bearer, &reader] {
                assert_eq!(read(path.to_string(), who.clone()).await, expected, "{path}");
            }
        }
        let month = read(format!("{one}?days=30"), bearer.clone()).await;
        assert_eq!((month["period_days"].as_i64(), month["resolved"]["total"].as_i64(), month["open"]["total"].as_i64()), (Some(30), Some(0), Some(5)));
        assert!(month["resolved_avg_days"]["total"].is_null() && month["resolved_avg_days"]["high"].is_null());
        // Who reads nothing gets figures of nothing, and an organization that is not theirs narrows to nothing
        for (path, who) in [("/api/summary", &other), ("/api/summary?org=acme", &other), ("/api/summary?org=nowhere", &bearer)] {
            let nothing = read(path.to_string(), who.clone()).await;
            assert_eq!((nothing["open"]["total"].as_i64(), nothing["resolved"]["total"].as_i64()), (Some(0), Some(0)), "{path}");
            assert!(nothing["overdue_days"]["avg"].is_null() && nothing["overdue_days"]["max"].is_null() && nothing["resolved_avg_days"]["total"].is_null(), "{path}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_overdue_view_tells_where_the_late_ones_are_and_since_when() {
        use chrono::Datelike;

        let app = app(open_registration());
        let (owner, viewer, stranger) = late_project(&app).await;
        let today = chrono::Utc::now().date_naive();
        let ago = |back: i64| today - chrono::Duration::days(back);
        let days = |n: &str| format!("{n}<span class=\"unit\"> days</span>");
        let tables = regex::Regex::new(r#"<table class="([^"]*)">(<colgroup>)?"#).unwrap();

        for scope in ["/product", "/product/acme/infra"] {
            for reader in [&owner, &viewer] {
                let page = app.get(&format!("{scope}?view=overdue"), Some(reader)).await;
                assert_eq!(page.status, StatusCode::OK, "{scope}");
                let body = page.body;
                assert!(body.contains("<title>Overdue · Vulnizard</title>") && body.contains(&menu_entry(scope, "overdue", "Overdue", true)), "{scope}");
                // How many, how late
                assert!(body.contains(&format!("<div class=\"tile alert\"><div class=\"value\"><a href=\"{scope}?view=vulnerabilities&amp;show=overdue\">3</a></div><div class=\"label\">overdue vulnerabilities</div></div>")), "{scope}: {body}");
                assert!(body.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">average lateness</div>", days("7.3"))), "{scope}");
                assert!(body.contains(&format!("<div class=\"value\">{}</div><div class=\"label\">worst lateness</div>", days("13"))), "{scope}");
                // By application, the worst first; each leads to its overdue entries, in its project
                let project = if scope == "/product" { "<td class=\"project\"><a href=\"/product/acme/infra?view=overdue\" title=\"infra\">infra</a></td>" } else { "" };
                let row = |name: &str, count: i64, average: &str, worst: &str| {
                    format!(
                        "<tr><td><a href=\"/product/acme/infra?view=vulnerabilities&amp;show=overdue&amp;app={name}\">{name}</a></td>{project}<td>{count}</td><td>{}</td><td>{}</td></tr>",
                        days(average),
                        days(worst)
                    )
                };
                let (widget, gadget) = (row("widget", 2, "9.5", "13"), row("gadget", 1, "3", "3"));
                let at = |row: &str| body.find(row).unwrap_or_else(|| panic!("{scope}: no {row} in {body}"));
                assert!(at(&widget) < at(&gadget), "{scope}");
                // Every table is sized by the stylesheet
                let found: Vec<_> = tables.captures_iter(&body).collect();
                assert_eq!(found.len(), 3, "{scope}");
                assert!(found.iter().all(|t| t[1].starts_with("list fit") && t.get(2).is_some()), "{scope}");

                // Over time: today's overdue entries by week of detection and of deadline…
                let mut weeks: std::collections::BTreeMap<chrono::NaiveDate, (i64, i64)> = Default::default();
                let monday = |day: chrono::NaiveDate| day - chrono::Duration::days(i64::from(day.weekday().num_days_from_monday()));
                for (detected, due) in [(20, 13), (20, 6), (10, 3)] {
                    weeks.entry(monday(ago(detected))).or_default().0 += 1;
                    weeks.entry(monday(ago(due))).or_default().1 += 1;
                }
                for (week, (detected, due)) in &weeks {
                    assert!(body.contains(&format!("<tr><td>{week}</td><td>{detected}</td><td>{due}</td></tr>")), "{scope} {week}");
                }
                assert!(body.contains("detected that week <strong>3</strong>") && body.contains("due that week <strong>3</strong>"), "{scope}");
                // …and how many were overdue at the end of each day: none, then one, two, three
                for (back, count) in [(0, 3), (2, 3), (3, 2), (5, 2), (6, 1), (12, 1), (13, 0), (29, 0)] {
                    assert!(body.contains(&format!("<tr><td>{}</td><td>{count}</td></tr>", ago(back))), "{scope} {back}");
                    assert!(body.contains(&format!("<title>{} — {count} overdue</title>", ago(back))), "{scope} {back}");
                }
                // The window is the one of the History view, and a day leads to its state there
                assert!(body.contains(&format!("<a href=\"{scope}?view=overdue&amp;days=30\" class=\"active\">30 days</a>")) && body.contains(&format!("<a href=\"{scope}?view=overdue&amp;days=365\">1 year</a>")), "{scope}");
                assert!(body.contains(&format!("<a href=\"{scope}?view=history&amp;at={}\">", ago(4))), "{scope}");
                assert!(!body.contains(&format!("<tr><td>{}</td>", ago(30))), "{scope}");
                assert!(!body.contains("style=") && !body.contains("CVE-2024"), "{scope}");
            }
            let year = app.get(&format!("{scope}?view=overdue&days=365"), Some(&owner)).await.body;
            assert!(year.contains(&format!("<tr><td>{}</td><td>0</td></tr>", ago(364))) && !year.contains(&format!("<tr><td>{}</td>", ago(365))), "{scope}");
            // Sorted on request
            let fewest = app.get(&format!("{scope}?view=overdue&sort=count&dir=asc"), Some(&owner)).await.body;
            assert!(fewest.find("app=gadget\">").unwrap() < fewest.find("app=widget\">").unwrap(), "{scope}");
        }

        // The list narrowed to one application, as the rows above link to it
        for scope in ["/product", "/product/acme/infra"] {
            let list = format!("{scope}?view=vulnerabilities");
            let cves = |body: &str| -> Vec<u32> { (5001..=5006).filter(|n| body.contains(&format!("CVE-2024-{n}</a>"))).collect() };
            let get = |query: &'static str| {
                let (app, owner, list) = (&app, owner.clone(), list.clone());
                async move { app.get(&format!("{list}{query}"), Some(&owner)).await.body }
            };
            let widget = get("&show=overdue&app=widget").await;
            assert_eq!(cves(&widget), [5001, 5003], "{scope}");
            assert!(widget.contains(&format!("<p class=\"narrowed\">Only the application <strong>widget</strong> · <a href=\"{list}&amp;show=overdue\">Show all</a></p>")), "{scope}: {widget}");
            // The narrowing follows from one list to the other, and through a sort
            assert!(widget.contains(&format!("<a href=\"{list}&amp;app=widget\">To review</a>")), "{scope}");
            assert!(widget.contains(&format!("<a href=\"{list}&amp;show=overdue&amp;app=widget\" class=\"active\">Overdue</a>")), "{scope}");
            assert!(widget.contains("show=overdue&amp;app=widget&amp;sort=cvss&amp;dir=asc"), "{scope}");
            assert_eq!(cves(&get("&show=overdue&app=gadget").await), [5006], "{scope}");
            assert_eq!(cves(&get("&app=widget").await), [5001, 5003, 5004, 5005], "{scope}");
            assert_eq!(cves(&get("&show=handled&app=widget").await), [5002], "{scope}");
            assert!(get("&show=handled&app=gadget").await.contains("No decision yet."), "{scope}");
            // A name is matched whole, and one nobody runs lists nothing
            assert_eq!(cves(&get("&app=widge").await), [] as [u32; 0], "{scope}");
            // By severity, as the figures of the overview link to it; both together
            let critical = get("&severity=critical").await;
            assert_eq!(cves(&critical), [5001, 5006], "{scope}");
            assert!(critical.contains(&format!("Only the CVEs of severity <strong>Critical</strong> · <a href=\"{list}\">Show all</a>")), "{scope}");
            assert_eq!(cves(&get("&show=overdue&severity=medium").await), [5003], "{scope}");
            assert_eq!(cves(&get("&severity=none").await), [5005], "{scope}");
            assert_eq!(cves(&get("&severity=low").await), [5004], "{scope}");
            let both = get("&severity=critical&app=gadget").await;
            assert_eq!(cves(&both), [5006], "{scope}");
            assert!(both.contains("Only the application <strong>gadget</strong>, the CVEs of severity <strong>Critical</strong>"), "{scope}");
            // What is not a severity narrows nothing; a name is written back escaped
            let bogus = get("&severity=bogus").await;
            assert!(cves(&bogus).len() == 5 && !bogus.contains("class=\"narrowed\""), "{scope}");
            let evil = get("&app=%3Cscript%3Ealert(1)%3C%2Fscript%3E").await;
            assert!(!evil.contains("<script>alert") && evil.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{scope}");
        }
        // Somebody else's entries are not theirs to narrow to
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities&app=widget", Some(&stranger)).await.status, StatusCode::NOT_FOUND);
        assert!(!app.get("/product?view=vulnerabilities&app=widget", Some(&stranger)).await.body.contains("CVE-2024-500"));

        // Nothing overdue: the view says so, for who reads nothing as for a project in time
        let outside = app.get("/product?view=overdue", Some(&stranger)).await.body;
        assert!(outside.contains("<strong>Nothing is overdue.</strong>") && !outside.contains("widget") && !outside.contains("By application"));
        assert_eq!(app.get("/product/acme/infra?view=overdue", Some(&stranger)).await.status, StatusCode::NOT_FOUND);
        // Once decided nothing is late any more, and what was late before stays in the chart of the days
        let db = Database::connect(&app.db_path).unwrap();
        let project = db.find_project("acme", "infra").unwrap().unwrap();
        for cve in ["CVE-2024-5001", "CVE-2024-5003", "CVE-2024-5006"] {
            let id = db.project_entries_for_cve(project, cve).unwrap()[0].0;
            assert_eq!(app.post(&format!("/orgs/acme/projects/infra/watchlist/{id}"), Some(&owner), "status=not_applicable").await.status, StatusCode::SEE_OTHER);
        }
        let calm = app.get("/product/acme/infra?view=overdue", Some(&owner)).await.body;
        assert!(calm.contains("<strong>Nothing is overdue.</strong>") && !calm.contains("By application") && !calm.contains("app=widget"));
        assert!(calm.contains(&format!("<tr><td>{today}</td><td>0</td></tr>")) && calm.contains(&format!("<tr><td>{}</td><td>3</td></tr>", ago(1))));
        let overview = app.get("/product/acme/infra", Some(&owner)).await.body;
        assert!(overview.contains("<div class=\"tile\"><div class=\"value\">0</div><div class=\"label\">overdue on their remediation deadline</div></div>"));
        assert!(overview.contains(&format!("<div class=\"value\">{NO_DATA}</div><div class=\"label\">worst lateness</div>")));
    }

    // ---------- the executive role ----------

    fn id_of(app: &TestApp, username: &str) -> i64 {
        Database::connect(&app.db_path).unwrap().get_credentials(username).unwrap().unwrap().0.id
    }

    /// Accepts, in the browser, the one invitation waiting for an account
    async fn accept_in_settings(app: &TestApp, username: &str, session: &str) {
        let db = Database::connect(&app.db_path).unwrap();
        let waiting = db.received_invitations(id_of(app, username)).unwrap();
        assert_eq!(waiting.len(), 1, "{username}");
        let accepted = app.post(&format!("/invitations/{}/accept", waiting[0].id), Some(session), "").await;
        assert_eq!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.body);
    }

    async fn api_token(app: &TestApp, session: &str) -> String {
        tokens_of(&app.post("/settings/tokens", Some(session), "name=t&password=a-long-password").await.body).remove(0)
    }

    /// One message to the MCP server over HTTP, as a program sends it
    async fn mcp(app: &TestApp, token: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
        let message = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let req = HttpRequest::post("/mcp")
            .header(header::HOST, "127.0.0.1:8000")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json");
        let reply = app.send(req.body(Body::from(message.to_string())).unwrap()).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        serde_json::from_str(&reply.body).unwrap()
    }

    /// The result of a tool, and whether it is a failure
    async fn mcp_tool(app: &TestApp, token: &str, name: &str, arguments: serde_json::Value) -> (bool, String) {
        let answer = mcp(app, token, "tools/call", serde_json::json!({ "name": name, "arguments": arguments })).await;
        if let Some(error) = answer.get("error") {
            return (true, error["message"].as_str().unwrap().to_string());
        }
        (answer["result"]["isError"].as_bool().unwrap(), answer["result"]["content"][0]["text"].as_str().unwrap().to_string())
    }

    /// The first figure of an overview, without a link: what an executive reads
    fn bare_figure(count: i64) -> String {
        format!("<div class=\"tile\"><div class=\"value\">{count}</div><div class=\"label\">open vulnerabilities</div></div>")
    }

    struct Executives {
        /// Administrator of the instance and owner of acme
        owner: String,
        viewer: String,
        /// Owner of globex
        other: String,
        /// Executive of the project acme / infra
        exec: String,
        /// Executive of the organization acme
        board: String,
        /// Executive of the instance
        chair: String,
        /// Executive of acme / infra and viewer of globex / shop
        mixed: String,
    }

    /// acme / infra holds 5 open vulnerabilities (3 overdue), acme / web 1 and
    /// globex / shop 5. The executive role is given at each level, through the
    /// forms that give the other roles.
    async fn executives(app: &TestApp) -> Executives {
        let (owner, viewer, other) = late_project(app).await;
        assert_eq!(app.post("/projects", Some(&owner), "org=acme&name=web").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.post("/orgs/acme/projects/web/applications", Some(&owner), "name=gadget&version=2.0&vendor=acme").await.status, StatusCode::SEE_OTHER);
        app.post("/orgs", Some(&other), "name=globex").await;
        app.post("/projects", Some(&other), "org=globex&name=shop").await;
        assert_eq!(app.post("/orgs/globex/projects/shop/applications", Some(&other), "name=widget&version=1.0&vendor=acme").await.status, StatusCode::SEE_OTHER);

        // On one project: invited by the owner, accepted from the settings
        let exec = app.register("exec").await;
        assert_eq!(app.post("/orgs/acme/projects/infra/members", Some(&owner), "username=exec&role=executive").await.status, StatusCode::SEE_OTHER);
        let settings = app.get("/settings", Some(&exec)).await.body;
        assert!(settings.contains("<td data-label=\"Role\">executive</td>"), "{settings}");
        accept_in_settings(app, "exec", &exec).await;
        // On an organization
        let board = app.register("board").await;
        assert_eq!(app.post("/orgs/acme/members", Some(&owner), "username=board&role=executive").await.status, StatusCode::SEE_OTHER);
        accept_in_settings(app, "board", &board).await;
        // On the instance: given by the administrator
        let chair = app.register("chair").await;
        let given = app.post(&format!("/admin/users/{}/assign", id_of(app, "chair")), Some(&owner), "scope=instance&role=executive").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
        // Executive in one place, viewer in another
        let mixed = app.register("mixed").await;
        let given = app.post(&format!("/admin/users/{}/assign", id_of(app, "mixed")), Some(&owner), "scope=project%3Aacme%2Finfra&role=executive").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
        assert_eq!(app.post("/orgs/globex/projects/shop/members", Some(&other), "username=mixed&role=viewer").await.status, StatusCode::SEE_OTHER);
        accept_in_settings(app, "mixed", &mixed).await;

        let db = Database::connect(&app.db_path).unwrap();
        let project = |org: &str, name: &str| db.find_project(org, name).unwrap().unwrap();
        use crate::rbac::Role;
        assert_eq!(db.project_role(id_of(app, "exec"), project("acme", "infra")).unwrap(), Some(Role::Executive));
        assert_eq!(db.project_role(id_of(app, "exec"), project("acme", "web")).unwrap(), None);
        assert_eq!(db.project_role(id_of(app, "board"), project("acme", "web")).unwrap(), Some(Role::Executive));
        assert_eq!(db.project_role(id_of(app, "chair"), project("globex", "shop")).unwrap(), Some(Role::Executive));
        assert_eq!(db.project_role(id_of(app, "mixed"), project("globex", "shop")).unwrap(), Some(Role::Viewer));
        Executives { owner, viewer, other, exec, board, chair, mixed }
    }

    /// Routes and MCP tools that were classified for an account confined to the
    /// Overview: allowed (`CONFINED_ROUTES`, `CONFINED_API`, `mcp::CONFINED_TOOLS`)
    /// or refused, which is what happens to anything not listed there
    const CLASSIFIED_ROUTES: usize = 126;
    const CLASSIFIED_TOOLS: usize = 26;

    /// A route with its parameters filled: the project the executive holds, and 1 for the rest
    fn filled(route: &str) -> String {
        let mut out = String::new();
        let mut rest = route;
        while let Some(start) = rest.find('{') {
            let end = start + rest[start..].find('}').unwrap();
            out.push_str(&rest[..start]);
            out.push_str(match &rest[start + 1..end] {
                "org" => "acme",
                "project" => "infra",
                _ => "1",
            });
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// Nothing of the projects may be in an answer that refuses
    fn tells_nothing(body: &str) -> bool {
        !["CVE-2024", "widget", "gadget", "acme", "infra", "globex"].iter().any(|data| body.contains(data))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_executive_is_refused_every_route_tool_and_endpoint_but_those_of_its_overview() {
        let app = app(with_inventory());
        let world = executives(&app).await;
        assert_eq!(app.post("/admin/mcp", Some(&world.owner), "http_enabled=1&allow_write=1").await.status, StatusCode::SEE_OTHER);
        let token = api_token(&app, &world.exec).await;
        let viewer_token = api_token(&app, &world.viewer).await;
        let bearer = format!("Bearer {token}");

        let routes = declared_routes();
        assert!(routes.len() >= 110, "only {} routes found: the source is no longer read correctly", routes.len());
        // Every route was looked at with an executive in mind. One more route: it is refused to an
        // executive unless it is added to CONFINED_ROUTES or CONFINED_API; decide, then count it here.
        assert_eq!(routes.len(), CLASSIFIED_ROUTES, "a route was added or removed: decide what an executive gets of it, then update CLASSIFIED_ROUTES");
        // What is allowed names routes that exist: an entry cannot outlive its route
        for (method, route) in CONFINED_ROUTES {
            assert!(routes.iter().any(|r| r == route), "{method} {route} is allowed to an executive but is not a route");
        }
        for route in CONFINED_API {
            assert!(routes.iter().any(|r| r == route), "{route} is allowed to an executive but is not a route");
        }

        // ---- The pages: every route of the UI, for GET and for POST ----
        let mut refused = 0;
        for route in routes.iter().filter(|r| !r.starts_with("/api") && !r.starts_with("/scim") && *r != "/mcp") {
            let path = filled(route);
            for method in ["GET", "POST"] {
                if CONFINED_ROUTES.contains(&(method, route.as_str())) {
                    continue;
                }
                let reply = if method == "GET" {
                    app.get(&path, Some(&world.exec)).await
                } else {
                    app.post(&path, Some(&world.exec), "name=x&username=x&role=owner&status=treated&org=acme&project_id=1&scope=instance").await
                };
                // The refusal of a missing permission; a route that has no such method says so before
                assert!(
                    matches!(reply.status, StatusCode::FORBIDDEN | StatusCode::METHOD_NOT_ALLOWED),
                    "{method} {route} answered {} to an executive: classify it in CONFINED_ROUTES or leave it refused",
                    reply.status
                );
                assert!(tells_nothing(&reply.body), "{method} {route}: {}", reply.body);
                refused += 1;
            }
        }
        assert!(refused >= 150, "only {refused} refusals: the sweep no longer covers the routes");
        // A page that does not exist is refused the same way: nothing tells what exists
        assert_eq!(app.get("/nothing-here", Some(&world.exec)).await.status, StatusCode::FORBIDDEN);
        // The sweep is about the role, not about the pages: a viewer of the same project opens them
        for path in ["/cve", "/vendors", "/projects", "/orgs/acme", "/product/acme/infra?view=vulnerabilities", "/orgs/acme/audit/export"] {
            assert_eq!(app.get(path, Some(&world.viewer)).await.status, StatusCode::OK, "{path}");
        }
        // What is allowed answers
        for path in ["/product", "/product/acme/infra", "/settings", "/settings/mfa", "/static/app.css"] {
            assert_eq!(app.get(path, Some(&world.exec)).await.status, StatusCode::OK, "{path}");
        }
        assert_eq!(app.get("/", Some(&world.exec)).await.location.as_deref(), Some("/product"));
        // Nothing was changed by what was refused
        let db = Database::connect(&app.db_path).unwrap();
        assert!(db.get_org("x", id_of(&app, "exec")).unwrap().is_none() && db.list_orgs(id_of(&app, "exec")).unwrap().is_empty());
        assert!(db.summary_only(id_of(&app, "exec")).unwrap());

        // ---- The REST API: every endpoint ----
        for route in routes.iter().filter(|r| r.starts_with("/api")) {
            let path = filled(route);
            for method in ["GET", "POST"] {
                let req = HttpRequest::builder().method(method).uri(&path).header(header::HOST, "localhost").header(header::AUTHORIZATION, &bearer);
                let reply = app.send(req.body(Body::empty()).unwrap()).await;
                if method == "GET" && CONFINED_API.contains(&route.as_str()) {
                    assert_eq!(reply.status, StatusCode::OK, "{route}: {}", reply.body);
                    continue;
                }
                // The inventory endpoint takes the token of a source, never the one of an account
                let expected: &[StatusCode] = if route == "/api/inventory" && method == "POST" {
                    &[StatusCode::UNAUTHORIZED]
                } else {
                    &[StatusCode::FORBIDDEN, StatusCode::METHOD_NOT_ALLOWED]
                };
                assert!(expected.contains(&reply.status), "{method} {route} answered {} to an executive", reply.status);
                assert!(tells_nothing(&reply.body), "{method} {route}: {}", reply.body);
            }
        }
        assert_eq!(app.api("/api/nothing-here", Some(&bearer)).await.status, StatusCode::NOT_FOUND);
        assert_eq!(app.api("/api/cve", Some(&format!("Bearer {viewer_token}"))).await.status, StatusCode::OK);
        // Provisioning has its own tokens
        for route in routes.iter().filter(|r| r.starts_with("/scim")) {
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                let req = HttpRequest::builder().method(method).uri(filled(route)).header(header::HOST, "localhost").header(header::AUTHORIZATION, &bearer);
                let status = app.send(req.body(Body::empty()).unwrap()).await.status;
                assert!(matches!(status, StatusCode::UNAUTHORIZED | StatusCode::METHOD_NOT_ALLOWED), "{method} {route}: {status}");
            }
        }
        // The figures it may ask, and the names they go with
        let figures: serde_json::Value = serde_json::from_str(&app.api("/api/summary", Some(&bearer)).await.body).unwrap();
        assert_eq!((figures["open"]["total"].as_i64(), figures["overdue"]["total"].as_i64()), (Some(5), Some(3)), "{figures}");
        let one: serde_json::Value = serde_json::from_str(&app.api("/api/organizations/acme/projects/infra/summary?days=30", Some(&bearer)).await.body).unwrap();
        assert_eq!((one["open"]["total"].as_i64(), one["period_days"].as_i64()), (Some(5), Some(30)));
        let names: serde_json::Value = serde_json::from_str(&app.api("/api/summary/projects", Some(&bearer)).await.body).unwrap();
        assert_eq!(names, serde_json::json!([{ "org": "acme", "project": "infra", "role": "executive" }]));
        // A project it does not hold answers as one that does not exist
        let elsewhere = app.api("/api/organizations/acme/projects/web/summary", Some(&bearer)).await;
        let nowhere = app.api("/api/organizations/acme/projects/nope/summary", Some(&bearer)).await;
        assert_eq!((elsewhere.status, &elsewhere.body), (StatusCode::NOT_FOUND, &nowhere.body));
        // An organization it holds nothing in narrows the figures to nothing
        let none: serde_json::Value = serde_json::from_str(&app.api("/api/summary?org=globex", Some(&bearer)).await.body).unwrap();
        assert_eq!(none["open"]["total"].as_i64(), Some(0));

        // ---- MCP: every tool ----
        let every: Vec<String> = crate::mcp::tool_catalog(true).into_iter().map(|(name, _, _)| name).collect();
        assert_eq!(every.len(), CLASSIFIED_TOOLS, "a tool was added or removed: decide whether an executive is offered it (mcp::CONFINED_TOOLS), then update CLASSIFIED_TOOLS");
        let names_of = |answer: &serde_json::Value| -> Vec<String> {
            let mut names: Vec<String> = answer["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
            names.sort();
            names
        };
        // A viewer is offered them all; the executive, its two
        assert_eq!(names_of(&mcp(&app, &viewer_token, "tools/list", serde_json::json!({})).await).len(), every.len());
        assert_eq!(names_of(&mcp(&app, &token, "tools/list", serde_json::json!({})).await), ["get_summary", "list_projects"]);
        let arguments = serde_json::json!({ "org": "acme", "project": "infra", "id": "CVE-2024-5001", "vendor": "acme", "day": "2024-01-01" });
        for name in &every {
            let (failed, text) = mcp_tool(&app, &token, name, arguments.clone()).await;
            if crate::mcp::CONFINED_TOOLS.contains(&name.as_str()) {
                assert!(!failed, "{name}: {text}");
            } else {
                // The answer of a tool that does not exist
                assert_eq!((failed, text.as_str()), (true, format!("Unknown tool: {name}").as_str()), "{name}");
            }
        }
        let (_, text) = mcp_tool(&app, &token, "get_summary", serde_json::json!({ "org": "acme", "project": "infra" })).await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["open"]["total"].as_i64(), Some(5));
        let (_, text) = mcp_tool(&app, &token, "get_summary", serde_json::json!({})).await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["open"]["total"].as_i64(), Some(5));
        let (failed, text) = mcp_tool(&app, &token, "get_summary", serde_json::json!({ "org": "acme", "project": "web" })).await;
        assert!(failed && text.contains("project 'acme/web' not found"), "{text}");
        let (_, text) = mcp_tool(&app, &token, "list_projects", serde_json::json!({})).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            serde_json::json!([{ "org": "acme", "project": "infra", "summary_only": true }])
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_executive_reads_the_figures_of_what_it_holds_and_nothing_else() {
        let app = app(open_registration());
        let world = executives(&app).await;
        let stranger = app.register("nobody").await;
        let project_entry = |org: &str, project: &str| format!("<a href=\"/product/{org}/{project}\"");
        /// Everything of the page that could lead somewhere or tell something beyond the figures
        fn only_figures(body: &str, scope: &str) {
            for gone in [
                "view=", "/cve", "/vendors", "/weaknesses", "/projects", "/orgs", "/admin", "/sync", "/applications", "/subscriptions",
                "CVE database", "Manage projects", "Sync now", "CVE-2024", "widget", "gadget", "<form method=\"post\" action=\"/orgs",
            ] {
                assert!(!body.contains(gone), "{scope}: {gone}");
            }
            for kept in ["Database synced", "Database never synced"] {
                if body.contains(kept) {
                    return;
                }
            }
            panic!("{scope}: the synchronization status is gone");
        }

        // ---- On one project ----
        let page = app.get("/product/acme/infra", Some(&world.exec)).await;
        assert_eq!(page.status, StatusCode::OK);
        let body = page.body;
        assert!(body.contains(&bare_figure(5)), "{body}");
        assert!(body.contains("<div class=\"tile alert\"><div class=\"value\">3</div><div class=\"label\">overdue on their remediation deadline</div></div>"));
        assert!(body.contains("<tr class=\"total\"><td>All</td><td>5</td><td>3</td>"), "{body}");
        assert!(body.contains("<title>Overview · Vulnizard</title>") && body.contains("Your role: executive"));
        only_figures(&body, "infra");
        // The period is chosen, the menu names the project it holds and no other
        assert!(body.contains("<a href=\"/product/acme/infra?period=30\">30 days</a>"));
        assert_eq!(app.get("/product/acme/infra?period=30", Some(&world.exec)).await.status, StatusCode::OK);
        assert!(body.contains(&project_entry("acme", "infra")) && !body.contains("web") && !body.contains("shop"), "{body}");
        // All projects: the same figures, those of that project alone (the owner counts web too)
        let all = app.get("/product", Some(&world.exec)).await.body;
        assert!(all.contains(&bare_figure(5)), "{all}");
        only_figures(&all, "*");
        assert!(app.get("/product", Some(&world.owner)).await.body.contains(&open_figure("/product", 6)));
        // Another project answers as it does to someone who holds nothing
        let elsewhere = app.get("/product/acme/web", Some(&world.exec)).await;
        let unknown = app.get("/product/acme/web", Some(&stranger)).await;
        assert_eq!((elsewhere.status, &elsewhere.body), (StatusCode::NOT_FOUND, &unknown.body));
        // Every other view of the Overview address is refused, at both scopes
        for view in ["vulnerabilities", "review", "overdue", "applications", "subscriptions", "history", "evolution", "audit", "settings"] {
            let one = app.get(&format!("/product/acme/infra?view={view}"), Some(&world.exec)).await;
            assert_eq!(one.status, StatusCode::FORBIDDEN, "{view}");
            assert!(tells_nothing(&one.body), "{view}");
            if view != "settings" {
                assert_eq!(app.get(&format!("/product?view={view}"), Some(&world.exec)).await.status, StatusCode::FORBIDDEN, "* {view}");
            }
        }
        // A narrowing of a list is not a way in either
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities&show=overdue&severity=critical", Some(&world.exec)).await.status, StatusCode::FORBIDDEN);
        // Its own settings: nothing of the organization, the invitations it has
        let settings = app.get("/settings", Some(&world.exec)).await.body;
        assert!(settings.contains("API tokens") && settings.contains("Change password") && !settings.contains("CVE database"));

        // ---- On an organization: each of its projects, and "all projects" of it ----
        let all = app.get("/product", Some(&world.board)).await.body;
        assert!(all.contains(&bare_figure(6)), "{all}");
        only_figures(&all, "board *");
        assert!(all.contains(&project_entry("acme", "infra")) && all.contains(&project_entry("acme", "web")) && !all.contains("shop"));
        let web = app.get("/product/acme/web", Some(&world.board)).await.body;
        assert!(web.contains(&bare_figure(1)), "{web}");
        only_figures(&web, "board web");
        assert_eq!(app.get("/product/globex/shop", Some(&world.board)).await.status, StatusCode::NOT_FOUND);
        // The organization itself stays closed: members, audit, projects
        for path in ["/orgs/acme", "/orgs/acme/audit/export", "/orgs", "/projects", "/product/acme/web?view=history"] {
            assert_eq!(app.get(path, Some(&world.board)).await.status, StatusCode::FORBIDDEN, "{path}");
        }

        // ---- On the instance: every project of every organization ----
        let all = app.get("/product", Some(&world.chair)).await.body;
        assert!(all.contains(&bare_figure(11)), "{all}");
        only_figures(&all, "chair *");
        // The organization filter of the bar works on what it holds
        assert!(all.contains(&org_entry("acme", "acme", false)) && all.contains(&org_entry("globex", "globex", false)), "{all}");
        let chosen = app.post("/org-filter", Some(&world.chair), "org=globex&back=/product").await;
        assert_eq!(chosen.status, StatusCode::SEE_OTHER);
        let cookies = format!("{}; {}", world.chair, chosen.cookie.clone().unwrap());
        let narrowed = app.get("/product", Some(&cookies)).await.body;
        assert!(narrowed.contains(&bare_figure(5)) && narrowed.contains("All projects of globex"), "{narrowed}");
        assert!(narrowed.contains(&project_entry("globex", "shop")) && !narrowed.contains(&project_entry("acme", "infra")));
        assert!(app.get("/product/globex/shop", Some(&world.chair)).await.body.contains(&bare_figure(5)));
        for path in ["/cve", "/cve/CVE-2024-5001", "/vendors", "/weaknesses", "/admin", "/admin/users", "/orgs/globex"] {
            assert_eq!(app.get(path, Some(&world.chair)).await.status, StatusCode::FORBIDDEN, "{path}");
        }
        // An executive of the instance does not start a synchronization
        assert_eq!(app.post("/sync", Some(&world.chair), "back=/product").await.status, StatusCode::FORBIDDEN);
        assert!(app.sync_rx.try_recv().is_err());

        // ---- Executive of acme / infra, viewer of globex / shop ----
        let mixed = &world.mixed;
        // One role above executive: the reference database is there
        for path in ["/cve", "/vendors", "/weaknesses", "/projects", "/settings"] {
            assert_eq!(app.get(path, Some(mixed)).await.status, StatusCode::OK, "{path}");
        }
        // Where it is a viewer, it is a viewer
        let shop = app.get("/product/globex/shop", Some(mixed)).await.body;
        assert!(shop.contains(&open_figure("/product/globex/shop", 5)) && shop.contains(&menu_entry("/product/globex/shop", "vulnerabilities", "Vulnerabilities", false)));
        assert!(shop.contains("CVE database"));
        let listed = app.get("/product/globex/shop?view=vulnerabilities", Some(mixed)).await;
        assert!(listed.status == StatusCode::OK && listed.body.contains("CVE-2024-5001"));
        // Where it is an executive, it is an executive: the figures, without a way to the lists
        let infra = app.get("/product/acme/infra", Some(mixed)).await.body;
        assert!(infra.contains(&bare_figure(5)) && infra.contains("Your role: executive"), "{infra}");
        for gone in ["/product/acme/infra?view=", "CVE-2024", "widget"] {
            assert!(!infra.contains(gone), "{gone}");
        }
        // From there the menu leads to the Overview of the other project, never to a view infra does not have
        assert!(infra.contains("<a href=\"/product/globex/shop\""));
        assert!(shop.contains("<a href=\"/product/acme/infra\"") && !shop.contains("/product/acme/infra?view="));
        for path in [
            "/product/acme/infra?view=vulnerabilities",
            "/product/acme/infra?view=history",
            "/product/acme/infra?view=settings",
        ] {
            assert_eq!(app.get(path, Some(mixed)).await.status, StatusCode::FORBIDDEN, "{path}");
        }
        // Everything else of that project answers as it does to a stranger
        for path in ["/orgs/acme/projects/infra/reports/2024-01-01", "/orgs/acme", "/orgs/acme/audit/export"] {
            assert_eq!(app.get(path, Some(mixed)).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        let entry = {
            let db = Database::connect(&app.db_path).unwrap();
            db.project_entries_for_cve(db.find_project("acme", "infra").unwrap().unwrap(), "CVE-2024-5001").unwrap()[0].0
        };
        for (path, form) in [
            (format!("/orgs/acme/projects/infra/watchlist/{entry}"), "status=treated"),
            ("/orgs/acme/projects/infra/applications".to_string(), "name=x&version=1"),
            ("/orgs/acme/projects/infra/members".to_string(), "username=mixed&role=owner"),
            ("/orgs/acme/projects/infra/delete".to_string(), "name=infra"),
        ] {
            assert_eq!(app.post(&path, Some(mixed), form).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        // All projects: the figures count both, the lists show the one it reads
        let all = app.get("/product", Some(mixed)).await.body;
        assert!(all.contains(&open_figure("/product", 10)), "{all}");
        let list = app.get("/product?view=vulnerabilities", Some(mixed)).await;
        assert_eq!(list.status, StatusCode::OK);
        assert!(list.body.contains("shop") && list.body.contains("CVE-2024-5001") && !list.body.contains("infra</") && !list.body.contains("CVE-2024-5006"), "{}", list.body);
        for view in ["applications", "history", "audit", "overdue"] {
            let page = app.get(&format!("/product?view={view}"), Some(mixed)).await;
            assert_eq!(page.status, StatusCode::OK, "{view}");
            assert!(!page.body.contains(">infra<") && !page.body.contains("gadget"), "{view}");
        }
        // (the menu of the bar names infra, for its Overview; the list of projects does not)
        let managed = app.get("/projects", Some(mixed)).await.body;
        assert!(managed.contains("shop") && !managed.split("<main>").nth(1).unwrap().contains("infra"));
        // The same through the API and MCP
        let token = api_token(&app, mixed).await;
        let bearer = format!("Bearer {token}");
        let figures: serde_json::Value = serde_json::from_str(&app.api("/api/summary", Some(&bearer)).await.body).unwrap();
        assert_eq!(figures["open"]["total"].as_i64(), Some(10));
        assert_eq!(app.api("/api/organizations/acme/projects/infra/summary", Some(&bearer)).await.status, StatusCode::OK);
        assert_eq!(app.api("/api/organizations/globex/projects/shop/watchlist", Some(&bearer)).await.status, StatusCode::OK);
        for path in ["/api/organizations/acme/projects/infra", "/api/organizations/acme/projects/infra/watchlist", "/api/organizations/acme/projects/infra/reports", "/api/organizations/acme/audit"] {
            assert_eq!(app.api(path, Some(&bearer)).await.status, StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(app.api("/api/cve", Some(&bearer)).await.status, StatusCode::OK);
        assert_eq!(app.post("/admin/mcp", Some(&world.owner), "http_enabled=1").await.status, StatusCode::SEE_OTHER);
        let (failed, text) = mcp_tool(&app, &token, "list_watchlist", serde_json::json!({ "org": "acme", "project": "infra" })).await;
        assert!(failed && text.contains("not found"), "{text}");
        let (failed, text) = mcp_tool(&app, &token, "list_watchlist", serde_json::json!({})).await;
        assert!(!failed && text.contains("CVE-2024-5001") && !text.contains("CVE-2024-5006"), "{text}");
        let (failed, text) = mcp_tool(&app, &token, "get_evolution", serde_json::json!({ "org": "acme", "project": "infra" })).await;
        assert!(failed && text.contains("not found"), "{text}");
        let (_, text) = mcp_tool(&app, &token, "get_summary", serde_json::json!({ "org": "acme", "project": "infra" })).await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["open"]["total"].as_i64(), Some(5));
        let (_, text) = mcp_tool(&app, &token, "list_projects", serde_json::json!({})).await;
        let projects: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(projects[0]["project"], "shop");
        assert_eq!(projects[1], serde_json::json!({ "org": "acme", "project": "infra", "summary_only": true }));

        // Nothing changed for the others: the viewer still reads, the owner still decides
        assert!(app.get("/product/acme/infra", Some(&world.viewer)).await.body.contains(&open_figure("/product/acme/infra", 5)));
        assert_eq!(app.get("/product/globex/shop?view=vulnerabilities", Some(&world.other)).await.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_executive_role_is_given_where_the_others_are_and_by_the_same_people() {
        let app = app(open_registration());
        let world = executives(&app).await;
        let db = Database::connect(&app.db_path).unwrap();
        use crate::rbac::Role;
        let infra = db.find_project("acme", "infra").unwrap().unwrap();
        let web = db.find_project("acme", "web").unwrap().unwrap();

        // Every form that gives a role offers it, viewer staying the one offered first
        let offered = "<option value=\"executive\">executive";
        let first = "<option value=\"viewer\" selected>viewer";
        for path in ["/orgs/acme", "/product/acme/infra?view=settings", &format!("/admin/users/{}", id_of(&app, "viewer")), "/admin/users?new=1", "/admin/sso?new=1"] {
            let body = app.get(path, Some(&world.owner)).await.body;
            assert!(body.contains(offered), "{path}");
            if !path.starts_with("/admin/sso") {
                assert!(body.contains(first), "{path}");
            }
        }
        assert!(app.get("/orgs/acme", Some(&world.owner)).await.body.contains("<strong>executive</strong>: the figures of the Overview only."));
        // The members of a project list who is executive there, as they list the others
        let members = app.get("/product/acme/infra?view=settings", Some(&world.owner)).await.body;
        assert!(members.contains("exec") && members.contains("executive"));

        // Who may give viewer may give executive, and nobody else: an editor may not
        let editor = app.register("editor").await;
        assert_eq!(app.post("/orgs/acme/members", Some(&world.owner), "username=editor&role=editor").await.status, StatusCode::SEE_OTHER);
        accept_in_settings(&app, "editor", &editor).await;
        app.register("guest").await;
        for role in ["viewer", "executive"] {
            for path in ["/orgs/acme/members", "/orgs/acme/projects/infra/members"] {
                let form = format!("username=guest&role={role}");
                assert_eq!(app.post(path, Some(&editor), &form).await.status, StatusCode::FORBIDDEN, "{path} {role}");
                assert_eq!(app.post(path, Some(&world.viewer), &form).await.status, StatusCode::FORBIDDEN, "{path} {role}");
                assert_eq!(app.post(path, Some(&world.other), &form).await.status, StatusCode::NOT_FOUND, "{path} {role}");
            }
        }
        assert!(db.received_invitations(id_of(&app, "guest")).unwrap().is_empty());
        // A role nobody knows is still refused
        assert_eq!(app.post("/orgs/acme/members", Some(&world.owner), "username=guest&role=manager").await.status, StatusCode::BAD_REQUEST);
        // Only an administrator gives it on the instance, or to anyone from the administration
        let guest_id = id_of(&app, "guest");
        for scope in ["instance", "organization%3Aacme", "project%3Aacme%2Finfra"] {
            let form = format!("scope={scope}&role=executive");
            assert_eq!(app.post(&format!("/admin/users/{guest_id}/assign"), Some(&editor), &form).await.status, StatusCode::FORBIDDEN, "{scope}");
            assert_eq!(app.post(&format!("/admin/users/{guest_id}/assign"), Some(&world.owner), &form).await.status, StatusCode::SEE_OTHER, "{scope}");
        }
        let rights: Vec<(String, String)> = db.user_assignments(guest_id).unwrap().into_iter().map(|a| (a.level, a.role)).collect();
        assert_eq!(rights.len(), 3);
        assert!(rights.iter().all(|(_, role)| role == "executive"), "{rights:?}");
        assert!(app.get(&format!("/admin/users/{guest_id}"), Some(&world.owner)).await.body.contains("executive"));
        // An account created with it
        let created = app.post("/admin/users", Some(&world.owner), "username=report&password=a-long-password&scope=organization%3Aacme&role=executive").await;
        assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
        assert_eq!(db.org_role(id_of(&app, "report"), db.list_all_orgs().unwrap().iter().find(|(_, name)| name == "acme").unwrap().0).unwrap(), Some(Role::Executive));

        // The role a provider gives at the first sign-in, and the one of a provisioned group
        let form = "name=Board+SSO&slug=board-sso&issuer=https%3A%2F%2Fid.example.org&client_id=vulnizard&client_secret=s3cret&scopes=openid+email\
                    &auto_create=1&scope=organization%3Aacme&default_role=executive";
        let saved = app.post("/admin/sso", Some(&world.owner), form).await;
        assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
        assert_eq!(db.get_sso_provider("board-sso").unwrap().unwrap().default_role.as_deref(), Some("executive"));
        let group = db.scim_create_group(crate::db::Scope::Instance, "board", None).unwrap();
        let given = app.post(&format!("/admin/sso/scim/groups/{group}/roles"), Some(&world.owner), "scope=project%3Aacme%2Fweb&role=executive").await;
        assert_eq!(given.status, StatusCode::SEE_OTHER, "{}", given.body);
        assert_eq!(db.list_group_roles(group).unwrap()[0].role, "executive");

        // The highest role wins on a project; the others are not touched
        let board_id = id_of(&app, "board");
        assert_eq!(app.post("/orgs/acme/projects/web/members", Some(&world.owner), "username=board&role=viewer").await.status, StatusCode::SEE_OTHER);
        accept_in_settings(&app, "board", &world.board).await;
        assert_eq!(db.project_role(board_id, web).unwrap(), Some(Role::Viewer));
        assert_eq!(db.project_role(board_id, infra).unwrap(), Some(Role::Executive));
        assert_eq!(app.get("/product/acme/web?view=vulnerabilities", Some(&world.board)).await.status, StatusCode::OK);
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities", Some(&world.board)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.get("/cve", Some(&world.board)).await.status, StatusCode::OK);
        // An executive of a project who is viewer of its organization reads it
        assert_eq!(app.post(&format!("/admin/users/{}/assign", id_of(&app, "exec")), Some(&world.owner), "scope=organization%3Aacme&role=viewer").await.status, StatusCode::SEE_OTHER);
        assert_eq!(db.project_role(id_of(&app, "exec"), infra).unwrap(), Some(Role::Viewer));
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities", Some(&world.exec)).await.status, StatusCode::OK);
        // Taken back, the confinement is back
        assert_eq!(app.post(&format!("/admin/users/{}/assign", id_of(&app, "exec")), Some(&world.owner), "scope=organization%3Aacme&role=none").await.status, StatusCode::SEE_OTHER);
        assert_eq!(app.get("/product/acme/infra?view=vulnerabilities", Some(&world.exec)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(app.get("/cve", Some(&world.exec)).await.status, StatusCode::FORBIDDEN);
        // The owner changes an executive member into a viewer from the list of members
        assert_eq!(app.post("/orgs/acme/members", Some(&world.owner), "username=board&role=viewer").await.status, StatusCode::SEE_OTHER);
        // (a member already there is not invited again: the change waits for nothing)
        let _ = world.chair;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_slack_destination_comes_with_the_way_to_get_its_address() {
        let app = app(open_registration());
        let admin = app.register("root").await;
        let page = app.get("/admin/notifications?tab=destinations&new=slack", Some(&admin)).await;
        assert_eq!(page.status, StatusCode::OK);
        // The steps, the logo to upload, and a link that opens Slack with the app described
        for shown in ["Getting the webhook address from Slack", "Install to Workspace", "href=\"/static/logo.png\"", "Incoming Webhooks"] {
            assert!(page.body.contains(shown), "{shown}");
        }
        let link = page.body.split("href=\"https://api.slack.com/apps?new_app=1&amp;manifest_json=").nth(1).expect("the link to Slack").split('"').next().unwrap().to_string();
        assert!(page.body.contains("target=\"_blank\" rel=\"noopener noreferrer\""));
        // What Slack is given: valid JSON, wholly encoded, that switches incoming webhooks on
        assert!(link.chars().all(|c| c.is_ascii_alphanumeric() || c == '%'), "{link}");
        let manifest: serde_json::Value = serde_json::from_str(&percent_encoding::percent_decode_str(&link).decode_utf8().unwrap()).unwrap();
        assert_eq!(manifest["settings"]["incoming_webhooks"]["incoming_webhooks_enabled"], true);
        assert_eq!(manifest["oauth_config"]["scopes"]["bot"], serde_json::json!(["incoming-webhook"]));
        let name = manifest["display_information"]["name"].as_str().unwrap();
        let description = manifest["display_information"]["description"].as_str().unwrap();
        assert!(name.len() <= 35 && description.len() <= 140);
        // The other kinds have no such guide, and the project form has the same one
        assert!(!app.get("/admin/notifications?tab=destinations&new=ntfy", Some(&admin)).await.body.contains("api.slack.com"));
        let project = app.get("/product/default/default?view=settings&new=slack", Some(&admin)).await;
        assert!(project.status == StatusCode::OK && project.body.contains("api.slack.com/apps?new_app=1"));
    }
}
