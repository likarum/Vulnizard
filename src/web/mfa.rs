//! Two-step sign-in of local accounts: authenticator app (TOTP), passkeys
//! (WebAuthn) and recovery codes; enrolment from the settings; and the gate
//! that holds an account to its enrolment while a second factor is required
//! and missing.
//!
//! Accounts that sign in through single sign-on only have no password here:
//! their second factor belongs to the identity provider. API tokens are not
//! concerned either (HTTP Basic with the password is refused once a second
//! factor is set or required).

use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;
use serde_json::{json, Value};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

use super::pages::{check_credentials, redirect, start_session, ActionResult, HtmlResult};
use super::views::{enc, page};
use super::{blocking, AppError, AppState, St, User};
use crate::auth;
use crate::db::{Account, Actor, Database, MfaPending, MfaStatus, SecurityEvent};
use crate::mfa;

const MFA_COOKIE: &str = "vulnizard_mfa";
/// Time given to answer the second step, or to finish registering a passkey
const PENDING_TTL_SECS: i64 = 300;

// ==========================================
// WebAuthn relying party
// ==========================================

/// Passkeys are bound to the host of `web.base_url`. Browsers only allow them
/// on HTTPS (or on `localhost`), and never on a bare IP address.
fn webauthn(st: &AppState) -> Result<Webauthn, String> {
    let origin = Url::parse(&st.config.web.base_url).map_err(|_| "web.base_url is not a valid URL".to_string())?;
    let host = match origin.host() {
        Some(url::Host::Domain(domain)) => domain.to_string(),
        Some(_) => return Err("web.base_url uses an IP address; passkeys need a host name".into()),
        None => return Err("web.base_url has no host".into()),
    };
    if origin.scheme() != "https" && host != "localhost" && !host.ends_with(".localhost") {
        return Err("web.base_url is not HTTPS; passkeys need HTTPS (or localhost)".into());
    }
    WebauthnBuilder::new(&host, &origin)
        .and_then(|builder| builder.rp_name("Vulnizard").build())
        .map_err(|e| format!("passkeys are not available: {e}"))
}

pub(super) fn passkeys_available(st: &AppState) -> bool {
    webauthn(st).is_ok()
}

fn credential_id(passkey: &Passkey) -> String {
    hex::encode(passkey.cred_id())
}

fn stored_passkeys(db: &Database, user_id: i64) -> Result<Vec<Passkey>, AppError> {
    Ok(db
        .passkeys(user_id)?
        .into_iter()
        .filter_map(|(_, data)| serde_json::from_str(&data).ok())
        .collect())
}

// ==========================================
// Second step of the login
// ==========================================

fn mfa_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    format!(
        "{MFA_COOKIE}={value}; Path=/login; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

fn pending_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == MFA_COOKIE)
        .map(|(_, v)| auth::hash_token(v))
}

fn pending_login(db: &Database, headers: &axum::http::HeaderMap) -> Result<Option<(String, MfaPending)>, AppError> {
    let Some(hash) = pending_token(headers) else {
        return Ok(None);
    };
    Ok(db.mfa_pending(&hash, "login")?.map(|pending| (hash, pending)))
}

/// Throttling key of the second step of an account. It is separate from the
/// password's: a right password must not wipe the count of wrong codes,
/// otherwise the codes could be guessed by signing in again and again.
fn guard_key(user_id: i64) -> String {
    auth::ThrottleKey::second_step(user_id)
}

/// What follows an accepted password: the session, or the second step
pub(super) fn after_password(st: &AppState, db: &Database, user_id: i64) -> ActionResult {
    if !db.has_second_factor(user_id)? {
        return start_session(st, db, user_id);
    }
    if st.login_guard.is_locked(&guard_key(user_id)) {
        return Err(AppError::TooMany);
    }
    let (token, hash) = auth::new_token();
    db.create_mfa_pending(&hash, user_id, "login", None, PENDING_TTL_SECS)?;
    Ok((
        [(header::SET_COOKIE, mfa_cookie(st, &token, PENDING_TTL_SECS))],
        Redirect::to("/login/mfa"),
    )
        .into_response())
}

/// Opens the session and forgets the pending check
fn finish_login(st: &AppState, db: &Database, hash: &str, user_id: i64) -> ActionResult {
    st.login_guard.record(&guard_key(user_id), true);
    db.delete_mfa_pending(hash)?;
    let mut response = start_session(st, db, user_id)?;
    if let Ok(cookie) = HeaderValue::from_str(&mfa_cookie(st, "", 0)) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

fn back_to_login(st: &AppState) -> Response {
    ([(header::SET_COOKIE, mfa_cookie(st, "", 0))], Redirect::to("/login")).into_response()
}

fn second_step_page(st: &AppState, status: &MfaStatus, error: Option<&str>) -> Markup {
    let passkeys = !status.passkeys.is_empty() && webauthn(st).is_ok();
    page(
        "Second step",
        None,
        html! {
            h1 { "Second step" }
            @if let Some(e) = error { p.error { (e) } }
            @if passkeys {
                form.stack.card id="passkey-login" {
                    p { "Use the passkey or security key registered for your account." }
                    button type="button" data-passkey { "Use a passkey" }
                    p.muted data-passkey-message {}
                }
            }
            form.stack.card method="post" action="/login/mfa" {
                label {
                    @if status.totp { "Code of your authenticator app, or a recovery code" } @else { "Recovery code" }
                    input type="text" name="code" required autofocus[!passkeys] autocomplete="one-time-code" maxlength="32";
                }
                button type="submit" { "Continue" }
            }
            p { a href="/login" { "Use another account" } }
            @if passkeys { script src="/static/mfa.js" defer {} }
        },
    )
}

pub async fn second_step_form(State(st): St, headers: axum::http::HeaderMap) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        match pending_login(&db, &headers)? {
            Some((_, pending)) => Ok(second_step_page(&st, &db.mfa_status(pending.user_id)?, None).into_response()),
            None => Ok(back_to_login(&st)),
        }
    })
}

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

/// Records what an account did to its own sign-in
fn trail(db: &Database, user: &Account, event: &str, detail: Option<&str>) -> Result<(), AppError> {
    Ok(db.log_security_event(&Actor::user(user.id, &user.username), Some(user.id), event, detail)?)
}

/// Same, during the second step: the account is known, its session not open yet
fn trail_of(db: &Database, user_id: i64, event: &str) -> Result<(), AppError> {
    let name = db.get_account(user_id)?.map(|a| a.username).unwrap_or_default();
    Ok(db.log_security_event(&Actor::user(user_id, &name), Some(user_id), event, None)?)
}

/// Table of security events (the account column only where several accounts show)
pub(super) fn events_table(events: &[SecurityEvent], with_account: bool) -> Markup {
    html! {
        table.list.fit {
            (super::views::columns(if with_account { "when - name name" } else { "when - name" }, true))
            thead { tr { th { "When (UTC)" } th { "Event" } @if with_account { th { "Account" } } th { "By" } } }
            tbody {
                @for e in events {
                    tr {
                        td.nowrap { (e.at) }
                        td { (e.label()) @if let Some(d) = &e.detail { " — " span.muted { (d) } } }
                        @if with_account { td { (e.username) } }
                        td { (e.actor) }
                    }
                }
                @if events.is_empty() { tr { td colspan=(if with_account { "4" } else { "3" }) .muted { "Nothing yet." } } }
            }
        }
    }
}

/// Accepts a code of the authenticator app or a recovery code, each once
fn code_is_valid(db: &Database, user_id: i64, code: &str) -> Result<bool, AppError> {
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() == 6 && compact.bytes().all(|c| c.is_ascii_digit()) {
        if let Some((secret, true, last_step)) = db.totp(user_id)? {
            if let Some(step) = mfa::verify(&secret, &compact, mfa::current_step(), last_step) {
                return Ok(db.accept_totp_step(user_id, step)?);
            }
        }
        return Ok(false);
    }
    let used = db.use_recovery_code(user_id, &auth::hash_token(&mfa::normalize_recovery_code(code)))?;
    if used {
        trail_of(db, user_id, "recovery_code_used")?;
    }
    Ok(used)
}

/// Counts a wrong answer to the second step; the lock is recorded when it sets in
fn wrong_answer(st: &AppState, db: &Database, user_id: i64) -> Result<(), AppError> {
    let key = guard_key(user_id);
    st.login_guard.record(&key, false);
    if st.login_guard.is_locked(&key) {
        trail_of(db, user_id, "second_step_locked")?;
    }
    Ok(())
}

pub async fn second_step(State(st): St, headers: axum::http::HeaderMap, Form(form): Form<CodeForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let Some((hash, pending)) = pending_login(&db, &headers)? else {
            return Ok(back_to_login(&st));
        };
        if st.login_guard.is_locked(&guard_key(pending.user_id)) {
            return Err(AppError::TooMany);
        }
        if code_is_valid(&db, pending.user_id, &form.code)? {
            return finish_login(&st, &db, &hash, pending.user_id);
        }
        wrong_answer(&st, &db, pending.user_id)?;
        if !db.fail_mfa_pending(&hash)? {
            return Ok(back_to_login(&st));
        }
        Ok((
            StatusCode::UNAUTHORIZED,
            second_step_page(&st, &db.mfa_status(pending.user_id)?, Some("This code is not valid.")),
        )
            .into_response())
    })
}

/// JSON error of the passkey endpoints (read by `mfa.js`)
fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn json_failure(e: AppError) -> Response {
    match e {
        AppError::Bad(message) => json_error(StatusCode::BAD_REQUEST, &message),
        AppError::TooMany => json_error(StatusCode::TOO_MANY_REQUESTS, "Too many attempts, try again later."),
        AppError::Forbidden => json_error(StatusCode::FORBIDDEN, "Forbidden."),
        AppError::NotFound => json_error(StatusCode::NOT_FOUND, "Not found."),
        AppError::Login | AppError::Unauthorized => json_error(StatusCode::UNAUTHORIZED, "Sign in again."),
        AppError::Internal(e) => {
            tracing::error!("passkey endpoint failed: {e:#}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")
        }
    }
}

pub async fn passkey_login_start(State(st): St, headers: axum::http::HeaderMap) -> Response {
    blocking(|| -> Result<Response, AppError> {
        let db = st.db()?;
        let Some((hash, pending)) = pending_login(&db, &headers)? else {
            return Ok(json_error(StatusCode::UNAUTHORIZED, "Sign in again."));
        };
        let passkeys = stored_passkeys(&db, pending.user_id)?;
        if passkeys.is_empty() {
            return Err(AppError::Bad("No passkey is registered for this account.".into()));
        }
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        let (challenge, state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("passkey challenge: {e}")))?;
        db.set_mfa_pending_state(&hash, Some(&serde_json::to_string(&state).map_err(anyhow::Error::from)?))?;
        Ok(Json(challenge).into_response())
    })
    .unwrap_or_else(json_failure)
}

pub async fn passkey_login_finish(
    State(st): St,
    headers: axum::http::HeaderMap,
    Json(credential): Json<PublicKeyCredential>,
) -> Response {
    blocking(|| -> Result<Response, AppError> {
        let db = st.db()?;
        let Some((hash, pending)) = pending_login(&db, &headers)? else {
            return Ok(json_error(StatusCode::UNAUTHORIZED, "Sign in again."));
        };
        // A challenge serves once
        let state: Option<PasskeyAuthentication> = pending.state.as_deref().and_then(|s| serde_json::from_str(s).ok());
        db.set_mfa_pending_state(&hash, None)?;
        let Some(state) = state else {
            return Err(AppError::Bad("No passkey check is in progress.".into()));
        };
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        let result = match webauthn.finish_passkey_authentication(&credential, &state) {
            Ok(result) => result,
            Err(e) => {
                tracing::info!("passkey refused for user {}: {e}", pending.user_id);
                wrong_answer(&st, &db, pending.user_id)?;
                db.fail_mfa_pending(&hash)?;
                return Ok(json_error(StatusCode::UNAUTHORIZED, "This passkey was not accepted."));
            }
        };
        // Keep the signature counter of the credential that was used
        for mut passkey in stored_passkeys(&db, pending.user_id)? {
            if passkey.cred_id() == result.cred_id() {
                passkey.update_credential(&result);
                let data = serde_json::to_string(&passkey).map_err(anyhow::Error::from)?;
                db.touch_passkey(pending.user_id, &credential_id(&passkey), &data)?;
            }
        }
        let session = finish_login(&st, &db, &hash, pending.user_id)?;
        let mut response = Json(json!({ "redirect": "/" })).into_response();
        for cookie in session.headers().get_all(header::SET_COOKIE) {
            response.headers_mut().append(header::SET_COOKIE, cookie.clone());
        }
        Ok(response)
    })
    .unwrap_or_else(json_failure)
}

// ==========================================
// Sign-in with a passkey alone
// ==========================================
//
// The passkey proves possession of the device and, because user verification
// is required (PIN, fingerprint, face), something the user knows or is: it
// stands for both steps. The account is the one the authenticator stored.

const PASSKEY_LOGIN_COOKIE: &str = "vulnizard_passkey";

fn passkey_login_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    format!(
        "{PASSKEY_LOGIN_COOKIE}={value}; Path=/login; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

pub async fn passwordless_start(State(st): St, super::ClientAddr(client): super::ClientAddr) -> Response {
    blocking(|| -> Result<Response, AppError> {
        super::count_start(&st, &client)?;
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        let (challenge, state) = webauthn
            .start_discoverable_authentication()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("passkey challenge: {e}")))?;
        let (token, hash) = auth::new_token();
        st.db()?.create_passkey_login(&hash, &serde_json::to_string(&state).map_err(anyhow::Error::from)?, PENDING_TTL_SECS)?;
        Ok((
            [(header::SET_COOKIE, passkey_login_cookie(&st, &token, PENDING_TTL_SECS))],
            Json(challenge),
        )
            .into_response())
    })
    .unwrap_or_else(json_failure)
}

pub async fn passwordless_finish(
    State(st): St,
    headers: axum::http::HeaderMap,
    Json(credential): Json<PublicKeyCredential>,
) -> Response {
    blocking(|| -> Result<Response, AppError> {
        let db = st.db()?;
        let refused = || Ok(json_error(StatusCode::UNAUTHORIZED, "This passkey was not accepted."));
        let token = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| *k == PASSKEY_LOGIN_COOKIE)
            .map(|(_, v)| auth::hash_token(v));
        // A challenge serves once
        let state: Option<DiscoverableAuthentication> = match token {
            Some(hash) => db.take_passkey_login(&hash)?.and_then(|s| serde_json::from_str(&s).ok()),
            None => None,
        };
        let Some(state) = state else {
            return Err(AppError::Bad("No passkey sign-in is in progress; start again.".into()));
        };
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        // Which account does the authenticator say it is?
        let Ok((handle, used)) = webauthn.identify_discoverable_authentication(&credential) else {
            return refused();
        };
        let Some(user_id) = db.user_by_mfa_handle(&handle.to_string())? else {
            return refused();
        };
        // The answer is checked against the one credential it names, of that account
        let passkeys = stored_passkeys(&db, user_id)?;
        let Some(expected) = passkeys.iter().find(|p| AsRef::<[u8]>::as_ref(p.cred_id()) == used) else {
            return refused();
        };
        let result = match webauthn.finish_discoverable_authentication_v2(&credential, state, DiscoverableKey::from(expected)) {
            Ok(result) => result,
            Err(e) => {
                tracing::info!("passkey sign-in refused for user {user_id}: {e}");
                return refused();
            }
        };
        for mut passkey in passkeys {
            if passkey.cred_id() == result.cred_id() {
                passkey.update_credential(&result);
                let data = serde_json::to_string(&passkey).map_err(anyhow::Error::from)?;
                db.touch_passkey(user_id, &credential_id(&passkey), &data)?;
            }
        }
        let session = start_session(&st, &db, user_id)?;
        let mut response = Json(json!({ "redirect": "/" })).into_response();
        for cookie in session.headers().get_all(header::SET_COOKIE) {
            response.headers_mut().append(header::SET_COOKIE, cookie.clone());
        }
        if let Ok(cookie) = HeaderValue::from_str(&passkey_login_cookie(&st, "", 0)) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        Ok(response)
    })
    .unwrap_or_else(json_failure)
}

// ==========================================
// Gate: required and missing
// ==========================================

/// While a second factor is required of the signed-in account and none is
/// set, every page leads to the enrolment and nothing else is accepted.
pub async fn gate(State(state): St, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let open = path == "/settings/mfa"
        || path.starts_with("/settings/mfa/")
        || path.starts_with("/static/")
        || path.starts_with("/login")
        || path == "/logout";
    if open {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let must_enrol = blocking(|| -> Result<bool, AppError> {
        match super::session_account(&parts, &state)? {
            Some(account) => Ok(state.db()?.must_enrol_mfa(account.id)?),
            None => Ok(false),
        }
    });
    match must_enrol {
        Ok(false) => next.run(Request::from_parts(parts, body)).await,
        Ok(true) if matches!(parts.method, Method::GET | Method::HEAD) => Redirect::to("/settings/mfa").into_response(),
        Ok(true) => AppError::Forbidden.into_response(),
        Err(e) => e.into_response(),
    }
}

// ==========================================
// Settings
// ==========================================

fn confirm_password(st: &AppState, db: &Database, user: &Account, password: &str) -> Result<(), AppError> {
    if check_credentials(st, db, &user.username, password, &super::pages::Attempt::Session(user.id))?.is_none() {
        return Err(AppError::Bad("Current password is incorrect.".into()));
    }
    Ok(())
}

/// Removing the last factor is refused while one is required
fn may_remove_factor(db: &Database, user_id: i64, status: &MfaStatus, removing_totp: bool) -> Result<(), AppError> {
    let left = (status.totp && !removing_totp) as usize + status.passkeys.len() - (!removing_totp) as usize;
    if left == 0 && db.mfa_required(user_id)? {
        return Err(AppError::Bad("A second factor is required for your account: add another one before removing this one.".into()));
    }
    Ok(())
}

fn password_field() -> Markup {
    html! {
        label { "Current password" input type="password" name="password" required autocomplete="current-password"; }
    }
}

/// Short status shown in the account settings
pub(super) fn settings_summary(db: &Database, user: &Account) -> Result<Markup, AppError> {
    let status = db.mfa_status(user.id)?;
    Ok(html! {
        h2 { "Two-step sign-in" }
        p {
            @if !db.has_password(user.id)? {
                span.muted { "You sign in through single sign-on: the second step is handled by your identity provider." }
            } @else if status.enrolled() {
                "Enabled"
                @if status.totp { " — authenticator app" }
                @if !status.passkeys.is_empty() { " — " (status.passkeys.len()) " passkey(s)" }
                ". "
                a href="/settings/mfa" { "Manage" }
            } @else {
                "Not enabled. " a href="/settings/mfa" { "Set it up" }
            }
        }
    })
}

fn manage_page(st: &AppState, db: &Database, user: &Account, message: Option<Markup>) -> HtmlResult {
    let status = db.mfa_status(user.id)?;
    let has_password = db.has_password(user.id)?;
    let required = db.mfa_required(user.id)?;
    let passkeys = webauthn(st);
    let events = db.list_security_events(Some(user.id), 20)?;
    let awaiting = db.orgs_awaiting_mfa(user.id)?;
    Ok(page(
        "Two-step sign-in",
        Some(user),
        html! {
            p { a href="/settings" { "← Settings" } }
            h1 { "Two-step sign-in" }
            @if let Some(m) = message { (m) }
            @if !has_password {
                p { "You sign in through single sign-on: the second step is handled by your identity provider." }
            } @else {
                @if required && !status.enrolled() {
                    div.card.notice {
                        strong { "A second factor is required for your account. " }
                        "Set up an authenticator app or a passkey to continue."
                    }
                } @else if required {
                    p.muted { "A second factor is required for your account." }
                }
                @if !awaiting.is_empty() {
                    div.card.notice {
                        strong { "Closed until you set up a second factor: " }
                        (awaiting.join(", ")) ". These organizations require two-step sign-in from their members."
                    }
                }
                p.muted {
                    "After your password, Vulnizard asks for a code of an authenticator app, or a passkey. "
                    "API tokens are not concerned; signing in to the API with your password stops working."
                }

                h2 { "Authenticator app" }
                @if status.totp {
                    p { "Enabled." }
                    form.row method="post" action="/settings/mfa/totp/delete" {
                        (password_field())
                        button.danger type="submit" { "Remove the authenticator app" }
                    }
                } @else {
                    form.row method="post" action="/settings/mfa/totp" {
                        (password_field())
                        button type="submit" { "Set up an authenticator app" }
                    }
                }

                h2 { "Passkeys and security keys" }
                @if !status.passkeys.is_empty() {
                    table.list.fit {
                        (super::views::columns("- when when act", true))
                        thead { tr { th { "Name" } th { "Added" } th { "Last used" } th {} } }
                        tbody {
                            @for key in &status.passkeys {
                                tr {
                                    td { (key.name) }
                                    td { (key.created_at) }
                                    td { (key.last_used_at.as_deref().unwrap_or("never")) }
                                    td.right {
                                        form.inline method="post" action={ "/settings/mfa/passkeys/" (key.id) "/delete" } {
                                            input type="password" name="password" placeholder="Current password" required autocomplete="current-password";
                                            " " button.small.danger type="submit" { "Remove" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @match &passkeys {
                    Ok(_) => {
                        form.row id="passkey-register" {
                            input type="text" name="name" placeholder="Name, e.g. laptop" maxlength="64" required;
                            input type="password" name="password" placeholder="Current password" required autocomplete="current-password";
                            button type="button" data-passkey { "Add a passkey" }
                            span.muted data-passkey-message {}
                        }
                        script src="/static/mfa.js" defer {}
                    }
                    Err(reason) => {
                        p.muted { "Passkeys are not available on this instance: " (reason) "." }
                    }
                }

                @if status.enrolled() {
                    h2 { "Recovery codes" }
                    @if status.recovery_left == 0 {
                        div.card.notice {
                            strong { "You have no recovery code. " }
                            "Without one, losing your device locks you out until an administrator resets your second factor."
                        }
                    } @else {
                        p { (status.recovery_left) " unused code(s). Each code works once, in place of your second factor." }
                    }
                    form.row method="post" action="/settings/mfa/recovery" {
                        (password_field())
                        button.secondary type="submit" { "Generate new recovery codes" }
                    }
                    p.muted { "Generating new codes cancels the previous ones." }
                }

                h2 { "Recent activity" }
                (events_table(&events, false))
            }
        },
    ))
}

pub async fn manage(State(st): St, User(user): User) -> HtmlResult {
    blocking(|| manage_page(&st, &st.db()?, &user, None))
}

#[derive(Deserialize)]
pub struct PasswordOnly {
    password: String,
}

fn totp_setup_page(st: &AppState, user: &Account, secret: &str, error: Option<&str>) -> Markup {
    let host = Url::parse(&st.config.web.base_url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
    let uri = mfa::otpauth_uri("Vulnizard", &format!("{}@{host}", user.username), secret);
    page(
        "Authenticator app",
        Some(user),
        html! {
            p { a href="/settings/mfa" { "← Two-step sign-in" } }
            h1 { "Set up an authenticator app" }
            @if let Some(e) = error { p.error { (e) } }
            div.card {
                p { "Scan this code with your authenticator app, or enter the key by hand." }
                @if let Some(svg) = mfa::qr_svg(&uri) { div.qr { (PreEscaped(svg)) } }
                p { "Key: " code.token { (secret) } }
            }
            form.stack.card method="post" action="/settings/mfa/totp/confirm" {
                label {
                    "Code shown by the app"
                    input type="text" name="code" required autofocus inputmode="numeric" autocomplete="one-time-code" maxlength="10";
                }
                button type="submit" { "Enable" }
            }
        },
    )
}

pub async fn totp_begin(State(st): St, User(user): User, Form(form): Form<PasswordOnly>) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        confirm_password(&st, &db, &user, &form.password)?;
        let secret = mfa::new_secret();
        if !db.begin_totp(user.id, &secret)? {
            return Err(AppError::Bad("An authenticator app is already set up.".into()));
        }
        Ok(totp_setup_page(&st, &user, &secret, None))
    })
}

fn recovery_codes_card(codes: &[String]) -> Markup {
    html! {
        div.card {
            p { strong { "Recovery codes — keep them somewhere safe, they will not be shown again." } }
            p.muted { "Each code works once, in place of your second factor." }
            ul.plain { @for code in codes { li { code.token { (code) } } } }
        }
    }
}

fn new_recovery_codes(db: &Database, user_id: i64) -> Result<Vec<String>, AppError> {
    let codes = mfa::new_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| auth::hash_token(c)).collect();
    db.replace_recovery_codes(user_id, &hashes)?;
    Ok(codes)
}

pub async fn totp_confirm(State(st): St, User(user): User, Form(form): Form<CodeForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let Some((secret, false, _)) = db.totp(user.id)? else {
            return Ok(redirect("/settings/mfa".into()));
        };
        let accepted = match mfa::verify(&secret, &form.code, mfa::current_step(), 0) {
            Some(step) => db.accept_totp_step(user.id, step)?,
            None => false,
        };
        if !accepted {
            return Ok((
                StatusCode::BAD_REQUEST,
                totp_setup_page(&st, &user, &secret, Some("This code is not valid. Check the clock of your device and try again.")),
            )
                .into_response());
        }
        trail(&db, &user, "totp_enabled", None)?;
        // First factor: the recovery codes come with it
        let message = if db.mfa_status(user.id)?.recovery_left == 0 {
            trail(&db, &user, "recovery_codes_generated", None)?;
            recovery_codes_card(&new_recovery_codes(&db, user.id)?)
        } else {
            html! {}
        };
        Ok(manage_page(&st, &db, &user, Some(html! { p { strong { "Authenticator app enabled." } } (message) }))?.into_response())
    })
}

pub async fn totp_delete(State(st): St, User(user): User, Form(form): Form<PasswordOnly>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        confirm_password(&st, &db, &user, &form.password)?;
        let status = db.mfa_status(user.id)?;
        if status.totp {
            may_remove_factor(&db, user.id, &status, true)?;
            trail(&db, &user, "totp_removed", None)?;
        }
        db.delete_totp(user.id)?;
        Ok(redirect("/settings/mfa".into()))
    })
}

pub async fn recovery_regenerate(State(st): St, User(user): User, Form(form): Form<PasswordOnly>) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        confirm_password(&st, &db, &user, &form.password)?;
        if !db.has_second_factor(user.id)? {
            return Err(AppError::Bad("Set up a second factor first.".into()));
        }
        let codes = new_recovery_codes(&db, user.id)?;
        trail(&db, &user, "recovery_codes_generated", None)?;
        manage_page(&st, &db, &user, Some(recovery_codes_card(&codes)))
    })
}

#[derive(Deserialize)]
pub struct PasskeyStart {
    password: String,
    name: String,
}

/// Key of the pending registration of an account (one at a time)
fn registration_key(user_id: i64) -> String {
    format!("register:{user_id}")
}

pub async fn passkey_register_start(State(st): St, User(user): User, Json(form): Json<PasskeyStart>) -> Response {
    blocking(|| -> Result<Response, AppError> {
        let db = st.db()?;
        confirm_password(&st, &db, &user, &form.password)?;
        let name = form.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(AppError::Bad("Give this passkey a name (64 characters at most).".into()));
        }
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        let handle = Uuid::parse_str(&db.mfa_handle(user.id)?).map_err(anyhow::Error::from)?;
        let existing = stored_passkeys(&db, user.id)?.iter().map(|p| p.cred_id().clone()).collect();
        let (challenge, registration) = webauthn
            .start_passkey_registration(handle, &user.username, &user.username, Some(existing))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("passkey registration: {e}")))?;
        let state = json!({ "name": name, "registration": registration }).to_string();
        db.create_mfa_pending(&registration_key(user.id), user.id, "register", Some(&state), PENDING_TTL_SECS)?;
        // Ask the authenticator to remember the account, so that the passkey can also
        // sign in on its own (without typing a username). Old security keys may decline:
        // the passkey then only serves as second step.
        let mut challenge = serde_json::to_value(&challenge).map_err(anyhow::Error::from)?;
        challenge["publicKey"]["authenticatorSelection"]["residentKey"] = json!("preferred");
        Ok(Json(challenge).into_response())
    })
    .unwrap_or_else(json_failure)
}

pub async fn passkey_register_finish(
    State(st): St,
    User(user): User,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Response {
    blocking(|| -> Result<Response, AppError> {
        let db = st.db()?;
        let key = registration_key(user.id);
        let pending = db.mfa_pending(&key, "register")?;
        db.delete_mfa_pending(&key)?;
        let state: Option<Value> = pending.and_then(|p| p.state).and_then(|s| serde_json::from_str(&s).ok());
        let Some(state) = state else {
            return Err(AppError::Bad("No passkey registration is in progress; start again.".into()));
        };
        let registration: PasskeyRegistration =
            serde_json::from_value(state["registration"].clone()).map_err(anyhow::Error::from)?;
        let name = state["name"].as_str().unwrap_or("passkey");
        let webauthn = webauthn(&st).map_err(AppError::Bad)?;
        let passkey = webauthn
            .finish_passkey_registration(&credential, &registration)
            .map_err(|e| AppError::Bad(format!("This passkey was not accepted ({e}).")))?;
        let data = serde_json::to_string(&passkey).map_err(anyhow::Error::from)?;
        if !db.add_passkey(user.id, name, &credential_id(&passkey), &data)? {
            return Err(AppError::Bad("This passkey is already registered.".into()));
        }
        trail(&db, &user, "passkey_added", Some(name))?;
        Ok(Json(json!({ "redirect": "/settings/mfa" })).into_response())
    })
    .unwrap_or_else(json_failure)
}

pub async fn passkey_delete(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(form): Form<PasswordOnly>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        confirm_password(&st, &db, &user, &form.password)?;
        let status = db.mfa_status(user.id)?;
        let Some(passkey) = status.passkeys.iter().find(|k| k.id == id) else {
            return Err(AppError::NotFound);
        };
        may_remove_factor(&db, user.id, &status, false)?;
        db.delete_passkey(user.id, id)?;
        trail(&db, &user, "passkey_removed", Some(&passkey.name))?;
        Ok(redirect("/settings/mfa".into()))
    })
}

/// Gives up one's own role in an organization. No right is needed: nobody
/// has to stay where they were added.
pub async fn org_leave(State(st): St, User(user): User, Path(org): Path<String>) -> ActionResult {
    blocking(|| {
        if !st.db()?.leave_org(&org, user.id)? {
            return Err(AppError::NotFound);
        }
        Ok(redirect("/orgs".into()))
    })
}

pub async fn script(headers: axum::http::HeaderMap) -> impl IntoResponse {
    super::pages::asset(&headers, "text/javascript; charset=utf-8", include_str!("mfa.js"))
}

// ==========================================
// Requirement on an organization
// ==========================================

#[derive(Deserialize)]
pub struct RequireForm {
    #[serde(default)]
    required: String,
}

impl RequireForm {
    pub(super) fn required(&self) -> bool {
        self.required == "1"
    }
}

pub async fn org_requirement(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Form(form): Form<RequireForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = super::pages::load_org(&db, &user, &org)?;
        if !org.can(crate::rbac::Permission::ManageMembers) {
            return Err(AppError::Forbidden);
        }
        if db.org_requires_mfa(org.id)? != form.required() {
            // Whoever turns it on must pass it, or they would close the organization on themselves
            if form.required() && db.has_password(user.id)? && !db.has_second_factor(user.id)? {
                return Err(AppError::Bad("Set up two-step sign-in for your own account first (Settings → Two-step sign-in).".into()));
            }
            db.set_org_requires_mfa(org.id, form.required())?;
            let detail = format!("organization {}: {}", org.name, if form.required() { "required" } else { "not required" });
            db.log_security_event(&Actor::user(user.id, &user.username), None, "mfa_requirement", Some(&detail))?;
        }
        Ok(redirect(format!("/orgs/{}", enc(&org.name))))
    })
}
