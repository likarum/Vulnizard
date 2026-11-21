//! First-run setup: while no account exists, `/setup` creates the
//! administrator for whoever holds the one-time setup code (printed in the
//! server log and by `vulnizard setup-code`). `/welcome` then lists what an
//! administrator may want to do next. Once an account exists the setup page
//! is gone for good.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use super::admin::require_admin;
use super::pages::{hash_new_password, session_cookie, ActionResult, HtmlResult};
use super::views::page;
use super::{blocking, AppError, AppState, ClientAddr, St, User, SESSION_TTL_SECS};
use crate::auth;
use crate::db::{Actor, SetupClosed};

fn form_page(error: Option<&str>, username: &str) -> Markup {
    page(
        "Set up this instance",
        None,
        html! {
            h1 { "Welcome to Vulnizard" }
            p { "This instance has no account yet. Create its administrator to start." }
            @if let Some(e) = error { p.error { (e) } }
            form.stack.card method="post" action="/setup" {
                label {
                    "Setup code"
                    input type="text" name="code" required autofocus autocomplete="off" autocapitalize="characters"
                        spellcheck="false" placeholder="XXXXX-XXXXX-XXXXX-XXXXX";
                }
                p.muted {
                    "The code is in the log of the server, written when it started, and "
                    code { "vulnizard setup-code" } " prints it. It proves you have access to the server."
                }
                label { "Administrator username" input type="text" name="username" required autocomplete="username" value=(username); }
                label { "Email (optional)" input type="email" name="email" autocomplete="email"; }
                label { "Password" input type="password" name="password" required autocomplete="new-password"; }
                label { "Password, again" input type="password" name="confirm" required autocomplete="new-password"; }
                p.muted { "At least " (auth::MIN_PASSWORD_LEN) " characters." }
                button type="submit" { "Create the administrator" }
            }
            p.muted {
                "Automated deployment? " code { "vulnizard user create <name> --admin" } " does the same from the command line."
            }
        },
    )
}

pub async fn form(State(st): St) -> ActionResult {
    blocking(|| {
        if !st.db()?.setup_is_open()? {
            return Ok(Redirect::to("/login").into_response());
        }
        Ok(form_page(None, "").into_response())
    })
}

#[derive(Deserialize)]
pub struct SetupForm {
    code: String,
    username: String,
    #[serde(default)]
    email: String,
    password: String,
    confirm: String,
}

fn throttle_key(client: &str) -> String {
    format!("setup:{client}")
}

pub async fn submit(State(st): St, ClientAddr(client): ClientAddr, Form(form): Form<SetupForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        // Once set up, the page does not exist
        if !db.setup_is_open()? {
            return Err(AppError::NotFound);
        }
        let key = throttle_key(&client);
        if st.login_guard.is_locked(&key) {
            return Err(AppError::TooMany);
        }
        let username = form.username.trim();
        let fail = |status: StatusCode, msg: &str| -> ActionResult { Ok((status, form_page(Some(msg), username)).into_response()) };
        // The code first: nothing else is told to who does not have it
        if !db.setup_code_matches(&form.code)? {
            st.login_guard.record(&key, false);
            return fail(StatusCode::UNAUTHORIZED, "Wrong setup code.");
        }
        if !auth::valid_slug(username, 3, 32) || auth::is_reserved_username(username) {
            return fail(StatusCode::BAD_REQUEST, "Username: 3 to 32 letters, digits, '-', '_' or '.'.");
        }
        if form.password != form.confirm {
            return fail(StatusCode::BAD_REQUEST, "The two passwords differ.");
        }
        if form.password.chars().count() < auth::MIN_PASSWORD_LEN {
            return fail(StatusCode::BAD_REQUEST, "Password is too short.");
        }
        if form.password.len() > auth::MAX_PASSWORD_LEN {
            return fail(StatusCode::BAD_REQUEST, "Password is too long.");
        }
        let email = Some(form.email.trim()).filter(|e| !e.is_empty());
        if email.is_some_and(|e| e.parse::<lettre::Address>().is_err()) {
            return fail(StatusCode::BAD_REQUEST, "Invalid email address.");
        }
        let hash = hash_new_password(&st, &form.password)?;
        let id = match db.create_first_administrator(username, email, &hash) {
            Ok(id) => id,
            // Someone else finished the setup in the meantime
            Err(e) if e.downcast_ref::<SetupClosed>().is_some() => return Err(AppError::NotFound),
            Err(e) => return Err(e.into()),
        };
        st.login_guard.record(&key, true);
        db.log_security_event(&Actor::user(id, username), Some(id), "instance_set_up", Some(&format!("from {client}")))?;
        tracing::info!("instance set up: administrator '{username}' created from {client}");
        let (token, token_hash) = auth::new_token();
        db.create_session(id, &token_hash, SESSION_TTL_SECS)?;
        Ok((
            [(header::SET_COOKIE, session_cookie(&st, &token, SESSION_TTL_SECS))],
            Redirect::to("/welcome"),
        )
            .into_response())
    })
}

/// What an administrator may want to do after the setup; nothing is required
pub async fn welcome(State(st): St, User(user): User) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let synced = db.last_sync_runs()?.iter().any(|r| r.status == "completed");
        let providers = db.list_sso_providers()?.len();
        let scim_tokens = db.list_scim_tokens()?.len();
        let mfa_required = db.instance_requires_mfa()?;
        let own_factor = db.mfa_status(user.id)?.enrolled();
        let step = |done: bool, title: &str, text: &str, href: &str, action: &str| -> Markup {
            html! {
                div.card {
                    h3 { @if done { span.tag { "done" } " " } (title) }
                    p { (text) }
                    p { a.button href=(href) { (action) } }
                }
            }
        };
        Ok(page(
            "Welcome",
            Some(&user),
            html! {
                h1 { "Welcome, " (user.username) }
                p { "The instance is set up and you are its administrator. Everything below is optional and can be done later from " a href="/admin" { "Admin" } "." }
                (step(synced, "Vulnerability data",
                    "The first synchronization downloads the CVE database. It runs in the background and takes a while the first time.",
                    "/admin/sources", "Sources and synchronization"))
                (step(own_factor, "Protect your own account",
                    "Add an authenticator app or a passkey to the administrator account.",
                    "/settings/mfa", "Two-step sign-in"))
                (step(mfa_required, "Require two-step sign-in",
                    "Ask every account that signs in with a password to set up a second step.",
                    "/admin/users", "Accounts and requirement"))
                (step(providers > 0, "Single sign-on",
                    "Declare an OpenID Connect provider, and choose whether accounts are created at first sign-in.",
                    "/admin/sso", "Single sign-on"))
                (step(scim_tokens > 0, "Provisioning",
                    "Create a SCIM token so that your directory creates, updates and disables accounts.",
                    "/admin/sso", "Provisioning tokens"))
                (step(false, "Track something",
                    "Create a project, add the applications you run, and subscribe to vendors or products.",
                    "/product", "My products"))
                p.muted { "This page stays at " a href="/welcome" { "/welcome" } "." }
            },
        ))
    })
}

/// Tells in the log how to set up an instance that has no account yet
pub fn announce(state: &AppState) {
    let code = match state.db().map_err(|_| ()).and_then(|db| db.setup_code().map_err(|_| ())) {
        Ok(Some(code)) => code,
        _ => return,
    };
    tracing::info!(
        "no account yet: open {}/setup and enter the setup code {code} to create the administrator \
         (or run 'vulnizard user create <name> --admin')",
        state.config.web.base_url.trim_end_matches('/')
    );
}
