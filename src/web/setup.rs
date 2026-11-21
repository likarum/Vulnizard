//! First-run setup: while no account exists, `/setup` creates the
//! administrator for whoever holds the one-time setup code (printed in the
//! server log and by `vulnizard setup-code`). The code is new at every start
//! of the server. Once an account exists the setup page is gone for good.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use super::pages::{hash_new_password, session_cookie, ActionResult};
use super::views::page;
use super::{blocking, AppError, AppState, ClientAddr, St, SESSION_TTL_SECS};
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
                    "The code is in the log of the server, written when it last started (it changes at every start), and "
                    code { "vulnizard setup-code" } " prints it. It proves you have access to the server."
                }
                label { "Administrator username" input type="text" name="username" required autocomplete="username" value=(username); }
                label { "Email (optional)" input type="email" name="email" autocomplete="email"; }
                p.muted {
                    "Used for notifications only. There is no password reset by email: a lost password is reset by another administrator, or with "
                    code { "vulnizard user passwd <name>" } " on the server."
                }
                label { "Password" input type="password" name="password" required autocomplete="new-password"; }
                label { "Password, again" input type="password" name="confirm" required autocomplete="new-password"; }
                p.muted { (auth::PASSWORD_RULES) }
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
        if let Err(why) = auth::check_new_password(&form.password, username) {
            return fail(StatusCode::BAD_REQUEST, &why);
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
            Redirect::to("/"),
        )
            .into_response())
    })
}

/// At the start of the server, an instance without accounts gets a new setup
/// code, and the log tells how to use it
pub fn announce(state: &AppState) {
    let code = match state.db().map_err(|_| ()).and_then(|db| db.renew_setup_code().map_err(|_| ())) {
        Ok(Some(code)) => code,
        _ => return,
    };
    tracing::info!(
        "no account yet: open {}/setup and enter the setup code {code} to create the administrator \
         (or run 'vulnizard user create <name> --admin')",
        state.config.web.base_url.trim_end_matches('/')
    );
}
