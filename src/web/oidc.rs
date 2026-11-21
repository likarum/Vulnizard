//! Single sign-on with OpenID Connect: authorization code flow with PKCE.
//!
//! ID token validation: the token is obtained directly from the provider's
//! token endpoint over TLS, authenticated with the client secret. In that
//! case OpenID Connect Core (§3.1.3.7, rule 6) allows relying on the TLS
//! server validation instead of checking the token signature. Issuer,
//! audience, expiry and nonce are always verified. This is why the issuer
//! must be an `https` URL (plain `http` is accepted for loopback only).

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::header::{self, HeaderValue};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::pages::{auth_page, start_session_for};
use super::SSO_SESSION_TTL_SECS;
use super::{blocking, AppError, AppState, St};
use crate::auth;
use crate::db::Provider;
use crate::db::Database;

/// With `__Host-` (secure contexts) the cookie cannot be planted by a sibling subdomain
const STATE_COOKIE: &str = "vz_oidc";
const SECURE_STATE_COOKIE: &str = "__Host-vz_oidc";
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);
const STATE_TTL_SECS: i64 = 600;

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("vulnizard/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// `https` everywhere, `http` only towards the local machine
fn check_endpoint(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).with_context(|| format!("invalid URL: {raw}"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => bail!("OIDC endpoints must use https: {raw}"),
    }
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Provider metadata, fetched once and cached
/// Every provider a user may sign in with: the one of the configuration
/// file, then those declared in the administration UI.
pub fn enabled_providers(st: &AppState, db: &Database) -> Result<Vec<Provider>> {
    let mut providers: Vec<Provider> = st.config.oidc.iter().map(Provider::from_config).collect();
    providers.extend(db.list_sso_providers()?.into_iter().filter(|p| p.enabled));
    Ok(providers)
}

fn find_provider(st: &AppState, slug: &str) -> Result<Option<Provider>, AppError> {
    blocking(|| {
        let db = st.db()?;
        Ok(enabled_providers(st, &db)?.into_iter().find(|p| p.slug == slug))
    })
}

/// Provider metadata, fetched once per provider and cached
async fn discovery(st: &AppState, provider: &Provider) -> Result<Discovery> {
    // The issuer is part of the key: editing a provider never reuses stale metadata
    let key = format!("{} {}", provider.slug, provider.issuer);
    if let Some(cached) = st.oidc_discovery.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(cached.clone());
    }
    // A provider that is down is not hammered by every login attempt
    if let Some(until) = st.oidc_retry_after.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        if std::time::Instant::now() < *until {
            bail!("provider metadata unavailable (retrying shortly)");
        }
    }
    let fetched = fetch_discovery(&provider.issuer).await;
    if fetched.is_err() {
        st.oidc_retry_after
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone(), std::time::Instant::now() + DISCOVERY_RETRY);
    }
    let doc = fetched?;
    st.oidc_discovery.lock().unwrap_or_else(|e| e.into_inner()).insert(key, doc.clone());
    Ok(doc)
}

/// Checks that an issuer URL is acceptable (used when a provider is saved)
pub fn check_issuer(issuer: &str) -> Result<()> {
    check_endpoint(issuer).map(|_| ())
}

async fn fetch_discovery(configured_issuer: &str) -> Result<Discovery> {
    let issuer = check_endpoint(configured_issuer)?;
    let url = format!("{}/.well-known/openid-configuration", issuer.as_str().trim_end_matches('/'));
    let doc: Discovery = http_client()?
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| anyhow!("cannot fetch the provider metadata: {}", e.without_url()))?
        .json()
        .await
        .context("invalid provider metadata")?;
    if !same_issuer(&doc.issuer, configured_issuer) {
        bail!("provider metadata issuer does not match the configured issuer");
    }
    check_endpoint(&doc.authorization_endpoint)?;
    // Endpoints the server itself calls: a self-hosted provider may live on a
    // private network, but its metadata cannot point the server at another
    // internal host.
    for endpoint in std::iter::once(&doc.token_endpoint).chain(doc.userinfo_endpoint.iter()) {
        let url = check_endpoint(endpoint)?;
        let same_host = url.host_str() == issuer.host_str();
        if !same_host {
            let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
            let port = url.port_or_known_default().unwrap_or(443);
            let internal = tokio::task::spawn_blocking(move || crate::notify::resolves_to_internal(&host, port))
                .await
                .unwrap_or(true);
            if internal {
                bail!("provider metadata points to an internal host other than the issuer");
            }
        }
    }
    Ok(doc)
}

/// Redirect URI to register at the provider
pub fn redirect_uri(st: &AppState, slug: &str) -> String {
    format!(
        "{}/auth/oidc/{}/callback",
        st.config.web.base_url.trim_end_matches('/'),
        slug
    )
}

fn state_cookie_name(st: &AppState) -> &'static str {
    if st.secure_cookies() {
        SECURE_STATE_COOKIE
    } else {
        STATE_COOKIE
    }
}

fn state_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        state_cookie_name(st),
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

/// (slug, label) of the providers shown on the login page
pub fn login_buttons(st: &AppState) -> Vec<(String, String)> {
    blocking(|| {
        st.db()
            .ok()
            .and_then(|db| enabled_providers(st, &db).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.slug, p.name))
            .collect()
    })
}

fn login_error(st: &AppState, message: &str) -> Response {
    let mut resp = (
        StatusCode::BAD_REQUEST,
        auth_page("Log in", Some(message), false, false, &login_buttons(st), super::mfa::passkeys_available(st)),
    )
        .into_response();
    if let Ok(cookie) = HeaderValue::from_str(&state_cookie(st, "", 0)) {
        resp.headers_mut().append(header::SET_COOKIE, cookie);
    }
    resp
}

/// Starts the login: redirects the browser to the identity provider
pub async fn login(
    State(st): St,
    super::ClientAddr(client): super::ClientAddr,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let Some(provider) = find_provider(&st, &slug)? else {
        return Err(AppError::NotFound);
    };
    super::count_start(&st, &client)?;
    let config = &provider;
    let doc = match discovery(&st, config).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::warn!("SSO unavailable: {e:#}");
            return Ok(login_error(&st, "Single sign-on is unavailable, try again later."));
        }
    };

    let (state, state_hash) = auth::new_token();
    let (nonce, _) = auth::new_token();
    let (verifier, _) = auth::new_token();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let saved = blocking(|| -> Result<()> {
        Database::connect(&st.db_path)?.save_oidc_state(&provider.slug, &state_hash, &verifier, &nonce, STATE_TTL_SECS)
    });
    if let Err(e) = saved {
        tracing::warn!("SSO login not started: {e:#}");
        return Ok(login_error(&st, "Single sign-on is busy, try again in a moment."));
    }

    let mut url = url::Url::parse(&doc.authorization_endpoint).map_err(|e| AppError::Internal(e.into()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri(&st, &provider.slug))
        .append_pair("scope", &config.scopes)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    Ok((
        [(header::SET_COOKIE, state_cookie(&st, &state, STATE_TTL_SECS))],
        Redirect::to(url.as_str()),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

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

/// Identity asserted by the provider
struct Identity {
    /// Storage key: issuer + subject
    key: String,
    subject: String,
    /// The provider vouches for the email address
    email_verified: bool,
    username: Option<String>,
    email: Option<String>,
    groups: Vec<String>,
}

fn claim_str(claims: &Value, key: &str) -> Option<String> {
    claims.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

/// Decodes and validates the ID token claims (see the module documentation)
fn validate_id_token(id_token: &str, issuer: &str, client_id: &str, nonce: &str) -> Result<Value> {
    let payload = id_token.split('.').nth(1).ok_or_else(|| anyhow!("malformed ID token"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("malformed ID token")?;
    let claims: Value = serde_json::from_slice(&bytes).context("malformed ID token")?;

    if !claim_str(&claims, "iss").is_some_and(|iss| same_issuer(&iss, issuer)) {
        bail!("ID token issuer mismatch");
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|a| a.as_str() == Some(client_id))
                // Several audiences: the authorized party must be us
                && (list.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => false,
    };
    if !audience_ok {
        bail!("ID token audience mismatch");
    }
    let now = chrono::Utc::now().timestamp();
    if !claims.get("exp").and_then(Value::as_i64).is_some_and(|exp| exp > now - 60) {
        bail!("ID token expired");
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        bail!("ID token nonce mismatch");
    }
    if claim_str(&claims, "sub").is_none() {
        bail!("ID token has no subject");
    }
    Ok(claims)
}

async fn fetch_identity(
    st: &AppState,
    config: &Provider,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> Result<Identity> {
    let doc = discovery(st, config).await?;
    let client = http_client()?;
    let tokens: Value = client
        .post(&doc.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri(st, &config.slug)),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| anyhow!("token request failed: {}", e.without_url()))?
        .json()
        .await
        .context("invalid token response")?;

    let id_token = tokens.get("id_token").and_then(Value::as_str).ok_or_else(|| anyhow!("no ID token"))?;
    let mut claims = validate_id_token(id_token, &doc.issuer, &config.client_id, nonce)?;
    let subject = claim_str(&claims, "sub").ok_or_else(|| anyhow!("no subject"))?;

    // UserInfo completes the claims; its subject must match the ID token
    if let (Some(endpoint), Some(access_token)) =
        (&doc.userinfo_endpoint, tokens.get("access_token").and_then(Value::as_str))
    {
        let userinfo: Value = client
            .get(endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| anyhow!("userinfo request failed: {}", e.without_url()))?
            .json()
            .await
            .context("invalid userinfo response")?;
        if claim_str(&userinfo, "sub").as_deref() != Some(subject.as_str()) {
            bail!("userinfo subject mismatch");
        }
        if let (Some(target), Some(source)) = (claims.as_object_mut(), userinfo.as_object()) {
            for (key, value) in source {
                target.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }

    Ok(Identity {
        // Accounts are bound to the issuer and the subject together
        key: format!("{} {}", doc.issuer.trim_end_matches('/'), subject),
        email_verified: match claims.get("email_verified") {
            Some(Value::Bool(verified)) => *verified,
            Some(Value::String(verified)) => verified == "true",
            _ => false,
        },
        username: claim_str(&claims, "preferred_username"),
        email: claim_str(&claims, "email"),
        groups: claims
            .get("groups")
            .and_then(Value::as_array)
            .map(|g| g.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        subject,
    })
}

/// Local username derived from the provider's claims
fn local_username(identity: &Identity) -> String {
    // An unverified email is not an identity: it is never used to name the account
    let source = identity
        .username
        .clone()
        .or_else(|| {
            identity
                .email
                .as_deref()
                .filter(|_| identity.email_verified)
                .and_then(|e| e.split('@').next())
                .map(String::from)
        })
        .unwrap_or_default();
    let slug: String = source
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .take(32)
        .collect();
    let slug = slug.trim_matches(|c| c == '-' || c == '.').to_string();
    if auth::valid_slug(&slug, 3, 32) && !auth::is_reserved_username(&slug) {
        slug
    } else {
        format!("user-{}", &auth::hash_token(&identity.subject)[..8])
    }
}

/// Finds, links or creates the local account of an identity
/// Domain restriction: with allowed domains, only a verified email of one of
/// them may sign in (indispensable for public providers such as Google).
fn domain_allowed(provider: &Provider, identity: &Identity) -> bool {
    if provider.allowed_domains.is_empty() {
        return true;
    }
    identity.email_verified
        && identity
            .email
            .as_deref()
            .and_then(|e| e.rsplit_once('@'))
            .is_some_and(|(_, domain)| provider.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
}

fn resolve_account(st: &AppState, config: &Provider, identity: &Identity) -> Result<crate::db::Account, String> {
    use crate::db::Scope;

    if !domain_allowed(config, identity) {
        return Err("Your email address is not allowed to sign in with this provider.".into());
    }
    let internal = |e: anyhow::Error| {
        tracing::error!("SSO account resolution failed: {e:#}");
        "Internal error during sign-in.".to_string()
    };
    let db = st.db().map_err(|_| "Internal error during sign-in.".to_string())?;
    // Only an instance provider can make administrators
    let is_admin = config
        .admin_group
        .as_ref()
        .filter(|_| config.scope == Scope::Instance)
        .map(|group| identity.groups.iter().any(|g| g == group));
    let username = local_username(identity);
    let exact_name = identity.username.as_deref().filter(|u| auth::valid_slug(u, 3, 32));

    let mut found = db.find_oidc_account(&identity.key).map_err(internal)?;
    // An account provisioned by SCIM for this very scope, under exactly this
    // name, is the same person: the provider vouches for it
    // Never through a public provider, where anybody chooses their name
    if found.is_none() && !super::admin::is_public_issuer(&config.issuer) {
        // Names the provider vouches for: its username, and its verified email
        let mut names: Vec<&str> = identity.username.as_deref().into_iter().collect();
        if identity.email_verified {
            names.extend(identity.email.as_deref());
        }
        if let Some(id) = db.find_provisioned_account(config.scope, &names).map_err(internal)? {
            db.set_oidc_subject(id, &identity.key).map_err(internal)?;
            found = db.find_oidc_account(&identity.key).map_err(internal)?;
        }
    }
    if found.is_none() && config.link_existing_accounts {
        // Only an exact `preferred_username` links: no email fallback, no rewriting
        if let Some(exact) = exact_name {
            found = db.link_oidc_account(exact, &identity.key, config.scope).map_err(internal)?;
        }
    }
    let account = match found {
        Some((_, true)) => return Err("This account is disabled.".into()),
        Some((account, false)) => {
            // An account can only use the providers of where it belongs
            let origin = db.user_origin(account.id).map_err(internal)?;
            if !db.scope_contains(config.scope, origin).map_err(internal)? {
                return Err("This account cannot sign in with this provider.".into());
            }
            account
        }
        None if config.auto_create => {
            // The account belongs to what the provider belongs to
            match db.create_oidc_account(&username, identity.email.as_deref(), &identity.key, is_admin.unwrap_or(false), config.scope) {
                Ok(id) => {
                    db.get_account(id).map_err(internal)?.ok_or("Internal error during sign-in.")?
                }
                Err(e) if e.to_string() == "Username already taken" => {
                    return Err(format!(
                        "A local account named “{username}” already exists and is not linked to your identity. Ask an administrator."
                    ))
                }
                Err(e) => return Err(internal(e)),
            }
        }
        None => return Err("No account exists for your identity. Ask an administrator.".into()),
    };
    // Only an account of the instance can be an administrator
    let instance_account = db.user_origin(account.id).map_err(internal)? == Scope::Instance;
    if let Some(is_admin) = is_admin.filter(|_| instance_account) {
        db.sync_admin_flag(account.id, is_admin).map_err(internal)?;
    }
    // Default role of the provider, where it belongs, if the account has no right there yet
    if let Some(role) = config.default_role.as_deref().and_then(crate::rbac::Role::parse) {
        let grant = || -> anyhow::Result<()> {
            if !db.may_hold_right(account.id, config.scope)? {
                return Ok(());
            }
            match config.scope {
                Scope::Instance => {
                    if db.user_assignments(account.id)?.is_empty() {
                        db.set_instance_role(account.id, Some(role))?;
                    }
                }
                Scope::Organization(org) => {
                    if !db.list_orgs(account.id)?.iter().any(|o| o.id == org) {
                        db.set_org_member(org, account.id, role)?;
                    }
                }
                Scope::Project(project) => {
                    if db.project_role(account.id, project)?.is_none() {
                        db.set_project_member(project, account.id, role)?;
                    }
                }
            }
            Ok(())
        };
        grant().map_err(internal)?;
    }
    Ok(account)
}

/// Return from the identity provider
pub async fn callback(
    State(st): St,
    Path(slug): Path<String>,
    Query(q): Query<CallbackQuery>,
    parts: Parts,
) -> Result<Response, AppError> {
    let Some(provider) = find_provider(&st, &slug)? else {
        return Err(AppError::NotFound);
    };
    let config = &provider;
    if q.error.is_some() {
        return Ok(login_error(&st, "Sign-in was refused by the identity provider."));
    }
    let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return Ok(login_error(&st, "Invalid sign-in response."));
    };
    // The state must be the one this browser started with (login CSRF)
    if cookie_value(&parts, state_cookie_name(&st)).as_deref() != Some(state) {
        return Ok(login_error(&st, "Sign-in session expired, try again."));
    }
    let pending = blocking(|| st.db()?.take_oidc_state(&provider.slug, &auth::hash_token(state)).map_err(AppError::from))?;
    let Some((verifier, nonce)) = pending else {
        return Ok(login_error(&st, "Sign-in session expired, try again."));
    };

    let identity = match fetch_identity(&st, config, code, &verifier, &nonce).await {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!("SSO sign-in failed: {e:#}");
            return Ok(login_error(&st, "Sign-in failed at the identity provider."));
        }
    };

    blocking(|| {
        let account = match resolve_account(&st, config, &identity) {
            Ok(account) => account,
            Err(message) => return Ok(login_error(&st, &message)),
        };
        let mut resp = start_session_for(&st, &st.db()?, account.id, SSO_SESSION_TTL_SECS)?;
        if let Ok(cookie) = HeaderValue::from_str(&state_cookie(&st, "", 0)) {
            resp.headers_mut().append(header::SET_COOKIE, cookie);
        }
        Ok(resp)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(claims: Value) -> String {
        let enc = |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        format!("{}.{}.sig", enc(&serde_json::json!({ "alg": "RS256" })), enc(&claims))
    }

    fn claims() -> Value {
        serde_json::json!({
            "iss": "https://id.example.org", "aud": "vulnizard", "sub": "u1",
            "nonce": "n1", "exp": chrono::Utc::now().timestamp() + 300,
        })
    }

    fn check(c: Value) -> Result<Value> {
        validate_id_token(&token(c), "https://id.example.org/", "vulnizard", "n1")
    }

    #[test]
    fn id_token_claims_are_validated() {
        assert!(check(claims()).is_ok());
        for (key, bad) in [
            ("iss", serde_json::json!("https://evil.example.org")),
            ("aud", serde_json::json!("other-client")),
            ("aud", serde_json::json!(["vulnizard", "other"])), // no azp
            ("nonce", serde_json::json!("replayed")),
            ("exp", serde_json::json!(chrono::Utc::now().timestamp() - 3600)),
            ("sub", serde_json::json!("")),
        ] {
            let mut c = claims();
            c[key] = bad;
            assert!(check(c).is_err(), "{key} should be rejected");
        }
        let mut multi = claims();
        multi["aud"] = serde_json::json!(["vulnizard", "other"]);
        multi["azp"] = serde_json::json!("vulnizard");
        assert!(check(multi).is_ok());
        assert!(validate_id_token("garbage", "https://id.example.org", "vulnizard", "n1").is_err());
    }

    #[test]
    fn endpoints_require_https_except_loopback() {
        assert!(check_endpoint("https://id.example.org/authorize").is_ok());
        assert!(check_endpoint("http://127.0.0.1:9000/token").is_ok());
        assert!(check_endpoint("http://localhost:9000/token").is_ok());
        assert!(check_endpoint("http://id.example.org/token").is_err());
        assert!(check_endpoint("http://localhost.evil.example/token").is_err());
        assert!(check_endpoint("ftp://id.example.org/").is_err());
    }

    #[test]
    fn usernames_are_derived_safely() {
        let id = |username: Option<&str>, email: Option<&str>| Identity {
            key: "https://id.example.org subject-1".into(),
            subject: "subject-1".into(),
            email_verified: true,
            username: username.map(String::from),
            email: email.map(String::from),
            groups: vec![],
        };
        assert_eq!(local_username(&id(Some("Mehdi B"), None)), "mehdi-b");
        assert_eq!(local_username(&id(None, Some("jane.doe@example.org"))), "jane.doe");
        assert_eq!(local_username(&id(Some("../x"), None)), "user-".to_string() + &auth::hash_token("subject-1")[..8]);
        assert!(local_username(&id(None, None)).starts_with("user-"));
        // Names of automatic actors of the audit trail are never given to an account
        assert!(local_username(&id(Some("System"), None)).starts_with("user-"));
        // An unverified email never names the account
        let mut unverified = id(None, Some("root@example.org"));
        unverified.email_verified = false;
        assert!(local_username(&unverified).starts_with("user-"));
    }

    #[test]
    fn domain_restriction_needs_a_verified_email() {
        let provider = |domains: &[&str]| Provider {
            slug: "p".into(),
            name: "P".into(),
            issuer: "https://id.example.org".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
            scopes: "openid".into(),
            auto_create: true,
            link_existing_accounts: false,
            admin_group: None,
            allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
            enabled: true,
            from_config: false,
            scope: crate::db::Scope::Instance,
            scope_label: String::new(),
            default_role: None,
        };
        let id = |email: Option<&str>, verified: bool| Identity {
            key: "k".into(),
            subject: "s".into(),
            email_verified: verified,
            username: None,
            email: email.map(String::from),
            groups: vec![],
        };
        let corp = provider(&["corp.example"]);
        assert!(domain_allowed(&corp, &id(Some("a@Corp.Example"), true)));
        assert!(!domain_allowed(&corp, &id(Some("a@corp.example"), false)));
        assert!(!domain_allowed(&corp, &id(Some("a@gmail.com"), true)));
        assert!(!domain_allowed(&corp, &id(Some("a@corp.example@gmail.com"), true)));
        assert!(!domain_allowed(&corp, &id(Some("a@evilcorp.example"), true)));
        assert!(!domain_allowed(&corp, &id(None, true)));
        assert!(domain_allowed(&provider(&[]), &id(None, false)));
    }
}
