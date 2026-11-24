//! Instance administration: status, sync, user management.

use axum::extract::{Form, Path, Query, State};
use maud::html;
use serde::Deserialize;

use super::pages::{hash_new_password, redirect, ActionResult, HtmlResult};
use super::views::{self, layout, Nav};
use super::{blocking, AppError, St, User};
use crate::auth;
use crate::db::{normalize_domains, Account, Provider, CONFIG_PROVIDER};
use crate::settings;

pub(super) fn require_admin(user: &Account) -> Result<(), AppError> {
    if user.is_admin {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) fn admin_tabs(active: &str) -> maud::Markup {
    views::tabs(&[
        ("/admin", "Status", active == "status"),
        ("/admin/sources", "Vulnerability sources", active == "sources"),
        ("/admin/notifications", "Notifications", active == "notifications"),
        ("/admin/deadlines", "Deadlines", active == "deadlines"),
        ("/admin/mcp", "MCP", active == "mcp"),
        ("/admin/users", "Users", active == "users"),
        ("/admin/sso", "Single sign-on", active == "sso"),
        ("/admin/security", "Security log", active == "security"),
    ])
}

pub async fn admin(State(st): St, User(user): User) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let stats = db.stats()?;
        let mut syncs = db.recent_syncs(200)?;
        let sync_total = syncs.len();
        let listing = views::Listing::from_page("started", true);
        listing.apply(
            &mut syncs,
            |r| format!("{} {} {}", r.source, r.status, r.error.as_deref().unwrap_or("")),
            |r, column| match column {
                "source" => Some(views::SortKey::text(&r.source)),
                "started" => Some(views::SortKey::text(&r.started_at)),
                "status" => Some(views::SortKey::text(&r.status)),
                "added" => Some(views::SortKey::num(r.added as f64)),
                "updated" => Some(views::SortKey::num(r.updated as f64)),
                "unchanged" => Some(views::SortKey::num(r.same as f64)),
                _ => None,
            },
        );
        let providers = super::oidc::enabled_providers(&st, &db)?;
        let config = st.effective_config(&db)?;
        let interval = config.web.sync_interval_minutes;
        Ok(layout(
            Nav::Admin,
            "Admin",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("status"))
                div.card {
                    dl.meta {
                        dt { "CVE entries" } dd { (stats.total_cves) }
                        dt { "With CVSS" } dd { (stats.with_cvss) }
                        dt { "With EPSS" } dd { (stats.with_epss) }
                        dt { "Known exploited (KEV)" } dd { (stats.kev_count) }
                        dt { "Critical (CVSS ≥ 9)" } dd { (stats.critical_count) }
                        dt { "Background sync" }
                        dd { @if interval > 0 { "every " (interval) " min" } @else { "disabled" } }
                        dt { "Sources" } dd { (config.sync.sources.join(", ")) " · " a href="/admin/sources" { "manage" } }
                        dt { "Single sign-on" }
                        dd {
                            @if providers.is_empty() { "not configured" } @else {
                                (providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "))
                            }
                            " · " a href="/admin/sso" { "manage" }
                        }
                        dt { "Self-registration" }
                        dd { @if st.config.web.allow_registration { "open" } @else { "closed" } }
                        dt { "Key of stored secrets" }
                        dd {
                            code { (crate::secrets::key_path(&st.db_path).display()) }
                            " " span.muted { "— back it up apart from the database (" code { "vulnizard key export" } ")" }
                        }
                    }
                }
                h2 { "Recent syncs" }
                (listing.filter_box("Filter: source, status, error…", syncs.len(), sync_total))
                div.scroll {
                    table.list.fit.dense {
                        (views::columns("kind when when kind num num num -", true))
                        thead {
                            tr {
                                (listing.th("source", "Source")) (listing.th("started", "Started (UTC)")) th { "Completed" }
                                (listing.th("status", "Status")) (listing.th("added", "Added")) (listing.th("updated", "Updated")) (listing.th("unchanged", "Unchanged"))
                                th { "Error" }
                            }
                        }
                        tbody {
                            @for s in &syncs {
                                tr {
                                    td { (s.source) }
                                    td.nowrap { (s.started_at) }
                                    td.nowrap { (s.completed_at.as_deref().unwrap_or("—")) }
                                    td { (s.status) }
                                    td { (s.added) }
                                    td { (s.updated) }
                                    td { (s.same) }
                                    td { (s.error.as_deref().unwrap_or("")) }
                                }
                            }
                            @if syncs.is_empty() { tr { td colspan="8" .muted { "No sync yet." } } }
                        }
                    }
                }
            },
        ))
    })
}

#[derive(Deserialize, Default)]
pub struct SyncForm {
    #[serde(default)]
    back: String,
}

/// Starts a sync cycle now (button of the page header)
pub async fn sync_now(State(st): St, User(user): User, Form(form): Form<SyncForm>) -> ActionResult {
    require_admin(&user)?;
    // A request for sources that just ran or are already waiting is simply not repeated:
    // the header shows the state of the synchronization either way
    let asked = blocking(|| -> Result<Result<Vec<String>, String>, AppError> { Ok(st.request_sync(&st.db()?, None, user.id)) })?;
    if let Err(reason) = asked {
        if reason.contains("scheduler") {
            return Err(AppError::Internal(anyhow::anyhow!("scheduler is not running")));
        }
    }
    // Back to the page the button was on (local paths only)
    let back = form.back.as_str();
    let local = back.starts_with('/')
        && !back.starts_with("//")
        && !back.contains('\\')
        && !back.chars().any(|c| c.is_control());
    Ok(redirect(if local { back.to_string() } else { "/admin".into() }))
}

// ==========================================
// Users and their rights
// ==========================================

#[derive(Deserialize, Default)]
pub struct UsersQuery {
    /// Shows the creation form
    new: Option<String>,
}

/// Choices of the "where" selector of a right: (value, label)
fn scope_choices(db: &crate::db::Database) -> Result<Vec<(String, String)>, AppError> {
    let mut choices = vec![("instance".to_string(), "Whole instance (every organization and project)".to_string())];
    for (_, org) in db.list_all_orgs()? {
        choices.push((format!("organization:{org}"), format!("Organization {org} (all its projects)")));
    }
    for p in db.list_all_projects()? {
        choices.push((format!("project:{}/{}", p.org, p.name), format!("Project {} / {}", p.org, p.name)));
    }
    Ok(choices)
}

/// Gives, changes or removes (`role` = None) a right at one of the three levels.
/// `scope` is a value of [`scope_choices`].
fn apply_right(db: &crate::db::Database, user_id: i64, scope: &str, role: Option<crate::rbac::Role>) -> Result<(), AppError> {
    use crate::db::Scope;
    let bad = || AppError::Bad("Unknown organization or project.".into());
    // An account coming from a project or an organization never gets a right outside it
    let outside = || AppError::Bad("This account can only hold rights inside the project or organization it comes from.".into());
    let allowed = |target: Scope| -> Result<(), AppError> {
        if role.is_some() && !db.may_hold_right(user_id, target)? {
            return Err(outside());
        }
        Ok(())
    };
    if scope == "instance" {
        allowed(Scope::Instance)?;
        db.set_instance_role(user_id, role).map_err(AppError::bad)?;
    } else if let Some(org) = scope.strip_prefix("organization:") {
        let (org_id, _) = db.list_all_orgs()?.into_iter().find(|(_, name)| name == org).ok_or_else(bad)?;
        allowed(Scope::Organization(org_id))?;
        match role {
            Some(role) => db.set_org_member(org_id, user_id, role)?,
            None => {
                db.remove_org_member(org_id, user_id)?;
            }
        }
    } else if let Some((org, project)) = scope.strip_prefix("project:").and_then(|p| p.split_once('/')) {
        let project_id = db.find_project(org, project)?.ok_or_else(bad)?;
        allowed(Scope::Project(project_id))?;
        match role {
            Some(role) => db.set_project_member(project_id, user_id, role)?,
            None => {
                db.remove_project_member(project_id, user_id)?;
            }
        }
    } else {
        return Err(bad());
    }
    Ok(())
}

fn scope_select(choices: &[(String, String)], with_none: bool) -> maud::Markup {
    html! {
        select name="scope" {
            @if with_none { option value="" { "— no right for now —" } }
            @for (value, label) in choices { option value=(value) { (label) } }
        }
    }
}

fn role_select(with_remove: bool) -> maud::Markup {
    html! {
        select name="role" {
            @for role in crate::rbac::Role::ALL.iter().rev() {
                option value=(role.as_str()) { (role.as_str()) " — " (role.description()) }
            }
            @if with_remove { option value="none" { "remove this right" } }
        }
    }
}

pub async fn users(
    State(st): St,
    User(user): User,
    Query(q): Query<UsersQuery>,
    parts: axum::http::request::Parts,
) -> Result<axum::response::Response, AppError> {
    require_admin(&user)?;
    let flash = take_flash(&parts);
    let page = blocking(|| -> HtmlResult {
        let db = st.db()?;
        let all_accounts = db.list_accounts()?;
        let choices = scope_choices(&db)?;
        let mut accounts = all_accounts.clone();
        let listing = views::Listing::from_page("user", false);
        listing.apply(
            &mut accounts,
            |a| format!("{} {}", a.username, a.email.as_deref().unwrap_or("")),
            |a, column| match column {
                "user" => Some(views::SortKey::text(&a.username)),
                "admin" => Some(views::SortKey::num(a.is_admin as u8)),
                "instance" => Some(views::SortKey::text(a.instance_role.as_deref().unwrap_or(""))),
                "rights" => Some(views::SortKey::num(a.assignments as f64)),
                "status" => Some(views::SortKey::num(a.disabled as u8)),
                "login" => Some(views::SortKey::text(a.last_login_at.as_deref().unwrap_or(""))),
                _ => None,
            },
        );
        let adding = q.new.is_some();
        let requires_mfa = db.instance_requires_mfa()?;
        Ok(layout(
            Nav::Admin,
            "Users",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("users"))
                @if let Some(msg) = &flash { div.card.notice { (msg) } }

                form.row method="post" action="/admin/mfa" {
                    label.check {
                        input type="checkbox" name="required" value="1" checked[requires_mfa];
                        " Require two-step sign-in from every account that signs in with a password"
                    }
                    button.small.secondary type="submit" { "Save" }
                }

                @if adding {
                    h2 { "Add a user" }
                    form.stack.card method="post" action="/admin/users" {
                        label { "Username" input type="text" name="username" required maxlength="32" autocomplete="off" autofocus; }
                        label { "Email (optional)" input type="email" name="email" autocomplete="off"; }
                        label { "Initial password (at least " (auth::MIN_PASSWORD_LEN) " characters)" input type="password" name="password" required autocomplete="new-password"; }
                        label.check { input type="checkbox" name="admin" value="1"; " Administrator of the instance (users, settings, sources)" }
                        label { "First right" (scope_select(&choices, true)) }
                        label { "Role" (role_select(false)) }
                        p.muted { "More rights can be added afterwards from the user's page." }
                        div.row {
                            button type="submit" { "Create user" }
                            " " a href="/admin/users" { "Cancel" }
                        }
                    }
                } @else {
                    div.head {
                        p.muted {
                            "Rights exist at three levels: the whole instance, an organization (all its projects), or a single project. "
                            "The highest one applies. Administrators additionally manage the instance itself."
                        }
                        a.button href="/admin/users?new=1" { "Add a user" }
                    }
                }

                (listing.filter_box("Filter: username, email…", accounts.len(), all_accounts.len()))
                form method="post" action="/admin/users/bulk" {
                    // Actions on the checked users, right above the list. filter.js greys them out
                    // while nothing is checked; without it they stay usable and the server refuses
                    // an empty selection.
                    div.toolbar data-selection="ids" {
                        select name="action" aria-label="Action on the selected users" {
                            option value="assign" { "Give or change a right" }
                            option value="enable" { "Enable" }
                            option value="disable" { "Disable" }
                            option value="grant_admin" { "Make administrator" }
                            option value="revoke_admin" { "Remove administrator" }
                        }
                        (scope_select(&choices, false))
                        (role_select(true))
                        button type="submit" { "Apply" }
                        span.muted.selection-count {}
                    }
                    div.scroll {
                        table.list.fit.dense {
                            (views::columns("check - kind kind kind flag flag when", true))
                            thead {
                                tr {
                                    th {}
                                    (listing.th("user", "User")) th { "Sign-in" } (listing.th("admin", "Administrator"))
                                    (listing.th("instance", "Instance role")) (listing.th("rights", "Other rights"))
                                    (listing.th("status", "Status")) (listing.th("login", "Last login (UTC)"))
                                }
                            }
                            tbody {
                                @for a in &accounts {
                                    tr {
                                        td { input type="checkbox" name="ids" value=(a.id) aria-label={ "Select " (a.username) }; }
                                        td {
                                            a href={ "/admin/users/" (a.id) } { strong { (a.username) } }
                                            @if a.id == user.id { " " span.muted { "(you)" } }
                                            @if let Some(email) = &a.email { div.muted { (email) } }
                                        }
                                        td {
                                            @if a.has_password { span.tag { "password" } " " }
                                            @if a.sso { span.tag { "SSO" } }
                                        }
                                        td { @if a.is_admin { "yes" } @else { span.muted { "no" } } }
                                        td { @if let Some(role) = &a.instance_role { (role) } @else { span.muted { "—" } } }
                                        td { @if a.assignments > 0 { (a.assignments) } @else { span.muted { "none" } } }
                                        td { @if a.disabled { span.error { "disabled" } } @else { "active" } }
                                        td.nowrap { (a.last_login_at.as_deref().unwrap_or("never")) }
                                    }
                                }
                                @if accounts.is_empty() { tr { td colspan="8" .muted { "No user matches." } } }
                            }
                        }
                    }
                    p.muted { "The actions above apply to the checked users. The right and the role only apply to “Give or change a right”. Your own account is skipped for status and administrator changes." }
                }
            },
        ))
    })?;
    Ok(with_flash_cleared(&st, &flash, page))
}

#[derive(Deserialize)]
pub struct NewUserForm {
    username: String,
    #[serde(default)]
    email: String,
    password: String,
    #[serde(default)]
    admin: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    role: String,
}

fn check_password(password: &str, username: &str) -> Result<(), AppError> {
    auth::check_new_password(password, username).map_err(AppError::Bad)
}

pub async fn user_create(State(st): St, User(user): User, Form(form): Form<NewUserForm>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let username = form.username.trim();
        if !auth::valid_slug(username, 3, 32) {
            return Err(AppError::Bad("Username: 3 to 32 letters, digits, '-', '_' or '.'.".into()));
        }
        check_password(&form.password, username)?;
        let email = Some(form.email.trim()).filter(|e| !e.is_empty());
        if email.is_some_and(|e| e.parse::<lettre::Address>().is_err()) {
            return Err(AppError::Bad("Invalid email address.".into()));
        }
        // The right is checked before anything is created
        let right = match form.scope.as_str() {
            "" => None,
            scope => Some((
                scope,
                crate::rbac::Role::parse(&form.role).ok_or_else(|| AppError::Bad("Unknown role.".into()))?,
            )),
        };
        let db = st.db()?;
        if let Some((scope, _)) = right {
            if !scope_choices(&db)?.iter().any(|(value, _)| value == scope) {
                return Err(AppError::Bad("Unknown organization or project.".into()));
            }
        }
        let hash = hash_new_password(&st, &form.password)?;
        let id = db
            .create_account(username, email, &hash, !form.admin.is_empty())
            .map_err(AppError::bad)?;
        if let Some((scope, role)) = right {
            apply_right(&db, id, scope, Some(role))?;
        }
        Ok(redirect(format!("/admin/users/{id}")))
    })
}

#[derive(Deserialize)]
pub struct UserActionForm {
    action: String,
}

/// Enable/disable or administrator change on one account. Returns false when
/// the account is the caller's own (never changed here).
fn account_action(db: &crate::db::Database, caller: &Account, id: i64, action: &str) -> Result<bool, AppError> {
    if id == caller.id {
        return Ok(false);
    }
    // Only an account of the instance can administer it
    if action == "grant_admin" && !db.may_hold_right(id, crate::db::Scope::Instance)? {
        return Err(AppError::Bad("Only an account of the instance can be administrator.".into()));
    }
    match action {
        "grant_admin" => db.set_admin(id, true),
        "revoke_admin" => db.set_admin(id, false),
        "disable" => db.set_disabled(id, true),
        "enable" => db.set_disabled(id, false),
        // Lost device: the account signs in with its password and enrols again if required
        "reset_mfa" => db.reset_mfa(id).and_then(|_| {
            db.log_security_event(&crate::db::Actor::user(caller.id, &caller.username), Some(id), "mfa_reset", None)
        }),
        _ => return Err(AppError::Bad("Invalid action".into())),
    }
    .map_err(AppError::bad)?;
    Ok(true)
}

pub async fn user_action(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(form): Form<UserActionForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        if !account_action(&st.db()?, &user, id, &form.action)? {
            return Err(AppError::Bad("You cannot change your own role or status.".into()));
        }
        Ok(redirect(format!("/admin/users/{id}")))
    })
}

/// Requires (or not) a second factor from every local account of the instance
pub async fn mfa_requirement(
    State(st): St,
    User(user): User,
    Form(form): Form<super::mfa::RequireForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        if db.instance_requires_mfa()? != form.required() {
            db.set_instance_requires_mfa(form.required())?;
            let detail = format!("instance: {}", if form.required() { "required" } else { "not required" });
            db.log_security_event(&crate::db::Actor::user(user.id, &user.username), None, "mfa_requirement", Some(&detail))?;
        }
        Ok(redirect("/admin/users".into()))
    })
}

/// Says whether a log still chains from its first entry, and offers its
/// signed export
pub(super) fn log_integrity(check: &crate::db::ChainCheck, fingerprint: &str, export: &str) -> maud::Markup {
    html! {
        div.card {
            p {
                @match check.broken_at {
                    None => { strong { "Chain intact" } " — " (check.entries) " entr" @if check.entries == 1 { "y" } @else { "ies" } ", each linked to the previous one." }
                    Some((position, id)) => {
                        strong.error { "Chain broken at entry " (position) " (id " (id) ")" }
                        ": this entry, or one before it, was changed or removed outside the application."
                    }
                }
            }
            p {
                a.button href={ (export) "?format=json" } { "Export (signed JSON)" }
                " " a href={ (export) "?format=csv" } { "CSV, for reading" }
            }
            p.muted {
                "The JSON export is signed by this instance (key " code { (fingerprint) } ") and can be checked anywhere with "
                code { "vulnizard log verify <file> --key " (fingerprint) } ". "
                "Keep exports somewhere else: whoever controls this server could rewrite the log and sign it again, and an earlier export is what shows it."
            }
        }
    }
}

/// A log export as a download
pub(super) fn export_response(export: &crate::trail::Export, format: &str, name: &str) -> Result<axum::response::Response, AppError> {
    use axum::http::header;
    use axum::response::IntoResponse;
    let (body, content_type, extension) = match format {
        "csv" => (crate::trail::to_csv(export), "text/csv; charset=utf-8", "csv"),
        "json" | "" => (
            serde_json::to_string_pretty(export).map_err(anyhow::Error::from)?,
            "application/json",
            "json",
        ),
        _ => return Err(AppError::Bad("Unknown format: json or csv.".into())),
    };
    let day = export.exported_at.get(..10).unwrap_or("export");
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"vulnizard-{name}-{day}.{extension}\"")),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct ExportQuery {
    #[serde(default)]
    pub format: String,
}

pub async fn security_log_export(State(st): St, User(user): User, Query(q): Query<ExportQuery>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| export_response(&st.db()?.export_security_log()?, &q.format, "security-log"))
}

/// Trail of account security events (second factors, requirement)
pub async fn security_log(State(st): St, User(user): User) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let mut events = db.list_security_events(None, 1000)?;
        let total = events.len();
        let listing = views::Listing::from_page("when", true);
        listing.apply(
            &mut events,
            |e| format!("{} {} {} {} {}", e.at, e.label(), e.username, e.actor, e.detail.as_deref().unwrap_or("")),
            |_, _| None,
        );
        let integrity = db.check_security_log()?;
        let fingerprint = db.log_key_fingerprint()?;
        Ok(layout(
            Nav::Admin,
            "Security log",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("security"))
                p.muted { "Second factors set up, removed or reset, recovery codes used, and changes of the requirement. Entries cannot be changed or removed." }
                (log_integrity(&integrity, &fingerprint, "/admin/security/export"))
                (listing.filter_box("Filter: account, event, author…", events.len(), total))
                (super::mfa::events_table(&events, true))
                @if total == 1000 { p.muted { "Showing the 1000 most recent entries." } }
            },
        ))
    })
}

/// Applies one action to every selected user
pub async fn users_bulk(
    State(st): St,
    User(user): User,
    Form(fields): Form<Vec<(String, String)>>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("");
        let ids: Vec<i64> = fields
            .iter()
            .filter(|(k, _)| k == "ids")
            .filter_map(|(_, v)| v.parse().ok())
            .take(1000)
            .collect();
        if ids.is_empty() {
            return Err(AppError::Bad("Select at least one user.".into()));
        }
        let db = st.db()?;
        let action = field("action");
        let mut done = 0;
        if action == "assign" {
            let role = match field("role") {
                "none" => None,
                name => Some(crate::rbac::Role::parse(name).ok_or_else(|| AppError::Bad("Unknown role.".into()))?),
            };
            let scope = field("scope");
            for id in &ids {
                // Unknown ids are ignored
                if db.get_account(*id)?.is_some() {
                    apply_right(&db, *id, scope, role)?;
                    done += 1;
                }
            }
        } else {
            for id in &ids {
                if db.get_account(*id)?.is_some() && account_action(&db, &user, *id, action)? {
                    done += 1;
                }
            }
        }
        Ok(flash_redirect(&st, "/admin/users", &format!("Applied to {done} of {} selected user(s).", ids.len())))
    })
}

/// One user: rights at the three levels, status, password
pub async fn user_detail(State(st): St, User(user): User, Path(id): Path<i64>) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let account = db.list_accounts()?.into_iter().find(|a| a.id == id).ok_or(AppError::NotFound)?;
        let rights = db.user_assignments(id)?;
        let choices = scope_choices(&db)?;
        let me = account.id == user.id;
        let mfa = db.mfa_status(id)?;
        let mfa_required = db.mfa_required(id)?;
        let security_events = db.list_security_events(Some(id), 20)?;
        Ok(layout(
            Nav::Admin,
            &account.username,
            Some(&user),
            html! {
                p { a href="/admin/users" { "← Users" } }
                h1 { (account.username) @if me { " " span.muted { "(you)" } } }
                div.card {
                    dl.meta {
                        @if let Some(email) = &account.email { dt { "Email" } dd { (email) } }
                        dt { "Sign-in" }
                        dd { @if account.has_password { "password " } @if account.sso { "SSO" } }
                        dt { "Two-step sign-in" }
                        dd {
                            @if !account.has_password { span.muted { "handled by the identity provider" } }
                            @else if mfa.enrolled() {
                                @if mfa.totp { "authenticator app " }
                                @if !mfa.passkeys.is_empty() { (mfa.passkeys.len()) " passkey(s)" }
                            } @else if mfa_required { span.error { "required, not set up" } }
                            @else { "not set up" }
                        }
                        dt { "Status" } dd { @if account.disabled { span.error { "disabled" } } @else { "active" } }
                        dt { "Administrator" } dd { @if account.is_admin { "yes" } @else { "no" } }
                        dt { "Last login (UTC)" } dd { (account.last_login_at.as_deref().unwrap_or("never")) }
                    }
                    @if !me {
                        form.row method="post" action={ "/admin/users/" (id) } {
                            @if account.disabled {
                                button.small type="submit" name="action" value="enable" { "Enable" }
                            } @else {
                                button.small.danger type="submit" name="action" value="disable" { "Disable" }
                            }
                            @if account.is_admin {
                                button.small.secondary type="submit" name="action" value="revoke_admin" { "Remove administrator" }
                            } @else {
                                button.small.secondary type="submit" name="action" value="grant_admin" { "Make administrator" }
                            }
                            @if mfa.enrolled() {
                                button.small.danger type="submit" name="action" value="reset_mfa" title="Removes the second factors of this account and closes its sessions (lost device)" { "Reset two-step sign-in" }
                            }
                        }
                    }
                }

                h2 { "Security events" }
                (super::mfa::events_table(&security_events, false))

                h2 { "Rights" }
                table.list.fit {
                    (views::columns("kind - kind act", true))
                    thead { tr { th { "Level" } th { "On" } th { "Role" } th {} } }
                    tbody {
                        @for r in &rights {
                            @let scope = match (r.level.as_str(), &r.org, &r.project) {
                                ("organization", Some(org), _) => format!("organization:{org}"),
                                ("project", Some(org), Some(project)) => format!("project:{org}/{project}"),
                                _ => "instance".to_string(),
                            };
                            tr {
                                td { (r.level) }
                                td {
                                    @match (r.level.as_str(), &r.org, &r.project) {
                                        ("organization", Some(org), _) => { (org) " " span.muted { "(all its projects)" } }
                                        ("project", Some(org), Some(project)) => { (org) " / " (project) }
                                        _ => { span.muted { "every organization and project" } }
                                    }
                                }
                                td { (r.role) }
                                td.right {
                                    form.inline method="post" action={ "/admin/users/" (id) "/assign" } {
                                        input type="hidden" name="scope" value=(scope);
                                        input type="hidden" name="role" value="none";
                                        button.small.danger type="submit" { "Remove" }
                                    }
                                }
                            }
                        }
                        @if rights.is_empty() { tr { td colspan="4" .muted { "No right: this user sees no project." } } }
                    }
                }
                form.row method="post" action={ "/admin/users/" (id) "/assign" } {
                    (scope_select(&choices, false))
                    (role_select(false))
                    button type="submit" { "Give this right" }
                }
                p.muted { "A project right gives access to that project only: the user neither sees nor manages the others." }

                @if !me {
                    h2 { "Reset the password" }
                    form.stack.card method="post" action="/admin/users/password" {
                        input type="hidden" name="user_id" value=(id);
                        label { "New password" input type="password" name="password" required autocomplete="new-password"; }
                        p.muted { "Signs the user out everywhere and revokes their API tokens." }
                        button type="submit" { "Reset password" }
                    }
                }
            },
        ))
    })
}

#[derive(Deserialize)]
pub struct AssignForm {
    scope: String,
    role: String,
}

pub async fn user_assign(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(form): Form<AssignForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        db.get_account(id)?.ok_or(AppError::NotFound)?;
        let role = match form.role.as_str() {
            "none" => None,
            name => Some(crate::rbac::Role::parse(name).ok_or_else(|| AppError::Bad("Unknown role.".into()))?),
        };
        apply_right(&db, id, &form.scope, role)?;
        Ok(redirect(format!("/admin/users/{id}")))
    })
}

#[derive(Deserialize)]
pub struct ResetForm {
    user_id: i64,
    password: String,
}

pub async fn user_password(State(st): St, User(user): User, Form(form): Form<ResetForm>) -> ActionResult {
    require_admin(&user)?;
    if form.user_id == user.id {
        return Err(AppError::Bad("Change your own password in Settings.".into()));
    }
    blocking(|| {
        let db = st.db()?;
        let target = db.get_account(form.user_id)?.ok_or(AppError::NotFound)?;
        check_password(&form.password, &target.username)?;
        db.set_password(form.user_id, &hash_new_password(&st, &form.password)?)?;
        Ok(redirect(format!("/admin/users/{}", form.user_id)))
    })
}

// ==========================================
// Vulnerability sources
// ==========================================

pub async fn sources(
    State(st): St,
    User(user): User,
    parts: axum::http::request::Parts,
) -> Result<axum::response::Response, AppError> {
    require_admin(&user)?;
    let flash = take_flash(&parts);
    let page = blocking(|| -> HtmlResult {
        let db = st.db()?;
        let config = st.effective_config(&db)?;
        let runs = db.last_sync_runs()?;
        let queued: Vec<String> = st.sync_queue.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let running: Vec<&str> = runs.iter().filter(|r| r.status == "running").map(|r| r.source.as_str()).collect();
        let busy = !queued.is_empty() || !running.is_empty();
        Ok(views::layout_refreshing(
            Nav::Admin,
            "Vulnerability sources",
            Some(&user),
            // The page follows the sync by itself until it is over
            busy.then_some(4),
            html! {
                h1 { "Administration" }
                (admin_tabs("sources"))
                @if let Some(msg) = &flash { div.card.notice { (msg) } }
                @if busy {
                    div.card.notice {
                        strong { "Synchronization in progress. " }
                        @if !running.is_empty() { "Running: " (running.join(", ")) ". " }
                        @if !queued.is_empty() { "Waiting: " (queued.join(", ")) ". " }
                        span.muted { "This page refreshes by itself." }
                    }
                }
                p.muted {
                    "A cycle starts " @if config.web.sync_interval_minutes > 0 { "every " (config.web.sync_interval_minutes) " minutes" } @else { "only on demand (no periodic sync)" }
                    ". A source that downloads a whole file does not do so at every cycle: it waits the time shown below, whatever the interval. "
                    strong { "Sync now downloads at once, without waiting" } ": not to be used repeatedly on the sources that fetch a whole file. "
                    "A disabled source can still be synchronized on demand."
                }
                table.list.fit {
                    (views::columns("name - - when - actions", true))
                    thead { tr { th { "Source" } th { "Provides" } th { "Periodic sync" } th { "Last run (UTC)" } th { "State" } th {} } }
                    tbody {
                        @let inventory = st.config.inventory.enabled;
                        @for (key, label, description) in settings::SOURCES.into_iter().filter(|(k, _, _)| !inventory && *k == settings::INVENTORY_SOURCE) {
                            tr.unavailable {
                                td { strong { (label) } div.muted { code { (key) } } }
                                td { (description) }
                                td colspan="4" { span.tag { "Not in this release" } }
                            }
                        }
                        @for (key, label, description) in settings::SOURCES.into_iter().filter(|(k, _, _)| inventory || *k != settings::INVENTORY_SOURCE) {
                            @let enabled = config.sync.sources.iter().any(|s| s == key);
                            @let run = runs.iter().find(|r| r.source == key);
                            @let is_running = running.contains(&key);
                            @let is_queued = queued.iter().any(|q| q == key);
                            tr {
                                td { strong { (label) } div.muted { code { (key) } } }
                                td { (description) }
                                td {
                                    @if enabled { "enabled" } @else { span.muted { "disabled" } }
                                    @let hours = crate::sources::min_hours(key);
                                    (views::info(html! {
                                        @if hours == 0 { "At every cycle" } @else { "At most every " (hours) " h" }
                                        ": " (crate::sources::fetches(key)) "."
                                    }))
                                }
                                td.nowrap { @if let Some(r) = run { (r.started_at) } @else { span.muted { "never" } } }
                                td {
                                    @if is_running {
                                        span.status { span.dot.running {} strong { "synchronizing…" } }
                                    } @else if is_queued {
                                        span.status { span.dot.waiting {} "waiting to start" }
                                    } @else if let Some(r) = run {
                                        @if r.status == "completed" {
                                            span.status { span.dot {} (r.added) " added, " (r.updated) " updated, " (r.same) " unchanged" }
                                        } @else if r.status == "unchanged" {
                                            span.status { span.dot {} "unchanged upstream, nothing downloaded" }
                                        } @else {
                                            span.status { span.dot.never {} span.error { "failed" } }
                                            @if let Some(e) = &r.error { div.muted { (views::truncate(e, 160)) } }
                                        }
                                    }
                                }
                                td.right.actions {
                                    form.inline method="post" action={ "/admin/sources/" (key) } {
                                        @if enabled {
                                            button.small.secondary type="submit" name="action" value="disable" { "Disable" }
                                        } @else {
                                            button.small type="submit" name="action" value="enable" { "Enable" }
                                        }
                                        " "
                                        button.small.secondary type="submit" name="action" value="sync" disabled[is_running || is_queued] { "Sync now" }
                                    }
                                }
                            }
                        }
                    }
                }

                h2 { "Settings" }
                form.stack.card method="post" action="/admin/sources" {
                    label {
                        "Minutes between two synchronizations (0 = no periodic sync)"
                        input type="number" name="interval" min="0" max="10080" value=(config.web.sync_interval_minutes) required;
                    }
                    label {
                        "NVD API key — " @if config.nvd.api_key.is_some() { "one is set; leave empty to keep it" } @else { "none set (slower, rate-limited syncs)" }
                        input type="password" name="nvd_api_key" autocomplete="new-password";
                    }
                    label.check { input type="checkbox" name="clear_nvd_api_key" value="1"; " Remove the API key saved here" }
                    button type="submit" { "Save" }
                }
                p.muted { "Changes apply at the next cycle, without restart. Request an NVD key at nvd.nist.gov/developers/request-an-api-key." }
            },
        ))
    })?;
    Ok(with_flash_cleared(&st, &flash, page))
}

#[derive(Deserialize)]
pub struct SourcesForm {
    interval: u64,
    #[serde(default)]
    nvd_api_key: String,
    #[serde(default)]
    clear_nvd_api_key: String,
}

pub async fn sources_settings(State(st): St, User(user): User, Form(form): Form<SourcesForm>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        if form.interval > 10_080 {
            return Err(AppError::Bad("The interval is at most one week.".into()));
        }
        let key = form.nvd_api_key.trim();
        if key.len() > 200 || key.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AppError::Bad("Invalid API key.".into()));
        }
        let db = st.db()?;
        settings::set_sync_interval(&db, form.interval)?;
        let _ = &st;
        if !form.clear_nvd_api_key.is_empty() {
            settings::set_nvd_api_key(&db, "")?;
        } else if !key.is_empty() {
            settings::set_nvd_api_key(&db, key)?;
        }
        Ok(redirect("/admin/sources".into()))
    })
}

pub async fn source_action(
    State(st): St,
    User(user): User,
    Path(source): Path<String>,
    Form(form): Form<UserActionForm>,
) -> ActionResult {
    require_admin(&user)?;
    if !settings::is_source(&source) || (source == settings::INVENTORY_SOURCE && !st.config.inventory.enabled) {
        return Err(AppError::NotFound);
    }
    blocking(|| {
        let db = st.db()?;
        match form.action.as_str() {
            "enable" => settings::set_source_enabled(&st.config, &db, &source, true)?,
            "disable" => settings::set_source_enabled(&st.config, &db, &source, false)?,
            "sync" => {
                return Ok(match st.request_sync(&db, Some(source.clone()), user.id) {
                    Ok(_) => flash_redirect(&st, "/admin/sources", &format!("Synchronization of {source} requested.")),
                    Err(reason) => flash_redirect(&st, "/admin/sources", &format!("Synchronization of {source} not requested: {reason}.")),
                });
            }
            _ => return Err(AppError::Bad("Invalid action".into())),
        }
        Ok(redirect("/admin/sources".into()))
    })
}

// ==========================================
// One-time messages of the administration pages
// ==========================================

const FLASH_COOKIE: &str = "vz_flash";

fn flash_cookie(st: &super::AppState, value: &str, max_age: i64) -> String {
    format!(
        "{FLASH_COOKIE}={value}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

/// Back to the notifications page with a one-time message. The message
/// travels in a short-lived cookie set by the server, not in the URL, so a
/// crafted link cannot put text in the administration UI.
/// Redirect to an administration page with a one-time message
pub(super) fn flash_redirect(st: &super::AppState, to: &str, message: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let value = views::enc(&views::truncate(message, 300));
    (
        [(axum::http::header::SET_COOKIE, flash_cookie(st, &value, 60))],
        axum::response::Redirect::to(to),
    )
        .into_response()
}

/// Attaches the removal of the one-time message once it was displayed
pub(super) fn with_flash_cleared(st: &super::AppState, flash: &Option<String>, page: maud::Markup) -> axum::response::Response {
    use axum::response::IntoResponse;
    match flash {
        Some(_) => ([(axum::http::header::SET_COOKIE, flash_cookie(st, "", 0))], page).into_response(),
        None => page.into_response(),
    }
}

pub(super) fn take_flash(parts: &axum::http::request::Parts) -> Option<String> {
    parts
        .headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == FLASH_COOKIE)
        .map(|(_, v)| percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned())
        .filter(|m| !m.is_empty())
}

// ==========================================
// MCP server
// ==========================================

pub async fn mcp(State(st): St, User(user): User) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let current = settings::mcp(&db)?;
        let endpoint = format!("{}/mcp", st.config.web.base_url.trim_end_matches('/'));
        let tools = crate::mcp::tool_catalog(st.config.inventory.enabled);
        Ok(layout(
            Nav::Admin,
            "MCP",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("mcp"))
                p.muted {
                    "The MCP server lets an AI assistant query Vulnizard and, if you allow it, act on it. "
                    "Over HTTP every call is made on behalf of the owner of the API token: the assistant sees that user's "
                    "organizations only and has that user's role."
                }

                h2 { "HTTP endpoint" }
                form.stack.card method="post" action="/admin/mcp" {
                    label.check {
                        input type="checkbox" name="http_enabled" value="1" checked[current.http_enabled];
                        " Enable the MCP endpoint of this server"
                    }
                    label.check {
                        input type="checkbox" name="allow_write" value="1" checked[current.allow_write];
                        " Expose the tools that modify data (projects, subscriptions, applications, decisions on CVEs)"
                    }
                    button type="submit" { "Save" }
                }
                dl.meta {
                    dt { "Status" }
                    dd {
                        @if current.http_enabled {
                            "enabled, " @if current.allow_write { "read and write tools" } @else { "read-only tools" }
                        } @else { "disabled" }
                    }
                    dt { "URL" } dd { code { (endpoint) } }
                    dt { "Authentication" } dd { "API token of a user (" a href="/settings" { "Settings" } "), sent as " code { "Authorization: Bearer <token>" } }
                    dt { "Claude Code" }
                    dd { code { "claude mcp add --transport http vulnizard " (endpoint) " --header \"Authorization: Bearer <token>\"" } }
                }

                h2 { "Local (stdio) server" }
                p.muted {
                    "On the machine holding the database, " code { "vulnizard mcp" } " serves the same tools without the web server. "
                    "It has full access to every project and is read-only unless started with " code { "--allow-write" } "; "
                    "it is not affected by the settings above."
                }

                h2 { "Tools" }
                table.list.fit {
                    (views::columns("name flag kind -", true))
                    thead { tr { th { "Tool" } th { "Access" } th { "Over HTTP" } th { "Description" } } }
                    tbody {
                        @for (name, description, write) in &tools {
                            tr {
                                td { code { (name) } }
                                td { @if *write { span.tag { "write" } } @else { "read" } }
                                td.nowrap {
                                    @if current.http_enabled && (!*write || current.allow_write) { "available" } @else { span.muted { "off" } }
                                }
                                td { (description) }
                            }
                        }
                    }
                }
            },
        ))
    })
}

#[derive(Deserialize)]
pub struct McpForm {
    #[serde(default)]
    http_enabled: String,
    #[serde(default)]
    allow_write: String,
}

pub async fn mcp_save(State(st): St, User(user): User, Form(form): Form<McpForm>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        settings::set_mcp(
            &st.db()?,
            settings::McpSettings {
                http_enabled: !form.http_enabled.is_empty(),
                allow_write: !form.allow_write.is_empty(),
            },
        )?;
        Ok(redirect("/admin/mcp".into()))
    })
}

// ==========================================
// Single sign-on providers
// ==========================================

#[derive(Deserialize, Default)]
pub struct SsoQuery {
    /// Prefills the form for a well-known provider
    preset: Option<String>,
    /// Slug of the provider to edit
    edit: Option<String>,
    /// Shows a creation form
    new: Option<String>,
    /// "scim" for the provisioning tab
    tab: Option<String>,
}

/// (name, slug, issuer, scopes) of the form presets
fn preset(key: &str) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match key {
        "google" => Some(("Google", "google", "https://accounts.google.com", "openid email profile")),
        "microsoft" => Some((
            "Microsoft",
            "microsoft",
            "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0",
            "openid email profile",
        )),
        "gitlab" => Some(("GitLab", "gitlab", "https://gitlab.com", "openid email profile")),
        _ => None,
    }
}

/// Providers where anybody can open an account: without a domain restriction,
/// automatic account creation would let the whole Internet in.
pub(super) fn is_public_issuer(issuer: &str) -> bool {
    let Ok(url) = url::Url::parse(issuer) else {
        return false;
    };
    match url.host_str() {
        Some("accounts.google.com") | Some("gitlab.com") => true,
        Some("login.microsoftonline.com") => ["/common", "/consumers", "/organizations"]
            .iter()
            .any(|shared| url.path().starts_with(shared)),
        _ => false,
    }
}

/// Value of the "belongs to" selector for a scope
fn scope_value(db: &crate::db::Database, scope: crate::db::Scope) -> Result<String, AppError> {
    use crate::db::Scope;
    Ok(match scope {
        Scope::Instance => "instance".to_string(),
        Scope::Organization(id) => db
            .list_all_orgs()?
            .into_iter()
            .find(|(org_id, _)| *org_id == id)
            .map(|(_, name)| format!("organization:{name}"))
            .unwrap_or_default(),
        Scope::Project(id) => db
            .list_all_projects()?
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| format!("project:{}/{}", p.org, p.name))
            .unwrap_or_default(),
    })
}

/// Scope chosen in a "belongs to" selector
fn parse_scope(db: &crate::db::Database, value: &str) -> Result<crate::db::Scope, AppError> {
    use crate::db::Scope;
    let bad = || AppError::Bad("Unknown organization or project.".into());
    if value == "instance" {
        Ok(Scope::Instance)
    } else if let Some(org) = value.strip_prefix("organization:") {
        let (id, _) = db.list_all_orgs()?.into_iter().find(|(_, name)| name == org).ok_or_else(bad)?;
        Ok(Scope::Organization(id))
    } else if let Some((org, project)) = value.strip_prefix("project:").and_then(|p| p.split_once('/')) {
        Ok(Scope::Project(db.find_project(org, project)?.ok_or_else(bad)?))
    } else {
        Err(bad())
    }
}

fn scope_text(scope: crate::db::Scope, label: &str) -> String {
    match scope {
        crate::db::Scope::Instance => "whole instance".to_string(),
        crate::db::Scope::Organization(_) => format!("organization {label}"),
        crate::db::Scope::Project(_) => format!("project {label}"),
    }
}

fn sso_tabs(scim: bool) -> maud::Markup {
    views::tabs(&[
        ("/admin/sso", "Sign-in providers", !scim),
        ("/admin/sso?tab=scim", "Provisioning (SCIM)", scim),
    ])
}

pub async fn sso(State(st): St, User(user): User, Query(q): Query<SsoQuery>) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        if q.tab.as_deref() == Some("scim") {
            return scim_page(&st, &db, &user, None, q.new.is_some());
        }
        let providers = db.list_sso_providers()?;
        let from_config = st.config.oidc.as_ref().map(Provider::from_config);
        let editing = q.edit.as_deref().and_then(|slug| providers.iter().find(|p| p.slug == slug));
        let preset = q.preset.as_deref().and_then(preset);
        // The form only shows when a provider is being added or edited
        let show_form = editing.is_some() || preset.is_some() || q.new.is_some();
        let (name, slug, issuer, scopes) = match (editing, preset) {
            (Some(p), _) => (p.name.as_str(), p.slug.as_str(), p.issuer.as_str(), p.scopes.as_str()),
            (None, Some((name, slug, issuer, scopes))) => (name, slug, issuer, scopes),
            _ => ("", "", "", "openid profile email groups"),
        };
        let choices = scope_choices(&db)?;
        let current_scope = match editing {
            Some(p) => scope_value(&db, p.scope)?,
            None => "instance".to_string(),
        };
        let row = |p: &Provider| -> maud::Markup {
            html! {
                tr {
                    td { strong { (p.name) } div.muted { code { (p.slug) } } }
                    td { (p.issuer) div.muted { "Redirect URI: " code { (super::oidc::redirect_uri(&st, &p.slug)) } } }
                    td {
                        (scope_text(p.scope, &p.scope_label))
                        @if let Some(role) = &p.default_role { div.muted { "default role: " (role) } }
                    }
                    td {
                        @if p.allowed_domains.is_empty() { span.muted { "any" } } @else { (p.allowed_domains.join(", ")) }
                    }
                    td {
                        @if p.auto_create { "creates accounts" } @else { "existing accounts only" }
                        @if p.link_existing_accounts { ", links local accounts" }
                        @if let Some(group) = &p.admin_group { ", admins: " code { (group) } }
                    }
                    td { @if p.enabled { "enabled" } @else { span.muted { "disabled" } } }
                    td.right.actions {
                        @if p.from_config {
                            span.muted { "configuration file" }
                        } @else {
                            a.btn href={ "/admin/sso?edit=" (p.slug) } { "Edit" } " "
                            form.inline method="post" action={ "/admin/sso/" (p.slug) } {
                                @if p.enabled {
                                    button.small.secondary type="submit" name="action" value="disable" { "Disable" }
                                } @else {
                                    button.small type="submit" name="action" value="enable" { "Enable" }
                                }
                                " "
                                button.small.danger type="submit" name="action" value="delete" { "Delete" }
                            }
                        }
                    }
                }
            }
        };
        Ok(layout(
            Nav::Admin,
            "Single sign-on",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("sso"))
                (sso_tabs(false))
                p.muted {
                    "Any OpenID Connect provider can be added: your own identity provider (Pocket-ID, Keycloak, Authentik, "
                    "Entra ID…) or a public one such as Google. A provider belongs to the whole instance, an organization or a "
                    "single project: the accounts it creates only exist there, and only instance accounts can hold instance rights."
                }
                div.scroll {
                    table.list.fit.dense {
                        (views::columns("name - who - - flag actions", true))
                        thead { tr { th { "Provider" } th { "Issuer" } th { "Belongs to" } th { "Email domains" } th { "Accounts" } th { "Status" } th {} } }
                        tbody {
                            @if let Some(p) = &from_config { (row(p)) }
                            @for p in &providers { (row(p)) }
                            @if providers.is_empty() && from_config.is_none() {
                                tr { td colspan="7" .muted { "No provider yet." } }
                            }
                        }
                    }
                }

                @if !show_form {
                    p { strong { "Add a provider: " } }
                    div.chips {
                        a href="/admin/sso?new=1" { "Generic OpenID Connect" }
                        @for (key, label) in [("google", "Google"), ("microsoft", "Microsoft Entra ID"), ("gitlab", "GitLab")] {
                            a href={ "/admin/sso?preset=" (key) } { (label) }
                        }
                    }
                } @else {
                    h2 { @if let Some(p) = editing { "Edit " (p.name) } @else { "Add a provider" } }
                    form.stack.card method="post" action="/admin/sso" {
                        label { "Button label" input type="text" name="name" value=(name) maxlength="40" required; }
                        label {
                            "Identifier (used in the redirect URI)"
                            @if editing.is_some() {
                                input type="text" name="slug" value=(slug) readonly;
                            } @else {
                                input type="text" name="slug" value=(slug) maxlength="32" required placeholder="e.g. pocket-id";
                            }
                        }
                        label {
                            "Belongs to"
                            select name="scope" {
                                @for (value, label) in &choices { option value=(value) selected[*value == current_scope] { (label) } }
                            }
                        }
                        label {
                            "Role given there at the first sign-in"
                            select name="default_role" {
                                option value="" { "none — rights are given afterwards" }
                                @for role in crate::rbac::Role::ALL.iter().rev() {
                                    option value=(role.as_str()) selected[editing.is_some_and(|p| p.default_role.as_deref() == Some(role.as_str()))] {
                                        (role.as_str()) " — " (role.description())
                                    }
                                }
                            }
                        }
                        label { "Issuer URL" input type="url" name="issuer" value=(issuer) required placeholder="https://id.example.org"; }
                        label { "Client ID" input type="text" name="client_id" value=[editing.map(|p| p.client_id.as_str())] required autocomplete="off"; }
                        label {
                            "Client secret" @if editing.is_some() { " (leave empty to keep the current one)" }
                            input type="password" name="client_secret" autocomplete="new-password" required[editing.is_none()];
                        }
                        label { "Scopes" input type="text" name="scopes" value=(scopes) required; }
                        label {
                            "Allowed email domains (comma-separated; empty = any)"
                            input type="text" name="allowed_domains" value=[editing.map(|p| p.allowed_domains.join(", "))] placeholder="example.org";
                        }
                        label.check {
                            input type="checkbox" name="auto_create" value="1" checked[editing.map(|p| p.auto_create).unwrap_or(true)];
                            " Create an account at the first sign-in"
                        }
                        label.check {
                            input type="checkbox" name="link_existing" value="1" checked[editing.is_some_and(|p| p.link_existing_accounts)];
                            " Link to the local account with the same username (trusted providers only)"
                        }
                        label {
                            "Administrators group (optional, from the “groups” claim; instance providers only)"
                            input type="text" name="admin_group" value=[editing.and_then(|p| p.admin_group.as_deref())];
                        }
                        div.row {
                            button type="submit" { @if editing.is_some() { "Save" } @else { "Add provider" } }
                            " " a href="/admin/sso" { "Cancel" }
                        }
                    }
                    p.muted {
                        "Register the redirect URI " code { (st.config.web.base_url.trim_end_matches('/')) "/auth/oidc/<identifier>/callback" }
                        " at the provider. With a public provider (Google, GitLab.com, shared Microsoft tenants), creating accounts "
                        "requires allowed email domains: otherwise anyone with an account there could sign in. "
                        "The client secret is stored in the database."
                    }
                }
            },
        ))
    })
}

/// SCIM tab: tokens, groups and the rights groups give
fn scim_page(
    st: &super::AppState,
    db: &crate::db::Database,
    user: &Account,
    new_token: Option<&str>,
    adding: bool,
) -> HtmlResult {
    let tokens = db.list_scim_tokens()?;
    let groups = db.scim_all_groups()?;
    let choices = scope_choices(db)?;
    let endpoint = format!("{}/scim/v2", st.config.web.base_url.trim_end_matches('/'));
    let mut group_rows = Vec::new();
    for group in &groups {
        group_rows.push((group, db.list_group_roles(group.id)?));
    }
    Ok(layout(
        Nav::Admin,
        "Provisioning",
        Some(user),
        html! {
            h1 { "Administration" }
            (admin_tabs("sso"))
            (sso_tabs(true))
            p.muted {
                "With SCIM 2.0 your identity provider creates, updates, deactivates and removes the accounts and the groups itself. "
                "A token belongs to the whole instance, an organization or a single project: it only sees and creates accounts there. "
                "Provisioned accounts sign in through a single sign-on provider of the same scope."
            }
            dl.meta {
                dt { "Base URL" } dd { code { (endpoint) } }
                dt { "Authentication" } dd { code { "Authorization: Bearer <token>" } }
                dt { "Supported" } dd { "Users and Groups (create, read, replace, patch, delete), filters, pagination, discovery endpoints" }
            }

            h2 { "Tokens" }
            @if let Some(token) = new_token {
                div.card {
                    p { "New token — copy it now, it will not be shown again:" }
                    code.token { (token) }
                }
            }
            table.list.fit {
                (views::columns("name - when when act", true))
                thead { tr { th { "Name" } th { "Belongs to" } th { "Created (UTC)" } th { "Last used (UTC)" } th {} } }
                tbody {
                    @for t in &tokens {
                        tr {
                            td { (t.name) }
                            td { (scope_text(t.scope, &t.scope_label)) }
                            td.nowrap { (t.created_at) }
                            td.nowrap { (t.last_used_at.as_deref().unwrap_or("never")) }
                            td.right {
                                form.inline method="post" action={ "/admin/sso/scim/tokens/" (t.id) "/delete" } {
                                    button.small.danger type="submit" { "Revoke" }
                                }
                            }
                        }
                    }
                    @if tokens.is_empty() { tr { td colspan="5" .muted { "No token." } } }
                }
            }
            @if adding {
                form.stack.card method="post" action="/admin/sso/scim/tokens" {
                    strong { "New token" }
                    label { "Name" input type="text" name="name" maxlength="64" required placeholder="e.g. Entra ID"; }
                    label {
                        "Belongs to"
                        select name="scope" {
                            @for (value, label) in &choices { option value=(value) { (label) } }
                        }
                    }
                    div.row {
                        button type="submit" { "Create token" }
                        " " a href="/admin/sso?tab=scim" { "Cancel" }
                    }
                }
            } @else {
                p { a.button href="/admin/sso?tab=scim&new=1" { "Add a token" } }
            }

            h2 { "Groups and the rights they give" }
            p.muted { "Groups are created by the identity provider. Every member of a group gets the rights listed for it, inside what the group belongs to." }
            table.list.fit {
                (views::columns("name who who -", true))
                thead { tr { th { "Group" } th { "Belongs to" } th { "Members" } th { "Rights given to its members" } } }
                tbody {
                    @for (group, roles) in &group_rows {
                        tr {
                            td { strong { (group.display_name) } }
                            td { (scope_text(group.scope, &group.scope_label)) }
                            td {
                                (group.members.len())
                                @if !group.members.is_empty() {
                                    div.muted { (views::truncate(&group.members.iter().map(|(_, name)| name.as_str()).collect::<Vec<_>>().join(", "), 80)) }
                                }
                            }
                            td {
                                @for role in roles {
                                    form.row method="post" action={ "/admin/sso/scim/groups/" (group.id) "/roles/" (role.id) "/delete" } {
                                        span { strong { (role.role) } " on " (role.label) }
                                        button.small.danger type="submit" { "Remove" }
                                    }
                                }
                                form.row method="post" action={ "/admin/sso/scim/groups/" (group.id) "/roles" } {
                                    select name="scope" {
                                        @for (value, label) in &choices { option value=(value) { (label) } }
                                    }
                                    select name="role" {
                                        @for role in crate::rbac::Role::ALL.iter().rev() { option value=(role.as_str()) { (role.as_str()) } }
                                    }
                                    button.small type="submit" { "Give" }
                                }
                            }
                        }
                    }
                    @if groups.is_empty() { tr { td colspan="4" .muted { "No group yet: they appear when the identity provider pushes them." } } }
                }
            }
        },
    ))
}

#[derive(Deserialize)]
pub struct ScimTokenForm {
    name: String,
    scope: String,
}

/// Creates a SCIM token and shows it once
pub async fn scim_token_create(State(st): St, User(user): User, Form(form): Form<ScimTokenForm>) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let name = form.name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(AppError::Bad("Invalid token name.".into()));
        }
        let scope = parse_scope(&db, &form.scope)?;
        let (token, hash) = auth::new_token();
        db.create_scim_token(name, &hash, scope)?;
        scim_page(&st, &db, &user, Some(&token), false)
    })
}

pub async fn scim_token_delete(State(st): St, User(user): User, Path(id): Path<i64>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        st.db()?.delete_scim_token(id)?;
        Ok(redirect("/admin/sso?tab=scim".into()))
    })
}

#[derive(Deserialize)]
pub struct GroupRoleForm {
    scope: String,
    role: String,
}

pub async fn scim_group_role_set(
    State(st): St,
    User(user): User,
    Path(group_id): Path<i64>,
    Form(form): Form<GroupRoleForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let scope = parse_scope(&db, &form.scope)?;
        let role = crate::rbac::Role::parse(&form.role).ok_or_else(|| AppError::Bad("Unknown role.".into()))?;
        db.set_group_role(group_id, scope, role).map_err(AppError::bad)?;
        Ok(redirect("/admin/sso?tab=scim".into()))
    })
}

pub async fn scim_group_role_remove(
    State(st): St,
    User(user): User,
    Path((group_id, role_id)): Path<(i64, i64)>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        if !st.db()?.remove_group_role(group_id, role_id)? {
            return Err(AppError::NotFound);
        }
        Ok(redirect("/admin/sso?tab=scim".into()))
    })
}

#[derive(Deserialize)]
pub struct ProviderForm {
    name: String,
    slug: String,
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_secret: String,
    scopes: String,
    #[serde(default)]
    allowed_domains: String,
    #[serde(default)]
    auto_create: String,
    #[serde(default)]
    link_existing: String,
    #[serde(default)]
    admin_group: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    default_role: String,
}

pub async fn sso_save(State(st): St, User(user): User, Form(form): Form<ProviderForm>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let bad = |msg: &str| AppError::Bad(msg.to_string());
        let db = st.db()?;
        let scope = match form.scope.as_str() {
            "" => crate::db::Scope::Instance,
            value => parse_scope(&db, value)?,
        };
        let default_role = match form.default_role.as_str() {
            "" => None,
            name => Some(crate::rbac::Role::parse(name).ok_or_else(|| bad("Unknown role."))?.as_str().to_string()),
        };
        let provider = Provider {
            slug: form.slug.trim().to_lowercase(),
            name: form.name.trim().to_string(),
            issuer: form.issuer.trim().trim_end_matches('/').to_string(),
            client_id: form.client_id.trim().to_string(),
            client_secret: form.client_secret.trim().to_string(),
            scopes: form.scopes.split_whitespace().collect::<Vec<_>>().join(" "),
            auto_create: !form.auto_create.is_empty(),
            link_existing_accounts: !form.link_existing.is_empty(),
            // Only an instance provider can designate administrators
            admin_group: Some(form.admin_group.trim().to_string())
                .filter(|g| !g.is_empty() && scope == crate::db::Scope::Instance),
            allowed_domains: normalize_domains(&form.allowed_domains),
            enabled: true,
            from_config: false,
            scope,
            scope_label: String::new(),
            default_role,
        };
        if !auth::valid_slug(&provider.slug, 1, 32) || provider.slug == CONFIG_PROVIDER {
            return Err(bad("Identifier: letters, digits, '-', '_' or '.' (\"config\" is reserved)."));
        }
        if provider.name.is_empty() || provider.name.chars().count() > 40 {
            return Err(bad("Invalid button label."));
        }
        if provider.client_id.is_empty() || provider.client_id.len() > 300 || provider.client_secret.len() > 500 {
            return Err(bad("Invalid client ID or secret."));
        }
        super::oidc::check_issuer(&provider.issuer).map_err(|_| bad("The issuer must be an https URL."))?;
        if !provider.scopes.split(' ').any(|s| s == "openid") || provider.scopes.len() > 300 {
            return Err(bad("Scopes must include \"openid\"."));
        }
        if provider.allowed_domains.iter().any(|d| !d.contains('.') || d.len() > 100) || provider.allowed_domains.len() > 50 {
            return Err(bad("Invalid email domain."));
        }
        if provider.auto_create && provider.allowed_domains.is_empty() && is_public_issuer(&provider.issuer) {
            return Err(bad(
                "This is a public provider: set allowed email domains, or disable account creation.",
            ));
        }
        if provider.link_existing_accounts && is_public_issuer(&provider.issuer) {
            return Err(bad(
                "Linking local accounts is not available with a public provider: its usernames are chosen freely.",
            ));
        }
        db.save_sso_provider(&provider).map_err(AppError::bad)?;
        Ok(redirect("/admin/sso".into()))
    })
}

pub async fn sso_action(
    State(st): St,
    User(user): User,
    Path(slug): Path<String>,
    Form(form): Form<UserActionForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let found = match form.action.as_str() {
            "enable" => db.set_sso_provider_enabled(&slug, true)?,
            "disable" => db.set_sso_provider_enabled(&slug, false)?,
            "delete" => db.delete_sso_provider(&slug)?,
            _ => return Err(AppError::Bad("Invalid action".into())),
        };
        if !found {
            return Err(AppError::NotFound);
        }
        Ok(redirect("/admin/sso".into()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_issuers_are_recognized() {
        assert!(is_public_issuer("https://accounts.google.com"));
        assert!(is_public_issuer("https://gitlab.com"));
        assert!(is_public_issuer("https://login.microsoftonline.com/common/v2.0"));
        assert!(is_public_issuer("https://login.microsoftonline.com/consumers/v2.0"));
        // A dedicated tenant or a self-hosted provider is not public
        assert!(!is_public_issuer("https://login.microsoftonline.com/8b1f-tenant/v2.0"));
        assert!(!is_public_issuer("https://id.example.org"));
        assert!(!is_public_issuer("https://gitlab.example.org"));
        assert!(!is_public_issuer("not a url"));
    }
}
