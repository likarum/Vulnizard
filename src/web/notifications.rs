//! Notifications in the UI: destinations (where messages go) and rules
//! (which project sends what to which destination), in the project settings
//! and in the administration; browser notifications (Web Push).

use axum::extract::{Form, Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::{admin_tabs, flash_redirect, require_admin, take_flash, with_flash_cleared};
use super::pages::{load_project, redirect, require, ActionResult, HtmlResult};
use super::views::{self, enc, layout, product_url, Nav};
use super::{blocking, AppError, AppState, MaybeUser, St, User};
use crate::changes::EVENT_TYPES;
use crate::config::Config;
use crate::db::{Database, Destination, Notification, Org, OrgProject, DESTINATION_KINDS};
use crate::notify;
use crate::rbac::Permission;

type Fields = Vec<(String, String)>;

fn field<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .unwrap_or("")
}

fn kind_label(kind: &str) -> &'static str {
    DESTINATION_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, label)| *label)
        .unwrap_or("Unknown")
}

// ==========================================
// Destination forms
// ==========================================

/// Chips choosing the type of destination to add (the form only shows once a
/// type is chosen, with the fields of that type).
fn kind_chips(base: &str, chosen: Option<&str>) -> Markup {
    let sep = if base.contains('?') { '&' } else { '?' };
    html! {
        div.chips {
            @for (kind, label) in DESTINATION_KINDS {
                a href={ (base) (sep) "new=" (kind) } class=[(chosen == Some(kind)).then_some("active")] { (label) }
            }
        }
    }
}

/// Browsers one account may register for notifications. Each one is a URL
/// the server calls when notifying: few, so that slow ones cannot hold the
/// notification run for long.
const MAX_PUSH_SUBSCRIPTIONS: usize = 5;

/// Fields of a destination of the given type. The SMTP server is only asked
/// for an email destination.
fn destination_fields(kind: &str, default_smtp: bool) -> Markup {
    html! {
        input type="hidden" name="kind" value=(kind);
        label { "Name" input type="text" name="name" maxlength="64" required placeholder="e.g. team phone"; }
        @match kind {
            "email" => {
                label { "Recipient" input type="email" name="to" required placeholder="security@example.org"; }
                fieldset {
                    legend { "SMTP server used for this destination" }
                    @if default_smtp {
                        p.muted { "Leave the server empty to use the default one of this instance." }
                    }
                    label { "Server" input type="text" name="smtp_host" maxlength="200" placeholder="smtp.example.org" required[!default_smtp]; }
                    label { "Port (465 = TLS, 25 = plain, other = STARTTLS)" input type="number" name="smtp_port" min="1" max="65535" value="587"; }
                    label { "Username (optional)" input type="text" name="smtp_username" maxlength="200" autocomplete="off"; }
                    label { "Password" input type="password" name="smtp_password" maxlength="500" autocomplete="new-password"; }
                    label { "Sender" input type="text" name="smtp_from" maxlength="200" placeholder="Vulnizard <vulnizard@example.org>"; }
                }
            }
            "browser" => {
                p.muted {
                    "Sends a notification to the browsers of the people who can read the project. "
                    "Each person enables it for their own browser in " a href="/settings" { "Settings" } "."
                }
            }
            "ntfy" => { label { "Topic URL" input type="url" name="url" maxlength="500" required placeholder="https://ntfy.example.org/vulnizard"; } }
            "slack" => { label { "Incoming webhook URL" input type="url" name="url" maxlength="500" required; } }
            _ => { label { "URL (receives a JSON POST)" input type="url" name="url" maxlength="500" required; } }
        }
    }
}

/// Validates a destination form and builds its stored settings
///
/// `instance_smtp` allows an email destination without its own server, sent
/// through the SMTP server of the instance. Only administrators get it:
/// otherwise anyone able to create a project could make the instance send
/// mail, under its sender address, to any recipient.
fn destination_config(config: &Config, kind: &str, fields: &Fields, instance_smtp: bool) -> Result<Value, AppError> {
    let bad = |msg: &str| AppError::Bad(msg.to_string());
    match kind {
        "email" => {
            let to = field(fields, "to");
            if to.parse::<lettre::Address>().is_err() {
                return Err(bad("Invalid recipient address."));
            }
            let host = field(fields, "smtp_host");
            if host.is_empty() {
                if !instance_smtp {
                    return Err(bad("Give this destination its own SMTP server: only an administrator can send through the server of the instance (Admin → Notifications)."));
                }
                if config.smtp.is_none() {
                    return Err(bad("An SMTP server is required for this destination."));
                }
                return Ok(json!({ "to": to }));
            }
            let valid_host = host.len() <= 200
                && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
            if !valid_host {
                return Err(bad("Invalid SMTP server."));
            }
            let port: u16 = field(fields, "smtp_port")
                .parse()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| bad("Invalid SMTP port."))?;
            crate::notify::check_smtp_settings(config, host, port).map_err(|e| bad(&format!("SMTP server refused: {e}.")))?;
            let from = field(fields, "smtp_from");
            if from.parse::<lettre::message::Mailbox>().is_err() {
                return Err(bad("Invalid sender address."));
            }
            let username = Some(field(fields, "smtp_username")).filter(|u| !u.is_empty());
            // The password is taken verbatim (it may start or end with a space)
            let password = fields
                .iter()
                .find(|(k, _)| k == "smtp_password")
                .map(|(_, v)| v.as_str())
                .filter(|p| !p.is_empty() && username.is_some());
            Ok(json!({
                "to": to,
                "smtp": { "host": host, "port": port, "username": username, "password": password, "from": from },
            }))
        }
        "ntfy" | "slack" | "webhook" => {
            let url = field(fields, "url");
            notify::check_webhook_url(config, url).map_err(|e| AppError::Bad(format!("Invalid target URL: {e}")))?;
            Ok(json!({ "url": url }))
        }
        "browser" => Ok(json!({})),
        _ => Err(bad("Invalid destination type.")),
    }
}

fn destination_name(fields: &Fields) -> Result<&str, AppError> {
    let name = field(fields, "name");
    if name.is_empty() || name.chars().count() > 64 {
        return Err(AppError::Bad("Invalid destination name.".into()));
    }
    Ok(name)
}

fn events_and_cvss(fields: &Fields) -> Result<(Vec<String>, Option<f64>), AppError> {
    let events: Vec<String> = fields
        .iter()
        .filter(|(k, v)| k == "events" && EVENT_TYPES.iter().any(|(kind, _)| kind == v))
        .map(|(_, v)| v.clone())
        .collect();
    let min_cvss = match field(fields, "min_cvss") {
        "" => None,
        raw => Some(
            raw.parse::<f64>()
                .ok()
                .filter(|v| (0.0..=10.0).contains(v))
                .ok_or_else(|| AppError::Bad("Minimum CVSS must be between 0 and 10.".into()))?,
        ),
    };
    Ok((events, min_cvss))
}

fn rule_filters() -> Markup {
    html! {
        fieldset {
            legend { "Events (none checked = all)" }
            @for (kind, label) in EVENT_TYPES {
                label { input type="checkbox" name="events" value=(kind); " " (label) }
            }
        }
        label { "Minimum CVSS (optional)" input type="number" name="min_cvss" min="0" max="10" step="0.1"; }
    }
}

// ==========================================
// Project settings
// ==========================================

/// Notification part of the project settings: its rules, the destinations it
/// can use, and its own destinations. `new_kind` shows the creation form.
pub fn project_section(
    db: &Database,
    _config: &Config,
    org: &Org,
    project: &OrgProject,
    new_kind: Option<&str>,
) -> Result<Markup, AppError> {
    let rules = db.list_notifications(project.id)?;
    let destinations = db.list_project_destinations(project.id)?;
    let manage = org.can(Permission::ManageProjects);
    let base = format!("/orgs/{}/projects/{}", enc(&org.name), enc(&project.name));
    let settings_url = product_url(Some((&org.name, &project.name)), "settings");
    let unused: Vec<&Destination> = destinations.iter().filter(|d| !rules.iter().any(|r| r.destination_id == d.id)).collect();
    let new_kind = new_kind.filter(|k| DESTINATION_KINDS.iter().any(|(kind, _)| kind == k));

    Ok(html! {
        h2 { "Notifications" }
        p.muted { "Sent after each sync when a CVE of a subscribed vendor or product changes." }
        table.list {
            thead { tr { th { "Destination" } th { "Type" } th { "Target" } th { "Events" } th { "Min CVSS" } th { "Status" } th {} } }
            tbody {
                @for n in &rules {
                    tr {
                        td { (n.name) }
                        td { (kind_label(&n.kind)) }
                        td {
                            // A webhook URL or a topic is a secret of whoever manages the destination
                            @if manage && destinations.iter().any(|d| d.id == n.destination_id && d.scope == "project") {
                                (views::truncate(&n.target, 60))
                            } @else { span.muted { "managed elsewhere" } }
                        }
                        td { @if n.events.is_empty() { "all" } @else { (n.events.join(", ")) } }
                        td { @if let Some(m) = n.min_cvss { (format!("{m:.1}")) } @else { "—" } }
                        td { @if n.enabled { "enabled" } @else { span.muted { "disabled" } } }
                        td.right.nowrap {
                            @if manage {
                                form.inline method="post" action={ (base) "/notifications/" (n.id) "/toggle" } {
                                    button.small.secondary type="submit" { @if n.enabled { "Disable" } @else { "Enable" } }
                                }
                                " "
                                form.inline method="post" action={ (base) "/notifications/" (n.id) "/delete" } {
                                    button.small.danger type="submit" { "Stop" }
                                }
                            }
                        }
                    }
                }
                @if rules.is_empty() { tr { td colspan="7" .muted { "This project does not notify anyone yet." } } }
            }
        }
        @if manage && !unused.is_empty() {
            form.stack.card method="post" action={ (base) "/notifications" } {
                strong { "Notify a destination" }
                label {
                    "Destination"
                    select name="destination_id" {
                        @for d in &unused {
                            option value=(d.id) {
                                (d.name) " — " (kind_label(&d.kind))
                                @match d.scope.as_str() {
                                    "project" => {}
                                    "organization" => { " (organization)" }
                                    _ => { " (instance)" }
                                }
                            }
                        }
                    }
                }
                (rule_filters())
                button type="submit" { "Start notifying" }
            }
        }

        h2 { "Destinations of this project" }
        p.muted { "Where this project's messages can go. A destination created here is only usable by this project." }
        table.list {
            thead { tr { th { "Name" } th { "Type" } th { "Target" } th { "Belongs to" } th {} } }
            tbody {
                @for d in &destinations {
                    tr {
                        td { (d.name) }
                        td { (kind_label(&d.kind)) }
                        td { @if manage && d.scope == "project" { (views::truncate(&d.target(), 60)) } @else { span.muted { "managed elsewhere" } } }
                        td {
                            @match d.scope.as_str() {
                                "project" => { "this project" }
                                "organization" => { span.muted { "organization " (org.name) } }
                                _ => { span.muted { "whole instance" } }
                            }
                        }
                        td.right {
                            @if manage && d.scope == "project" {
                                form.inline method="post" action={ (base) "/destinations/" (d.id) "/delete" } {
                                    button.small.danger type="submit" { "Delete" }
                                }
                            }
                        }
                    }
                }
                @if destinations.is_empty() { tr { td colspan="5" .muted { "No destination yet." } } }
            }
        }
        @if manage {
            @match new_kind {
                Some(kind) => {
                    h2 { "New destination: " (kind_label(kind)) }
                    (kind_chips(&settings_url, Some(kind)))
                    form.stack.card method="post" action={ (base) "/destinations" } {
                        (destination_fields(kind, false))
                        label.check { input type="checkbox" name="notify" value="1" checked; " Start notifying this project through it" }
                        div.row {
                            button type="submit" { "Add destination" }
                            " " a href=(settings_url) { "Cancel" }
                        }
                    }
                }
                None => {
                    p { strong { "Add a destination: " } }
                    (kind_chips(&settings_url, None))
                }
            }
        }
    })
}

/// Creates a destination belonging to the project
pub async fn project_destination_create(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let config = st.effective_config(&db)?;
        let kind = field(&fields, "kind");
        let name = destination_name(&fields)?;
        let settings = destination_config(&config, kind, &fields, false)?;
        let id = db
            .create_destination("project", Some(project.id), name, kind, &settings, false)
            .map_err(AppError::bad)?;
        if !field(&fields, "notify").is_empty() {
            db.create_rule(project.id, id, &[], None).map_err(AppError::bad)?;
        }
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}

pub async fn project_destination_delete(
    State(st): St,
    User(user): User,
    Path((org, project, id)): Path<(String, String, i64)>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        // Only a destination owned by this project
        let owned = db
            .get_destination(id)?
            .is_some_and(|d| d.scope == "project" && d.scope_id == Some(project.id));
        if !owned {
            return Err(AppError::NotFound);
        }
        db.delete_destination(id)?;
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}

/// Starts notifying a destination: an existing one (`destination_id`), or a
/// new destination of the project given inline (`kind` + its fields).
pub async fn rule_create(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let (events, min_cvss) = events_and_cvss(&fields)?;
        let destination_id = match field(&fields, "destination_id") {
            "" => {
                let config = st.effective_config(&db)?;
                let kind = field(&fields, "kind");
                // Inline form: `target` holds the URL or the address
                let mut inline = fields.clone();
                let target = field(&fields, "target").to_string();
                inline.push(("url".into(), target.clone()));
                inline.push(("to".into(), target));
                let settings = destination_config(&config, kind, &inline, false)?;
                db.create_destination("project", Some(project.id), destination_name(&fields)?, kind, &settings, false)
                    .map_err(AppError::bad)?
            }
            raw => raw.parse().map_err(|_| AppError::Bad("Invalid destination.".into()))?,
        };
        db.create_rule(project.id, destination_id, &events, min_cvss)
            .map_err(AppError::bad)?;
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}

#[derive(Clone, Copy)]
enum RuleAction {
    Delete,
    Toggle,
}

fn rule_action(st: &AppState, user: &crate::db::Account, (org, project, id): (String, String, i64), action: RuleAction) -> ActionResult {
    let db = st.db()?;
    let (org, project) = load_project(&db, user, &org, &project)?;
    require(&org, Permission::ManageProjects)?;
    match action {
        RuleAction::Delete => db.delete_notification(project.id, id)?,
        RuleAction::Toggle => db.toggle_notification(project.id, id)?,
    }
    Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
}

pub async fn rule_delete(State(st): St, User(user): User, Path(path): Path<(String, String, i64)>) -> ActionResult {
    blocking(|| rule_action(&st, &user, path, RuleAction::Delete))
}

pub async fn rule_toggle(State(st): St, User(user): User, Path(path): Path<(String, String, i64)>) -> ActionResult {
    blocking(|| rule_action(&st, &user, path, RuleAction::Toggle))
}

// ==========================================
// Administration
// ==========================================

#[derive(Deserialize, Default)]
pub struct AdminQuery {
    tab: Option<String>,
    /// Type of the destination being added
    new: Option<String>,
}

/// Choices of the "belongs to" selector of an instance or organization destination
fn owner_choices(db: &Database) -> Result<Vec<(String, String)>, AppError> {
    let mut choices = vec![("instance".to_string(), "Whole instance (usable by every project)".to_string())];
    for (_, org) in db.list_all_orgs()? {
        choices.push((format!("organization:{org}"), format!("Organization {org} (usable by its projects)")));
    }
    for p in db.list_all_projects()? {
        choices.push((format!("project:{}/{}", p.org, p.name), format!("Project {} / {} only", p.org, p.name)));
    }
    Ok(choices)
}

fn parse_owner(db: &Database, value: &str) -> Result<(&'static str, Option<i64>), AppError> {
    let bad = || AppError::Bad("Unknown organization or project.".into());
    if value == "instance" {
        Ok(("instance", None))
    } else if let Some(org) = value.strip_prefix("organization:") {
        let (id, _) = db.list_all_orgs()?.into_iter().find(|(_, name)| name == org).ok_or_else(bad)?;
        Ok(("organization", Some(id)))
    } else if let Some((org, project)) = value.strip_prefix("project:").and_then(|p| p.split_once('/')) {
        Ok(("project", Some(db.find_project(org, project)?.ok_or_else(bad)?)))
    } else {
        Err(bad())
    }
}

pub async fn admin(
    State(st): St,
    User(user): User,
    Query(q): Query<AdminQuery>,
    parts: axum::http::request::Parts,
) -> Result<axum::response::Response, AppError> {
    require_admin(&user)?;
    let flash = take_flash(&parts);
    let page = blocking(|| -> HtmlResult {
        let db = st.db()?;
        let config = st.effective_config(&db)?;
        let tab = q.tab.as_deref().unwrap_or("projects");
        let body = match tab {
            "destinations" => admin_destinations(&db, &config, q.new.as_deref())?,
            "delivery" => html! {
                form.stack.card method="post" action="/admin/notifications/delivery" {
                    label.check {
                        input type="checkbox" name="allow_private" value="1" checked[config.web.allow_private_webhooks];
                        " Allow webhook, Slack and ntfy targets on private or loopback addresses"
                    }
                    p.muted { "Needed for a self-hosted ntfy or webhook receiver on your network. It lets any project editor make the server send requests to internal addresses." }
                    button type="submit" { "Save" }
                }
            },
            _ => admin_rules(&db)?,
        };
        Ok(layout(
            Nav::Admin,
            "Notifications",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("notifications"))
                @if let Some(msg) = &flash { div.card.notice { (msg) } }
                (views::tabs(&[
                    ("/admin/notifications", "Enabled per project", tab == "projects"),
                    ("/admin/notifications?tab=destinations", "Destinations", tab == "destinations"),
                    ("/admin/notifications?tab=delivery", "Delivery", tab == "delivery"),
                ]))
                (body)
            },
        ))
    })?;
    Ok(with_flash_cleared(&st, &flash, page))
}

/// Tab: which project notifies which destination
fn admin_rules(db: &Database) -> Result<Markup, AppError> {
    let mut all = db.list_all_notifications()?;
    let total = all.len();
    let listing = views::Listing::from_page("project", false);
    listing.apply(
        &mut all,
        |i| format!("{} {} {} {} {}", i.org, i.project, i.notification.name, i.notification.kind, i.notification.target),
        |i, column| match column {
            "project" => Some(views::SortKey::text(format!("{} {}", i.org, i.project))),
            "name" => Some(views::SortKey::text(&i.notification.name)),
            "type" => Some(views::SortKey::text(&i.notification.kind)),
            "status" => Some(views::SortKey::num(i.notification.enabled as u8)),
            _ => None,
        },
    );
    Ok(html! {
        p.muted { "Which project notifies which destination. Rules are created in each project's settings." }
        (listing.filter_box("Filter: project, destination, type, target…", all.len(), total))
        table.list {
            thead {
                tr {
                    (listing.th("project", "Project")) (listing.th("name", "Destination")) (listing.th("type", "Type"))
                    th { "Target" } th { "Events" } th { "Min CVSS" } (listing.th("status", "Status")) th {}
                }
            }
            tbody {
                @for item in &all {
                    @let n: &Notification = &item.notification;
                    tr {
                        td.nowrap { a href=(product_url(Some((&item.org, &item.project)), "settings")) { (item.project) } " " span.muted { (item.org) } }
                        td { (n.name) }
                        td { (kind_label(&n.kind)) }
                        td { (views::truncate(&n.target, 50)) }
                        td { @if n.events.is_empty() { "all" } @else { (n.events.join(", ")) } }
                        td { @if let Some(m) = n.min_cvss { (format!("{m:.1}")) } @else { "—" } }
                        td { @if n.enabled { "enabled" } @else { span.muted { "disabled" } } }
                        td.right.nowrap {
                            form.inline method="post" action={ "/admin/notifications/" (n.id) } {
                                button.small type="submit" name="action" value="test" { "Send test" }
                                " "
                                button.small.secondary type="submit" name="action" value="toggle" { @if n.enabled { "Disable" } @else { "Enable" } }
                                " "
                                button.small.danger type="submit" name="action" value="delete" { "Stop" }
                            }
                        }
                    }
                }
                @if all.is_empty() { tr { td colspan="8" .muted { "No project notifies anyone yet." } } }
            }
        }
    })
}

/// Tab: every destination, whatever it belongs to
fn admin_destinations(db: &Database, config: &Config, new_kind: Option<&str>) -> Result<Markup, AppError> {
    let mut all = db.list_all_destinations()?;
    let total = all.len();
    let listing = views::Listing::from_page("owner", false);
    listing.apply(
        &mut all,
        |d| format!("{} {} {} {} {}", d.name, d.kind, d.target(), d.scope, d.scope_label),
        |d, column| match column {
            "name" => Some(views::SortKey::text(&d.name)),
            "type" => Some(views::SortKey::text(&d.kind)),
            "owner" => Some(views::SortKey::text(format!("{} {}", d.scope, d.scope_label))),
            "rules" => Some(views::SortKey::num(d.rules as f64)),
            _ => None,
        },
    );
    let new_kind = new_kind.filter(|k| DESTINATION_KINDS.iter().any(|(kind, _)| kind == k));
    let base = "/admin/notifications?tab=destinations";
    // Organization of every project, to tell how many projects a shared destination is offered to
    let projects: Vec<Option<i64>> = {
        let mut stmt = db.conn().prepare("SELECT organization_id FROM projects")?;
        let rows = stmt.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
        rows
    };
    Ok(html! {
        p.muted {
            "Every destination. Each belongs to the instance, an organization or a single project, which decides who can use it. "
            "A project is notified through a destination once it has a rule for it (its Settings). "
            "“Browser notifications” reach the people who enabled them for their browser in their own Settings; a test goes to your browsers."
        }
        (listing.filter_box("Filter: name, type, target, owner…", all.len(), total))
        table.list {
            thead {
                tr {
                    (listing.th("name", "Name")) (listing.th("type", "Type")) th { "Target" }
                    (listing.th("owner", "Belongs to")) (listing.th("rules", "Used by")) th { "Instance events" } th {}
                }
            }
            tbody {
                @for d in &all {
                    tr {
                        td { (d.name) }
                        td { (kind_label(&d.kind)) }
                        td { (views::truncate(&d.target(), 50)) }
                        td {
                            @match d.scope.as_str() {
                                "instance" => { "whole instance" }
                                "organization" => { "organization " (d.scope_label) }
                                _ => { "project " (d.scope_label) }
                            }
                        }
                        td {
                            // A shared destination is offered to every project of its scope; a rule makes a project use it
                            @match d.scope.as_str() {
                                "instance" => { (d.rules) " of " (projects.len()) " project" @if projects.len() != 1 { "s" } div.muted { "available to all" } }
                                "organization" => {
                                    @let within = projects.iter().filter(|org| **org == d.scope_id).count();
                                    (d.rules) " of " (within) " project" @if within != 1 { "s" } div.muted { "available to its organization" }
                                }
                                _ => { @if d.rules > 0 { "its project" } @else { span.muted { "not used yet" } } }
                            }
                        }
                        td { @if d.system_events { "sync finished" } @else { span.muted { "—" } } }
                        td.right.nowrap {
                            form.inline method="post" action={ "/admin/notifications/destinations/" (d.id) } {
                                button.small type="submit" name="action" value="test" { "Send test" }
                                " "
                                button.small.danger type="submit" name="action" value="delete" { "Delete" }
                            }
                        }
                    }
                }
                @if all.is_empty() { tr { td colspan="7" .muted { "No destination yet." } } }
            }
        }
        @match new_kind {
            Some(kind) => {
                h2 { "New destination: " (kind_label(kind)) }
                (kind_chips(base, Some(kind)))
                form.stack.card method="post" action="/admin/notifications/destinations" {
                    label {
                        "Belongs to"
                        select name="owner" {
                            @for (value, label) in owner_choices(db)? { option value=(value) { (label) } }
                        }
                    }
                    (destination_fields(kind, config.smtp.is_some()))
                    label.check {
                        input type="checkbox" name="system_events" value="1";
                        " Also tell it when a manual synchronization finishes (instance destinations only)"
                    }
                    div.row {
                        button type="submit" { "Add destination" }
                        " " a href=(base) { "Cancel" }
                    }
                }
            }
            None => {
                p { strong { "Add a destination: " } }
                (kind_chips(base, None))
            }
        }
    })
}

pub async fn admin_destination_create(State(st): St, User(user): User, Form(fields): Form<Fields>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let config = st.effective_config(&db)?;
        let (scope, scope_id) = parse_owner(&db, field(&fields, "owner"))?;
        let kind = field(&fields, "kind");
        let name = destination_name(&fields)?;
        let settings = destination_config(&config, kind, &fields, true)?;
        db.create_destination(scope, scope_id, name, kind, &settings, !field(&fields, "system_events").is_empty())
            .map_err(AppError::bad)?;
        Ok(flash_redirect(&st, "/admin/notifications?tab=destinations", &format!("Destination “{name}” added.")))
    })
}

#[derive(Deserialize)]
pub struct ActionForm {
    action: String,
}

pub async fn admin_destination_action(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(form): Form<ActionForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let destination = db.get_destination(id)?.ok_or(AppError::NotFound)?;
        let back = "/admin/notifications?tab=destinations";
        Ok(match form.action.as_str() {
            "delete" => {
                db.delete_destination(id)?;
                flash_redirect(&st, back, &format!("Destination “{}” deleted.", destination.name))
            }
            "test" => {
                let config = st.effective_config(&db)?;
                let outcome = if destination.kind == "browser" {
                    // Browsers are addressed per person: the test goes to those of whoever asks
                    let registered = db.list_push_subscriptions(user.id)?.len();
                    if registered == 0 {
                        Err(anyhow::anyhow!(
                            "none of your browsers is registered. Enable notifications for this browser first, in Settings → Browser notifications"
                        ))
                    } else {
                        crate::push::deliver(&db, &config, user.id, "Vulnizard test", "Browser notifications work.", "/settings").and_then(
                            |reached| match reached {
                                0 => Err(anyhow::anyhow!(
                                    "the push service refused or did not answer for your {registered} registered browser(s) (see the server log)"
                                )),
                                n => Ok(format!("sent to {n} of your {registered} registered browser(s)")),
                            },
                        )
                    }
                } else {
                    notify::send_system(&config, &destination, "Test", "Test message sent from the Vulnizard administration.")
                        .map(|()| "sent".to_string())
                };
                match outcome {
                    Ok(detail) => flash_redirect(&st, back, &format!("Test through “{}”: {detail}.", destination.name)),
                    Err(e) => flash_redirect(&st, back, &format!("Test through “{}” failed: {e}", destination.name)),
                }
            }
            _ => return Err(AppError::Bad("Invalid action".into())),
        })
    })
}

#[derive(Deserialize)]
pub struct DeliveryForm {
    #[serde(default)]
    allow_private: String,
}

pub async fn admin_delivery(State(st): St, User(user): User, Form(form): Form<DeliveryForm>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        crate::settings::set_private_webhooks(&st.db()?, !form.allow_private.is_empty())?;
        Ok(flash_redirect(&st, "/admin/notifications?tab=delivery", "Delivery settings saved."))
    })
}

/// Test, enable/disable or stop a rule of any project
pub async fn admin_rule_action(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(form): Form<ActionForm>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let item = db.get_notification(id)?.ok_or(AppError::NotFound)?;
        let name = item.notification.name.clone();
        let back = "/admin/notifications";
        Ok(match form.action.as_str() {
            "toggle" => {
                db.admin_toggle_notification(id)?;
                flash_redirect(&st, back, &format!("Notification to “{name}” updated."))
            }
            "delete" => {
                db.admin_delete_notification(id)?;
                flash_redirect(&st, back, &format!("Notification to “{name}” stopped."))
            }
            "test" => {
                let config = st.effective_config(&db)?;
                let project_id = db.find_project(&item.org, &item.project)?.unwrap_or_default();
                let dispatch = notify::test_dispatch(item.notification, project_id, &item.org, &item.project);
                match notify::send(&config, &db, &dispatch) {
                    Ok(()) => flash_redirect(&st, back, &format!("Test sent through “{name}”.")),
                    Err(e) => flash_redirect(&st, back, &format!("Test through “{name}” failed: {e}")),
                }
            }
            _ => return Err(AppError::Bad("Invalid action".into())),
        })
    })
}

// ==========================================
// Browser notifications (Web Push)
// ==========================================

/// Part of the user's Settings page
pub fn settings_section(db: &Database, user: &crate::db::Account) -> Result<Markup, AppError> {
    let browsers = db.list_push_subscriptions(user.id)?;
    Ok(html! {
        h2 { "Browser notifications" }
        div.card id="push-box" {
            p data-status { "Checking this browser…" }
            div.row {
                button type="button" data-enable hidden { "Enable on this browser" }
                button.secondary type="button" data-disable hidden { "Disable on this browser" }
            }
            p.muted {
                "You are notified here by the projects that send to “browser notifications”, and when a synchronization you started is over. "
                "The message only wakes your browser, which then asks Vulnizard for the content: nothing about your vulnerabilities goes through the browser vendor's push service. "
                "Requires HTTPS (or localhost)."
            }
            @if !browsers.is_empty() {
                p.muted { (browsers.len()) " browser(s) enabled for your account:" }
                ul.plain {
                    @for (_, label) in &browsers { li.muted { (label.as_deref().unwrap_or("unnamed browser")) } }
                }
            }
        }
        script src="/static/push.js" defer {}
    })
}

/// Public key the browser needs to subscribe
pub async fn push_key(State(st): St, User(_): User) -> Result<Json<Value>, AppError> {
    blocking(|| Ok(Json(json!({ "key": crate::push::public_key(&st.db()?)? }))))
}

#[derive(Deserialize)]
pub struct SubscriptionBody {
    endpoint: String,
    #[serde(default)]
    label: String,
}

pub async fn push_subscribe(State(st): St, User(user): User, Json(body): Json<SubscriptionBody>) -> Result<Json<Value>, AppError> {
    blocking(|| {
        // The endpoint comes from the browser: only a public https push service is accepted
        crate::push::check_endpoint(&st.config, &body.endpoint)
            .map_err(|_| AppError::Bad("Invalid push endpoint.".into()))?;
        let label: String = body.label.chars().filter(|c| !c.is_control()).take(80).collect();
        let db = st.db()?;
        if db.list_push_subscriptions(user.id)?.len() >= MAX_PUSH_SUBSCRIPTIONS {
            return Err(AppError::Bad("Too many browsers registered.".into()));
        }
        db.add_push_subscription(user.id, &body.endpoint, Some(&label).filter(|l| !l.is_empty()).map(|l| l.as_str()))?;
        Ok(Json(json!({ "ok": true })))
    })
}

pub async fn push_unsubscribe(State(st): St, User(user): User, Json(body): Json<SubscriptionBody>) -> Result<Json<Value>, AppError> {
    blocking(|| {
        st.db()?.remove_push_subscription(user.id, &body.endpoint)?;
        Ok(Json(json!({ "ok": true })))
    })
}

/// Messages waiting for the signed-in user; read (and removed) by the service
/// worker when a push wakes it. Without a session the list is empty.
pub async fn push_inbox(State(st): St, headers: axum::http::HeaderMap, MaybeUser(user): MaybeUser) -> Result<impl IntoResponse, AppError> {
    // Reading empties the inbox: another site must not be able to trigger it
    let cross_site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|site| site != "same-origin");
    let items = match user.filter(|_| !cross_site) {
        Some(user) => blocking(|| st.db()?.push_take(user.id).map_err(AppError::from))?,
        None => Vec::new(),
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(items)))
}

pub async fn push_script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("push.js"),
    )
}

pub async fn service_worker() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("sw.js"),
    )
}
