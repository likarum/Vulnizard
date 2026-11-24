//! Notifications in the UI: destinations (where messages go, and what each
//! one sends), in the project settings for those of the project and in the
//! administration for all of them; browser notifications (Web Push).

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
use super::{blocking, AppError, MaybeUser, St, User};
use crate::changes::EVENT_TYPES;
use crate::config::Config;
use crate::db::{Database, Destination, Org, OrgProject, DESTINATION_KINDS};
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

/// Name of an event type in a column header or a summary
fn event_short(kind: &str) -> &'static str {
    match kind {
        "created" => "New CVE",
        "description" => "Description",
        "metrics" => "CVSS",
        "vendors" => "Vendors/products",
        "references" => "References",
        "weaknesses" => "Weaknesses",
        "kev" => "CISA KEV",
        "service" => "New service",
        _ => "Other",
    }
}

/// What a form says a destination sends: the event types checked under
/// `events` and the minimum CVSS under `min_cvss` (the names of the fields)
fn events_and_cvss(fields: &Fields, events: &str, min_cvss: &str) -> Result<(Vec<String>, Option<f64>), AppError> {
    let checked: Vec<String> = EVENT_TYPES
        .iter()
        .filter(|(kind, _)| fields.iter().any(|(k, v)| k == events && v == kind))
        .map(|(kind, _)| kind.to_string())
        .collect();
    let min_cvss = match field(fields, min_cvss) {
        "" => None,
        raw => Some(
            raw.parse::<f64>()
                .ok()
                .filter(|v| (0.0..=10.0).contains(v))
                .ok_or_else(|| AppError::Bad("Minimum CVSS must be between 0 and 10.".into()))?,
        ),
    };
    Ok((checked, min_cvss))
}

fn cvss_value(min_cvss: Option<f64>) -> String {
    min_cvss.map(|m| format!("{m:.1}")).unwrap_or_default()
}

/// The event types a destination sends, in words
fn events_summary(events: &[String]) -> String {
    let known: Vec<&str> = EVENT_TYPES.iter().filter(|(kind, _)| events.iter().any(|e| e == kind)).map(|(kind, _)| *kind).collect();
    if known.len() == EVENT_TYPES.len() {
        "every event".to_string()
    } else if known.is_empty() {
        "no event".to_string()
    } else {
        known.iter().map(|kind| event_short(kind)).collect::<Vec<_>>().join(", ")
    }
}

/// What a destination covers: the projects whose notifications it receives
fn covers(d: &Destination) -> Markup {
    html! {
        @match d.scope.as_str() {
            "instance" => { "all projects" }
            "organization" => { "projects of organization " (d.scope_label) }
            _ => { "project " (d.scope_label) }
        }
    }
}

/// What a destination sends, as it is set on it
fn sends(d: &Destination) -> Markup {
    let silent = d.events.is_empty() && !d.system_events;
    html! {
        @if !d.enabled {
            span.muted { "nothing: disabled" }
        } @else if silent {
            span.muted { "nothing: no event checked" }
        } @else {
            @if !d.events.is_empty() {
                (events_summary(&d.events))
                @if let Some(m) = d.min_cvss.filter(|m| *m > 0.0) { ", CVSS " (format!("{m:.1}")) " and above" }
            }
            @if d.system_events {
                div.muted { @if d.events.is_empty() { "only instance events (sync finished)" } @else { "and instance events (sync finished)" } }
            }
        }
    }
}

// ==========================================
// Project settings
// ==========================================

/// Notification part of the project settings: one table of the destinations
/// belonging to the project, with what each one sends, editable in place.
/// Destinations of the organization and of the instance are not listed: they
/// are not managed here, and their names and targets belong to whoever
/// manages them. `new_kind` shows the creation form.
pub fn project_section(
    db: &Database,
    _config: &Config,
    org: &Org,
    project: &OrgProject,
    new_kind: Option<&str>,
) -> Result<Markup, AppError> {
    let destinations = db.list_project_destinations(project.id)?;
    let manage = org.can(Permission::ManageProjects);
    let base = format!("/orgs/{}/projects/{}", enc(&org.name), enc(&project.name));
    let settings_url = product_url(Some((&org.name, &project.name)), "settings");
    let new_kind = new_kind.filter(|k| DESTINATION_KINDS.iter().any(|(kind, _)| kind == k));
    let columns = format!("- check{} flag act", " check".repeat(EVENT_TYPES.len()));

    Ok(html! {
        h2 { "Notifications" }
        p.muted {
            "Sent after each sync when a CVE of a subscribed vendor or product changes. "
            "One row per destination of this project: check the events it is told about. "
            "A destination with no event checked sends nothing for this project."
        }
        form method="post" action={ (base) "/notifications" } {
            table.list.fit.events {
                (views::columns(&columns, true))
                thead {
                    tr {
                        th { "Destination" }
                        th.up title="Enabled: unchecked, the destination sends nothing" { span { "Enabled" } }
                        @for (kind, label) in EVENT_TYPES { th.up title=(label) { span { (event_short(kind)) } } }
                        th { "Min CVSS" }
                        th {}
                    }
                }
                tbody {
                    @for d in &destinations {
                        tr {
                            td {
                                (d.name)
                                div.muted {
                                    (kind_label(&d.kind))
                                    // A webhook URL or a topic is a secret of whoever manages the destination
                                    @if manage && d.kind != "browser" { " · " (views::truncate(&d.target(), 60)) }
                                }
                                @if manage { input type="hidden" name="id" value=(d.id); }
                            }
                            td.tick data-label="Enabled" {
                                input type="checkbox" name={ "enabled_" (d.id) } value="1" checked[d.enabled] disabled[!manage]
                                    aria-label={ "Enabled: " (d.name) };
                            }
                            @for (kind, label) in EVENT_TYPES {
                                td.tick data-label=(event_short(kind)) {
                                    input type="checkbox" name={ "events_" (d.id) } value=(kind)
                                        checked[d.events.iter().any(|e| e == kind)] disabled[!manage]
                                        aria-label={ (label) ": " (d.name) };
                                }
                            }
                            td data-label="Min CVSS" {
                                input type="number" name={ "min_cvss_" (d.id) } min="0" max="10" step="0.1"
                                    value=(cvss_value(d.min_cvss)) disabled[!manage] aria-label={ "Minimum CVSS: " (d.name) };
                            }
                            td.right.actions {
                                @if manage {
                                    // Its form is outside the table one: Enter in a field saves, it never deletes
                                    button.small.danger type="submit" form={ "delete-destination-" (d.id) } { "Delete" }
                                }
                            }
                        }
                    }
                    @if destinations.is_empty() {
                        tr { td colspan=(EVENT_TYPES.len() + 4) .muted { "This project has no destination of its own yet." } }
                    }
                }
            }
            @if manage && !destinations.is_empty() {
                p { button type="submit" { "Save notifications" } }
            }
        }
        @if manage {
            @for d in &destinations {
                form id={ "delete-destination-" (d.id) } method="post" action={ (base) "/destinations/" (d.id) "/delete" } {}
            }
        }
        p.muted {
            "Destinations of the organization or of the whole instance, if there are any, also receive the notifications of this project. "
            "They are managed by their administrators, not here."
        }
        @if manage {
            @match new_kind {
                Some(kind) => {
                    h2 { "New destination: " (kind_label(kind)) }
                    (kind_chips(&settings_url, Some(kind)))
                    form.stack.card method="post" action={ (base) "/destinations" } {
                        (destination_fields(kind, false))
                        p.muted { "It starts with every event checked: uncheck in the table what it should not send." }
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

/// Creates a destination belonging to the project. It sends every event
/// until the table says otherwise.
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
        db.create_destination("project", Some(project.id), name, kind, &settings, false)
            .map_err(AppError::bad)?;
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

/// Saves the table of the project settings: for each destination of the
/// project named by an `id` field, the events checked (`events_<id>`), the
/// minimum CVSS (`min_cvss_<id>`) and whether it is enabled (`enabled_<id>`).
/// A destination that is not one of this project is refused, whatever it is.
pub async fn project_notifications_save(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let own = db.list_project_destinations(project.id)?;
        // Everything is checked before anything is written
        let mut changes = Vec::new();
        for (_, raw) in fields.iter().filter(|(k, _)| k == "id") {
            let id: i64 = raw.trim().parse().map_err(|_| AppError::NotFound)?;
            if !own.iter().any(|d| d.id == id) {
                return Err(AppError::NotFound);
            }
            let (events, min_cvss) = events_and_cvss(&fields, &format!("events_{id}"), &format!("min_cvss_{id}"))?;
            changes.push((id, events, min_cvss, !field(&fields, &format!("enabled_{id}")).is_empty()));
        }
        for (id, events, min_cvss, enabled) in changes {
            db.update_destination_settings(id, &events, min_cvss, enabled, None)?;
        }
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}

// ==========================================
// Administration
// ==========================================

#[derive(Deserialize, Default)]
pub struct AdminQuery {
    tab: Option<String>,
    /// Type of the destination being added
    new: Option<String>,
    /// Browser destination whose test found no browser to send to: the page
    /// offers to enable notifications on this one
    enable: Option<i64>,
}

/// Choices of the "belongs to" selector of an instance or organization destination
fn owner_choices(db: &Database) -> Result<Vec<(String, String)>, AppError> {
    let mut choices = vec![("instance".to_string(), "Whole instance (receives the notifications of every project)".to_string())];
    for (_, org) in db.list_all_orgs()? {
        choices.push((format!("organization:{org}"), format!("Organization {org} (receives those of its projects)")));
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
            "destinations" => admin_destinations(&db, &config, &user, q.new.as_deref(), q.enable)?,
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
                    ("/admin/notifications", "Per project", tab == "projects"),
                    ("/admin/notifications?tab=destinations", "Destinations", tab == "destinations"),
                    ("/admin/notifications?tab=delivery", "Delivery", tab == "delivery"),
                ]))
                (body)
            },
        ))
    })?;
    Ok(with_flash_cleared(&st, &flash, page))
}

/// Tab: for each project, every destination that receives its notifications
fn admin_rules(db: &Database) -> Result<Markup, AppError> {
    let mut all = db.list_all_notifications()?;
    let total = all.len();
    let owner = |scope: &str| match scope {
        "project" => "the project",
        "organization" => "its organization",
        _ => "the instance",
    };
    let listing = views::Listing::from_page("project", false);
    listing.apply(
        &mut all,
        |i| format!("{} {} {} {} {}", i.org, i.project, i.notification.name, i.notification.kind, owner(&i.notification.scope)),
        |i, column| match column {
            "project" => Some(views::SortKey::text(format!("{} {}", i.org, i.project))),
            "name" => Some(views::SortKey::text(&i.notification.name)),
            "type" => Some(views::SortKey::text(&i.notification.kind)),
            "owner" => Some(views::SortKey::text(owner(&i.notification.scope))),
            "status" => Some(views::SortKey::num(i.notification.enabled as u8)),
            _ => None,
        },
    );
    Ok(html! {
        p.muted {
            "For each project, the destinations that receive its notifications: its own, those of its organization and those of the instance. "
            "What a destination sends is set on the destination (the gear in the Destinations tab, or the settings of the project for its own). "
            "The test sends a sample change of that project."
        }
        (listing.filter_box("Filter: project, destination, type…", all.len(), total))
        div.scroll {
            table.list.fit.dense {
                (views::columns("project name kind who - flag flag act", true))
                thead {
                    tr {
                        (listing.th("project", "Project")) (listing.th("name", "Destination")) (listing.th("type", "Type"))
                        (listing.th("owner", "Belongs to")) th { "Events" } th { "Min CVSS" } (listing.th("status", "Status")) th {}
                    }
                }
                tbody {
                    @for item in &all {
                        @let n = &item.notification;
                        tr {
                            td.project { a href=(product_url(Some((&item.org, &item.project)), "settings")) title=(item.project) { (item.project) } " " span.muted { (item.org) } }
                            td { a href={ "/admin/notifications/destinations/" (n.id) } { (n.name) } }
                            td { (kind_label(&n.kind)) }
                            td { (owner(&n.scope)) }
                            td { (events_summary(&n.events)) }
                            td { @if let Some(m) = n.min_cvss { (format!("{m:.1}")) } @else { "—" } }
                            td { @if !n.enabled { span.muted { "disabled" } } @else if n.events.is_empty() { span.muted { "sends nothing" } } @else { "enabled" } }
                            td.right.actions {
                                form.inline method="post" action={ "/admin/notifications/" (n.id) } {
                                    input type="hidden" name="project" value=(item.project_id);
                                    button.small type="submit" name="action" value="test" { "Send test" }
                                }
                            }
                        }
                    }
                    @if all.is_empty() { tr { td colspan="8" .muted { "No destination receives the notifications of a project yet." } } }
                }
            }
        }
    })
}

/// Tab: every destination, whatever it belongs to
fn admin_destinations(
    db: &Database,
    config: &Config,
    user: &crate::db::Account,
    new_kind: Option<&str>,
    enable: Option<i64>,
) -> Result<Markup, AppError> {
    let mut all = db.list_all_destinations()?;
    let total = all.len();
    // Only while it is still true: once a browser is registered the test is simply sent
    let enable = match enable.and_then(|id| all.iter().find(|d| d.id == id && d.kind == "browser")) {
        Some(destination) if db.list_push_subscriptions(user.id)?.is_empty() => Some(push_test_offer(destination)),
        _ => None,
    };
    let listing = views::Listing::from_page("owner", false);
    listing.apply(
        &mut all,
        |d| format!("{} {} {} {} {}", d.name, d.kind, d.target(), d.scope, d.scope_label),
        |d, column| match column {
            "name" => Some(views::SortKey::text(&d.name)),
            "type" => Some(views::SortKey::text(&d.kind)),
            "owner" => Some(views::SortKey::text(format!("{} {}", d.scope, d.scope_label))),
            _ => None,
        },
    );
    let new_kind = new_kind.filter(|k| DESTINATION_KINDS.iter().any(|(kind, _)| kind == k));
    let base = "/admin/notifications?tab=destinations";
    Ok(html! {
        p.muted {
            "Every destination. What it belongs to decides what it receives, by itself: a destination of the instance gets the notifications of every project, "
            "one of an organization those of its projects, one of a project those of that project. "
            "The gear opens what it sends: event types, minimum CVSS, enabled or not. "
            "“Browser notifications” reach the people who enabled them for their browser in their own Settings; a test goes to your browsers."
        }
        @if let Some(offer) = enable { (offer) }
        (listing.filter_box("Filter: name, type, target, owner…", all.len(), total))
        div.scroll {
            table.list.fit.dense {
                (views::columns("- kind - - wide actions", true))
                thead {
                    tr {
                        (listing.th("name", "Name")) (listing.th("type", "Type")) th { "Target" }
                        (listing.th("owner", "Covers")) th { "Sends" } th {}
                    }
                }
                tbody {
                    @for d in &all {
                        tr {
                            td { (d.name) }
                            td { (kind_label(&d.kind)) }
                            td { (views::truncate(&d.target(), 50)) }
                            td { (covers(d)) }
                            td { (sends(d)) }
                            td.right.actions {
                                a.btn.gear href={ "/admin/notifications/destinations/" (d.id) } title="Configure what it sends"
                                    aria-label={ "Configure " (d.name) } { span aria-hidden="true" { "\u{2699}\u{fe0e}" } }
                                " "
                                form.inline method="post" action={ "/admin/notifications/destinations/" (d.id) } {
                                    button.small type="submit" name="action" value="test" { "Send test" }
                                    " "
                                    button.small.danger type="submit" name="action" value="delete" { "Delete" }
                                }
                            }
                        }
                    }
                    @if all.is_empty() { tr { td colspan="6" .muted { "No destination yet." } } }
                }
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
                        input type="checkbox" name="system_events" value="1" checked;
                        " Also tell it when a manual synchronization finishes (instance destinations only)"
                    }
                    p.muted { "It starts enabled, with every event checked and no minimum CVSS: its gear in the list changes that." }
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

/// Shown when a test through a browser destination found none of the
/// administrator's browsers registered: a button enables notifications on
/// this browser (push.js: permission, registration) and then sends the test.
/// Without JavaScript, or where the browser cannot receive notifications, the
/// button stays hidden and the text points to the Settings page.
fn push_test_offer(destination: &Destination) -> Markup {
    html! {
        div.card.notice id="push-test" {
            p {
                strong { "Test through “" (destination.name) "”: none of your browsers is registered." }
                " Browser notifications reach each person on the browsers they enabled, and a test goes to yours."
            }
            p data-fallback {
                "Enable notifications for this browser first, in "
                a href="/settings" { "Settings → Browser notifications" }
                ", then send the test again."
            }
            p data-status hidden {}
            form method="post" action={ "/admin/notifications/destinations/" (destination.id) } {
                input type="hidden" name="action" value="test";
                button type="button" data-enable hidden { "Enable notifications on this browser and send the test" }
            }
        }
        script src="/static/push.js" defer {}
    }
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

/// Configuration of one destination (the gear of the list): what it sends
pub async fn admin_destination(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let d = db.get_destination(id)?.ok_or(AppError::NotFound)?;
        let back = "/admin/notifications?tab=destinations";
        Ok(layout(
            Nav::Admin,
            "Notifications",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("notifications"))
                p { a href=(back) { "← Destinations" } }
                h2 { "Destination “" (d.name) "”" }
                p.muted {
                    (kind_label(&d.kind)) " · " (views::truncate(&d.target(), 80)) " · receives the notifications of "
                    (covers(&d)) "."
                }
                form.stack.card method="post" action={ "/admin/notifications/destinations/" (d.id) } {
                    input type="hidden" name="action" value="save";
                    label.check { input type="checkbox" name="enabled" value="1" checked[d.enabled]; " Enabled (unchecked, it sends nothing)" }
                    fieldset {
                        legend { "Events it sends (none checked = nothing about CVEs and projects)" }
                        @for (kind, label) in EVENT_TYPES {
                            label { input type="checkbox" name="events" value=(kind) checked[d.events.iter().any(|e| e == kind)]; " " (label) }
                        }
                    }
                    label { "Minimum CVSS (empty = none)" input type="number" name="min_cvss" min="0" max="10" step="0.1" value=(cvss_value(d.min_cvss)); }
                    @if d.scope == "instance" {
                        fieldset {
                            legend { "Instance events" }
                            label { input type="checkbox" name="system_events" value="1" checked[d.system_events]; " A manual synchronization finished" }
                        }
                    }
                    div.row {
                        button type="submit" { "Save" }
                        " " a href=(back) { "Cancel" }
                    }
                }
            },
        ))
    })
}

/// Save what a destination sends, test it or delete it
pub async fn admin_destination_action(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let destination = db.get_destination(id)?.ok_or(AppError::NotFound)?;
        let back = "/admin/notifications?tab=destinations";
        Ok(match field(&fields, "action") {
            "save" => {
                let (events, min_cvss) = events_and_cvss(&fields, "events", "min_cvss")?;
                let enabled = !field(&fields, "enabled").is_empty();
                let system_events = !field(&fields, "system_events").is_empty();
                db.update_destination_settings(id, &events, min_cvss, enabled, Some(system_events))?;
                flash_redirect(&st, back, &format!("Destination “{}” saved.", destination.name))
            }
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
                        // Nowhere to send it yet: not a failure, the page offers to enable this browser
                        return Ok(redirect(format!("{back}&enable={id}")));
                    }
                    crate::push::deliver(&db, &config, user.id, "Vulnizard test", "Browser notifications work.", "/settings").and_then(
                        |reached| match reached {
                            0 => Err(anyhow::anyhow!(
                                "the push service refused or did not answer for your {registered} registered browser(s) (see the server log)"
                            )),
                            n => Ok(format!("sent to {n} of your {registered} registered browser(s)")),
                        },
                    )
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

/// Sends a sample change of a project through a destination that receives
/// its notifications (`id`: the destination, `project`: the project)
pub async fn admin_project_test(
    State(st): St,
    User(user): User,
    Path(id): Path<i64>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        if field(&fields, "action") != "test" {
            return Err(AppError::Bad("Invalid action".into()));
        }
        let project: i64 = field(&fields, "project").parse().map_err(|_| AppError::NotFound)?;
        // Only a destination that covers this project
        let item = db
            .list_all_notifications()?
            .into_iter()
            .find(|n| n.project_id == project && n.notification.id == id)
            .ok_or(AppError::NotFound)?;
        let name = item.notification.name.clone();
        let back = "/admin/notifications";
        let config = st.effective_config(&db)?;
        let dispatch = notify::test_dispatch(item.notification, project, &item.org, &item.project);
        Ok(match notify::send(&config, &db, &dispatch) {
            Ok(()) => flash_redirect(&st, back, &format!("Test sent through “{name}”.")),
            Err(e) => flash_redirect(&st, back, &format!("Test through “{name}” failed: {e}")),
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
/// worker when a push wakes it. Without a session nothing answers (the worker
/// then shows its generic message).
pub async fn push_inbox(State(st): St, headers: axum::http::HeaderMap, MaybeUser(user): MaybeUser) -> Result<axum::response::Response, AppError> {
    let Some(user) = user else {
        return Ok((axum::http::StatusCode::UNAUTHORIZED, [(header::CACHE_CONTROL, "no-store")], Json(json!({ "error": "sign in" }))).into_response());
    };
    // Reading empties the inbox: another site must not be able to trigger it
    let cross_site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|site| site != "same-origin");
    let items = if cross_site {
        Vec::new()
    } else {
        blocking(|| st.db()?.push_take(user.id).map_err(AppError::from))?
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response())
}

pub async fn push_script(headers: axum::http::HeaderMap) -> impl IntoResponse {
    super::pages::asset(&headers, "text/javascript; charset=utf-8", include_str!("push.js"))
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
