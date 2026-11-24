//! Inventory in the UI and the API: sources of a project (pushed by a
//! collector, or a file read in a Git repository), the checklist of the
//! components they discovered, and the ingestion endpoint.

use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use maud::{html, Markup};
use serde_json::{json, Value};

use super::pages::{load_project, redirect, require, ActionResult, HtmlResult};
use super::views::{self, enc, layout, product_url, Nav};
use super::{blocking, ApiError, AppError, AppState, St, User};
use crate::auth;
use crate::db::{Actor, Candidate, Database, InventorySource, Org, OrgProject};
use crate::inventory::{self, GitSource, GIT_PROVIDERS};
use crate::rbac::Permission;

type Fields = Vec<(String, String)>;

fn field<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .unwrap_or("")
}

fn signals(c: &Candidate) -> Markup {
    html! {
        @if c.probable_service() { strong { "probable service " } }
        @if c.exposed { span.tag.kev title="Reported as listening on the network" { "exposed" } " " }
        @if c.known_service { span.tag title="Well-known network service" { "service" } " " }
        @if c.known_cves > 0 { span.tag title="CVEs already published for a product of this name" { (c.known_cves) " CVEs known" } }
        @if !c.exposed && !c.known_service && c.known_cves == 0 { span.muted { "—" } }
    }
}

/// Part of the Applications view of a project: the checklist of discovered
/// components and the inventory sources.
/// The inventory is not part of the first release: closed unless enabled in
/// the configuration (`[inventory] enabled = true`).
fn require_enabled(st: &AppState) -> Result<(), AppError> {
    if st.config.inventory.enabled {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// What the Applications view shows while the feature is closed
fn unavailable_section() -> Markup {
    html! {
        section.unavailable aria-disabled="true" {
            h2 { "Discovered on your infrastructure " span.tag { "Not in this release" } }
            p {
                "Inventory sources will report what is deployed — pushed by a collector or read from a file in a Git "
                "repository — so that versions no longer have to be typed by hand. Planned for a later release."
            }
            div.row {
                button.secondary type="button" disabled { "Pushed by a collector" }
                " "
                button.secondary type="button" disabled { "File in a Git repository" }
            }
        }
    }
}

pub fn project_section(
    db: &Database,
    st: &AppState,
    org: &Org,
    project: &OrgProject,
    show: Option<&str>,
    new_kind: Option<&str>,
) -> Result<Markup, AppError> {
    if !st.config.inventory.enabled {
        return Ok(unavailable_section());
    }
    let sources = db.list_inventory_sources(project.id)?;
    let candidates = db.list_candidates(project.id)?;
    let manage = org.can(Permission::ManageProjects);
    let base = format!("/orgs/{}/projects/{}", enc(&org.name), enc(&project.name));
    let view = product_url(Some((&org.name, &project.name)), "applications");
    let show = match show {
        Some("ignored") => "ignored",
        Some("all") => "all",
        _ => "new",
    };
    let count = |state: &str| candidates.iter().filter(|c| c.state == state).count();
    let listed: Vec<&Candidate> = candidates.iter().filter(|c| show == "all" || c.state == show).collect();
    let new_kind = new_kind.filter(|k| matches!(*k, "push" | "git"));

    Ok(html! {
        @if !sources.is_empty() {
            h2 { "Discovered on your infrastructure" }
            p.muted {
                "Components reported by the inventory sources. Tick those you want to monitor: they become tracked applications "
                "that follow the deployed version. The most likely to matter come first — exposed on the network, well-known "
                "services, products with a CVE history."
            }
            div.chips {
                a href=(view) class=[(show == "new").then_some("active")] { "To choose (" (count("new")) ")" }
                a href={ (view) "&show=ignored" } class=[(show == "ignored").then_some("active")] { "Ignored (" (count("ignored")) ")" }
                a href={ (view) "&show=all" } class=[(show == "all").then_some("active")] { "All (" (candidates.len()) ")" }
            }
            form method="post" action={ (base) "/inventory/choose" } {
                table.list.fit {
                    (views::columns("check name kind - who kind", true))
                    thead { tr { th {} th { "Component" } th { "Version" } th { "Why it may matter" } th { "Source" } th { "State" } } }
                    tbody {
                        @for c in &listed {
                            tr {
                                td { @if manage { input type="checkbox" name="ids" value=(c.id) aria-label={ "Select " (c.name) }; } }
                                td { strong { (c.name) } @if let Some(v) = &c.vendor { " " span.muted { (v) } } }
                                td { (c.version.as_deref().unwrap_or("—")) }
                                td { (signals(c)) }
                                td { (c.source) }
                                td {
                                    @match c.state.as_str() {
                                        "monitored" => { "monitored" }
                                        "ignored" => { span.muted { "ignored" } }
                                        _ => { "to choose" }
                                    }
                                }
                            }
                        }
                        @if listed.is_empty() { tr { td colspan="6" .muted { "Nothing here." } } }
                    }
                }
                @if manage && !listed.is_empty() {
                    div.row {
                        button type="submit" name="action" value="monitor" { "Monitor the selected" }
                        button.secondary type="submit" name="action" value="ignore" { "Ignore the selected" }
                    }
                }
            }
        }

        h2 { "Inventory sources" }
        p.muted {
            "A source tells Vulnizard what is deployed, so you do not type versions by hand. "
            "Each delivery replaces the previous list of that source."
        }
        div.scroll {
            table.list.fit.dense {
                (views::columns("name kind - - when - actions", true))
                thead { tr { th { "Source" } th { "Group" } th { "How" } th { "Reads" } th { "Last delivery (UTC)" } th { "Result" } th {} } }
                tbody {
                    @for s in &sources {
                        tr {
                            td { strong { (s.name) } }
                            td { span.tag { (s.group) } }
                            td {
                                @if s.kind == "git" { "file in a Git repository" } @else { "pushed by a collector" }
                                @if s.auto_monitor { div.muted { "monitors everything" } }
                            }
                            td {
                                @match GitSource::from_config(&s.config).filter(|_| s.kind == "git") {
                                    Some(git) => { code { (git.file_url()) } }
                                    None => { span.muted { "what the collector sends" } }
                                }
                            }
                            td.nowrap { (s.last_run_at.as_deref().unwrap_or("never")) }
                            td {
                                @match s.last_status.as_deref() {
                                    Some("ok") => { (s.components) " components" }
                                    Some(_) => { span.error { "failed" } @if let Some(e) = &s.last_error { div.muted { (views::truncate(e, 160)) } } }
                                    None => { span.muted { "waiting for a first delivery" } }
                                }
                            }
                            td.right.actions {
                                @if manage {
                                    @if s.kind == "git" {
                                        form.inline method="post" action={ (base) "/inventory/sources/" (s.id) "/run" } {
                                            button.small.secondary type="submit" { "Read now" }
                                        }
                                        " "
                                    }
                                    form.inline method="post" action={ (base) "/inventory/sources/" (s.id) "/delete" } {
                                        button.small.danger type="submit" { "Delete" }
                                    }
                                }
                            }
                        }
                    }
                    @if sources.is_empty() { tr { td colspan="7" .muted { "No source yet." } } }
                }
            }
        }
        @if manage {
            @match new_kind {
                Some("git") => { (git_form(st, &base, &view)) }
                Some(_) => { (push_form(&base, &view)) }
                None => {
                    p { strong { "Add a source: " } }
                    div.chips {
                        a href={ (view) "&new=push" } { "Pushed by a collector" }
                        a href={ (view) "&new=git" } { "File in a Git repository" }
                    }
                }
            }
        }
    })
}

/// Fields common to every kind of source
fn common_fields(placeholder: &str) -> Markup {
    html! {
        label { "Name" input type="text" name="name" maxlength="64" required placeholder=(placeholder); }
        label {
            "Group (optional)"
            input type="text" name="group" maxlength="64" placeholder="e.g. web";
        }
        p.muted {
            "Sources with the same group are triaged together: ten identical web servers in the group “web” show each package once, "
            "and a decision on a CVE holds for the whole group. Left empty, the source is its own group."
        }
        label.check {
            input type="checkbox" name="auto_monitor" value="1";
            " Monitor everything this source reports (for a machine's package list: no need to tick each package)"
        }
    }
}

fn push_form(base: &str, view: &str) -> Markup {
    html! {
        h2 { "New source: pushed by a collector" }
        div.card.notice {
            p { strong { "How it works" } }
            ol.steps {
                li { "You get a token that can do one thing only: deliver the inventory of this source. What it delivers updates the applications monitored through this source." }
                li { "A collector (in your CI, in a deployment hook or on the host) sends the list of components with that token." }
                li { "Nothing is read from your infrastructure by Vulnizard, and no access to it is stored here." }
            }
        }
        form.stack.card method="post" action={ (base) "/inventory/sources" } {
            input type="hidden" name="kind" value="push";
            (common_fields("e.g. web-01"))
            div.row {
                button type="submit" { "Create and show the token" }
                " " a href=(view) { "Cancel" }
            }
        }
    }
}

fn git_form(st: &AppState, base: &str, view: &str) -> Markup {
    html! {
        h2 { "New source: file in a Git repository" }
        div.card.notice {
            p { strong { "What Vulnizard does with your repository" } }
            ol.steps {
                li { "It downloads " strong { "one file" } " — the inventory file you name below — over HTTPS, at each synchronization." }
                li { "It never clones the repository, never reads another file, and never writes to it." }
                li { "The access token you give must be " strong { "read-only" } " (a deploy token limited to this repository). It is stored in the database and never shown again." }
                li { "The file is produced by your pipeline: run the collector with " code { "--output" } " and commit the result, or generate a CycloneDX SBOM." }
            }
            p.muted {
                "File format: " code { r#"{"components":[{"name":"nginx","version":"1.30.6","vendor":"f5","exposed":true}]}"# }
                " or a CycloneDX JSON document."
            }
        }
        form.stack.card method="post" action={ (base) "/inventory/sources" } {
            input type="hidden" name="kind" value="git";
            (common_fields("e.g. nixos-repo"))
            label {
                "Git server"
                select name="provider" {
                    @for (key, label) in GIT_PROVIDERS { option value=(key) { (label) } }
                }
            }
            label {
                "Repository URL (for “Other”: the full URL of the file)"
                input type="url" name="repository" maxlength="500" required placeholder="https://git.example.org/owner/repo";
            }
            label { "Branch" input type="text" name="branch" maxlength="100" value="main"; }
            label { "Path of the inventory file in the repository" input type="text" name="path" maxlength="300" placeholder="inventory/io.json"; }
            label {
                "Read-only access token (leave empty for a public repository)"
                input type="password" name="token" maxlength="500" autocomplete="new-password";
            }
            div.row {
                button type="submit" { "Add and read now" }
                " " a href=(view) { "Cancel" }
            }
        }
        @if !st.config.web.allow_private_webhooks {
            p.muted {
                "A Git server on a private network requires “Allow private targets” in Admin → Notifications → Delivery."
            }
        }
    }
}

/// The first time an inventory reports system packages, the advisories of
/// their distribution are not loaded yet: fetch them now rather than at the
/// next periodic sync (the scheduler rescans the applications afterwards).
fn ensure_distro_advisories(st: &AppState, db: &Database) {
    let missing = matches!((db.has_distro_components(), db.has_distro_advisories()), (Ok(true), Ok(false)));
    if !missing {
        return;
    }
    let order = crate::scheduler::SyncOrder {
        request: crate::scheduler::SyncRequest::Source("distros".into()),
        by: None,
    };
    let sent = st.sync_trigger.lock().map(|tx| tx.send(order).is_ok()).unwrap_or(false);
    if sent {
        let mut queued = st.sync_queue.lock().unwrap_or_else(|e| e.into_inner());
        if !queued.iter().any(|s| s == "distros") {
            queued.push("distros".into());
        }
    }
}

/// Creates a source. A push source shows its token once; a Git source is
/// read at once so that a mistake is visible immediately.
pub async fn source_create(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(fields): Form<Fields>,
) -> HtmlResult {
    require_enabled(&st)?;
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let name = field(&fields, "name");
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(AppError::Bad("Invalid source name.".into()));
        }
        let group = field(&fields, "group");
        if group.chars().count() > 64 || group.chars().any(char::is_control) {
            return Err(AppError::Bad("Invalid group name.".into()));
        }
        let auto_monitor = field(&fields, "auto_monitor") == "1";
        let view = product_url(Some((&org.name, &project.name)), "applications");
        let scope = Some((org.name.as_str(), project.name.as_str()));
        match field(&fields, "kind") {
            "push" => {
                let (token, hash) = auth::new_token();
                db.create_inventory_source(project.id, name, group, "push", &json!({ "auto_monitor": auto_monitor }), Some(&hash))
                    .map_err(AppError::bad)?;
                let server = st.config.web.base_url.trim_end_matches('/');
                Ok(layout(
                    Nav::Product { scope, view: "applications" },
                    "Source created",
                    Some(&user),
                    html! {
                        h1 { "Source “" (name) "” created" }
                        div.card {
                            p { "Token of this source — copy it now, it will not be shown again:" }
                            code.token { (token) }
                            p.muted { "It can only deliver the inventory of this source — which updates, or stops tracking, the applications monitored through it. Keep it secret." }
                        }
                        h2 { "Send the inventory" }
                        p { "With the collector, which only sends what its configuration lists:" }
                        code.token { "VULNIZARD_TOKEN=<token> vulnizard-collector --server " (server) " --config collector.toml" }
                        p { "Or with any tool:" }
                        code.token {
                            "curl -X POST " (server) "/api/inventory -H \"Authorization: Bearer <token>\" -H \"Content-Type: application/json\" "
                            "-d '{\"components\":[{\"name\":\"nginx\",\"version\":\"1.30.6\",\"exposed\":true}]}'"
                        }
                        p { a.button href=(view) { "Back to the applications" } }
                    },
                ))
            }
            "git" => {
                let git = GitSource {
                    provider: field(&fields, "provider").to_string(),
                    repository: field(&fields, "repository").trim_end_matches('/').to_string(),
                    branch: field(&fields, "branch").to_string(),
                    path: field(&fields, "path").trim_start_matches('/').to_string(),
                    // Taken verbatim
                    token: fields.iter().find(|(k, _)| k == "token").map(|(_, v)| v.clone()).filter(|t| !t.is_empty()),
                };
                git.validate().map_err(|e| AppError::Bad(format!("{e}.")))?;
                let mut config = git.to_config();
                config["auto_monitor"] = json!(auto_monitor);
                let id = db
                    .create_inventory_source(project.id, name, group, "git", &config, None)
                    .map_err(AppError::bad)?;
                let source = db.get_inventory_source(project.id, id)?.ok_or(AppError::NotFound)?;
                let config = st.effective_config(&db)?;
                let outcome = inventory::pull(&db, &config, &source);
                ensure_distro_advisories(&st, &db);
                Ok(layout(
                    Nav::Product { scope, view: "applications" },
                    "Source created",
                    Some(&user),
                    html! {
                        h1 { "Source “" (name) "” created" }
                        div.card {
                            p { "Vulnizard reads this file, and only this file:" }
                            code.token { (git.file_url()) }
                        }
                        @match &outcome {
                            Ok(o) => {
                                div.card.notice {
                                    strong { "First reading succeeded: " (o.received) " components." }
                                    p { "It will be read again at each synchronization." }
                                }
                            }
                            Err(e) => {
                                div.card {
                                    p.error { strong { "The first reading failed: " } (views::truncate(&format!("{e:#}"), 300)) }
                                    p.muted { "The source is kept; fix the file, the token or the settings and use “Read now”." }
                                }
                            }
                        }
                        p { a.button href=(view) { "Back to the applications" } }
                    },
                ))
            }
            _ => Err(AppError::Bad("Invalid source type.".into())),
        }
    })
}

pub async fn source_delete(
    State(st): St,
    User(user): User,
    Path((org, project, id)): Path<(String, String, i64)>,
) -> ActionResult {
    require_enabled(&st)?;
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        if !db.delete_inventory_source(project.id, id, &Actor::user(user.id, &user.username))? {
            return Err(AppError::NotFound);
        }
        Ok(redirect(product_url(Some((&org.name, &project.name)), "applications")))
    })
}

/// Reads a Git source now
pub async fn source_run(
    State(st): St,
    User(user): User,
    Path((org, project, id)): Path<(String, String, i64)>,
) -> ActionResult {
    require_enabled(&st)?;
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let source = db.get_inventory_source(project.id, id)?.ok_or(AppError::NotFound)?;
        if source.kind != "git" {
            return Err(AppError::Bad("Only a Git source is read by Vulnizard.".into()));
        }
        let config = st.effective_config(&db)?;
        // The outcome (or the error) is recorded on the source and shown in the list
        let _ = inventory::pull(&db, &config, &source);
        ensure_distro_advisories(&st, &db);
        Ok(redirect(product_url(Some((&org.name, &project.name)), "applications")))
    })
}

/// Monitors or ignores the ticked components
pub async fn choose(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(fields): Form<Fields>,
) -> ActionResult {
    require_enabled(&st)?;
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let ids: Vec<i64> = fields
            .iter()
            .filter(|(k, _)| k == "ids")
            .filter_map(|(_, v)| v.parse().ok())
            .take(5000)
            .collect();
        if ids.is_empty() {
            return Err(AppError::Bad("Tick at least one component.".into()));
        }
        match field(&fields, "action") {
            "monitor" => db.monitor_components(project.id, &ids)?,
            "ignore" => db.ignore_components(project.id, &ids, &Actor::user(user.id, &user.username))?,
            _ => return Err(AppError::Bad("Invalid action".into())),
        };
        Ok(redirect(product_url(Some((&org.name, &project.name)), "applications")))
    })
}

/// Ingestion endpoint of the collectors: `POST /api/inventory` with the
/// token of a push source. The body is the simple format or a CycloneDX SBOM.
pub async fn api_ingest(State(st): St, headers: HeaderMap, body: String) -> Result<Json<Value>, ApiError> {
    require_enabled(&st)?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or(AppError::Unauthorized)?;
    blocking(|| {
        let db = st.db()?;
        let source: InventorySource = db
            .inventory_source_by_token(&auth::hash_token(token))?
            .ok_or(AppError::Unauthorized)?;
        let components = match inventory::parse_inventory(&body) {
            Ok(components) => components,
            Err(e) => {
                db.record_inventory_run(source.id, Some(&e.to_string()))?;
                return Err(AppError::Bad(e.to_string()).into());
            }
        };
        let outcome = db.ingest_inventory(&source, &components).map_err(AppError::bad)?;
        let config = st.effective_config(&db)?;
        inventory::announce(&db, &config, &source, &outcome);
        ensure_distro_advisories(&st, &db);
        Ok(Json(json!(outcome)))
    })
}
