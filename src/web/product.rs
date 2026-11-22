//! "My products" side: what the user runs and follows, for one project or
//! for all of them (`*`). Every view exists at both scopes.

use axum::extract::{Path, Query, State};
use chrono::{Duration, NaiveDate, Utc};
use maud::{html, Markup};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use super::charts::{self, Segment};
use super::pages::{load_project, nonempty, HtmlResult};
use super::views::{self, enc, layout, product_url, Listing, Nav, SortKey, PAGE};
use super::{blocking, AppError, St, User};
use crate::db::{
    state_at, timeline, Account, Breakdown, Database, LifecycleEvent, Org, OrgProject, ProjectSummary, TriageItem,
};
use crate::rbac::{Permission, Role};

#[derive(Deserialize, Default)]
pub struct ProductQuery {
    view: Option<String>,
    /// Review: "handled" lists the decided entries
    show: Option<String>,
    /// Evolution: day whose state is shown (YYYY-MM-DD)
    at: Option<String>,
    /// Evolution: length of the window in days
    days: Option<String>,
    /// Audit: decision filter
    decision: Option<String>,
    /// Settings: type of the notification destination being added
    new: Option<String>,
}

/// Selected project, or all the user's projects
struct Scope {
    project: Option<(Org, OrgProject)>,
    summaries: Vec<ProjectSummary>,
}

impl Scope {
    fn project_id(&self) -> Option<i64> {
        self.project.as_ref().map(|(_, p)| p.id)
    }

    fn names(&self) -> Option<(&str, &str)> {
        self.project.as_ref().map(|(o, p)| (o.name.as_str(), p.name.as_str()))
    }

    fn all(&self) -> bool {
        self.project.is_none()
    }

    fn url(&self, view: &str) -> String {
        product_url(self.names(), view)
    }

    /// Permission in the selected project (false at the `*` scope)
    fn can(&self, permission: Permission) -> bool {
        self.project.as_ref().is_some_and(|(org, _)| org.can(permission))
    }

    /// Permission in the project owning an item listed at the `*` scope
    fn can_in(&self, org: &str, project: &str, permission: Permission) -> bool {
        self.summaries
            .iter()
            .find(|p| p.org == org && p.name == project)
            .and_then(|p| Role::parse(&p.role))
            .is_some_and(|r| r.allows(permission))
    }

    /// Color slot of each project: by creation order, so a project keeps its
    /// color whatever the filter or the ranking.
    fn slots(&self) -> HashMap<i64, usize> {
        let mut ids: Vec<i64> = self.summaries.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.into_iter().enumerate().map(|(slot, id)| (id, slot)).collect()
    }
}

pub async fn product_all(State(st): St, User(user): User, Query(q): Query<ProductQuery>) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        render(&db, &st, &st.effective_config(&db)?, &user, None, &q)
    })
}

pub async fn product_project(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Query(q): Query<ProductQuery>,
) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let selected = load_project(&db, &user, &org, &project)?;
        render(&db, &st, &st.effective_config(&db)?, &user, Some(selected), &q)
    })
}

fn render(
    db: &Database,
    st: &super::AppState,
    config: &crate::config::Config,
    user: &Account,
    project: Option<(Org, OrgProject)>,
    q: &ProductQuery,
) -> HtmlResult {
    let scope = Scope {
        project,
        summaries: db.project_summaries(user.id)?,
    };
    let view = nonempty(&q.view).unwrap_or_else(|| "overview".into());
    let (title, body) = match view.as_str() {
        "review" => ("To review", review(db, user, &scope, q)?),
        "applications" => ("Applications", applications(db, st, user, &scope, q)?),
        "subscriptions" => ("Subscriptions", subscriptions(db, user, &scope)?),
        "evolution" => ("Evolution", evolution(db, user, &scope, q)?),
        "audit" => ("Audit", audit(db, user, &scope, q)?),
        "settings" if !scope.all() => ("Settings", settings(db, config, &scope, q.new.as_deref())?),
        _ => ("Overview", overview(db, user, &scope)?),
    };
    let heading = match scope.names() {
        Some((org, project)) => html! { (project) " " span.muted { "· " (org) } },
        None => html! { "All projects" },
    };
    Ok(layout(
        Nav::Product {
            scope: scope.names(),
            view: &view,
        },
        title,
        Some(user),
        html! {
            div.head {
                h1 { (heading) " " span.muted { "— " (title) } }
                @if let Some((org, _)) = &scope.project { span.muted { "Your role: " (org.role) } }
            }
            (body)
        },
    ))
}

fn onboarding(scope: &Scope) -> Markup {
    html! {
        div.card.notice {
            @if scope.summaries.is_empty() {
                strong { "Nothing is monitored yet." }
                ol.steps {
                    li { a href="/projects" { "Create a project" } " (one per server, product or team)." }
                    li { "Add the applications you run, with their version: CVEs affecting that version are listed to review." }
                    li { "Subscribe to vendors or products to follow every change on their CVEs." }
                }
            } @else {
                strong { "This project does not monitor anything yet." }
                ol.steps {
                    li { a href=(scope.url("applications")) { "Add the applications you run" } ", with their version." }
                    li { a href=(scope.url("subscriptions")) { "Subscribe to vendors or products" } " to follow their CVEs." }
                }
            }
        }
    }
}

// ==========================================
// Triage actions
// ==========================================

fn current_path() -> String {
    PAGE.try_with(|c| c.path.clone()).unwrap_or_default()
}

/// Buttons deciding on a watchlist entry. Accepting a risk asks for a justification.
fn triage_actions(item: &TriageItem) -> Markup {
    let action = format!(
        "/orgs/{}/projects/{}/watchlist/{}",
        enc(&item.org),
        enc(&item.project),
        item.entry_id
    );
    let back = current_path();
    let quick = |status: &str, label: &str, class: &str| -> Markup {
        html! {
            form.inline method="post" action=(action) {
                input type="hidden" name="status" value=(status);
                input type="hidden" name="back" value=(back);
                button class=(class) type="submit" { (label) }
            }
            " "
        }
    };
    html! {
        @if item.status == "untreated" {
            (quick("treated", "Close", "small"))
            details.inline {
                summary { span.btn { "Accept risk…" } }
                form.row method="post" action=(action) {
                    input type="hidden" name="status" value="accepted";
                    input type="hidden" name="back" value=(back);
                    input type="text" name="comment" placeholder="Justification (required)" maxlength="500" size="32" required;
                    button.small type="submit" { "Accept risk" }
                }
            }
            " "
            (quick("not_applicable", "Not applicable", "small secondary"))
        } @else {
            (quick("untreated", "Reopen", "small secondary"))
        }
    }
}

/// Author of an event: automatic origins never look like a user
fn actor_cell(e: &LifecycleEvent) -> Markup {
    html! {
        @if e.automatic { span.muted { em { (e.actor) } " (automatic)" } } @else { strong { (e.actor) } }
    }
}

fn project_cell(e: &LifecycleEvent) -> Markup {
    html! { (e.project) @if e.project_deleted { " " span.muted { "(deleted)" } } }
}

fn status_badge(status: &str) -> Markup {
    html! {
        span.status {
            svg.swatch width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" {
                rect width="10" height="10" rx="2" class={ "fill-" (charts::status_color(status)) } {}
            }
            (charts::status_label(status))
        }
    }
}

// ==========================================
// Overview (charts)
// ==========================================

fn count(breakdown: &[Breakdown], filter: impl Fn(&Breakdown) -> bool) -> i64 {
    breakdown.iter().filter(|b| filter(b)).map(|b| b.count).sum()
}

fn overview(db: &Database, user: &Account, scope: &Scope) -> Result<Markup, AppError> {
    let breakdown = db.watch_breakdown(user.id, scope.project_id())?;
    let applications = db.scoped_applications(user.id, scope.project_id())?;
    let subscriptions = db.scoped_subscriptions(user.id, scope.project_id())?;
    if applications.is_empty() && subscriptions.is_empty() {
        return Ok(onboarding(scope));
    }
    let open = db.scoped_triage(user.id, scope.project_id(), false, 500)?;
    let changes = db.recent_project_changes(user.id, scope.project_id(), 8)?;
    let untreated = count(&breakdown, |b| b.status == "untreated");
    let accepted = count(&breakdown, |b| b.status == "accepted");
    let critical = count(&breakdown, |b| b.status == "untreated" && b.severity == "critical");
    let kev = open.iter().filter(|i| i.kev).count() as i64;

    let today = Utc::now().date_naive();
    let events = db.lifecycle_events(user.id, scope.project_id())?;
    let month = timeline(&events, today - Duration::days(29), today);
    let evolution_link = |day: &str| format!("{}&at={day}", scope.url("evolution"));

    let charts = if scope.all() {
        overview_charts_all(scope, &breakdown)
    } else {
        overview_charts_project(scope, &breakdown, &applications)
    };

    Ok(html! {
        div.tiles {
            (views::tile(untreated, "CVEs to review", false))
            (views::tile(kev, "known exploited (KEV)", true))
            (views::tile(critical, "critical (CVSS ≥ 9)", true))
            (views::tile(accepted, "risks accepted", false))
        }
        (charts)
        div.card {
            h3 { "CVEs to review over the last 30 days " small { "— click a day to see the state at that date" } }
            (charts::stock_chart(&month, None, &evolution_link))
        }

        div.head {
            h2 { "To review first" }
            a href=(scope.url("review")) { "All " (untreated) " →" }
        }
        (views::triage_table(&open[..open.len().min(8)], scope.all(), None, |item| {
            if scope.can_in(&item.org, &item.project, Permission::Triage) { triage_actions(item) } else { html! {} }
        }))

        div.head {
            h2 { "Latest changes on subscribed products" }
            a href=(scope.url("evolution")) { "Evolution →" }
        }
        (views::project_changes(&changes, scope.all()))
    })
}

/// `*` scope: projects are told apart by color; severity levels are separate bars
fn overview_charts_all(scope: &Scope, breakdown: &[Breakdown]) -> Markup {
    let slots = scope.slots();
    let mut projects: Vec<&ProjectSummary> = scope.summaries.iter().collect();
    projects.sort_by_key(|p| p.id);
    let color = |id: i64| charts::project_color(slots.get(&id).copied().unwrap_or(usize::MAX));

    // One segment per project (those beyond the palette share "Other")
    let per_project = |filter: &dyn Fn(&Breakdown) -> bool| -> Vec<Segment> {
        let mut segments: Vec<Segment> = Vec::new();
        for p in &projects {
            let value = count(breakdown, |b| b.project_id == p.id && filter(b));
            let key = color(p.id);
            if key == "other" {
                match segments.iter_mut().find(|s| s.color == "other") {
                    Some(other) => other.value += value,
                    None => segments.push(Segment::new("Other projects", value, "other")),
                }
            } else {
                segments.push(Segment::new(p.name.clone(), value, key));
            }
        }
        segments
    };
    let by_project = per_project(&|b| b.status == "untreated");
    let by_severity: Vec<(String, Vec<Segment>)> = charts::SEVERITIES
        .iter()
        .map(|(key, label, _)| {
            (
                label.to_string(),
                per_project(&|b| b.status == "untreated" && b.severity == *key),
            )
        })
        .collect();
    let by_status: Vec<(String, Vec<Segment>)> = projects
        .iter()
        .map(|p| {
            (
                p.name.clone(),
                charts::STATUSES
                    .iter()
                    .map(|(key, label, class)| {
                        Segment::new(*label, count(breakdown, |b| b.project_id == p.id && b.status == *key), *class)
                    })
                    .collect(),
            )
        })
        .collect();
    let status_legend: Vec<Segment> = charts::STATUSES
        .iter()
        .map(|(key, label, class)| Segment::new(*label, count(breakdown, |b| b.status == *key), *class))
        .collect();

    html! {
        div.charts {
            div.card {
                h3 { "To review, by project" }
                (charts::donut(&by_project, "to review"))
            }
            div.card {
                h3 { "To review, by severity " small { "— colored by project" } }
                (charts::stacked_rows(&by_severity, &by_project))
            }
            div.card {
                h3 { "All tracked CVEs, by project and status" }
                (charts::stacked_rows(&by_status, &status_legend))
            }
        }
    }
}

/// One project: severity levels are told apart by color
fn overview_charts_project(
    scope: &Scope,
    breakdown: &[Breakdown],
    applications: &[crate::db::ScopedApplication],
) -> Markup {
    let by_severity: Vec<Segment> = charts::SEVERITIES
        .iter()
        .map(|(key, label, class)| {
            Segment::new(*label, count(breakdown, |b| b.status == "untreated" && b.severity == *key), *class)
        })
        .collect();
    let by_status: Vec<Segment> = charts::STATUSES
        .iter()
        .map(|(key, label, class)| Segment::new(*label, count(breakdown, |b| b.status == *key), *class))
        .collect();
    let slot = scope
        .project_id()
        .and_then(|id| scope.slots().get(&id).copied())
        .unwrap_or(0);
    let mut apps: Vec<&crate::db::ScopedApplication> = applications.iter().filter(|a| a.untreated > 0).collect();
    apps.sort_by(|a, b| b.untreated.cmp(&a.untreated));
    let by_app: Vec<(String, Vec<Segment>)> = apps
        .iter()
        .take(10)
        .map(|a| {
            (
                views::truncate(&a.name, 16),
                vec![Segment::new("to review", a.untreated, charts::project_color(slot))],
            )
        })
        .collect();
    html! {
        div.charts {
            div.card {
                h3 { "To review, by severity" }
                (charts::donut(&by_severity, "to review"))
            }
            div.card {
                h3 { "All tracked CVEs, by status" }
                (charts::donut(&by_status, "tracked"))
            }
            div.card {
                h3 { "To review, by application" }
                @if by_app.is_empty() { p.muted { "Nothing to review." } } @else { (charts::stacked_rows(&by_app, &[])) }
            }
        }
    }
}

// ==========================================
// To review
// ==========================================

fn review(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    let handled = nonempty(&q.show).as_deref() == Some("handled");
    let mut items = db.scoped_triage(user.id, scope.project_id(), handled, 2000)?;
    let total = items.len();
    // Default order: most urgent first (known exploited, then CVSS)
    let listing = Listing::from_page("urgency", true);
    listing.apply(&mut items, views::triage_text, views::triage_key);
    let base = scope.url("review");
    Ok(html! {
        div.chips {
            a href=(base) class=[(!handled).then_some("active")] { "To review" }
            a href={ (base) "&show=handled" } class=[handled.then_some("active")] { "Decided (accepted, closed, not applicable)" }
        }
        (listing.filter_box("Filter: CVE, application, project, text…", items.len(), total))
        @if handled {
            table.list {
                thead {
                    tr {
                        (listing.th("cve", "CVE")) (listing.th("cvss", "CVSS")) (listing.th("app", "Application"))
                        @if scope.all() { (listing.th("project", "Project")) }
                        (listing.th("status", "Decision")) th {}
                    }
                }
                tbody {
                    @for item in &items {
                        tr {
                            td.nowrap {
                                a href={ "/cve/" (enc(&item.cve_id)) } { (item.cve_id) }
                                @if item.kev { " " span.tag.kev { "KEV" } }
                            }
                            td.nowrap { (views::cvss_badge(item.cvss)) }
                            td.nowrap { (item.app_name) " " span.muted { (item.app_version.as_deref().unwrap_or("")) } @if !item.group.is_empty() { div { span.tag title="Group of inventory sources this decision holds for" { (item.group) } } } }
                            @if scope.all() { td.nowrap { a href=(product_url(Some((&item.org, &item.project)), "review")) { (item.project) } } }
                            td { (status_badge(&item.status)) }
                            td.right.nowrap {
                                @if scope.can_in(&item.org, &item.project, Permission::Triage) { (triage_actions(item)) }
                            }
                        }
                    }
                    @if items.is_empty() { tr { td colspan="6" .muted { "No decision yet." } } }
                }
            }
            p.muted { "Who decided what, and why: see " a href=(scope.url("audit")) { "Audit" } "." }
        } @else {
            (views::triage_table(&items, scope.all(), Some(&listing), |item| {
                if scope.can_in(&item.org, &item.project, Permission::Triage) { triage_actions(item) } else { html! {} }
            }))
            p.muted {
                strong { "Close" } " once fixed · " strong { "Accept risk" } " to keep it knowingly, with a justification · "
                strong { "Not applicable" } " if it does not concern your deployment."
            }
        }
    })
}

// ==========================================
// Applications & subscriptions
// ==========================================

fn applications(
    db: &Database,
    st: &super::AppState,
    user: &Account,
    scope: &Scope,
    q: &ProductQuery,
) -> Result<Markup, AppError> {
    let mut apps = db.scoped_applications(user.id, scope.project_id())?;
    // A machine reports hundreds of packages: those without anything to review are hidden unless asked
    let quiet = apps.iter().filter(|a| !a.group.is_empty() && a.untreated == 0).count();
    let show_quiet = q.show.as_deref() == Some("quiet") || quiet <= 30;
    if !show_quiet {
        apps.retain(|a| a.group.is_empty() || a.untreated > 0);
    }
    let total = apps.len();
    let listing = Listing::from_page("name", false);
    listing.apply(
        &mut apps,
        |a| format!("{} {} {} {} {} {}", a.name, a.vendor.as_deref().unwrap_or(""), a.version.as_deref().unwrap_or(""), a.project, a.group, a.sources.join(" ")),
        |a, column| match column {
            "name" => Some(SortKey::text(&a.name)),
            "vendor" => Some(SortKey::text(a.vendor.as_deref().unwrap_or(""))),
            "version" => Some(SortKey::text(a.version.as_deref().unwrap_or(""))),
            "project" => Some(SortKey::text(&a.project)),
            "group" => Some(SortKey::text(&a.group)),
            "review" => Some(SortKey::num(a.untreated as f64)),
            _ => None,
        },
    );
    let manage = scope.can(Permission::ManageProjects);
    let back = current_path();
    Ok(html! {
        p.muted { "Applications you run, with the deployed version. They are rescanned after every sync; changing the version closes the CVEs it fixes." }
        (listing.filter_box("Filter: application, version, group, source…", apps.len(), total))
        @if !show_quiet {
            p.muted {
                (quiet) " packages reported by inventory sources have nothing to review and are hidden. "
                a href={ (current_path()) (if current_path().contains('?') { "&" } else { "?" }) "show=quiet" } { "Show them" }
            }
        }
        table.list {
            thead {
                tr {
                    (listing.th("name", "Application")) (listing.th("vendor", "Vendor")) (listing.th("version", "Version"))
                    (listing.th("group", "Group / sources"))
                    @if scope.all() { (listing.th("project", "Project")) }
                    (listing.th("review", "To review")) th {}
                }
            }
            tbody {
                @for app in &apps {
                    @let base = format!("/orgs/{}/projects/{}/applications/{}", enc(&app.org), enc(&app.project), app.id);
                    tr {
                        td { (app.name) @if let Some(ecosystem) = &app.ecosystem { " " span.tag { (ecosystem) } } }
                        td { (app.vendor.as_deref().unwrap_or("—")) }
                        td {
                            @if manage && app.group.is_empty() {
                                form.inline method="post" action={ (base) "/version" } {
                                    input type="hidden" name="back" value=(back);
                                    input type="text" name="version" value=[app.version.as_deref()] size="12" maxlength="64" required;
                                    " " button.small.secondary type="submit" { "Update" }
                                }
                            } @else { (app.version.as_deref().unwrap_or("—")) }
                        }
                        td {
                            @if app.group.is_empty() { span.muted { "added by hand" } } @else {
                                span.tag { (app.group) } " "
                                span.muted title=(app.sources.join(", ")) {
                                    @if app.sources.len() == 1 { (app.sources[0]) } @else { (app.sources.len()) " sources" }
                                }
                            }
                        }
                        @if scope.all() { td { a href=(product_url(Some((&app.org, &app.project)), "applications")) { (app.project) } } }
                        td {
                            (app.untreated)
                            @if app.known_cves == Some(0) {
                                " " span.tag.warn title="No source holds a CVE under this name: nothing can be matched. Check the product name and vendor against the CVE database, or give the package ecosystem." { "unknown to the sources" }
                            } @else if let (0, Some(known)) = (app.untreated, app.known_cves) {
                                " " span.muted title="CVEs the sources hold under this name, whatever the version" { "of " (known) " known" }
                            }
                        }
                        td.right {
                            @if manage && app.group.is_empty() {
                                form.inline method="post" action={ (base) "/delete" } {
                                    input type="hidden" name="back" value=(back);
                                    button.small.danger type="submit" { "Remove" }
                                }
                            }
                        }
                    }
                }
                @if apps.is_empty() { tr { td colspan="7" .muted { "No application tracked yet." } } }
            }
        }
        @if let (true, Some((org, project))) = (manage, scope.names()) {
            h2 { "Add an application" }
            form.row method="post" action={ "/orgs/" (enc(org)) "/projects/" (enc(project)) "/applications" } {
                input type="hidden" name="back" value=(back);
                input type="text" name="name" placeholder="product, e.g. vaultwarden" maxlength="100" required;
                input type="text" name="version" placeholder="version, e.g. 1.37.4" maxlength="64";
                input type="text" name="vendor" placeholder="vendor (optional)" maxlength="100";
                select name="ecosystem" title="Package ecosystem, to also match the advisories of its package" {
                    option value="" { "no package ecosystem" }
                    @for ecosystem in crate::db::watchlist::PACKAGE_ECOSYSTEMS { option value=(ecosystem) { (ecosystem) } }
                }
                button type="submit" { "Add and scan" }
            }
            p.muted {
                "Use the product and vendor names of the " a href="/vendors" { "CVE database" }
                " (e.g. product " code { "openssh" } ", vendor " code { "openbsd" } "): the product is matched exactly, case and separators aside. With a vendor, only its products are matched, including those named after the application (" code { "nginx_open_source" } " for " code { "nginx" } "). "
                "A package ecosystem also matches the advisories published for the package of that name (Go module, npm or PyPI package, crate, Maven artifact), "
                "which is the only way to follow software the NVD does not describe. "
                "An application marked " em { "unknown to the sources" } " has no CVE recorded under its name at any version."
            }
        } @else if scope.all() {
            p.muted { "Select a project in the menu to add, update or remove applications, and to connect an inventory source." }
        }
        @if let Some((org, project)) = &scope.project {
            (super::inventory::project_section(db, st, org, project, q.show.as_deref(), q.new.as_deref())?)
        }
    })
}

fn subscriptions(db: &Database, user: &Account, scope: &Scope) -> Result<Markup, AppError> {
    let mut subs = db.scoped_subscriptions(user.id, scope.project_id())?;
    let total = subs.len();
    let listing = Listing::from_page("vendor", false);
    listing.apply(
        &mut subs,
        |s| format!("{} {} {}", s.vendor, s.product, s.project),
        |s, column| match column {
            "vendor" => Some(SortKey::text(&s.vendor)),
            "product" => Some(SortKey::text(&s.product)),
            "project" => Some(SortKey::text(&s.project)),
            _ => None,
        },
    );
    let manage = scope.can(Permission::ManageProjects);
    Ok(html! {
        p.muted { "Every change on a CVE of these vendors or products is recorded in the project's history and sent to its notifications." }
        (listing.filter_box("Filter: vendor, product…", subs.len(), total))
        table.list {
            thead {
                tr {
                    (listing.th("vendor", "Vendor")) (listing.th("product", "Product"))
                    @if scope.all() { (listing.th("project", "Project")) }
                    th {}
                }
            }
            tbody {
                @for s in &subs {
                    tr {
                        td { a href={ "/vendors/" (enc(&s.vendor)) "?project=" (s.project_id) } { (s.vendor) } }
                        td {
                            @if s.product.is_empty() { span.muted { "all products" } } @else {
                                a href={ "/cve?vendor=" (enc(&s.vendor)) "&product=" (enc(&s.product)) } { (s.product) }
                            }
                        }
                        @if scope.all() { td { a href=(product_url(Some((&s.org, &s.project)), "subscriptions")) { (s.project) } } }
                        td.right {
                            @if manage {
                                form.inline method="post" action="/subscriptions" {
                                    input type="hidden" name="project_id" value=(s.project_id);
                                    input type="hidden" name="vendor" value=(s.vendor);
                                    input type="hidden" name="product" value=(s.product);
                                    input type="hidden" name="action" value="unsubscribe";
                                    input type="hidden" name="back" value="project";
                                    button.small.secondary type="submit" { "Unsubscribe" }
                                }
                            }
                        }
                    }
                }
                @if subs.is_empty() { tr { td colspan="4" .muted { "No subscription yet." } } }
            }
        }
        @if let (true, Some(id)) = (manage, scope.project_id()) {
            h2 { "Subscribe" }
            form.row method="post" action="/subscriptions" {
                input type="hidden" name="project_id" value=(id);
                input type="hidden" name="action" value="subscribe";
                input type="hidden" name="back" value="project";
                input type="text" name="vendor" placeholder="vendor, e.g. openbsd" maxlength="200" required;
                input type="text" name="product" placeholder="product (empty = all)" maxlength="200";
                button type="submit" { "Subscribe" }
            }
            p.muted {
                "Names must match the CVE database exactly. Easier: "
                a href={ "/vendors?project=" (id) } { "browse vendors and products" } " and subscribe from there."
            }
        } @else if scope.all() {
            p.muted { "Select a project in the menu to subscribe or unsubscribe." }
        }
    })
}

// ==========================================
// Evolution over time, and state at a date
// ==========================================

fn evolution(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    let today = Utc::now().date_naive();
    let days = match nonempty(&q.days).as_deref() {
        Some("90") => 90,
        Some("365") => 365,
        _ => 30,
    };
    let at = nonempty(&q.at)
        .and_then(|d| NaiveDate::parse_from_str(&d, "%Y-%m-%d").ok())
        .map(|d| d.min(today))
        .unwrap_or(today);
    // The window always contains the selected day
    let to = if at < today - Duration::days(days - 1) { at + Duration::days(days / 2).min(today - at) } else { today };
    let from = to - Duration::days(days - 1);

    let events = db.lifecycle_events(user.id, scope.project_id())?;
    let stats = timeline(&events, from, to);
    let mut state = state_at(&events, at);
    let in_status = {
        let counts: Vec<String> = state.iter().map(|s| s.status.clone()).collect();
        move |status: &str| counts.iter().filter(|s| *s == status).count() as i64
    };
    let state_total = state.len();
    // Default order: to review first, then by urgency
    let listing = Listing::from_page("urgency", true);
    listing.apply(
        &mut state,
        |i| {
            format!(
                "{} {} {} {} {} {}",
                i.event.cve_id,
                i.event.app_name,
                i.event.project,
                charts::status_label(&i.status),
                i.event.actor,
                i.event.comment.as_deref().unwrap_or("")
            )
        },
        |i, column| match column {
            "cve" => Some(SortKey::text(&i.event.cve_id)),
            "cvss" => Some(SortKey::opt(i.event.cvss)),
            "app" => Some(SortKey::text(&i.event.app_name)),
            "project" => Some(SortKey::text(&i.event.project)),
            "status" => Some(SortKey::text(&i.status)),
            "since" => Some(SortKey::text(&i.event.at)),
            "by" => Some(SortKey::text(&i.event.actor)),
            _ => None,
        },
    );
    let at_s = at.to_string();
    let base = scope.url("evolution");
    let link = |day: &str| format!("{base}&days={days}&at={day}");
    let changes = db.recent_project_changes(user.id, scope.project_id(), 30)?;
    let reports = match scope.project_id() {
        Some(id) => db.list_reports(id, 30)?,
        None => Vec::new(),
    };

    Ok(html! {
        div.chips {
            @for (n, label) in [(30, "30 days"), (90, "90 days"), (365, "1 year")] {
                a href={ (base) "&days=" (n) "&at=" (at_s) } class=[(days == n).then_some("active")] { (label) }
            }
        }
        div.card {
            h3 { "Stock: CVEs to review and accepted risks " small { "— " (from) " to " (to) } }
            (charts::stock_chart(&stats, Some(&at_s), &link))
        }
        div.card {
            h3 { "Activity per day: new entries and decisions" }
            (charts::activity_chart(&stats, Some(&at_s), &link))
        }
        p.muted { "Click a day in a chart to review the state at the end of that day." }

        div.head {
            h2 { "State on " (at_s) @if at == today { " (today)" } }
            form.row method="get" action=(scope.url("")) {
                input type="hidden" name="view" value="evolution";
                input type="hidden" name="days" value=(days);
                input type="date" name="at" value=(at_s) max=(today.to_string());
                button.secondary type="submit" { "Show" }
            }
        }
        div.tiles {
            (views::tile(in_status("untreated"), "to review", false))
            (views::tile(in_status("accepted"), "risks accepted", false))
            (views::tile(in_status("treated"), "closed", false))
            (views::tile(in_status("not_applicable"), "not applicable", false))
        }
        (listing.filter_box("Filter: CVE, application, status, author…", state.len(), state_total))
        table.list {
            thead {
                tr {
                    (listing.th("cve", "CVE")) (listing.th("cvss", "CVSS")) (listing.th("app", "Application"))
                    @if scope.all() { (listing.th("project", "Project")) }
                    (listing.th("status", "Status that day")) (listing.th("since", "Since (UTC)")) (listing.th("by", "By"))
                    th { "Justification" }
                }
            }
            tbody {
                @for item in state.iter().take(500) {
                    @let e = &item.event;
                    tr {
                        td.nowrap {
                            a href={ "/cve/" (enc(&e.cve_id)) } { (e.cve_id) }
                            @if e.kev { " " span.tag.kev { "KEV" } }
                        }
                        td.nowrap { (views::cvss_badge(e.cvss)) }
                        td.nowrap { (e.app_name) " " span.muted { (e.app_version.as_deref().unwrap_or("")) } }
                        @if scope.all() { td.nowrap { (project_cell(e)) } }
                        td { (status_badge(&item.status)) }
                        td.nowrap { (e.at) }
                        td { (actor_cell(e)) }
                        td { (e.comment.as_deref().unwrap_or("")) }
                    }
                }
                @if state.is_empty() { tr { td colspan="8" .muted { "Nothing was tracked at that date." } } }
            }
        }
        @if state.len() > 500 { p.muted { "Showing 500 of " (state.len()) " entries." } }

        h2 { "Changes on subscribed products" }
        (views::project_changes(&changes, scope.all()))
        @if !reports.is_empty() {
            @if let Some((org, project)) = scope.names() {
                h2 { "Daily reports" }
                p {
                    @for r in &reports {
                        a href={ "/orgs/" (enc(org)) "/projects/" (enc(project)) "/reports/" (r.day) } { (r.day) }
                        " " span.muted { "(" (r.changes) ")" } " · "
                    }
                }
            }
        }
    })
}

// ==========================================
// Audit: who decided what
// ==========================================

const DECISIONS: [(&str, &str); 6] = [
    ("accepted", "Risk accepted"),
    ("all", "All decisions"),
    ("treated", "Closed"),
    ("not_applicable", "Not applicable"),
    ("untreated", "Reopened"),
    ("removed", "Removed"),
];

fn audit(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    let filter = nonempty(&q.decision)
        .filter(|d| DECISIONS.iter().any(|(key, _)| key == d))
        .unwrap_or_else(|| "accepted".into());
    let events = db.lifecycle_events(user.id, scope.project_id())?;
    let matches = |e: &LifecycleEvent| match (e.kind.as_str(), filter.as_str()) {
        ("detected", _) => false,
        (_, "all") => true,
        ("removed", f) => f == "removed",
        ("status", f) => e.status.as_deref() == Some(f),
        _ => false,
    };
    let mut decisions: Vec<&LifecycleEvent> = events.iter().rev().filter(|e| matches(e)).collect();
    let total = decisions.len();
    // Default order: most recent first
    let listing = Listing::from_page("when", true);
    listing.apply(
        &mut decisions,
        |e| {
            format!(
                "{} {} {} {} {} {}",
                e.cve_id,
                e.app_name,
                e.project,
                e.actor,
                charts::status_label(e.status.as_deref().unwrap_or("")),
                e.comment.as_deref().unwrap_or("")
            )
        },
        |e, column| match column {
            "when" => Some(SortKey::num(e.id as f64)),
            "who" => Some(SortKey::text(&e.actor)),
            "decision" => Some(SortKey::text(e.status.as_deref().unwrap_or("removed"))),
            "cve" => Some(SortKey::text(&e.cve_id)),
            "cvss" => Some(SortKey::opt(e.cvss)),
            "app" => Some(SortKey::text(&e.app_name)),
            "project" => Some(SortKey::text(&e.project)),
            _ => None,
        },
    );
    // Who accepted how many risks
    let mut by_actor: BTreeMap<&str, i64> = BTreeMap::new();
    for e in events
        .iter()
        .filter(|e| e.kind == "status" && e.status.as_deref() == Some("accepted") && !e.automatic)
    {
        *by_actor.entry(e.actor.as_str()).or_default() += 1;
    }
    let base = scope.url("audit");

    Ok(html! {
        p.muted { "Every decision on a tracked CVE, with its author and justification. Entries are never rewritten: a later decision adds a line." }
        @if !by_actor.is_empty() {
            p {
                "Risks accepted by: "
                @for (actor, n) in &by_actor { strong { (actor) } " (" (n) ") " }
            }
        }
        div.chips {
            @for (key, label) in DECISIONS {
                a href={ (base) "&decision=" (key) } class=[(filter == key).then_some("active")] { (label) }
            }
        }
        (listing.filter_box("Filter: author, CVE, application, justification…", decisions.len(), total))
        table.list {
            thead {
                tr {
                    (listing.th("when", "When (UTC)")) (listing.th("who", "Who")) (listing.th("decision", "Decision"))
                    (listing.th("cve", "CVE")) (listing.th("cvss", "CVSS")) (listing.th("app", "Application"))
                    @if scope.all() { (listing.th("project", "Project")) }
                    th { "Justification" }
                }
            }
            tbody {
                @for e in decisions.iter().take(500) {
                    tr {
                        td.nowrap { (e.at) }
                        td { (actor_cell(e)) }
                        td.nowrap {
                            @if e.kind == "removed" {
                                span.muted { "removed" }
                            } @else {
                                span.muted { (charts::status_label(e.previous.as_deref().unwrap_or(""))) " → " }
                                (status_badge(e.status.as_deref().unwrap_or("")))
                            }
                        }
                        td.nowrap {
                            a href={ "/cve/" (enc(&e.cve_id)) } { (e.cve_id) }
                            @if e.kev { " " span.tag.kev { "KEV" } }
                        }
                        td.nowrap { (views::cvss_badge(e.cvss)) }
                        td.nowrap { (e.app_name) " " span.muted { (e.app_version.as_deref().unwrap_or("")) } }
                        @if scope.all() { td.nowrap { (project_cell(e)) } }
                        td { (e.comment.as_deref().unwrap_or("")) }
                    }
                }
                @if decisions.is_empty() { tr { td colspan="8" .muted { "No decision of this kind yet." } } }
            }
        }
        @if decisions.len() > 500 { p.muted { "Showing the 500 most recent of " (decisions.len()) "." } }
    })
}

// ==========================================
// Project settings
// ==========================================

fn settings(db: &Database, config: &crate::config::Config, scope: &Scope, new_kind: Option<&str>) -> Result<Markup, AppError> {
    let Some((org, project)) = &scope.project else {
        return Err(AppError::NotFound);
    };
    let notifications = super::notifications::project_section(db, config, org, project, new_kind)?;
    let mut members = db.list_project_members(project.id)?;
    if !org.can(crate::rbac::Permission::ManageMembers) {
        // Who holds a role on the whole instance is not a reader's business
        members.retain(|m| m.level != "instance");
    }
    let base = format!("/orgs/{}/projects/{}", enc(&org.name), enc(&project.name));
    Ok(html! {
        @if let Some(d) = &project.description { p.muted { (d) } }
        (notifications)

        h2 { "Members" }
        p.muted { "Who can access this project, and where the right comes from. A right given here applies to this project only." }
        table.list {
            thead { tr { th { "User" } th { "Role" } th { "Level" } th {} } }
            tbody {
                @for m in &members {
                    tr {
                        td { (m.username) }
                        td { (m.role) }
                        td {
                            @match m.level.as_str() {
                                "project" => { "this project" }
                                "organization" => { span.muted { "organization " (org.name) } }
                                _ => { span.muted { "whole instance" } }
                            }
                        }
                        td.right {
                            @if m.level == "project" && org.can(Permission::ManageMembers) {
                                form.inline method="post" action={ (base) "/members/" (m.user_id) "/delete" } {
                                    button.small.danger type="submit" { "Remove" }
                                }
                            }
                        }
                    }
                }
                @if members.is_empty() { tr { td colspan="4" .muted { "No member." } } }
            }
        }
        @if org.can(Permission::ManageMembers) {
            form.row method="post" action={ (base) "/members" } {
                input type="text" name="username" placeholder="username" required;
                select name="role" {
                    @for role in Role::ALL.iter().rev() { option value=(role.as_str()) { (role.as_str()) } }
                }
                button type="submit" { "Give access to this project" }
            }
        }

        @if org.can(Permission::DeleteProject) {
            h2 { "Danger zone" }
            form.row method="post" action={ (base) "/delete" } {
                input type="text" name="name" placeholder="Type the project name to confirm" size="32" required;
                button.danger type="submit" { "Delete project" }
            }
            p.muted { "Applications, subscriptions and notifications are deleted. The decision history stays in the audit view." }
        }
    })
}
