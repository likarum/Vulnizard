//! "My products" side: what the user runs and follows, for one project or
//! for all of them (`*`). Every view exists at both scopes.

use axum::extract::{Form, Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{Datelike, Duration, NaiveDate, Utc};
use maud::{html, Markup};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use super::charts::{self, Segment};
use super::pages::{load_summary_project, nonempty, redirect, HtmlResult};
use super::views::{self, enc, layout, product_url, Listing, Nav, SortKey, PAGE};
use super::{blocking, AppError, St, User, SESSION_TTL_SECS};
use crate::db::{
    state_at, timeline, Account, Database, LifecycleEvent, Org, OrgProject, ProjectChange, ProjectSummary, ScopedApplication,
    ScopedSubscription, StateItem, TriageItem,
};
use crate::deadlines::{band, overdue_per_day, EntryTrack, Figures, BANDS};
use crate::rbac::{Permission, Role};

#[derive(Deserialize, Default)]
pub struct ProductQuery {
    view: Option<String>,
    /// Vulnerabilities: "handled" lists the decided entries, "overdue" those
    /// to review that are past their remediation deadline
    show: Option<String>,
    /// History: day whose state is shown (YYYY-MM-DD)
    at: Option<String>,
    /// History: length of the window in days
    days: Option<String>,
    /// Audit: decision filter
    decision: Option<String>,
    /// Settings: type of the notification destination being added
    new: Option<String>,
    /// Overview: length in days of the period the averages are taken over
    period: Option<String>,
    /// Vulnerabilities: only the entries of the application of this name
    app: Option<String>,
    /// Vulnerabilities: only the CVEs of this severity (a key of `charts::SEVERITIES`)
    severity: Option<String>,
}

/// Selected project, or all the user's projects, or those of them that
/// belong to the organization chosen in the menu
struct Scope {
    project: Option<(Org, OrgProject)>,
    /// Organization "all projects" is narrowed to; never set with a project.
    /// It hides rows the user's rights give: no right ever comes from it.
    org: Option<String>,
    /// The projects the user reads (viewer or more), of that organization
    /// only when one is chosen: what the lists are about
    summaries: Vec<ProjectSummary>,
    /// The account holds roles, and all of them are executive: at the `*`
    /// scope too, the Overview is all there is
    confined: bool,
    /// Projects of the scope the user is only executive of: counted by the
    /// figures, absent from every list
    figures_only: usize,
    /// Color slot of each of the user's projects, whatever the organization chosen
    slots: HashMap<i64, usize>,
}

impl Scope {
    /// What the page shows: the project selected in the address, or all the
    /// user's projects narrowed to the organization chosen in the menu. That
    /// choice was checked against the user's projects when the request came in.
    fn load(db: &Database, user: &Account, project: Option<(Org, OrgProject)>) -> Result<Self, AppError> {
        let mut summaries = db.project_summaries(user.id)?;
        let held = db.held_projects(user.id)?;
        // Confined by the roles it was given, or because none of the projects it holds is one it reads
        let confined = db.summary_only(user.id)? || (!held.is_empty() && !held.iter().any(|p| p.can_view()));
        // By creation order, so a project keeps its color whatever the filter or the ranking
        let mut ids: Vec<i64> = summaries.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        let slots = ids.into_iter().enumerate().map(|(slot, id)| (id, slot)).collect();
        let org = match project {
            Some(_) => None,
            None => PAGE.try_with(|c| c.org.clone()).ok().flatten(),
        };
        if let Some(org) = &org {
            summaries.retain(|p| p.org == *org);
        }
        let figures_only = held
            .iter()
            .filter(|p| !p.can_view())
            .filter(|p| project.as_ref().is_none_or(|(_, selected)| selected.id == p.id))
            .filter(|p| org.as_ref().is_none_or(|org| p.org == *org))
            .count();
        Ok(Scope {
            project,
            org,
            summaries,
            confined,
            figures_only,
            slots,
        })
    }

    // Everything a view lists or counts is read through the methods below, so
    // that the chosen organization narrows all of it and no view forgets to.

    fn applications(&self, db: &Database, user: &Account) -> Result<Vec<ScopedApplication>, AppError> {
        let mut rows = db.scoped_applications(user.id, self.project_id())?;
        rows.retain(|a| self.org.as_ref().is_none_or(|org| a.org == *org));
        Ok(rows)
    }

    fn subscriptions(&self, db: &Database, user: &Account) -> Result<Vec<ScopedSubscription>, AppError> {
        let mut rows = db.scoped_subscriptions(user.id, self.project_id())?;
        rows.retain(|s| self.org.as_ref().is_none_or(|org| s.org == *org));
        Ok(rows)
    }

    fn triage(&self, db: &Database, user: &Account, handled: bool, limit: i64) -> Result<Vec<TriageItem>, AppError> {
        Ok(db.scoped_triage(user.id, self.project_id(), self.org.as_deref(), handled, limit)?)
    }

    /// The entries to review that are past their remediation deadline, most overdue first
    fn overdue(&self, db: &Database, user: &Account) -> Result<Vec<TriageItem>, AppError> {
        Ok(db.scoped_overdue(user.id, self.project_id(), self.org.as_deref())?)
    }

    fn changes(&self, db: &Database, user: &Account, limit: i64) -> Result<Vec<ProjectChange>, AppError> {
        Ok(db.recent_project_changes(user.id, self.project_id(), self.org.as_deref(), limit)?)
    }

    fn events(&self, db: &Database, user: &Account) -> Result<Vec<LifecycleEvent>, AppError> {
        let mut rows = db.lifecycle_events(user.id, self.project_id())?;
        rows.retain(|e| self.org.as_ref().is_none_or(|org| e.org == *org));
        Ok(rows)
    }

    /// The history of each entry, with the delays of its organization
    fn tracks(&self, db: &Database, user: &Account) -> Result<Vec<EntryTrack>, AppError> {
        Ok(db.entry_tracks(Some(user.id), self.project_id(), self.org.as_deref())?)
    }

    /// The executive figures, the averages being taken over the last
    /// `period_days` days. They count every project of the scope the user
    /// holds a role on, those it is only executive of included.
    fn figures(&self, db: &Database, user: &Account, period_days: i64) -> Result<Figures, AppError> {
        Ok(db.figures(Some(user.id), self.project_id(), self.org.as_deref(), period_days)?)
    }

    /// Whether a view other than the Overview may be opened: the project is
    /// read, or at the `*` scope the account is not confined to its figures
    fn may_open_views(&self) -> bool {
        match &self.project {
            Some((org, _)) => org.can(Permission::View),
            None => !self.confined,
        }
    }

    /// May open the lists of entries a figure counts: the right to read the
    /// project, or at the `*` scope one of the projects
    fn can_list(&self) -> bool {
        match &self.project {
            Some((org, _)) => org.can(Permission::View),
            None => self.summaries.iter().any(|p| Role::parse(&p.role).is_some_and(|r| r.allows(Permission::View))),
        }
    }

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

    /// Projects an addition made from this page may go to: the selected one,
    /// or at the `*` scope every project the user may manage
    fn manageable(&self) -> Vec<&ProjectSummary> {
        self.summaries
            .iter()
            .filter(|p| self.project_id().is_none_or(|id| p.id == id))
            .filter(|p| Role::parse(&p.role).is_some_and(|r| r.allows(Permission::ManageProjects)))
            .collect()
    }
}

#[derive(Deserialize)]
pub struct OrgFilterForm {
    /// Name of the organization; empty: all of them
    #[serde(default)]
    org: String,
    #[serde(default)]
    back: String,
}

/// Records the organization chosen in the menu of the products bar. The
/// answer is the same whatever is asked: an organization the account sees no
/// project of is forgotten like one that does not exist, and the choice is
/// checked again on every page (`chosen_org`).
pub async fn org_filter(State(st): St, User(user): User, Form(form): Form<OrgFilterForm>) -> Result<Response, AppError> {
    blocking(|| {
        // The organizations of the bar are those of the projects the account holds a role on
        let visible = st.db()?.held_projects(user.id)?.iter().any(|p| p.org == form.org);
        let (value, max_age) = if visible { (enc(&form.org), SESSION_TTL_SECS) } else { (String::new(), 0) };
        let cookie = format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
            views::ORG_COOKIE,
            if st.secure_cookies() { "; Secure" } else { "" }
        );
        // Only a page of this site is come back to
        let back = form.back.as_str();
        let local = back.starts_with('/')
            && !back.starts_with("//")
            && !back.contains('\\')
            && !back.chars().any(|c| c.is_control());
        let to = if local { back.to_string() } else { "/product".to_string() };
        Ok(([(header::SET_COOKIE, cookie)], redirect(to)).into_response())
    })
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
        // The Overview answers to an executive of the project; every other view asks to read it
        let selected = load_summary_project(&db, &user, &org, &project)?;
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
    let scope = Scope::load(db, user, project)?;
    let view = nonempty(&q.view).unwrap_or_else(|| "overview".into());
    let view = views::canonical_view(&view);
    // Anything that is not one of the other views shows the Overview
    let other_view = views::PRODUCT_VIEWS.iter().any(|(key, _)| *key == view && *key != "overview") || (view == "settings" && !scope.all());
    if other_view && !scope.may_open_views() {
        return Err(AppError::Forbidden);
    }
    let (title, body) = match view {
        "vulnerabilities" => ("Vulnerabilities", vulnerabilities(db, user, &scope, q)?),
        "overdue" => ("Overdue", overdue(db, user, &scope, q)?),
        "applications" => ("Applications", applications(db, st, user, &scope, q)?),
        "subscriptions" => ("Subscriptions", subscriptions(db, user, &scope)?),
        "history" => ("History", history(db, user, &scope, q)?),
        "audit" => ("Audit", audit(db, user, &scope, q)?),
        "settings" if !scope.all() => ("Settings", settings(db, config, &scope, q.new.as_deref())?),
        _ => ("Overview", overview(db, user, &scope, q)?),
    };
    let heading = match (scope.names(), &scope.org) {
        (Some((org, project)), _) => html! { (project) " " span.muted { "· " (org) } },
        (None, Some(org)) => html! { "All projects of " (org) },
        (None, None) => html! { "All projects" },
    };
    Ok(layout(
        Nav::Product {
            scope: scope.names(),
            view,
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
    html! { span.cut title=(e.project) { (e.project) } @if e.project_deleted { " " span.muted { "(deleted)" } } }
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
// Overview: the executive figures, and nothing else
// ==========================================

/// A number of days as a figure: "12 days", "2.5 days", or a dash when there
/// is nothing to measure (never 0, which would read as "at once")
fn days_figure(days: Option<f64>) -> Markup {
    html! {
        @match days {
            Some(days) => {
                (if days.fract() == 0.0 { format!("{days:.0}") } else { format!("{days:.1}") })
                span.unit { (if days == 1.0 { " day" } else { " days" }) }
            }
            None => { span.nodata title="Nothing to measure" { "—" } }
        }
    }
}

/// A figure in a tile. `href` leads to the list of what it counts.
fn figure(value: Markup, label: &str, href: Option<String>, alert: bool) -> Markup {
    html! {
        div class=(if alert { "tile alert" } else { "tile" }) {
            div.value {
                @match href {
                    Some(href) => { a href=(href) { (value) } }
                    None => { (value) }
                }
            }
            div.label { (label) }
        }
    }
}

/// A count of entries, linked to the list showing them when there is one to show
fn count_link(count: i64, href: Option<String>) -> Markup {
    html! {
        @match href.filter(|_| count > 0) {
            Some(href) => { a href=(href) { (count) } }
            None => { (count) }
        }
    }
}

fn severity_label(label: &str, color: &str) -> Markup {
    html! {
        span.status {
            svg.swatch width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" {
                rect width="10" height="10" rx="2" class={ "fill-" (color) } {}
            }
            (label)
        }
    }
}

fn overview(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    // Where the user is only executive, what is monitored is not its to see: the figures say it
    if scope.figures_only == 0 && scope.applications(db, user)?.is_empty() && scope.subscriptions(db, user)?.is_empty() {
        return Ok(onboarding(scope));
    }
    let period = match nonempty(&q.period).as_deref() {
        Some("30") => 30,
        Some("365") => 365,
        _ => 90,
    };
    let f = scope.figures(db, user, period)?;
    // A count leads to the list of what it counts, for who may open that list
    let list = scope.can_list().then(|| scope.url("vulnerabilities"));
    let to = |narrowing: &str| list.as_ref().map(|base| format!("{base}{narrowing}"));
    let base = scope.url("overview");
    let last = match period {
        30 => "30 days",
        365 => "365 days",
        _ => "90 days",
    };
    let (open, overdue, resolved, took) = (f.open.bands(), f.overdue.bands(), f.resolved.bands(), f.resolved_avg_days.bands());

    Ok(html! {
        p.muted {
            "Where the tracked vulnerabilities stand on " (f.as_of) " (UTC). A vulnerability is one CVE affecting one application; "
            strong { "open" } " means still to review."
        }
        div.tiles {
            (figure(html! { (f.open.total) }, "open vulnerabilities", to("").filter(|_| f.open.total > 0), false))
            (figure(html! { (f.overdue.total) }, "overdue on their remediation deadline", to("&show=overdue").filter(|_| f.overdue.total > 0), f.overdue.total > 0))
            (figure(days_figure(f.overdue_days.avg), "average lateness of the overdue ones", None, false))
            (figure(days_figure(f.overdue_days.max.map(|days| days as f64)), "worst lateness", None, false))
            (figure(days_figure(f.resolved_avg_days.total), &format!("average time to resolve, last {last}"), None, false))
        }
        div.chips.period {
            span.muted { "Time to resolve over the last" }
            @for (n, label) in [(30, "30 days"), (90, "90 days"), (365, "365 days")] {
                a href={ (base) @if n != 90 { "?period=" (n) } } class=[(period == n).then_some("active")] { (label) }
            }
            (views::info(html! {
                strong { "Resolved" } " means decided: closed, not applicable or risk accepted. The time runs from the detection of the vulnerability to that decision. "
                "The average is over the decisions taken during the last " (last) " (" (f.as_of - Duration::days(period - 1)) " to " (f.as_of)
                ", UTC) that still stand: one reopened since does not count. "
                strong { "Overdue" } ": still to review after its remediation deadline; the lateness is the number of days past that deadline."
            }))
        }

        h2 { "By severity" }
        table.list.fit.totals {
            (views::columns("- num num kind num", true))
            thead {
                tr {
                    th { "Severity" } th { "Open" } th { "Overdue" } th { "Average time to resolve" }
                    th { "Resolved in " (last) }
                }
            }
            tbody {
                @for (i, (key, label, color)) in charts::SEVERITIES.iter().enumerate() {
                    tr {
                        td { (severity_label(label, color)) }
                        td { (count_link(*open[i], to(&format!("&severity={key}")))) }
                        td { (count_link(*overdue[i], to(&format!("&show=overdue&severity={key}")))) }
                        td { (days_figure(*took[i])) }
                        td { (resolved[i]) }
                    }
                }
                tr.total {
                    td { "All" }
                    td { (count_link(f.open.total, to(""))) }
                    td { (count_link(f.overdue.total, to("&show=overdue"))) }
                    td { (days_figure(f.resolved_avg_days.total)) }
                    td { (f.resolved.total) }
                }
            }
        }
        p.muted {
            "The severity is the one each CVE has today. "
            @if list.is_some() {
                "What is late and where: " a href=(scope.url("overdue")) { "Overdue" }
                ". Charts, and the state of any past day: " a href=(scope.url("history")) { "History" } "."
            }
        }
    })
}

// ==========================================
// Breakdown charts of the state of a day (History)
// ==========================================

/// Entries of a day counted per project, status and severity
struct Breakdown {
    /// [`GONE`] for a project that no longer exists
    project_id: i64,
    status: String,
    /// A key of `charts::SEVERITIES`
    severity: &'static str,
    count: i64,
}

/// Stands for the projects deleted since the day shown
const GONE: i64 = -1;

fn count(breakdown: &[Breakdown], filter: impl Fn(&Breakdown) -> bool) -> i64 {
    breakdown.iter().filter(|b| filter(b)).map(|b| b.count).sum()
}

/// The state of a day, counted for the charts. The severity is today's.
fn breakdown_of(scope: &Scope, state: &[StateItem]) -> Vec<Breakdown> {
    let mut counts: BTreeMap<(i64, &str, usize), i64> = BTreeMap::new();
    for item in state {
        let e = &item.event;
        let project = scope
            .summaries
            .iter()
            // A project created since under the name of a deleted one is another project
            .find(|p| !e.project_deleted && p.org == e.org && p.name == e.project)
            .map_or(GONE, |p| p.id);
        *counts.entry((project, item.status.as_str(), band(e.cvss))).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((project_id, status, band), count)| Breakdown { project_id, status: status.to_string(), severity: BANDS[band], count })
        .collect()
}

/// `*` scope: projects are told apart by color; severity levels are separate bars
fn breakdown_charts_all(scope: &Scope, breakdown: &[Breakdown]) -> Markup {
    let slots = &scope.slots;
    let mut projects: Vec<(i64, String)> = scope.summaries.iter().map(|p| (p.id, p.name.clone())).collect();
    projects.sort_by_key(|(id, _)| *id);
    if breakdown.iter().any(|b| b.project_id == GONE) {
        projects.push((GONE, "Deleted projects".to_string()));
    }
    let color = |id: i64| charts::project_color(slots.get(&id).copied().unwrap_or(usize::MAX));

    // One segment per project (those beyond the palette share "Other")
    let per_project = |filter: &dyn Fn(&Breakdown) -> bool| -> Vec<Segment> {
        let mut segments: Vec<Segment> = Vec::new();
        for (id, name) in &projects {
            let value = count(breakdown, |b| b.project_id == *id && filter(b));
            let key = color(*id);
            if key == "other" {
                match segments.iter_mut().find(|s| s.color == "other") {
                    Some(other) => other.value += value,
                    None => segments.push(Segment::new("Other projects", value, "other")),
                }
            } else {
                segments.push(Segment::new(name.clone(), value, key));
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
        .map(|(id, name)| {
            (
                views::truncate(name, 16),
                charts::STATUSES
                    .iter()
                    .map(|(key, label, class)| {
                        Segment::new(*label, count(breakdown, |b| b.project_id == *id && b.status == *key), *class)
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
fn breakdown_charts_project(scope: &Scope, breakdown: &[Breakdown], state: &[StateItem]) -> Markup {
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
        .and_then(|id| scope.slots.get(&id).copied())
        .unwrap_or(0);
    let mut per_app: BTreeMap<&str, i64> = BTreeMap::new();
    for item in state.iter().filter(|i| i.status == "untreated") {
        *per_app.entry(item.event.app_name.as_str()).or_default() += 1;
    }
    let mut apps: Vec<(&str, i64)> = per_app.into_iter().collect();
    apps.sort_by(|a, b| b.1.cmp(&a.1));
    let by_app: Vec<(String, Vec<Segment>)> = apps
        .iter()
        .take(10)
        .map(|(name, untreated)| (views::truncate(name, 16), vec![Segment::new("to review", *untreated, charts::project_color(slot))]))
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
// Vulnerabilities: to review by default, decided on request
// ==========================================

fn vulnerabilities(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    let show = nonempty(&q.show);
    let handled = show.as_deref() == Some("handled");
    let overdue = show.as_deref() == Some("overdue");
    // Narrowed to one application or one severity, as the figures of the other views link to it
    let app = nonempty(&q.app);
    let severity = nonempty(&q.severity).and_then(|key| charts::SEVERITIES.iter().find(|(known, _, _)| *known == key));
    let narrowed = app.is_some() || severity.is_some();
    // What is narrowed afterwards is read whole, so that nothing is cut before
    let mut items = if overdue { scope.overdue(db, user)? } else { scope.triage(db, user, handled, if narrowed { -1 } else { 2000 })? };
    if let Some(app) = &app {
        items.retain(|i| i.app_name == *app);
    }
    if let Some((key, _, _)) = severity {
        items.retain(|i| BANDS[band(i.cvss)] == *key);
    }
    items.truncate(2000);
    // The narrowing stays when switching between the three lists
    let narrowing = format!(
        "{}{}",
        app.as_ref().map(|app| format!("&app={}", enc(app))).unwrap_or_default(),
        severity.map(|(key, _, _)| format!("&severity={key}")).unwrap_or_default()
    );
    let shown = if overdue { "&show=overdue" } else if handled { "&show=handled" } else { "" };
    let total = items.len();
    // Default order: most urgent first (known exploited, then CVSS); the most overdue first among the overdue
    let listing = if overdue { Listing::from_page("due", false) } else { Listing::from_page("urgency", true) };
    listing.apply(&mut items, views::triage_text, views::triage_key);
    let base = scope.url("vulnerabilities");
    // One project follows the delays of its organization; "all projects" may mix several
    let delays = match &scope.project {
        Some((org, _)) => db.org_delays(org.id)?,
        None => db.instance_delays()?,
    };
    Ok(html! {
        div.chips {
            a href={ (base) (narrowing) } class=[(!handled && !overdue).then_some("active")] { "To review" }
            a href={ (base) "&show=overdue" (narrowing) } class=[overdue.then_some("active")] { "Overdue" }
            a href={ (base) "&show=handled" (narrowing) } class=[handled.then_some("active")] { "Decided (accepted, closed, not applicable)" }
        }
        @if narrowed {
            p.narrowed {
                "Only "
                @if let Some(app) = &app { "the application " strong { (app) } }
                @if app.is_some() && severity.is_some() { ", " }
                @if let Some((_, label, _)) = severity { "the CVEs of severity " strong { (label) } }
                " · " a href={ (base) (shown) } { "Show all" }
            }
        }
        (listing.filter_box("Filter: CVE, application, project, text…", items.len(), total))
        @if handled {
            table.list.fit.decided {
                (views::triage_columns(scope.all(), "decision"))
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
                            td.cve {
                                a href={ "/cve/" (enc(&item.cve_id)) } { (item.cve_id) }
                                @if item.kev { " " span.tag.kev { "KEV" } }
                                @if item.version_unknown { " " span.tag.warn title="No source gives the versions this CVE affects: the application is kept out of caution. Read the CVE before deciding." { "version not given" } }
                            }
                            td.nowrap.cvss { (views::cvss_badge(item.cvss)) }
                            td.app { (item.app_name) " " span.muted { (item.app_version.as_deref().unwrap_or("")) } @if !item.group.is_empty() { div { span.tag title="Group of inventory sources this decision holds for" { (item.group) } } } }
                            @if scope.all() { td.project { a href=(product_url(Some((&item.org, &item.project)), "vulnerabilities")) title=(item.project) { (item.project) } } }
                            td { (status_badge(&item.status)) }
                            td.right.actions {
                                @if scope.can_in(&item.org, &item.project, Permission::Triage) { (triage_actions(item)) }
                            }
                        }
                    }
                    @if items.is_empty() { tr { td colspan=(if scope.all() { "6" } else { "5" }) .muted { "No decision yet." } } }
                }
            }
            p.muted { "Who decided what, and why: see " a href=(scope.url("audit")) { "Audit" } "." }
        } @else {
            @if overdue && total == 0 { p.muted { "No entry to review is past its deadline." } }
            (views::triage_table(&items, scope.all(), Some(&listing), |item| {
                if scope.can_in(&item.org, &item.project, Permission::Triage) { triage_actions(item) } else { html! {} }
            }))
            p.muted {
                strong { "Close" } " once fixed · " strong { "Accept risk" } " to keep it knowingly, with a justification · "
                strong { "Not applicable" } " if it does not concern your deployment."
            }
            p.muted {
                strong { "Due" } ": time left to decide, counted from the detection of the entry"
                @if scope.all() { " with the delays of the organization of each project" }
                ". Any decision stops it."
                (views::info(html! {
                    @if scope.all() { "Delays of the instance, which an organization may replace for its projects: " }
                    (delays.critical) " days for a critical CVE, " (delays.high) " for high, " (delays.medium) " for medium, "
                    (delays.low) " for low. A CVE without a score follows the medium delay. A CVE known to be exploited (KEV) is due in "
                    (delays.kev) " days when that is shorter. Reopening an entry or changing the version of the application does not move its deadline."
                }))
            }
        }
    })
}

// ==========================================
// Applications & subscriptions
// ==========================================

/// "+" button at the top of a view, opening the form that adds to it. A
/// `details` element: it opens without JavaScript.
fn add_button(label: &str, form: Markup) -> Markup {
    html! {
        details.add {
            summary { span.plus aria-hidden="true" { "+" } (label) }
            (form)
        }
    }
}

/// Project an addition goes to: the selected one, or at the `*` scope a
/// choice among those the user may manage. The server checks the right again
/// on the project it receives.
fn project_field(scope: &Scope, projects: &[&ProjectSummary]) -> Markup {
    let several_orgs = projects.iter().any(|p| Some(&p.org) != projects.first().map(|first| &first.org));
    html! {
        @if let Some(id) = scope.project_id() {
            input type="hidden" name="project_id" value=(id);
        } @else {
            label {
                "Project"
                select name="project_id" required {
                    @for p in projects {
                        option value=(p.id) { (p.name) @if several_orgs { " · " (p.org) } }
                    }
                }
            }
        }
    }
}

/// Said in place of the "+" button to who cannot add anything
fn cannot_add(scope: &Scope, what: &str) -> Markup {
    html! {
        p.muted {
            @if scope.summaries.is_empty() {
                a href="/projects" { "Create a project" } " to add " (what) "."
            } @else if scope.all() {
                "Adding " (what) " takes the owner or editor role, which you hold in none of your projects."
            } @else {
                "Adding " (what) " takes the owner or editor role in this project."
            }
        }
    }
}

fn applications(
    db: &Database,
    st: &super::AppState,
    user: &Account,
    scope: &Scope,
    q: &ProductQuery,
) -> Result<Markup, AppError> {
    let mut apps = scope.applications(db, user)?;
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
    let targets = scope.manageable();
    Ok(html! {
        p.muted { "Applications you run, with the deployed version. They are rescanned after every sync; changing the version closes the CVEs it fixes." }
        @if targets.is_empty() { (cannot_add(scope, "applications")) } @else {
            (add_button("Add an application", html! {
                form.stack method="post" action="/applications" {
                    input type="hidden" name="back" value=(back);
                    (project_field(scope, &targets))
                    label { "Product" input type="text" name="name" placeholder="e.g. vaultwarden" maxlength="100" required; }
                    label { "Version" input type="text" name="version" placeholder="e.g. 1.37.4" maxlength="64"; }
                    label { "Vendor (optional)" input type="text" name="vendor" placeholder="e.g. openbsd" maxlength="100"; }
                    label {
                        "Package ecosystem (optional)"
                        select name="ecosystem" title="Package ecosystem, to also match the advisories of its package" {
                            option value="" { "no package ecosystem" }
                            @for ecosystem in crate::db::watchlist::PACKAGE_ECOSYSTEMS { option value=(ecosystem) { (ecosystem) } }
                        }
                    }
                    button type="submit" { "Add and scan" }
                }
                p.muted {
                    "Use the product and vendor names of the " a href="/vendors" { "CVE database" }
                    " (e.g. product " code { "openssh" } ", vendor " code { "openbsd" } "): the product is matched exactly, case and separators aside. With a vendor (written as the CVE database writes it; " code { "sudo" } " also stands for " code { "sudo_project" } "), only its products are matched, including those named after the application (" code { "nginx_open_source" } " for " code { "nginx" } "). "
                    "A package ecosystem also matches the advisories published for the package of that name (Go module, npm or PyPI package, crate, Maven artifact), "
                    "which is the only way to follow software the NVD does not describe. "
                    "An application marked " em { "unknown to the sources" } " has no CVE recorded under its name at any version."
                }
            }))
        }
        (listing.filter_box("Filter: application, version, group, source…", apps.len(), total))
        @if !show_quiet {
            p.muted {
                (quiet) " packages reported by inventory sources have nothing to review and are hidden. "
                a href={ (current_path()) (if current_path().contains('?') { "&" } else { "?" }) "show=quiet" } { "Show them" }
            }
        }
        table.list.fit {
            // Without the right to change them there is no version field and no button: their columns shrink
            (views::columns(if manage { "name - version - project kind act" } else { "name - kind - project kind check" }, scope.all()))
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
                        @if scope.all() { td.project { a href=(product_url(Some((&app.org, &app.project)), "applications")) title=(app.project) { (app.project) } } }
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
        @if scope.all() {
            p.muted { "Select a project in the menu to update or remove applications, and to connect an inventory source." }
        }
        @if let Some((org, project)) = &scope.project {
            (super::inventory::project_section(db, st, org, project, q.show.as_deref(), q.new.as_deref())?)
        }
    })
}

fn subscriptions(db: &Database, user: &Account, scope: &Scope) -> Result<Markup, AppError> {
    let mut subs = scope.subscriptions(db, user)?;
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
    let targets = scope.manageable();
    Ok(html! {
        p.muted { "Every change on a CVE of these vendors or products is recorded in the project's history and sent to its notifications." }
        @if targets.is_empty() { (cannot_add(scope, "subscriptions")) } @else {
            (add_button("Add a subscription", html! {
                form.stack method="post" action="/subscriptions" {
                    input type="hidden" name="action" value="subscribe";
                    // Back to the page the form is on, at the scope it was opened from
                    input type="hidden" name="back" value=(if scope.all() { "all" } else { "project" });
                    (project_field(scope, &targets))
                    label { "Vendor" input type="text" name="vendor" placeholder="e.g. openbsd" maxlength="200" required; }
                    label { "Product (empty: every product of the vendor)" input type="text" name="product" placeholder="e.g. openssh" maxlength="200"; }
                    button type="submit" { "Subscribe" }
                }
                p.muted {
                    "Names must match the CVE database exactly. Easier: "
                    a href={ "/vendors" @if let Some(id) = scope.project_id() { "?project=" (id) } } { "browse vendors and products" }
                    " and subscribe from there."
                }
            }))
        }
        @if total == 0 {
            // An empty list read as a failure: say what belongs here, and what does not
            div.card.notice {
                p { strong { "No subscription yet." } }
                p {
                    "A subscription follows a vendor, or one product of a vendor, " strong { "without a version" }
                    ": every change on one of its CVEs goes into the daily report of the project and is sent to its notifications."
                }
                p {
                    "It is not a tracked application. An " a href=(scope.url("applications")) { "application" }
                    " has a name and a " strong { "version" } ": it is matched against the CVEs affecting that version, and feeds the list of "
                    a href=(scope.url("vulnerabilities")) { "vulnerabilities" } " to decide on. To know what affects what you run, add it to the "
                    a href=(scope.url("applications")) { "applications" } "; subscribe to be told of everything published about a vendor or a product."
                }
                @if !targets.is_empty() { p.muted { "Use the “+ Add a subscription” button above to subscribe." } }
            }
        } @else {
        (listing.filter_box("Filter: vendor, product…", subs.len(), total))
        table.list.fit {
            (views::columns("- - project act", scope.all()))
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
                        @if scope.all() { td.project { a href=(product_url(Some((&s.org, &s.project)), "subscriptions")) title=(s.project) { (s.project) } } }
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
                @if subs.is_empty() { tr { td colspan="4" .muted { "No subscription matches." } } }
            }
        }
        }
        @if scope.all() && total > 0 {
            p.muted { "Select a project in the menu to unsubscribe." }
        }
    })
}

// ==========================================
// Overdue: what is late, where, and since when
// ==========================================

/// Monday of the week of a day
fn week_of(day: NaiveDate) -> NaiveDate {
    day - Duration::days(i64::from(day.weekday().num_days_from_monday()))
}

/// The entries overdue today, counted per week of their detection and per
/// week of their due day: (Monday of the week, detected, due), every week
/// from the first to the last one included
fn overdue_weeks(late: &[(&EntryTrack, i64)]) -> Vec<(String, i64, i64)> {
    let mut weeks: BTreeMap<NaiveDate, (i64, i64)> = BTreeMap::new();
    for (track, _) in late {
        weeks.entry(week_of(track.detected)).or_default().0 += 1;
        weeks.entry(week_of(track.due)).or_default().1 += 1;
    }
    let (Some(first), Some(last)) = (weeks.keys().next().copied(), weeks.keys().next_back().copied()) else {
        return Vec::new();
    };
    first
        .iter_weeks()
        .take_while(|week| *week <= last)
        .map(|week| {
            let (detected, due) = weeks.get(&week).copied().unwrap_or_default();
            (week.to_string(), detected, due)
        })
        .collect()
}

/// Overdue entries of one application
struct LateApp<'a> {
    org: &'a str,
    project: &'a str,
    name: &'a str,
    count: i64,
    total_days: i64,
    worst: i64,
}

impl LateApp<'_> {
    fn average(&self) -> f64 {
        (self.total_days as f64 / self.count as f64 * 10.0).round() / 10.0
    }
}

fn overdue(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
    let today = Utc::now().date_naive();
    // The same window as the History view
    let days = match nonempty(&q.days).as_deref() {
        Some("90") => 90,
        Some("365") => 365,
        _ => 30,
    };
    let tracks = scope.tracks(db, user)?;
    // What is overdue today, with how many days past its deadline
    let late: Vec<(&EntryTrack, i64)> =
        tracks.iter().filter_map(|t| t.deadline(today).filter(|d| d.is_overdue()).map(|d| (t, d.overdue_days()))).collect();
    let per_day: Vec<(String, i64)> =
        overdue_per_day(&tracks, today - Duration::days(days - 1), today).into_iter().map(|(day, n)| (day.to_string(), n)).collect();
    let base = scope.url("overdue");
    let history = scope.url("history");
    let day_link = |day: &str| format!("{history}&at={day}");
    let window = html! {
        div.chips {
            @for (n, label) in [(30, "30 days"), (90, "90 days"), (365, "1 year")] {
                a href={ (base) "&days=" (n) } class=[(days == n).then_some("active")] { (label) }
            }
        }
        div.card.days {
            h3 { "Overdue at the end of each day " small { "— " (per_day.first().map_or("", |(day, _)| day.as_str())) " to " (today) " · click a day for its state" } }
            (charts::line_chart(&per_day, "p0", "overdue", 120.0, None, &day_link))
            details.daily {
                summary { "The figures of this chart, day by day" }
                table.list.fit {
                    (views::columns("- num", true))
                    thead { tr { th { "Day" } th { "Overdue" } } }
                    tbody { @for (day, n) in per_day.iter().rev() { tr { td { (day) } td { (n) } } } }
                }
            }
        }
    };
    if late.is_empty() {
        return Ok(html! {
            div.card.notice {
                strong { "Nothing is overdue." }
                " Every vulnerability to review is within its remediation deadline, or none is to review."
            }
            // What was late before is still worth a look
            @if per_day.iter().any(|(_, n)| *n > 0) { (window) }
        });
    }

    let mut by_app: BTreeMap<(&str, &str, &str), LateApp> = BTreeMap::new();
    for (track, days) in &late {
        let app = by_app.entry((track.org.as_str(), track.project.as_str(), track.app_name.as_str())).or_insert(LateApp {
            org: &track.org,
            project: &track.project,
            name: &track.app_name,
            count: 0,
            total_days: 0,
            worst: 0,
        });
        app.count += 1;
        app.total_days += days;
        app.worst = app.worst.max(*days);
    }
    // Worst first; the most entries, then the name, between equals
    let mut apps: Vec<LateApp> = by_app.into_values().collect();
    apps.sort_by(|a, b| b.worst.cmp(&a.worst).then(b.count.cmp(&a.count)).then(a.name.cmp(b.name)));
    let listing = Listing::from_page("", true);
    listing.apply(
        &mut apps,
        |a| format!("{} {}", a.name, a.project),
        |a, column| match column {
            "app" => Some(SortKey::text(a.name)),
            "project" => Some(SortKey::text(a.project)),
            "count" => Some(SortKey::num(a.count as f64)),
            "average" => Some(SortKey::num(a.average())),
            "worst" => Some(SortKey::num(a.worst as f64)),
            _ => None,
        },
    );
    let can_list = scope.can_list();
    let total: i64 = late.iter().map(|(_, days)| days).sum();
    let average = (total as f64 / late.len() as f64 * 10.0).round() / 10.0;
    let worst = late.iter().map(|(_, days)| *days).max().unwrap_or(0);
    let weeks = overdue_weeks(&late);

    Ok(html! {
        p.muted {
            "The vulnerabilities still to review after their remediation deadline: where they are, and whether they came at once or piled up. "
            "The lateness is the number of days past the deadline."
        }
        div.tiles {
            (figure(html! { (late.len()) }, "overdue vulnerabilities", can_list.then(|| format!("{}&show=overdue", scope.url("vulnerabilities"))), true))
            (figure(days_figure(Some(average)), "average lateness", None, false))
            (figure(days_figure(Some(worst as f64)), "worst lateness", None, false))
        }

        h2 { "By application" }
        table.list.fit {
            (views::columns("- project num num num", scope.all()))
            thead {
                tr {
                    (listing.th("app", "Application"))
                    @if scope.all() { (listing.th("project", "Project")) }
                    (listing.th("count", "Overdue")) (listing.th("average", "Average lateness")) (listing.th("worst", "Worst lateness"))
                }
            }
            tbody {
                @for app in &apps {
                    // The list of that application in its project, narrowed to what is overdue
                    @let list = format!("{}&show=overdue&app={}", product_url(Some((app.org, app.project)), "vulnerabilities"), enc(app.name));
                    tr {
                        td { @if can_list { a href=(list) { (app.name) } } @else { (app.name) } }
                        @if scope.all() { td.project { a href=(product_url(Some((app.org, app.project)), "overdue")) title=(app.project) { (app.project) } } }
                        td { (app.count) }
                        td { (days_figure(Some(app.average()))) }
                        td { (days_figure(Some(app.worst as f64))) }
                    }
                }
            }
        }

        h2 { "Over time" }
        p.muted {
            "A batch that arrived at once shows as one tall week of detection; a period without triage, as a number of overdue vulnerabilities climbing day after day."
        }
        div.card.days {
            h3 { "Today's overdue vulnerabilities, by week of detection and by week of deadline " small { "— weeks start on Monday" } }
            (charts::paired_bars(&weeks, ("detected that week", "p0"), ("due that week", "p1"), "Overdue vulnerabilities per week of detection and of deadline"))
            details.daily {
                summary { "The figures of this chart, week by week" }
                table.list.fit {
                    (views::columns("- num num", true))
                    thead { tr { th { "Week starting" } th { "Detected" } th { "Due" } } }
                    tbody {
                        @for (week, detected, due) in weeks.iter().rev().filter(|(_, detected, due)| detected + due > 0) {
                            tr { td { (week) } td { (detected) } td { (due) } }
                        }
                    }
                }
            }
        }
        (window)
    })
}

// ==========================================
// History: evolution over time, and state at a date
// ==========================================

fn history(db: &Database, user: &Account, scope: &Scope, q: &ProductQuery) -> Result<Markup, AppError> {
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

    let events = scope.events(db, user)?;
    let stats = timeline(&events, from, to);
    let accepted: Vec<(String, i64)> = stats.iter().map(|d| (d.day.clone(), d.accepted_total)).collect();
    let mut state = state_at(&events, at);
    let in_status = {
        let counts: Vec<String> = state.iter().map(|s| s.status.clone()).collect();
        move |status: &str| counts.iter().filter(|s| *s == status).count() as i64
    };
    let exploited = state.iter().filter(|i| i.status == "untreated" && i.event.kev).count() as i64;
    // The state of the day in charts, before the list is filtered
    let breakdown = breakdown_of(scope, &state);
    let breakdown_charts =
        if scope.all() { breakdown_charts_all(scope, &breakdown) } else { breakdown_charts_project(scope, &breakdown, &state) };
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
    let base = scope.url("history");
    let link = |day: &str| format!("{base}&days={days}&at={day}");
    let past = at < today;
    let previous = (at - Duration::days(1)).to_string();
    let next = (at + Duration::days(1)).to_string();
    let changes = scope.changes(db, user, 30)?;
    let reports = match scope.project_id() {
        Some(id) => db.list_reports(id, 30)?,
        None => Vec::new(),
    };

    Ok(html! {
        p.muted {
            "How the tracked CVEs evolved, and what they looked like on any past day. "
            strong { "Every day of a chart is a link" }
            ": point at it for its figures, click it to go back to that day. The date field does the same."
        }
        // Going back in time is the point of the view: the day shown is said first, with the ways to change it
        div.card.timetravel class=[past.then_some("past")] {
            div.when {
                @if past {
                    span.tag.warn { "Past state" }
                    " " strong { "You are looking at " (at_s) "." }
                    " The counters and the list below are those of the end of that day, not today's."
                } @else {
                    span.tag { "Today" }
                    " " strong { "You are looking at the current state." }
                    " Pick a day to see the state at the end of that day."
                }
            }
            form.row method="get" action=(scope.url("")) {
                input type="hidden" name="view" value="history";
                input type="hidden" name="days" value=(days);
                a.button href=(link(&previous)) title={ "State on " (previous) } { "← Previous day" }
                label { "Go to " input type="date" name="at" value=(at_s) max=(today.to_string()) required; }
                button type="submit" { "Show that day" }
                @if past {
                    a.button href=(link(&next)) title={ "State on " (next) } { "Next day →" }
                    a.button.today href={ (base) "&days=" (days) } { "Back to today" }
                }
            }
        }
        div.chips {
            @for (n, label) in [(30, "30 days"), (90, "90 days"), (365, "1 year")] {
                a href={ (base) "&days=" (n) "&at=" (at_s) } class=[(days == n).then_some("active")] { (label) }
            }
        }
        div.card.days {
            h3 { "CVEs to review, by severity " small { "— " (from) " to " (to) " · the severity is the one each CVE has today · click a day" } }
            (charts::severity_chart(&stats, Some(&at_s), &link))
            h3.next { "Accepted risks " small { "— " (stats.last().map_or(0, |d| d.accepted_total)) " on " (to) } }
            (charts::line_chart(&accepted, "st-accepted", "accepted risks", 60.0, Some(&at_s), &link))
            details.daily {
                summary { "The figures of these two charts, day by day" }
                table.list.fit {
                    (views::columns("- fig fig fig fig fig fig fig", true))
                    thead {
                        tr {
                            th { "Day" }
                            @for (_, label, _) in charts::SEVERITIES { th { (label) } }
                            th { "To review" } th { "Accepted" }
                        }
                    }
                    tbody {
                        @for d in stats.iter().rev() {
                            tr {
                                td { (d.day) }
                                @for n in d.open_by_severity { td { (n) } }
                                td { (d.open) } td { (d.accepted_total) }
                            }
                        }
                    }
                }
            }
        }
        div.card.days {
            h3 { "Activity per day: new entries and decisions " small { "— click a day" } }
            (charts::activity_chart(&stats, Some(&at_s), &link))
        }

        div.head {
            h2 { "State on " (at_s) @if past { " " span.tag.warn { "past" } } @else { " (today)" } }
            @if past { a href={ (base) "&days=" (days) } { "Back to today →" } }
        }
        div.tiles {
            (views::tile(in_status("untreated"), "to review", false))
            (views::tile(in_status("accepted"), "risks accepted", false))
            (views::tile(in_status("treated"), "closed", false))
            (views::tile(in_status("not_applicable"), "not applicable", false))
            (views::tile(exploited, "to review and known exploited (KEV)", true))
        }
        (breakdown_charts)
        (listing.filter_box("Filter: CVE, application, status, author…", state.len(), state_total))
        div.scroll {
            table.list.fit.dense {
                (views::columns("cve cvss app project decision when who -", scope.all()))
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
                            td.cve {
                                a href={ "/cve/" (enc(&e.cve_id)) } { (e.cve_id) }
                                @if e.kev { " " span.tag.kev { "KEV" } }
                            }
                            td.nowrap { (views::cvss_badge(e.cvss)) }
                            td { (e.app_name) " " span.muted { (e.app_version.as_deref().unwrap_or("")) } }
                            @if scope.all() { td { (project_cell(e)) } }
                            td { (status_badge(&item.status)) }
                            td.nowrap { (e.at) }
                            td { (actor_cell(e)) }
                            td { (e.comment.as_deref().unwrap_or("")) }
                        }
                    }
                    @if state.is_empty() { tr { td colspan="8" .muted { "Nothing was tracked at that date." } } }
                }
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
    let events = scope.events(db, user)?;
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
        div.scroll {
            table.list.fit.dense {
                (views::columns("when who decision cve cvss app project -", scope.all()))
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
                            td {
                                @if e.kind == "removed" {
                                    span.muted { "removed" }
                                } @else {
                                    span.muted { (charts::status_label(e.previous.as_deref().unwrap_or(""))) " → " }
                                    (status_badge(e.status.as_deref().unwrap_or("")))
                                }
                            }
                            td.cve {
                                a href={ "/cve/" (enc(&e.cve_id)) } { (e.cve_id) }
                                @if e.kev { " " span.tag.kev { "KEV" } }
                            }
                            td.nowrap { (views::cvss_badge(e.cvss)) }
                            td { (e.app_name) " " span.muted { (e.app_version.as_deref().unwrap_or("")) } }
                            @if scope.all() { td { (project_cell(e)) } }
                            td { (e.comment.as_deref().unwrap_or("")) }
                        }
                    }
                    @if decisions.is_empty() { tr { td colspan="8" .muted { "No decision of this kind yet." } } }
                }
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
        table.list.fit {
            (views::columns("- kind - act", true))
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
                    @for role in Role::ALL.iter().rev() { option value=(role.as_str()) selected[*role == Role::Viewer] { (role.as_str()) } }
                }
                button type="submit" { "Invite to this project" }
            }
            (super::invitations::pending_section(db, crate::db::Scope::Project(project.id), &base)?)
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
