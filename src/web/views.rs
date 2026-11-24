//! Shared HTML components (layout, badges, change rendering).

use maud::{html, Markup, DOCTYPE};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::changes::Event;
use crate::db::{Account, ChangeRow, CveSummary, ProjectChange, TriageItem};

/// Percent-encodes a value for use in a URL path segment or query value
pub fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Views of the "products" side, in navigation order: (key, label)
pub const PRODUCT_VIEWS: [(&str, &str); 6] = [
    ("overview", "Overview"),
    ("vulnerabilities", "Vulnerabilities"),
    ("applications", "Applications"),
    ("subscriptions", "Subscriptions"),
    ("history", "History"),
    ("audit", "Audit"),
];

/// Color themes, in the order of the menu: (key, label). The first one is the
/// default. Each has a day and a night palette in `app.css`.
pub const THEMES: [(&str, &str); 8] = [
    ("classic", "Classic"),
    ("forest", "Forest"),
    ("plum", "Plum"),
    ("sand", "Sand"),
    ("dracula", "Dracula"),
    ("nord", "Nord"),
    ("noctis", "Noctis"),
    ("contrast", "High contrast"),
];

/// Where the page sits in the navigation
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Nav<'a> {
    /// "My products" side: selected project (None = all) and active view
    Product {
        scope: Option<(&'a str, &'a str)>,
        view: &'a str,
    },
    /// "CVE database" side (reference information)
    Info(ExploreTab),
    Admin,
    None,
}

impl Nav<'_> {
    /// Products side without an active view (project and organization management)
    pub const PRODUCTS: Nav<'static> = Nav::Product { scope: None, view: "" };
}

/// Pages of the reference database
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExploreTab {
    Cves,
    Vendors,
    Weaknesses,
}

/// Data shown in the page chrome on every page: sync status and the user's
/// projects (for the project selector). Set per request by the
/// `page_context` middleware and read by [`layout`].
#[derive(Clone, Default)]
pub struct PageContext {
    /// Last completed sync, `YYYY-MM-DD HH:MM:SS` UTC
    pub last_sync: Option<String>,
    pub sync_running: bool,
    /// (organization, project) the user can access
    pub projects: Vec<(String, String)>,
    /// Organization the lists of "all projects" are narrowed to. Always one
    /// of those of `projects`: it is checked on every request, and it only
    /// hides rows; it never gives access to anything.
    pub org: Option<String>,
    /// Path and query of the current page (to come back after an action)
    pub path: String,
}

impl PageContext {
    /// Organizations the user sees a project of, in the order of the menu
    pub fn orgs(&self) -> Vec<&str> {
        let mut orgs: Vec<&str> = self.projects.iter().map(|(org, _)| org.as_str()).collect();
        orgs.dedup();
        orgs
    }
}

tokio::task_local! {
    pub static PAGE: PageContext;
}

/// Cookie holding the organization chosen in the menu (its name, percent-encoded)
pub const ORG_COOKIE: &str = "vz_org";

/// Key of a product view as written in an address. Views were renamed: the
/// addresses people bookmarked, and those in notifications already sent,
/// keep answering.
pub fn canonical_view(view: &str) -> &str {
    match view {
        "review" => "vulnerabilities",
        "evolution" => "history",
        other => other,
    }
}

/// URL of a product view for a scope
pub fn product_url(scope: Option<(&str, &str)>, view: &str) -> String {
    let base = match scope {
        Some((org, project)) => format!("/product/{}/{}", enc(org), enc(project)),
        None => "/product".to_string(),
    };
    if view.is_empty() || view == "overview" {
        base
    } else {
        format!("{base}?view={view}")
    }
}

/// A small "i" in a circle: the note shows in a bubble under the pointer, on
/// keyboard focus and on touch. No script.
pub fn info(note: Markup) -> Markup {
    html! {
        span.info tabindex="0" {
            span.i aria-hidden="true" { "i" }
            span.bubble role="note" { (note) }
        }
    }
}

/// "12 min ago" from a UTC `YYYY-MM-DD HH:MM:SS` timestamp
pub fn time_ago(timestamp: &str) -> String {
    let Ok(then) = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S") else {
        return timestamp.to_string();
    };
    let minutes = (chrono::Utc::now().naive_utc() - then).num_minutes().max(0);
    match minutes {
        0 => "just now".to_string(),
        1..=59 => format!("{minutes} min ago"),
        60..=1439 => format!("{} h ago", minutes / 60),
        _ => format!("{} d ago", minutes / 1440),
    }
}

/// Page without an active navigation section
pub fn page(title: &str, user: Option<&Account>, body: Markup) -> Markup {
    layout(Nav::None, title, user, body)
}

/// Page of the reference database
pub fn explore_page(tab: ExploreTab, title: &str, user: Option<&Account>, body: Markup) -> Markup {
    layout(Nav::Info(tab), title, user, body)
}

/// Row of tabs: (link, label, active)
pub fn tabs(items: &[(&str, &str, bool)]) -> Markup {
    html! {
        nav.tabs {
            @for (href, label, active) in items {
                a href=(href) class=[active.then_some("active")] { (label) }
            }
        }
    }
}

fn sync_status(ctx: &PageContext, user: Option<&Account>) -> Markup {
    html! {
        div.sync {
            @if ctx.sync_running {
                span.dot.running {} "Database sync in progress…"
            } @else if let Some(last) = &ctx.last_sync {
                span.dot {} span title={ (last) " UTC" } { "Database synced " (time_ago(last)) }
            } @else {
                span.dot.never {} "Database never synced"
            }
            @if user.is_some_and(|u| u.is_admin) && !ctx.sync_running {
                form.inline method="post" action="/sync" {
                    input type="hidden" name="back" value=(ctx.path);
                    button.small.secondary type="submit" { "Sync now" }
                }
            }
        }
    }
}

/// Organization selector, for who sees the projects of several: a no-script
/// dropdown whose entries are the buttons of one form. Choosing one narrows
/// the project menu and the lists of "all projects"; nothing else.
fn org_menu(ctx: &PageContext, back: &str) -> Markup {
    let orgs = ctx.orgs();
    html! {
        @if orgs.len() > 1 {
            details.menu.org {
                summary title="Switch organization" {
                    @match &ctx.org {
                        Some(org) => { (org) }
                        None => { "All organizations" }
                    }
                }
                form method="post" action="/org-filter" {
                    input type="hidden" name="back" value=(back);
                    ul {
                        li { button type="submit" name="org" value="" class=[ctx.org.is_none().then_some("active")] { "All organizations" } }
                        @for org in orgs {
                            li { button type="submit" name="org" value=(org) class=[(ctx.org.as_deref() == Some(org)).then_some("active")] { (org) } }
                        }
                    }
                }
            }
        }
    }
}

/// Project selector: a no-script dropdown keeping the current view
fn project_menu(ctx: &PageContext, scope: Option<(&str, &str)>, view: &str) -> Markup {
    let listed = || ctx.projects.iter().filter(|(org, _)| ctx.org.as_ref().is_none_or(|chosen| chosen == org));
    let several_orgs = listed().any(|(org, _)| Some(org) != listed().next().map(|(o, _)| o));
    html! {
        details.menu {
            summary title="Switch project" {
                @match (scope, &ctx.org) {
                    (Some((_, project)), _) => { (project) }
                    (None, Some(org)) => { "All projects" span.muted { " of " (org) } }
                    (None, None) => { "All projects" span.muted { " (*)" } }
                }
            }
            ul {
                li {
                    a href=(product_url(None, view)) class=[scope.is_none().then_some("active")] {
                        "All projects" @if let Some(org) = &ctx.org { " of " (org) } " (*)"
                    }
                }
                @for (org, project) in listed() {
                    @let current = scope == Some((org.as_str(), project.as_str()));
                    li {
                        a href=(product_url(Some((org, project)), view)) class=[current.then_some("active")] {
                            (project) @if several_orgs { " " span.muted { (org) } }
                        }
                    }
                }
                li.sep { a href="/projects" { "Manage projects…" } }
            }
        }
    }
}

/// Theme menu and day/night button. The choice lives in the browser, so the
/// two are driven by theme.js and hidden by the stylesheet where it does not run.
fn theme_controls() -> Markup {
    html! {
        div.theme {
            select data-theme-choice aria-label="Color theme" title="Color theme" autocomplete="off" {
                @for (key, label) in THEMES { option value=(key) { (label) } }
            }
            button.secondary type="button" data-mode-toggle title="Switch between day and night colors" {
                span.to-night { "☾ Night" }
                span.to-day { "☀ Day" }
            }
        }
    }
}

pub fn layout(nav: Nav, title: &str, user: Option<&Account>, body: Markup) -> Markup {
    layout_refreshing(nav, title, user, None, body)
}

/// Layout of a page that reloads itself every `refresh` seconds (used while
/// something is in progress; the page stops asking once it is over).
pub fn layout_refreshing(nav: Nav, title: &str, user: Option<&Account>, refresh: Option<u32>, body: Markup) -> Markup {
    let ctx = PAGE.try_with(|c| c.clone()).unwrap_or_default();
    let (scope, view) = match nav {
        Nav::Product { scope, view } => (scope, view),
        _ => (None, ""),
    };
    let on_products = matches!(nav, Nav::Product { .. });
    let info = |tab: ExploreTab, href: &str, label: &str| -> Markup {
        html! { a href=(href) class=[(nav == Nav::Info(tab)).then_some("active")] { (label) } }
    };
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                @if let Some(seconds) = refresh { meta http-equiv="refresh" content=(seconds); }
                title { (title) " · Vulnizard" }
                link rel="stylesheet" href="/static/app.css";
                link rel="icon" type="image/svg+xml" href="/static/logo.svg";
                // Not deferred: it sets the colors chosen in this browser before anything is drawn
                script src="/static/theme.js" {}
            }
            body {
                header.top {
                    div.bar {
                        a.brand href="/" { img src="/static/logo.svg" alt="" width="22" height="22"; "Vulnizard" }
                        // Nothing about the instance is shown to who is not signed in
                        @if user.is_some() { (sync_status(&ctx, user)) }
                        div.user {
                            (theme_controls())
                            @if let Some(u) = user {
                                @if u.is_admin {
                                    a href="/admin" class=[(nav == Nav::Admin).then_some("active")] { "Admin" }
                                }
                                a href="/settings" { (u.username) }
                                form.inline method="post" action="/logout" {
                                    button.link type="submit" { "Log out" }
                                }
                            } @else {
                                a href="/login" { "Log in" }
                            }
                        }
                    }
                    @if user.is_some() {
                        div.zones {
                            nav.zone.product {
                                span.zone-label { "My products" }
                                // From a products page the choice leads to all the projects of the view
                                // shown; from any other page, back to that page
                                (org_menu(&ctx, &if on_products && !view.is_empty() { product_url(None, view) } else { ctx.path.clone() }))
                                (project_menu(&ctx, scope, if view.is_empty() { "overview" } else { view }))
                                @for (key, label) in PRODUCT_VIEWS {
                                    a href=(product_url(scope, key)) class=[(on_products && view == key).then_some("active")] { (label) }
                                }
                                @if scope.is_some() {
                                    a href=(product_url(scope, "settings")) class=[(view == "settings").then_some("active")] { "Settings" }
                                }
                            }
                            nav.zone.info {
                                span.zone-label { "CVE database" }
                                (info(ExploreTab::Cves, "/cve", "CVEs"))
                                (info(ExploreTab::Vendors, "/vendors", "Vendors"))
                                (info(ExploreTab::Weaknesses, "/weaknesses", "Weaknesses"))
                            }
                        }
                    }
                }
                main { (body) }
                footer.bottom {
                    span {
                        "Vulnizard"
                        // The version helps whoever attacks: only for signed-in users
                        @if user.is_some() { " " (env!("CARGO_PKG_VERSION")) }
                    }
                    a href="https://github.com/likarum/Vulnizard" rel="noreferrer noopener" target="_blank" { "Source" }
                    a href="https://github.com/likarum/Vulnizard/blob/main/DISCLAIMER.md" rel="noreferrer noopener" target="_blank" { "Disclaimer" }
                    a href="https://github.com/likarum/Vulnizard/issues" rel="noreferrer noopener" target="_blank" { "Report a problem" }
                    span.muted { "Provided as is, without warranty." }
                }
                script src="/static/filter.js" defer {}
            }
        }
    }
}

// ==========================================
// Sortable, filterable lists
// ==========================================

/// Value a list is sorted on
pub enum SortKey {
    Text(String),
    Num(f64),
}

impl SortKey {
    pub fn text(value: impl AsRef<str>) -> Self {
        SortKey::Text(value.as_ref().to_lowercase())
    }

    pub fn num(value: impl Into<f64>) -> Self {
        SortKey::Num(value.into())
    }

    /// Missing numbers sort below every value
    pub fn opt(value: Option<f64>) -> Self {
        SortKey::Num(value.unwrap_or(f64::NEG_INFINITY))
    }

    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (SortKey::Text(a), SortKey::Text(b)) => a.cmp(b),
            (SortKey::Num(a), SortKey::Num(b)) => a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal),
            (SortKey::Num(_), SortKey::Text(_)) => std::cmp::Ordering::Less,
            (SortKey::Text(_), SortKey::Num(_)) => std::cmp::Ordering::Greater,
        }
    }
}

/// Sort and filter state of a list, carried by the `sort`, `dir` and `q`
/// query parameters. Works without JavaScript: column headers are links and
/// the filter is a GET form, both keeping the other parameters of the page.
pub struct Listing {
    pub sort: String,
    pub desc: bool,
    pub q: String,
    path: String,
    /// Other query parameters of the page (kept in every link)
    others: Vec<(String, String)>,
}

impl Listing {
    /// Reads the state from the current page. `default_sort` is only used to
    /// show which column orders the list when none was chosen.
    pub fn from_page(default_sort: &str, default_desc: bool) -> Self {
        let current = PAGE.try_with(|c| c.path.clone()).unwrap_or_default();
        Self::parse(&current, default_sort, default_desc)
    }

    pub fn parse(path_and_query: &str, default_sort: &str, default_desc: bool) -> Self {
        let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
        let mut listing = Listing {
            sort: default_sort.to_string(),
            desc: default_desc,
            q: String::new(),
            path: path.to_string(),
            others: Vec::new(),
        };
        let mut chosen = false;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "sort" if !value.is_empty() => {
                    listing.sort = value.chars().take(32).collect();
                    chosen = true;
                }
                "sort" => {}
                "dir" => listing.desc = value == "desc",
                "q" => listing.q = value.trim().chars().take(100).collect(),
                // A new order or filter restarts from the first page
                "page" => {}
                _ => listing.others.push((key.into_owned(), value.into_owned())),
            }
        }
        if !chosen {
            listing.sort = default_sort.to_string();
            listing.desc = default_desc;
        }
        listing
    }

    fn url(&self, sort: &str, desc: bool, q: &str) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in &self.others {
            query.append_pair(key, value);
        }
        if !sort.is_empty() {
            query.append_pair("sort", sort);
            query.append_pair("dir", if desc { "desc" } else { "asc" });
        }
        if !q.is_empty() {
            query.append_pair("q", q);
        }
        let query = query.finish();
        if query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, query)
        }
    }

    /// Query string of the current state (without `page`), for pagers
    pub fn query(&self) -> String {
        self.url(&self.sort, self.desc, &self.q)
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default()
    }

    /// Sortable column header: a click sorts on the column, a second one reverses
    pub fn th(&self, key: &str, label: &str) -> Markup {
        let active = self.sort == key;
        // Numbers and dates are most useful largest first
        let desc = if active { !self.desc } else { false };
        html! {
            th {
                a.sort href=(self.url(key, desc, &self.q)) class=[active.then_some("active")]
                    title=(if active { "Reverse the order" } else { "Sort on this column" }) {
                    (label)
                    @if active { span.arrow { (if self.desc { " ▼" } else { " ▲" }) } }
                }
            }
        }
    }

    /// Filter box; `shown` / `total` tell how many rows match
    pub fn filter_box(&self, placeholder: &str, shown: usize, total: usize) -> Markup {
        html! {
            form.filters method="get" action=(self.path) {
                @for (key, value) in &self.others { input type="hidden" name=(key) value=(value); }
                input type="hidden" name="sort" value=(self.sort);
                input type="hidden" name="dir" value=(if self.desc { "desc" } else { "asc" });
                input type="search" name="q" value=(self.q) placeholder=(placeholder) maxlength="100";
                button.secondary type="submit" { "Filter" }
                span.filter-status {
                    @if !self.q.is_empty() {
                        a href=(self.url(&self.sort, self.desc, "")) { "Clear" }
                        " " span.muted { (shown) " of " (total) }
                    } @else {
                        span.muted { (total) " row" @if total != 1 { "s" } }
                    }
                }
            }
        }
    }

    /// Filters the rows on the search text, then sorts them. `text` gives the
    /// searchable content of a row, `key` its value for a column.
    pub fn apply<T>(&self, items: &mut Vec<T>, text: impl Fn(&T) -> String, key: impl Fn(&T, &str) -> Option<SortKey>) {
        if !self.q.is_empty() {
            let needle = self.q.to_lowercase();
            items.retain(|item| text(item).to_lowercase().contains(&needle));
        }
        // An unknown column keeps the order given by the caller
        if items.first().is_some_and(|first| key(first, &self.sort).is_some()) {
            items.sort_by(|a, b| {
                let ordering = match (key(a, &self.sort), key(b, &self.sort)) {
                    (Some(a), Some(b)) => a.compare(&b),
                    _ => std::cmp::Ordering::Equal,
                };
                if self.desc {
                    ordering.reverse()
                } else {
                    ordering
                }
            });
        }
    }
}

/// Counter tile of the dashboards
pub fn tile(value: i64, label: &str, alert: bool) -> Markup {
    html! {
        div class=(if alert && value > 0 { "tile alert" } else { "tile" }) {
            div.value { (value) }
            div.label { (label) }
        }
    }
}

pub fn error_page(status: u16, message: &str) -> Markup {
    page(
        "Error",
        None,
        html! {
            h1 { (status) }
            p.error { (message) }
            p { a href="/" { "Back to home" } }
        },
    )
}

pub fn cvss_badge(score: Option<f64>) -> Markup {
    let (class, label) = match score {
        Some(s) if s >= 9.0 => ("sev critical", format!("{s:.1} Critical")),
        Some(s) if s >= 7.0 => ("sev high", format!("{s:.1} High")),
        Some(s) if s >= 4.0 => ("sev medium", format!("{s:.1} Medium")),
        Some(s) => ("sev low", format!("{s:.1} Low")),
        None => ("sev none", "N/A".to_string()),
    };
    html! { span class=(class) { (label) } }
}

pub fn short_date(date: Option<&str>) -> &str {
    date.and_then(|d| d.get(..10)).unwrap_or("—")
}

pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max_chars).collect();
        format!("{cut}…")
    }
}

/// Column header, sortable when the list has a [`Listing`]
pub fn th(listing: Option<&Listing>, key: &str, label: &str) -> Markup {
    match listing {
        Some(listing) => listing.th(key, label),
        None => html! { th { (label) } },
    }
}

pub fn cve_table(cves: &[CveSummary], listing: Option<&Listing>) -> Markup {
    html! {
        table.list.fit {
            (columns("cve cvss flag - day", true))
            thead {
                tr {
                    (th(listing, "id", "CVE")) (th(listing, "cvss", "CVSS")) (th(listing, "epss", "EPSS"))
                    th { "Description" } (th(listing, "updated", "Updated"))
                }
            }
            tbody {
                @for c in cves {
                    tr {
                        td.cve {
                            a href={ "/cve/" (enc(&c.cve_id)) } { (c.cve_id) }
                            @if c.kev { " " span.tag.kev title="CISA Known Exploited" { "KEV" } }
                        }
                        td.nowrap { (cvss_badge(c.cvss)) }
                        td.nowrap {
                            @if let Some(e) = c.epss { (format!("{:.1}%", e * 100.0)) } @else { "—" }
                        }
                        td { (truncate(c.description.as_deref().unwrap_or(""), 220)) }
                        td.nowrap { (short_date(c.modified_at.as_deref().or(c.published_at.as_deref()))) }
                    }
                }
                @if cves.is_empty() {
                    tr { td colspan="5" .muted { "No CVE found." } }
                }
            }
        }
    }
}

fn string_list(label: &str, class: &str, items: &[String]) -> Markup {
    html! {
        @if !items.is_empty() {
            div class=(class) {
                strong { (label) }
                ul { @for item in items.iter().take(20) { li { (item) } } }
                @if items.len() > 20 { p.muted { "… and " (items.len() - 20) " more" } }
            }
        }
    }
}

pub fn event_details(event: &Event) -> Markup {
    html! {
        div.event {
            span.tag { (event.label()) }
            @match event {
                Event::Created | Event::Kev => {}
                Event::Description { old, new } => {
                    @if let Some(old) = old { p.removed { (old) } }
                    @if let Some(new) = new { p.added { (new) } }
                }
                Event::Metrics { old, new } => {
                    p { (cvss_badge(*old)) " → " (cvss_badge(*new)) }
                }
                Event::Vendors { added, removed }
                | Event::References { added, removed }
                | Event::Weaknesses { added, removed } => {
                    (string_list("Added", "added", added))
                    (string_list("Removed", "removed", removed))
                }
            }
        }
    }
}

/// Change list for a single CVE (detail page)
pub fn change_history(changes: &[ChangeRow]) -> Markup {
    html! {
        @for change in changes {
            div.change {
                div.muted { (change.created_at) }
                @for event in &change.events { (event_details(event)) }
            }
        }
        @if changes.is_empty() {
            p.muted { "No change recorded yet." }
        }
    }
}

/// Change list across CVEs (project report)
pub fn report_changes(changes: &[ChangeRow]) -> Markup {
    html! {
        @for change in changes {
            div.change {
                div {
                    a href={ "/cve/" (enc(&change.cve_id)) } { strong { (change.cve_id) } }
                    " " (cvss_badge(change.cvss)) " "
                    span.muted { (change.created_at) }
                }
                @if let Some(desc) = &change.description { p { (truncate(desc, 300)) } }
                @for event in &change.events { (event_details(event)) }
            }
        }
        @if changes.is_empty() {
            p.muted { "No change in this report." }
        }
    }
}

/// One-line summary of the events of a change
pub fn event_tags(events: &[Event]) -> Markup {
    html! { @for e in events { span.tag { (e.label()) } " " } }
}

/// Latest changes on subscribed CVEs, across projects
pub fn project_changes(changes: &[ProjectChange], show_project: bool) -> Markup {
    html! {
        table.list.fit {
            (columns("cve cvss - project when", show_project))
            thead {
                tr {
                    th { "CVE" } th { "CVSS" } th { "What changed" }
                    @if show_project { th { "Project" } }
                    th { "When (UTC)" }
                }
            }
            tbody {
                @for c in changes {
                    tr {
                        td.cve { a href={ "/cve/" (enc(&c.cve_id)) } { (c.cve_id) } }
                        td.nowrap { (cvss_badge(c.cvss)) }
                        td { (event_tags(&c.events)) }
                        @if show_project {
                            td.project {
                                a href={ "/orgs/" (enc(&c.org)) "/projects/" (enc(&c.project)) } title=(c.project) { (c.project) }
                            }
                        }
                        td.nowrap { (c.created_at.replace('T', " ").trim_end_matches('Z')) }
                    }
                }
                @if changes.is_empty() {
                    tr { td colspan=(if show_project { "5" } else { "4" }) .muted {
                        "No change yet on the subscribed vendors and products."
                    } }
                }
            }
        }
    }
}

/// Watchlist entries to review. `actions` renders the buttons of a row.
/// Searchable text and sort keys of a watchlist entry
pub fn triage_text(item: &TriageItem) -> String {
    format!(
        "{} {} {} {} {} {}",
        item.cve_id,
        item.app_name,
        item.app_version.as_deref().unwrap_or(""),
        item.project,
        item.group,
        item.description.as_deref().unwrap_or("")
    )
}

pub fn triage_key(item: &TriageItem, column: &str) -> Option<SortKey> {
    match column {
        "cve" => Some(SortKey::text(&item.cve_id)),
        "cvss" => Some(SortKey::opt(item.cvss)),
        "app" => Some(SortKey::text(&item.app_name)),
        "project" => Some(SortKey::text(&item.project)),
        "status" => Some(SortKey::text(&item.status)),
        _ => None,
    }
}

/// Columns of a list of vulnerabilities to decide on. Their widths are set
/// by the stylesheet (`table.fit`): the table is as wide as its box at any
/// window width, and it is the long texts that wrap.
pub fn triage_columns(show_project: bool, middle: &str) -> Markup {
    columns(&format!("cve cvss app project {middle} actions"), show_project)
}

/// Column group of a list sized by the stylesheet (`table.fit`): one word per
/// column, separated by spaces. A name gives the column its width (`cve`,
/// `when`, `num`, `name`, `act`…: see the stylesheet); a dash is a column of
/// free text, which takes what is left. The `project` column is dropped when
/// the list is the one of a single project.
pub fn columns(names: &str, show_project: bool) -> Markup {
    html! {
        colgroup {
            @for name in names.split_whitespace().filter(|n| show_project || *n != "project") {
                col class=[(name != "-").then_some(name)];
            }
        }
    }
}

/// Vulnerabilities to review, with the buttons deciding on each
pub fn triage_table(
    items: &[TriageItem],
    show_project: bool,
    listing: Option<&Listing>,
    actions: impl Fn(&TriageItem) -> Markup,
) -> Markup {
    html! {
        table.list.triage.fit {
            (triage_columns(show_project, "desc"))
            thead {
                tr {
                    (th(listing, "cve", "CVE")) (th(listing, "cvss", "CVSS")) (th(listing, "app", "Application"))
                    @if show_project { (th(listing, "project", "Project")) }
                    th { "Description" } th {}
                }
            }
            tbody {
                @for item in items {
                    @let description = item.description.as_deref().unwrap_or("");
                    tr {
                        td.cve {
                            a href={ "/cve/" (enc(&item.cve_id)) } { (item.cve_id) }
                            @if item.kev { " " span.tag.kev title="CISA Known Exploited" { "KEV" } }
                            @if item.version_unknown { " " span.tag.warn title="No source gives the versions this CVE affects: the application is kept out of caution. Read the CVE before deciding." { "version not given" } }
                        }
                        td.nowrap.cvss { (cvss_badge(item.cvss)) }
                        td.app { (item.app_name) " " span.muted { (item.app_version.as_deref().unwrap_or("")) } @if !item.group.is_empty() { div { span.tag title="Group of inventory sources this decision holds for" { (item.group) } } } }
                        @if show_project {
                            td.project {
                                a href={ "/orgs/" (enc(&item.org)) "/projects/" (enc(&item.project)) } title=(item.project) { (item.project) }
                            }
                        }
                        // The title gives the text back where a narrow window cuts it after a few lines
                        td.desc { @if !description.is_empty() { div.clamp title=(truncate(description, 160)) { (truncate(description, 160)) } } }
                        td.right.actions { (actions(item)) }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan=(if show_project { "6" } else { "5" }) .muted { "Nothing to review." } }
                }
            }
        }
    }
}

pub const STYLESHEET: &str = include_str!("app.css");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_reads_and_rebuilds_the_query() {
        let l = Listing::parse("/product?view=review&sort=cvss&dir=desc&q=+open%20ssh+&page=3", "cve", false);
        assert_eq!((l.sort.as_str(), l.desc, l.q.as_str()), ("cvss", true, "open ssh"));
        // Other parameters are kept, the page is dropped
        assert_eq!(l.query(), "view=review&sort=cvss&dir=desc&q=open+ssh");
        let header = l.th("cvss", "CVSS").into_string();
        assert!(header.contains("dir=asc") && header.contains("▼"));
        let other = l.th("app", "Application").into_string();
        assert!(other.contains("sort=app") && other.contains("dir=asc") && !other.contains("▼"));

        let default = Listing::parse("/admin/users", "user", false);
        assert_eq!((default.sort.as_str(), default.desc, default.q.as_str()), ("user", false, ""));
        // Values are escaped in links and form fields
        let evil = Listing::parse("/x?q=%22%3E%3Cscript%3E&tab=%22%3E", "a", false);
        let html = format!("{}{}", evil.th("a", "A").into_string(), evil.filter_box("f", 0, 0).into_string());
        assert!(!html.contains("<script>") && html.contains("&quot;&gt;&lt;script&gt;"));
    }

    #[test]
    fn the_vulnerabilities_table_is_sized_by_the_stylesheet() {
        let item = TriageItem {
            entry_id: 1,
            cve_id: "CVE-2024-6387".into(),
            status: "untreated".into(),
            priority: None,
            app_name: "org.apache.logging.log4j:log4j-core-enterprise-distribution".into(),
            app_version: Some("2.17.1".into()),
            org: "acme".into(),
            project: "customer-facing-payment-platform".into(),
            cvss: Some(8.1),
            kev: true,
            description: Some("A race condition. ".repeat(30)),
            group: "web".into(),
            version_unknown: true,
        };
        let all = triage_table(std::slice::from_ref(&item), true, None, |_| html! { button { "Close" } }).into_string();
        // The columns are named for the stylesheet, which gives each its width
        assert!(all.contains("<table class=\"list triage fit\"><colgroup><col class=\"cve\"><col class=\"cvss\"><col class=\"app\"><col class=\"project\"><col class=\"desc\"><col class=\"actions\"></colgroup>"), "{all}");
        // Only the score is kept on one line: names, tags and buttons wrap inside their column
        assert_eq!(all.matches("nowrap").count(), 1, "{all}");
        assert!(all.contains("title=\"customer-facing-payment-platform\">customer-facing-payment-platform</a>"));
        for cell in ["<td class=\"cve\">", "<td class=\"nowrap cvss\">", "<td class=\"app\">", "<td class=\"project\">", "<td class=\"right actions\">"] {
            assert!(all.contains(cell), "{cell}");
        }
        // The description is cut at 160 characters, and its title keeps that text where the window cuts further
        let shown = format!("{}…", "A race condition. ".repeat(30).chars().take(160).collect::<String>());
        assert!(all.contains(&format!("<td class=\"desc\"><div class=\"clamp\" title=\"{shown}\">{shown}</div></td>")), "{all}");

        // One project: no project column, in the column group as in the rows
        let one = triage_table(&[item], false, None, |_| html! {}).into_string();
        assert!(one.contains("<col class=\"app\"><col class=\"desc\">") && !one.contains("class=\"project\""));
        let empty = triage_table(&[], false, None, |_| html! {}).into_string();
        assert!(empty.contains("colspan=\"5\"") && empty.contains("Nothing to review."));
        assert!(triage_columns(true, "decision").into_string().contains("<col class=\"project\"><col class=\"decision\"><col class=\"actions\">"));

        // The stylesheet fixes the layout, sizes every named column and lets long words break
        let comments = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap();
        let css = comments.replace_all(STYLESHEET, "").into_owned();
        assert!(css.contains("table.list.fit { table-layout: fixed; }") && css.contains("table.fit td { overflow-wrap: anywhere; }"));
        for column in ["cve", "cvss", "app", "project", "desc", "decision", "actions"] {
            // The description is the one column left without a width: it takes what remains
            assert_eq!(css.contains(&format!("table.fit col.{column} {{ width:")), column != "desc", "{column}");
        }
        // On a phone the rows are cards: the column group must not take part in them
        assert!(css.contains("table.list colgroup { display: none; }"));
    }

    #[test]
    fn a_list_names_its_columns_and_the_stylesheet_sizes_them() {
        // One name per column; the project column is dropped for a single project
        assert_eq!(
            columns("when who project -", true).into_string(),
            "<colgroup><col class=\"when\"><col class=\"who\"><col class=\"project\"><col></colgroup>"
        );
        assert_eq!(columns("when who project -", false).into_string(), "<colgroup><col class=\"when\"><col class=\"who\"><col></colgroup>");

        let comments = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap();
        let css = comments.replace_all(STYLESHEET, "").into_owned();
        // Between the phone layout and a wide window the same columns are tighter
        let narrow = css.split("@media (min-width: 761px) and (max-width: 1199px) {").nth(1).unwrap().split("\n}\n").next().unwrap();
        let sized = ["check", "cve", "cvss", "when", "day", "num", "flag", "kind", "decision", "name", "app", "who", "project", "wide", "version", "act", "actions"];
        for column in sized {
            assert!(css.contains(&format!("\ntable.fit col.{column} {{ width:")), "{column}");
            // One button keeps its width: its text has to fit
            assert_eq!(narrow.contains(&format!("table.fit col.{column} {{ width:")), column != "act", "{column} in a narrow window");
        }
        // No name is also a class of the page: a column that became a flex box would shift every column after it
        for column in sized.iter().chain(["desc"].iter()) {
            assert!(!css.contains(&format!("\n.{column} ")) && !css.contains(&format!(", .{column} ")), "{column}");
        }
        // A date goes over its time, and the header never sticks out of its column
        assert!(narrow.contains("table.fit td.nowrap { white-space: normal; }") && css.contains("table.fit th { overflow-wrap: break-word; }"));
        // Names cut on one line where the window is narrow carry a title
        assert!(narrow.contains("table.fit td.project a, table.fit .cut { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }"));

        // The lists of seven or eight columns keep a width they can be read at, and scroll in their own box below it
        assert!(css.contains("\n.scroll { overflow-x: auto; }") && narrow.contains("table.fit.dense { min-width: 960px; }"));
        assert!(!css.split("@media (max-width: 760px)").nth(1).unwrap().contains("min-width: 960px"));

        // Cells asking for it are aligned on the right: the rule comes after the one aligning every cell on the
        // left (same weight, the later wins), and the cards of a phone put them back on the left
        let left = css.find("table.list th, table.list td {").unwrap();
        let right = css.find("table.list td.right { text-align: right; }").unwrap();
        let phone = css.find("@media (max-width: 760px)").unwrap();
        assert!(left < right && right < phone);
        // The form a decision opens follows its buttons
        assert!(css.contains("table.list td.right form.row { justify-content: flex-end; }"));
        assert!(css[phone..].contains("table.list td, table.list td.nowrap, table.list td.right {") && css[phone..].contains("text-align: left;"));
    }

    #[test]
    fn the_lists_of_cves_and_of_changes_fit_the_window() {
        let cve = CveSummary {
            cve_id: "CVE-2024-6387".into(),
            description: Some("A race condition. ".repeat(30)),
            cvss: Some(8.1),
            epss: Some(0.42),
            kev: true,
            published_at: Some("2024-07-01T08:15:00Z".into()),
            modified_at: None,
        };
        let list = cve_table(&[cve], None).into_string();
        assert!(list.starts_with("<table class=\"list fit\"><colgroup><col class=\"cve\"><col class=\"cvss\"><col class=\"flag\"><col><col class=\"day\"></colgroup>"), "{list}");
        // The identifier is kept whole by the stylesheet (td.cve a), its tag may go under it
        assert!(list.contains("<td class=\"cve\"><a href=\"/cve/CVE%2D2024%2D6387\">CVE-2024-6387</a>"), "{list}");
        assert_eq!(list.matches("<col").count() - 1, list.matches("<th").count() - 1);

        let change = ProjectChange {
            cve_id: "CVE-2024-6387".into(),
            cvss: Some(8.1),
            org: "acme".into(),
            project: "customer-facing-payment-platform".into(),
            created_at: "2026-11-22T15:13:41Z".into(),
            events: vec![Event::Kev],
        };
        let all = project_changes(std::slice::from_ref(&change), true).into_string();
        assert!(all.starts_with("<table class=\"list fit\"><colgroup><col class=\"cve\"><col class=\"cvss\"><col><col class=\"project\"><col class=\"when\"></colgroup>"), "{all}");
        // A long project name no longer widens the table: it wraps, or is cut with its title where the window is narrow
        assert!(all.contains("<td class=\"project\"><a href=\"/orgs/acme/projects/customer%2Dfacing%2Dpayment%2Dplatform\" title=\"customer-facing-payment-platform\">"), "{all}");
        let one = project_changes(&[change], false).into_string();
        assert!(one.contains("<col class=\"cvss\"><col><col class=\"when\">") && !one.contains("class=\"project\""));
    }

    #[test]
    fn listing_filters_then_sorts() {
        let rows = || vec![("openssh", Some(8.1)), ("nginx", None), ("mongodb", Some(9.0)), ("OpenSSL", Some(5.0))];
        let text = |r: &(&str, Option<f64>)| r.0.to_string();
        let key = |r: &(&str, Option<f64>), col: &str| match col {
            "name" => Some(SortKey::text(r.0)),
            "cvss" => Some(SortKey::opt(r.1)),
            _ => None,
        };
        let names = |l: &Listing| {
            let mut items = rows();
            l.apply(&mut items, text, key);
            items.into_iter().map(|r| r.0).collect::<Vec<_>>()
        };
        assert_eq!(names(&Listing::parse("/x?sort=name", "name", false)), ["mongodb", "nginx", "openssh", "OpenSSL"]);
        assert_eq!(names(&Listing::parse("/x?sort=cvss&dir=desc", "name", false)), ["mongodb", "openssh", "OpenSSL", "nginx"]);
        assert_eq!(names(&Listing::parse("/x?sort=cvss", "name", false)), ["nginx", "OpenSSL", "openssh", "mongodb"]);
        assert_eq!(names(&Listing::parse("/x?q=OPENSS&sort=name&dir=desc", "name", false)), ["OpenSSL", "openssh"]);
        // Unknown column: the caller's order is kept
        assert_eq!(names(&Listing::parse("/x?sort=bogus", "name", false)), ["openssh", "nginx", "mongodb", "OpenSSL"]);
    }

    /// Variables set by the first rule of the stylesheet with this selector
    fn variables(css: &str, selector: &str) -> std::collections::BTreeMap<String, String> {
        let opening = format!("{selector} {{");
        let start = css
            .match_indices(&opening)
            // ":root {" must not be found inside "x:root {"
            .find(|(at, _)| css[..*at].chars().next_back().is_none_or(char::is_whitespace))
            .unwrap_or_else(|| panic!("no rule {selector}"))
            .0;
        let body = css[start + opening.len()..].split('}').next().unwrap();
        body.split(';')
            .filter_map(|declaration| declaration.trim().split_once(':'))
            .filter(|(name, _)| name.starts_with("--"))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .collect()
    }

    /// Relative luminance of `#rrggbb` (WCAG 2)
    fn luminance(color: &str) -> f64 {
        let hex = color.strip_prefix('#').filter(|h| h.len() == 6).unwrap_or_else(|| panic!("not #rrggbb: {color}"));
        let channel = |i: usize| {
            let c = u8::from_str_radix(&hex[i..i + 2], 16).unwrap() as f64 / 255.0;
            if c <= 0.04045 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4)
    }

    fn contrast(a: &str, b: &str) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    }

    #[test]
    fn every_theme_keeps_text_badges_and_dots_readable_by_day_and_by_night() {
        let comments = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap();
        let css = comments.replace_all(STYLESHEET, "").into_owned();
        let day = variables(&css, ":root");
        let night = variables(&css, ":root[data-mode=\"dark\"]");
        // Night is written twice (system setting without script, button): the two must not drift apart
        assert_eq!(night, variables(&css, ":root:not([data-mode=\"light\"])"));
        assert!(night.len() > 15 && night.keys().all(|name| day.contains_key(name)));

        // Text on its background: 4.5 (WCAG AA, normal size)
        let text_pairs = [
            ("--text", "--bg"), ("--text", "--surface"), ("--muted", "--bg"), ("--muted", "--surface"),
            ("--accent", "--bg"), ("--accent", "--surface"), ("--danger", "--bg"), ("--danger", "--surface"),
            ("--on-accent", "--accent"), ("--on-danger", "--danger"),
            ("--text", "--tag-bg"), ("--text", "--added"), ("--text", "--removed"),
            ("--accent", "--product-wash"), ("--text", "--product-wash"),
            ("--info-ink", "--info-bg"), ("--info-ink", "--info-wash"), ("--text", "--info-bg"), ("--text", "--info-wash"),
            ("--badge-critical-ink", "--badge-critical"), ("--badge-high-ink", "--badge-high"),
            ("--badge-medium-ink", "--badge-medium"), ("--badge-low-ink", "--badge-low"),
        ];
        // A dot or a mark told from what is around it: 3 (WCAG, graphical objects)
        let mark_pairs = [
            ("--ok", "--surface"), ("--busy", "--surface"), ("--neutral", "--surface"), ("--danger", "--surface"),
            ("--warn", "--surface"), ("--accent", "--surface"),
        ];
        let mut failures = Vec::new();
        for (theme, _) in THEMES {
            for mode in ["light", "dark"] {
                let mut palette = day.clone();
                if mode == "dark" {
                    palette.extend(night.clone());
                }
                if theme != THEMES[0].0 {
                    let own = variables(&css, &format!(":root[data-theme=\"{theme}\"][data-mode=\"{mode}\"]"));
                    assert!(own.keys().all(|name| day.contains_key(name)), "{theme} {mode} sets an unknown variable");
                    assert!(own.len() >= 6, "{theme} {mode}");
                    palette.extend(own);
                }
                let pairs = text_pairs.iter().map(|p| (p, 4.5)).chain(mark_pairs.iter().map(|p| (p, 3.0)));
                for ((ink, ground), required) in pairs {
                    let ratio = contrast(&palette[*ink], &palette[*ground]);
                    // Shown with --nocapture: the figures of the whole grid
                    println!("{theme:9} {mode:5} {ink:20} on {ground:16} {ratio:5.2} (min {required})");
                    if ratio < required {
                        failures.push(format!("{theme} {mode}: {ink} on {ground} is {ratio:.2}, below {required}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // The measure itself: black on white is 21, and a known pair
        assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 0.01);
        assert!((contrast("#767676", "#ffffff") - 4.54).abs() < 0.01);
    }
}
