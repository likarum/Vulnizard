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
    ("review", "To review"),
    ("applications", "Applications"),
    ("subscriptions", "Subscriptions"),
    ("evolution", "Evolution"),
    ("audit", "Audit"),
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
    /// Path and query of the current page (to come back after an action)
    pub path: String,
}

tokio::task_local! {
    pub static PAGE: PageContext;
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

/// Project selector: a no-script dropdown keeping the current view
fn project_menu(ctx: &PageContext, scope: Option<(&str, &str)>, view: &str) -> Markup {
    let several_orgs = ctx.projects.iter().any(|(org, _)| Some(org) != ctx.projects.first().map(|(o, _)| o));
    html! {
        details.menu {
            summary title="Switch project" {
                @match scope {
                    Some((_, project)) => { (project) }
                    None => { "All projects" span.muted { " (*)" } }
                }
            }
            ul {
                li { a href=(product_url(None, view)) class=[scope.is_none().then_some("active")] { "All projects (*)" } }
                @for (org, project) in &ctx.projects {
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
            }
            body {
                header.top {
                    div.bar {
                        a.brand href="/" { img src="/static/logo.svg" alt="" width="22" height="22"; "Vulnizard" }
                        // Nothing about the instance is shown to who is not signed in
                        @if user.is_some() { (sync_status(&ctx, user)) }
                        div.user {
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
        table.list {
            thead {
                tr {
                    (th(listing, "id", "CVE")) (th(listing, "cvss", "CVSS")) (th(listing, "epss", "EPSS"))
                    th { "Description" } (th(listing, "updated", "Updated"))
                }
            }
            tbody {
                @for c in cves {
                    tr {
                        td.nowrap {
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
        table.list {
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
                        td.nowrap { a href={ "/cve/" (enc(&c.cve_id)) } { (c.cve_id) } }
                        td.nowrap { (cvss_badge(c.cvss)) }
                        td { (event_tags(&c.events)) }
                        @if show_project {
                            td.nowrap {
                                a href={ "/orgs/" (enc(&c.org)) "/projects/" (enc(&c.project)) } { (c.project) }
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

pub fn triage_table(
    items: &[TriageItem],
    show_project: bool,
    listing: Option<&Listing>,
    actions: impl Fn(&TriageItem) -> Markup,
) -> Markup {
    html! {
        table.list.triage {
            thead {
                tr {
                    (th(listing, "cve", "CVE")) (th(listing, "cvss", "CVSS")) (th(listing, "app", "Application"))
                    @if show_project { (th(listing, "project", "Project")) }
                    th.plain { "Description" } th.plain {}
                }
            }
            tbody {
                @for item in items {
                    tr {
                        td.nowrap.cve {
                            a href={ "/cve/" (enc(&item.cve_id)) } { (item.cve_id) }
                            @if item.kev { " " span.tag.kev title="CISA Known Exploited" { "KEV" } }
                            @if item.version_unknown { " " span.tag.warn title="No source gives the versions this CVE affects: the application is kept out of caution. Read the CVE before deciding." { "version not given" } }
                        }
                        td.nowrap.cvss { (cvss_badge(item.cvss)) }
                        td.nowrap.app { (item.app_name) " " span.muted { (item.app_version.as_deref().unwrap_or("")) } @if !item.group.is_empty() { div { span.tag title="Group of inventory sources this decision holds for" { (item.group) } } } }
                        @if show_project {
                            td.nowrap.project {
                                a href={ "/orgs/" (enc(&item.org)) "/projects/" (enc(&item.project)) } { (item.project) }
                            }
                        }
                        td.desc { (truncate(item.description.as_deref().unwrap_or(""), 160)) }
                        td.right.nowrap.actions { (actions(item)) }
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
}
