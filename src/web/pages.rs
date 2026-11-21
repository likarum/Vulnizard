//! HTML pages and form handlers.

use axum::extract::{Form, Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{html, Markup};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use super::views::{self, enc, page};
use super::{blocking, AppError, AppState, St, User, SESSION_COOKIE, SESSION_TTL_SECS};
use crate::auth;
use crate::db::{Account, CveFilter, Database, Org, OrgProject};
use crate::rbac::{Permission, Role};

pub const PAGE_SIZE: i64 = 20;
/// Deep pagination forces large scans: unauthenticated pages are capped
pub const MAX_PAGE: i64 = 500;

pub(super) type HtmlResult = Result<Markup, AppError>;
pub(super) type ActionResult = Result<Response, AppError>;

pub(super) fn nonempty(value: &Option<String>) -> Option<String> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

pub(super) fn page_number(value: &Option<String>) -> i64 {
    value.as_deref().and_then(|p| p.parse::<i64>().ok()).unwrap_or(1).clamp(1, MAX_PAGE)
}

pub(super) fn pager(base: &str, query: &str, page: i64, has_next: bool) -> Markup {
    let link = |p: i64| {
        if query.is_empty() {
            format!("{base}?page={p}")
        } else {
            format!("{base}?{query}&page={p}")
        }
    };
    html! {
        div.pager {
            @if page > 1 { a href=(link(page - 1)) { "← Previous" } }
            span.muted { "Page " (page) }
            @if has_next { a href=(link(page + 1)) { "Next →" } }
        }
    }
}

pub(super) fn redirect(to: String) -> Response {
    Redirect::to(&to).into_response()
}

// ==========================================
// CVEs
// ==========================================

#[derive(Deserialize, Default, Clone)]
pub struct CveQuery {
    pub search: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub cvss: Option<String>,
    pub cwe: Option<String>,
    pub kev: Option<String>,
    pub tag: Option<String>,
    pub org: Option<String>,
    pub project: Option<String>,
    pub page: Option<String>,
}

/// Builds the CVE filter. Tag and project filters are scoped to the user.
pub fn build_filter(db: &Database, q: &CveQuery, user: Option<&Account>) -> Result<CveFilter, AppError> {
    let mut filter = CveFilter {
        search: nonempty(&q.search),
        vendor: nonempty(&q.vendor).map(|v| v.to_lowercase()),
        product: nonempty(&q.product).map(|p| p.to_lowercase()),
        cvss: nonempty(&q.cvss),
        cwe: nonempty(&q.cwe).map(|c| c.to_uppercase()),
        kev: nonempty(&q.kev).is_some(),
        ..Default::default()
    };
    if let Some(tag) = nonempty(&q.tag) {
        let user = user.ok_or(AppError::Login)?;
        filter.tag = Some((user.id, tag));
    }
    if let (Some(org), Some(project)) = (nonempty(&q.org), nonempty(&q.project)) {
        let user = user.ok_or(AppError::Login)?;
        let (_, project) = load_project(db, user, &org, &project)?;
        filter.project_id = Some(project.id);
    }
    Ok(filter)
}

pub async fn cve_list(State(st): St, User(user): User, Query(q): Query<CveQuery>) -> HtmlResult {
    // The CVE reference pages require a session; keep the rest of the handler Option-based.
    let user = Some(user);

    blocking(|| {
        let db = st.db()?;
        let mut filter = build_filter(&db, &q, user.as_ref())?;
        // Sorted by the database (the list is paginated): most recently updated first
        let listing = views::Listing::from_page("updated", true);
        filter.sort = Some(listing.sort.clone());
        filter.desc = listing.desc;
        let page_no = page_number(&q.page);
        let mut cves = db.list_cves(&filter, PAGE_SIZE + 1, (page_no - 1) * PAGE_SIZE)?;
        let has_next = cves.len() as i64 > PAGE_SIZE;
        cves.truncate(PAGE_SIZE as usize);
        let tags = match &user {
            Some(u) => db.list_user_tags(u.id)?,
            None => Vec::new(),
        };

        let cvss = nonempty(&q.cvss).unwrap_or_default();
        let tag = nonempty(&q.tag).unwrap_or_default();
        Ok(views::explore_page(
            views::ExploreTab::Cves,
            "CVEs",
            user.as_ref(),
            html! {
                h1 { "Vulnerabilities (CVE)" }
                @if let (Some(org), Some(project)) = (nonempty(&q.org), nonempty(&q.project)) {
                    p {
                        "Subscriptions of project "
                        a href={ "/orgs/" (enc(&org)) "/projects/" (enc(&project)) } { (org) "/" (project) }
                        " · " a href="/cve" { "clear" }
                    }
                }
                form.filters method="get" action="/cve" {
                    input type="search" name="search" placeholder="Keyword or CVE-ID" value=[nonempty(&q.search)];
                    input type="text" name="vendor" placeholder="vendor" value=[nonempty(&q.vendor)];
                    input type="text" name="product" placeholder="product" value=[nonempty(&q.product)];
                    input type="text" name="cwe" placeholder="CWE-79" size="9" value=[nonempty(&q.cwe)];
                    select name="cvss" {
                        option value="" { "Any CVSS" }
                        @for level in ["critical", "high", "medium", "low", "none"] {
                            option value=(level) selected[cvss == level] { (level) }
                        }
                    }
                    @if !tags.is_empty() {
                        select name="tag" {
                            option value="" { "Any tag" }
                            @for t in &tags { option value=(t) selected[&tag == t] { (t) } }
                        }
                    }
                    label { input type="checkbox" name="kev" value="1" checked[nonempty(&q.kev).is_some()]; " KEV" }
                    input type="hidden" name="sort" value=(listing.sort);
                    input type="hidden" name="dir" value=(if listing.desc { "desc" } else { "asc" });
                    @if let Some(org) = nonempty(&q.org) { input type="hidden" name="org" value=(org); }
                    @if let Some(project) = nonempty(&q.project) { input type="hidden" name="project" value=(project); }
                    button type="submit" { "Search" }
                }
                (views::cve_table(&cves, Some(&listing)))
                (pager("/cve", &listing.query(), page_no, has_next))
            },
        ))
    })
}

pub async fn cve_detail(State(st): St, User(user): User, Path(id): Path<String>) -> HtmlResult {
    // The CVE reference pages require a session; keep the rest of the handler Option-based.
    let user = Some(user);

    blocking(|| {
        let db = st.db()?;
        let id = id.to_uppercase();
        let cve = db.get_cve(&id)?.ok_or(AppError::NotFound)?;
        let changes = db.list_cve_changes(&id)?;
        let tags = match &user {
            Some(u) => db.list_cve_tags(u.id, &id)?,
            None => Vec::new(),
        };

        let mut vendors: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for p in &cve.affected_products {
            if let (Some(v), Some(prod)) = (p.vendor.as_deref(), p.product.as_deref()) {
                vendors.entry(v).or_default().insert(prod);
            }
        }
        let cve_path = format!("/cve/{}", enc(&id));

        Ok(views::explore_page(
            views::ExploreTab::Cves,
            &id,
            user.as_ref(),
            html! {
                h1 {
                    (id) " " (views::cvss_badge(cve.cvss_v3_score))
                    @if cve.kev_known_exploited { " " span.tag.kev { "KEV" } }
                }
                div.card {
                    p { (cve.description.as_deref().unwrap_or("No description available.")) }
                    dl.meta {
                        dt { "Published" } dd { (cve.published_at.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_else(|| "—".into())) }
                        dt { "Modified" } dd { (cve.modified_at.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_else(|| "—".into())) }
                        @if let Some(vector) = &cve.cvss_v3_vector { dt { "CVSS vector" } dd { (vector) } }
                        @if let Some(epss) = cve.epss_score {
                            dt { "EPSS" }
                            dd {
                                (format!("{:.2}%", epss * 100.0))
                                @if let Some(p) = cve.epss_percentile { " (percentile " (format!("{:.0}", p * 100.0)) ")" }
                            }
                        }
                        @if let Some(date) = &cve.kev_date_added { dt { "KEV added" } dd { (date) } }
                        @if cve.ssvc_exploitation.is_some() || cve.ssvc_automatable.is_some() || cve.ssvc_technical_impact.is_some() {
                            dt { "SSVC" }
                            dd {
                                "exploitation: " (cve.ssvc_exploitation.as_deref().unwrap_or("—"))
                                " · automatable: " (cve.ssvc_automatable.as_deref().unwrap_or("—"))
                                " · technical impact: " (cve.ssvc_technical_impact.as_deref().unwrap_or("—"))
                            }
                        }
                        @if !cve.cwe_ids.is_empty() {
                            dt { "Weaknesses" }
                            dd { @for cwe in &cve.cwe_ids { a href={ "/cve?cwe=" (enc(cwe)) } { (cwe) } " " } }
                        }
                        @if cve.exploit_public || cve.metasploit_module.is_some() || cve.nuclei_template.is_some() {
                            dt { "Exploitation" }
                            dd {
                                @if cve.exploit_public { span.tag { "public exploit" } " " }
                                @if let Some(m) = &cve.metasploit_module { span.tag { "metasploit" } " " (m) " " }
                                @if let Some(n) = &cve.nuclei_template { span.tag { "nuclei" } " " (n) }
                            }
                        }
                    }
                }

                @if let Some(u) = &user {
                    h2 { "My tags" }
                    div.card {
                        ul.chips {
                            @for tag in &tags {
                                li {
                                    form.inline method="post" action={ (cve_path) "/tags/delete" } {
                                        input type="hidden" name="tag" value=(tag);
                                        span.tag { (tag) } " "
                                        button.link type="submit" title="Remove tag" { "×" }
                                    }
                                }
                            }
                        }
                        form.row method="post" action={ (cve_path) "/tags" } {
                            input type="text" name="tag" placeholder="new-tag" maxlength="32" required;
                            button.secondary type="submit" { "Add tag" }
                        }
                        p.muted { "Tags are private to " (u.username) "." }
                    }
                }

                @if !vendors.is_empty() {
                    h2 { "Affected vendors & products" }
                    table.list {
                        thead { tr { th { "Vendor" } th { "Products" } } }
                        tbody {
                            @for (vendor, products) in &vendors {
                                tr {
                                    td.nowrap { a href={ "/vendors/" (enc(vendor)) } { (vendor) } }
                                    td {
                                        @for product in products {
                                            a href={ "/cve?vendor=" (enc(vendor)) "&product=" (enc(product)) } { (product) } " "
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                @if !cve.affected_packages.is_empty() {
                    h2 { "Affected packages" }
                    table.list {
                        thead { tr { th { "Ecosystem" } th { "Package" } th { "Vulnerable range" } th { "Fixed in" } } }
                        tbody {
                            @for pkg in &cve.affected_packages {
                                tr {
                                    td { (pkg.ecosystem) }
                                    td { (pkg.name) }
                                    td { (pkg.vulnerable_range.as_deref().unwrap_or("—")) }
                                    td { (pkg.fixed_version.as_deref().unwrap_or("—")) }
                                }
                            }
                        }
                    }
                }

                @if !cve.references.is_empty() || !cve.exploit_urls.is_empty() {
                    h2 { "References" }
                    div.card {
                        ul.plain {
                            @for r in &cve.references {
                                li {
                                    @if r.url.starts_with("https://") || r.url.starts_with("http://") {
                                        a href=(r.url) rel="noopener noreferrer nofollow" { (r.url) }
                                    } @else { (r.url) }
                                    @for tag in &r.tags { " " span.tag { (tag) } }
                                }
                            }
                            @for url in &cve.exploit_urls {
                                li {
                                    @if url.starts_with("https://") || url.starts_with("http://") {
                                        a href=(url) rel="noopener noreferrer nofollow" { (url) }
                                    } @else { (url) }
                                    " " span.tag { "exploit" }
                                }
                            }
                        }
                    }
                }

                h2 { "Change history" }
                (views::change_history(&changes))
            },
        ))
    })
}

#[derive(Deserialize)]
pub struct TagForm {
    tag: String,
}

pub async fn tag_add(
    State(st): St,
    User(user): User,
    Path(id): Path<String>,
    Form(form): Form<TagForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let id = id.to_uppercase();
        let tag = form.tag.trim().to_lowercase();
        if !auth::valid_slug(&tag, 1, 32) {
            return Err(AppError::Bad("Tags may only contain letters, digits, '-', '_' and '.'".into()));
        }
        db.get_cve(&id)?.ok_or(AppError::NotFound)?;
        db.add_tag(user.id, &id, &tag)?;
        Ok(redirect(format!("/cve/{}", enc(&id))))
    })
}

pub async fn tag_remove(
    State(st): St,
    User(user): User,
    Path(id): Path<String>,
    Form(form): Form<TagForm>,
) -> ActionResult {
    blocking(|| {
        let id = id.to_uppercase();
        st.db()?.remove_tag(user.id, &id, &form.tag)?;
        Ok(redirect(format!("/cve/{}", enc(&id))))
    })
}

// ==========================================
// Vendors, products, weaknesses
// ==========================================

#[derive(Deserialize, Default)]
pub struct ListQuery {
    search: Option<String>,
    page: Option<String>,
    project: Option<String>,
}

pub async fn vendors(State(st): St, User(user): User, Query(q): Query<ListQuery>) -> HtmlResult {
    // The CVE reference pages require a session; keep the rest of the handler Option-based.
    let user = Some(user);

    blocking(|| {
        let db = st.db()?;
        let search = nonempty(&q.search);
        let page_no = page_number(&q.page);
        let listing = views::Listing::from_page("vendor", false);
        let mut vendors =
            db.list_vendors_sorted(search.as_deref(), &listing.sort, listing.desc, 51, (page_no - 1) * 50)?;
        let has_next = vendors.len() > 50;
        vendors.truncate(50);
        let query = listing.query();

        Ok(views::explore_page(
            views::ExploreTab::Vendors,
            "Vendors",
            user.as_ref(),
            html! {
                h1 { "Vendors & products" }
                form.filters method="get" action="/vendors" {
                    input type="hidden" name="sort" value=(listing.sort);
                    input type="hidden" name="dir" value=(if listing.desc { "desc" } else { "asc" });
                    input type="search" name="search" placeholder="Vendor name" value=[search.clone()];
                    button type="submit" { "Search" }
                }
                table.list {
                    thead { tr { (listing.th("vendor", "Vendor")) (listing.th("products", "Products")) th {} } }
                    tbody {
                        @for v in &vendors {
                            tr {
                                td { a href={ "/vendors/" (enc(&v.vendor)) } { (v.vendor) } }
                                td { (v.products) }
                                td.right { a href={ "/cve?vendor=" (enc(&v.vendor)) } { "CVEs" } }
                            }
                        }
                        @if vendors.is_empty() { tr { td colspan="3" .muted { "No vendor found." } } }
                    }
                }
                (pager("/vendors", &query, page_no, has_next))
            },
        ))
    })
}

pub async fn vendor_detail(
    State(st): St,
    User(user): User,
    Path(vendor): Path<String>,
    Query(q): Query<ListQuery>,
) -> HtmlResult {
    // The CVE reference pages require a session; keep the rest of the handler Option-based.
    let user = Some(user);

    blocking(|| {
        let db = st.db()?;
        let mut products = db.list_products(&vendor)?;
        if products.is_empty() {
            return Err(AppError::NotFound);
        }
        let product_total = products.len();
        let listing = views::Listing::from_page("cves", true);
        listing.apply(
            &mut products,
            |p| p.product.clone(),
            |p, column| match column {
                "product" => Some(views::SortKey::text(&p.product)),
                "cves" => Some(views::SortKey::num(p.cves as f64)),
                _ => None,
            },
        );
        let projects = match &user {
            Some(u) => db.list_user_projects(u.id)?,
            None => Vec::new(),
        };
        // Selected project for the subscribe buttons (must be accessible)
        let selected = q
            .project
            .as_deref()
            .and_then(|p| p.parse::<i64>().ok())
            .and_then(|id| projects.iter().find(|p| p.id == id));
        let subscribed: BTreeSet<String> = match selected {
            Some(p) => db
                .list_subscriptions(p.id)?
                .into_iter()
                .filter(|s| s.vendor == vendor)
                .map(|s| s.product)
                .collect(),
            None => BTreeSet::new(),
        };

        let button = |product: &str| -> Markup {
            let Some(project) = selected else { return html! {} };
            let active = subscribed.contains(product);
            html! {
                form.inline method="post" action="/subscriptions" {
                    input type="hidden" name="project_id" value=(project.id);
                    input type="hidden" name="vendor" value=(vendor);
                    input type="hidden" name="product" value=(product);
                    @if active {
                        input type="hidden" name="action" value="unsubscribe";
                        button.small.secondary type="submit" { "Unsubscribe" }
                    } @else {
                        input type="hidden" name="action" value="subscribe";
                        button.small type="submit" { "Subscribe" }
                    }
                }
            }
        };

        Ok(views::explore_page(
            views::ExploreTab::Vendors,
            &vendor,
            user.as_ref(),
            html! {
                h1 { (vendor) }
                p { a href={ "/cve?vendor=" (enc(&vendor)) } { "All CVEs for this vendor" } }
                @if user.is_some() {
                    @if projects.is_empty() {
                        p.muted { "Create a project in an " a href="/orgs" { "organization" } " to subscribe to vendors and products." }
                    } @else {
                        form.filters method="get" action={ "/vendors/" (enc(&vendor)) } {
                            label for="project" { "Subscribe with project" }
                            select name="project" id="project" {
                                option value="" { "—" }
                                @for p in &projects {
                                    option value=(p.id) selected[selected.is_some_and(|s| s.id == p.id)] { (p.org) "/" (p.name) }
                                }
                            }
                            button.secondary type="submit" { "Select" }
                        }
                        @if selected.is_some() {
                            p { "Whole vendor (all products): " (button("")) }
                        }
                    }
                }
                (listing.filter_box("Filter products…", products.len(), product_total))
                table.list {
                    thead { tr { (listing.th("product", "Product")) (listing.th("cves", "CVEs")) th {} } }
                    tbody {
                        @for p in &products {
                            tr {
                                td { a href={ "/cve?vendor=" (enc(&vendor)) "&product=" (enc(&p.product)) } { (p.product) } }
                                td { (p.cves) }
                                td.right { (button(&p.product)) }
                            }
                        }
                    }
                }
            },
        ))
    })
}

#[derive(Deserialize)]
pub struct SubscriptionForm {
    project_id: i64,
    vendor: String,
    #[serde(default)]
    product: String,
    action: String,
    /// "project" to return to the project page instead of the vendor page
    #[serde(default)]
    back: String,
}

pub async fn subscription_update(
    State(st): St,
    User(user): User,
    Form(form): Form<SubscriptionForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let allowed = db
            .project_role(user.id, form.project_id)?
            .is_some_and(|role| role.allows(Permission::ManageProjects));
        if !allowed {
            return Err(AppError::Forbidden);
        }
        if form.vendor.is_empty() || form.vendor.len() > 200 || form.product.len() > 200 {
            return Err(AppError::Bad("Invalid vendor or product".into()));
        }
        let (vendor, product) = (form.vendor.trim().to_lowercase(), form.product.trim().to_lowercase());
        match form.action.as_str() {
            "subscribe" => db.subscribe(form.project_id, &vendor, &product)?,
            "unsubscribe" => db.unsubscribe(form.project_id, &form.vendor, &form.product)?,
            _ => return Err(AppError::Bad("Invalid action".into())),
        }
        if form.back == "project" {
            if let Some(p) = db
                .list_user_projects(user.id)?
                .into_iter()
                .find(|p| p.id == form.project_id)
            {
                return Ok(redirect(views::product_url(Some((&p.org, &p.name)), "subscriptions")));
            }
        }
        Ok(redirect(format!(
            "/vendors/{}?project={}",
            enc(&form.vendor),
            form.project_id
        )))
    })
}

pub async fn weaknesses(State(st): St, User(user): User, Query(q): Query<ListQuery>) -> HtmlResult {
    // The CVE reference pages require a session; keep the rest of the handler Option-based.
    let user = Some(user);

    blocking(|| {
        let db = st.db()?;
        let page_no = page_number(&q.page);
        let listing = views::Listing::from_page("cves", true);
        let search = nonempty(&q.search);
        let mut items =
            db.list_weaknesses_sorted(search.as_deref(), &listing.sort, listing.desc, 51, (page_no - 1) * 50)?;
        let has_next = items.len() > 50;
        items.truncate(50);
        Ok(views::explore_page(
            views::ExploreTab::Weaknesses,
            "Weaknesses",
            user.as_ref(),
            html! {
                h1 { "Weaknesses (CWE)" }
                form.filters method="get" action="/weaknesses" {
                    input type="hidden" name="sort" value=(listing.sort);
                    input type="hidden" name="dir" value=(if listing.desc { "desc" } else { "asc" });
                    input type="search" name="search" placeholder="CWE-79" value=[search.clone()];
                    button type="submit" { "Search" }
                }
                table.list {
                    thead { tr { (listing.th("cwe", "CWE")) (listing.th("cves", "CVEs")) th {} } }
                    tbody {
                        @for w in &items {
                            tr {
                                td { a href={ "/cve?cwe=" (enc(&w.cwe_id)) } { (w.cwe_id) } }
                                td { (w.cves) }
                                td.right {
                                    @if let Some(num) = w.cwe_id.strip_prefix("CWE-").filter(|n| n.chars().all(|c| c.is_ascii_digit())) {
                                        a href={ "https://cwe.mitre.org/data/definitions/" (num) ".html" } rel="noopener noreferrer" { "MITRE" }
                                    }
                                }
                            }
                        }
                        @if items.is_empty() { tr { td colspan="3" .muted { "No weakness found." } } }
                    }
                }
                (pager("/weaknesses", &listing.query(), page_no, has_next))
            },
        ))
    })
}

// ==========================================
// Authentication
// ==========================================

/// Verifies a username/password pair, behind the login guard (bounded
/// concurrency, per-username throttling). An unknown user still costs one
/// Argon2 verification so that timing does not reveal valid usernames.
///
/// Wrong passwords are counted per client address and account, so that
/// someone failing on purpose only locks themselves out, and per account
/// across every client with a higher limit, so that many addresses together
/// still cannot guess for long. The holder of a session confirming a change
/// has a counter of their own that nobody else can fill.
pub fn check_credentials(
    st: &AppState,
    db: &Database,
    username: &str,
    password: &str,
    from: &Attempt,
) -> Result<Option<Account>, AppError> {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    use auth::ThrottleKey;
    let (own_key, account_key) = match from {
        Attempt::Client(address) => (ThrottleKey::password(address, username), Some(ThrottleKey::account(username))),
        // A browser that already signed in to this account answers for itself only: what
        // others fail elsewhere does not lock out the owner of the account
        Attempt::KnownDevice(mark) => (ThrottleKey::device(mark), None),
        Attempt::Session(user_id) => (ThrottleKey::confirmation(*user_id), None),
    };
    let locked = st.login_guard.is_locked(&own_key)
        || account_key.as_deref().is_some_and(|k| st.login_guard.is_locked_at(k, auth::MAX_ACCOUNT_FAILURES));
    if password.len() > auth::MAX_PASSWORD_LEN || locked {
        return Err(AppError::TooMany);
    }
    let credentials = db.get_credentials(username)?;
    let _slot = st.login_guard.slot().ok_or(AppError::TooMany)?;
    let account = match credentials {
        Some((account, hash)) => auth::verify_password(password, &hash).then_some(account),
        None => {
            let dummy = DUMMY_HASH.get_or_init(|| auth::hash_password("vulnizard-dummy").unwrap_or_default());
            auth::verify_password(password, dummy);
            None
        }
    };
    st.login_guard.record(&own_key, account.is_some());
    // The counter of the account only goes up and expires with its window: a right
    // password (the owner's own scripts, say) does not give other clients new guesses
    if let (Some(key), None) = (&account_key, &account) {
        st.login_guard.record(key, false);
    }
    Ok(account)
}

const DEVICE_COOKIE: &str = "vulnizard_device";
/// How long a browser stays known after a sign-in
const DEVICE_TTL_SECS: i64 = 90 * 24 * 3600;

/// Mark left in a browser after a successful password: `user.issued.mac`.
/// It grants nothing by itself (the password and the second step are still
/// asked); it only tells this browser apart from the rest of the world when
/// counting wrong passwords.
fn device_cookie(st: &AppState, db: &Database, user_id: i64) -> String {
    let issued = chrono::Utc::now().timestamp();
    let mac = db.mac(&format!("device|{user_id}|{issued}"));
    format!(
        "{DEVICE_COOKIE}={user_id}.{issued}.{mac}; Path=/login; HttpOnly; SameSite=Lax; Max-Age={DEVICE_TTL_SECS}{}",
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

/// The mark of a browser known for this username, if its cookie is genuine and recent
fn known_device(db: &Database, headers: &axum::http::HeaderMap, username: &str) -> Option<String> {
    let value = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == DEVICE_COOKIE)
        .map(|(_, v)| v.to_string())?;
    let mut parts = value.splitn(3, '.');
    let (user_id, issued, mac) = (parts.next()?.parse::<i64>().ok()?, parts.next()?.parse::<i64>().ok()?, parts.next()?);
    let age = chrono::Utc::now().timestamp() - issued;
    if !(0..=DEVICE_TTL_SECS).contains(&age) {
        return None;
    }
    let expected = db.mac(&format!("device|{user_id}|{issued}"));
    let genuine = expected.len() == mac.len() && expected.bytes().zip(mac.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    let (account, _) = db.get_credentials(username).ok()??;
    (genuine && account.id == user_id).then(|| mac.to_string())
}

/// Where a password attempt comes from
pub enum Attempt {
    /// Someone not signed in, at this network address
    Client(String),
    /// Someone not signed in, in a browser that signed in to this account before (its mark)
    KnownDevice(String),
    /// The holder of a session of this account
    Session(i64),
}

/// Hashes a new password behind the same concurrency bound
pub(super) fn hash_new_password(st: &AppState, password: &str) -> Result<String, AppError> {
    let _slot = st.login_guard.slot().ok_or(AppError::TooMany)?;
    Ok(auth::hash_password(password)?)
}

pub(super) fn session_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if st.secure_cookies() { "; Secure" } else { "" }
    )
}

pub(super) fn start_session(st: &AppState, db: &Database, user_id: i64) -> ActionResult {
    start_session_for(st, db, user_id, SESSION_TTL_SECS)
}

pub(super) fn start_session_for(st: &AppState, db: &Database, user_id: i64, ttl_secs: i64) -> ActionResult {
    let (token, hash) = auth::new_token();
    db.create_session(user_id, &hash, ttl_secs)?;
    Ok((
        [(header::SET_COOKIE, session_cookie(st, &token, ttl_secs))],
        Redirect::to("/"),
    )
        .into_response())
}

/// Self-registration is opt-in (`web.allow_registration`); otherwise accounts
/// are created with `vulnizard user create`.
fn registration_open(st: &AppState) -> bool {
    st.config.web.allow_registration
}

pub(super) fn auth_page(
    title: &str,
    error: Option<&str>,
    register: bool,
    show_register_link: bool,
    sso: &[(String, String)],
    passkeys: bool,
) -> Markup {
    page(
        title,
        None,
        html! {
            h1 { (title) }
            @if let Some(e) = error { p.error { (e) } }
            form.stack.card method="post" action=(if register { "/register" } else { "/login" }) {
                label { "Username" input type="text" name="username" required autofocus autocomplete="username"; }
                @if register {
                    label { "Email (optional)" input type="email" name="email" autocomplete="email"; }
                }
                label {
                    "Password"
                    input type="password" name="password" required
                        autocomplete=(if register { "new-password" } else { "current-password" });
                }
                @if register {
                    p.muted { "At least " (auth::MIN_PASSWORD_LEN) " characters." }
                }
                button type="submit" { (title) }
            }
            @if !register {
                @if passkeys {
                    form.stack id="passkey-signin" {
                        button.secondary type="button" data-passkey { "Log in with a passkey" }
                        span.muted data-passkey-message {}
                    }
                    script src="/static/mfa.js" defer {}
                }
                @for (slug, name) in sso {
                    p { a.button href={ "/auth/oidc/" (enc(slug)) "/login" } { "Log in with " (name) } }
                }
            }
            @if !register && show_register_link {
                p { "No account yet? " a href="/register" { "Register" } }
            }
        },
    )
}

pub async fn filter_script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("filter.js"),
    )
}

pub async fn login_form(State(st): St) -> HtmlResult {
    blocking(|| {
        Ok(auth_page("Log in", None, false, registration_open(&st), &super::oidc::login_buttons(&st), super::mfa::passkeys_available(&st)))
    })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login(
    State(st): St,
    super::ClientAddr(client): super::ClientAddr,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let username = form.username.trim();
        let from = match known_device(&db, &headers, username) {
            Some(mark) => Attempt::KnownDevice(mark),
            None => Attempt::Client(client),
        };
        match check_credentials(&st, &db, username, &form.password, &from)? {
            Some(account) => {
                let mut response = super::mfa::after_password(&st, &db, account.id)?;
                if let Ok(cookie) = axum::http::HeaderValue::from_str(&device_cookie(&st, &db, account.id)) {
                    response.headers_mut().append(header::SET_COOKIE, cookie);
                }
                Ok(response)
            }
            None => Ok((
                axum::http::StatusCode::UNAUTHORIZED,
                auth_page("Log in", Some("Invalid username or password."), false, false, &super::oidc::login_buttons(&st), super::mfa::passkeys_available(&st)),
            )
                .into_response()),
        }
    })
}

pub async fn register_form(State(st): St) -> HtmlResult {
    blocking(|| {
        if !registration_open(&st) {
            return Err(AppError::Bad("Registration is disabled on this instance.".into()));
        }
        Ok(auth_page("Register", None, true, false, &[], false))
    })
}

#[derive(Deserialize)]
pub struct RegisterForm {
    username: String,
    #[serde(default)]
    email: String,
    password: String,
}

pub async fn register(State(st): St, Form(form): Form<RegisterForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        if !registration_open(&st) {
            return Err(AppError::Bad("Registration is disabled on this instance.".into()));
        }
        let fail = |msg: &str| -> ActionResult {
            Ok((
                axum::http::StatusCode::BAD_REQUEST,
                auth_page("Register", Some(msg), true, false, &[], false),
            )
                .into_response())
        };
        let username = form.username.trim();
        if !auth::valid_slug(username, 3, 32) {
            return fail("Username: 3 to 32 letters, digits, '-', '_' or '.'.");
        }
        if form.password.chars().count() < auth::MIN_PASSWORD_LEN {
            return fail("Password is too short.");
        }
        if form.password.len() > auth::MAX_PASSWORD_LEN {
            return fail("Password is too long.");
        }
        let email = Some(form.email.trim()).filter(|e| !e.is_empty());
        if email.is_some_and(|e| e.parse::<lettre::Address>().is_err()) {
            return fail("Invalid email address.");
        }
        let hash = hash_new_password(&st, &form.password)?;
        match db.register_account(username, email, &hash) {
            Ok(id) => start_session(&st, &db, id),
            Err(e) => match AppError::bad(e) {
                AppError::Bad(msg) => fail(&msg),
                other => Err(other),
            },
        }
    })
}

pub async fn logout(State(st): St, parts: axum::http::request::Parts) -> ActionResult {
    blocking(|| {
        if let Some(token) = super::session_token(&parts) {
            st.db()?.delete_session(&auth::hash_token(&token))?;
        }
        Ok((
            [(header::SET_COOKIE, session_cookie(&st, "", 0))],
            Redirect::to("/login"),
        )
            .into_response())
    })
}

// ==========================================
// Settings (password, API tokens)
// ==========================================

fn settings_page(db: &Database, user: &Account, new_token: Option<&str>, message: Option<&str>) -> HtmlResult {
    let tokens = db.list_api_tokens(user.id)?;
    let has_password = db.has_password(user.id)?;
    Ok(page(
        "Settings",
        Some(user),
        html! {
            h1 { "Settings" }
            @if let Some(m) = message { p { strong { (m) } } }

            h2 { "API tokens" }
            @if let Some(token) = new_token {
                div.card {
                    p { "New token — copy it now, it will not be shown again:" }
                    code.token { (token) }
                }
            }
            p.muted { "Use with " code { "Authorization: Bearer <token>" } " on " code { "/api/…" } " (HTTP Basic with your password also works)." }
            table.list {
                thead { tr { th { "Name" } th { "Created" } th { "Last used" } th {} } }
                tbody {
                    @for t in &tokens {
                        tr {
                            td { (t.name) }
                            td { (t.created_at) }
                            td { (t.last_used_at.as_deref().unwrap_or("never")) }
                            td.right {
                                form.inline method="post" action={ "/settings/tokens/" (t.id) "/delete" } {
                                    button.small.danger type="submit" { "Revoke" }
                                }
                            }
                        }
                    }
                    @if tokens.is_empty() { tr { td colspan="4" .muted { "No token." } } }
                }
            }
            form.row method="post" action="/settings/tokens" {
                input type="text" name="name" placeholder="Token name" maxlength="64" required;
                @if has_password {
                    input type="password" name="password" placeholder="Current password" required autocomplete="current-password";
                }
                button type="submit" { "Create token" }
            }

            (super::notifications::settings_section(db, user)?)

            (super::mfa::settings_summary(db, user)?)

            h2 { "Change password" }
            form.stack.card method="post" action="/settings/password" {
                label { "Current password" input type="password" name="current" required autocomplete="current-password"; }
                label { "New password" input type="password" name="new" required autocomplete="new-password"; }
                p.muted { "Changing the password signs out every session and revokes every API token." }
                button type="submit" { "Change password" }
            }
        },
    ))
}

pub async fn settings(State(st): St, User(user): User) -> HtmlResult {
    blocking(|| settings_page(&st.db()?, &user, None, None))
}

#[derive(Deserialize)]
pub struct TokenForm {
    name: String,
    #[serde(default)]
    password: String,
}

pub async fn token_create(State(st): St, User(user): User, Form(form): Form<TokenForm>) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let name = form.name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(AppError::Bad("Invalid token name".into()));
        }
        // A token outlives the session and is not asked for a second step: holding a
        // session must not be enough to mint one. (Accounts that only sign in through
        // SSO have no password to give.)
        if db.has_password(user.id)?
            && check_credentials(&st, &db, &user.username, &form.password, &Attempt::Session(user.id))?.is_none()
        {
            return Err(AppError::Bad("Current password is incorrect.".into()));
        }
        let (token, hash) = auth::new_token();
        db.create_api_token(user.id, name, &hash)?;
        settings_page(&db, &user, Some(&token), None)
    })
}

pub async fn token_delete(State(st): St, User(user): User, Path(id): Path<i64>) -> ActionResult {
    blocking(|| {
        st.db()?.delete_api_token(user.id, id)?;
        Ok(redirect("/settings".into()))
    })
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current: String,
    new: String,
}

pub async fn password_change(State(st): St, User(user): User, Form(form): Form<PasswordForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        if check_credentials(&st, &db, &user.username, &form.current, &Attempt::Session(user.id))?.is_none() {
            return Err(AppError::Bad("Current password is incorrect.".into()));
        }
        if form.new.chars().count() < auth::MIN_PASSWORD_LEN || form.new.len() > auth::MAX_PASSWORD_LEN {
            return Err(AppError::Bad("New password is too short or too long.".into()));
        }
        db.set_password(user.id, &hash_new_password(&st, &form.new)?)?;
        // Every session and API token was invalidated: open a fresh session
        start_session(&st, &db, user.id)
    })
}

// ==========================================
// Organizations
// ==========================================

/// Organization of the user; any role grants read access
pub(super) fn load_org(db: &Database, user: &Account, org: &str) -> Result<Org, AppError> {
    let org = db.get_org(org, user.id)?.ok_or(AppError::NotFound)?;
    if !org.can(Permission::View) {
        return Err(AppError::NotFound);
    }
    Ok(org)
}

/// Project the user can access, by names. The returned `Org` carries the
/// user's effective role *on this project* (instance, organization or
/// project level), which the permission checks of project pages use.
pub fn load_project(
    db: &Database,
    user: &Account,
    org: &str,
    project: &str,
) -> Result<(Org, OrgProject), AppError> {
    db.get_project_for_user(org, project, user.id)?.ok_or(AppError::NotFound)
}

/// Permission check against the user's role in the organization
pub(super) fn require(org: &Org, permission: Permission) -> Result<(), AppError> {
    if org.can(permission) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub async fn orgs(State(st): St, User(user): User) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let orgs = db.list_orgs(user.id)?;
        let awaiting = db.orgs_awaiting_mfa(user.id)?;
        let own = db.own_org_memberships(user.id)?;
        Ok(views::layout(
            views::Nav::PRODUCTS,
            "Organizations",
            Some(&user),
            html! {
                p { a href="/projects" { "← Projects" } }
                h1 { "Organizations" }
                p.muted { "An organization groups projects and the people who can access them." }
                table.list {
                    thead { tr { th { "Name" } th { "Your role" } th {} } }
                    tbody {
                        @for o in &orgs {
                            tr {
                                td { a href={ "/orgs/" (enc(&o.name)) } { (o.name) } }
                                td { (o.role) }
                                td.right {
                                    // A role held through the instance or a group is not one's own to give up
                                    @if own.contains(&o.name) {
                                        form.inline method="post" action={ "/orgs/" (enc(&o.name)) "/leave" } {
                                            button.small.secondary type="submit" { "Leave" }
                                        }
                                    }
                                }
                            }
                        }
                        @for name in &awaiting {
                            tr {
                                td { (name) }
                                td { span.muted { "closed: requires two-step sign-in — " } a href="/settings/mfa" { "set it up" } }
                                td.right {
                                    form.inline method="post" action={ "/orgs/" (enc(name)) "/leave" } {
                                        button.small.secondary type="submit" { "Leave" }
                                    }
                                }
                            }
                        }
                        @if orgs.is_empty() && awaiting.is_empty() { tr { td colspan="3" .muted { "You are not a member of any organization yet." } } }
                    }
                }
                h2 { "New organization" }
                form.row method="post" action="/orgs" {
                    input type="text" name="name" placeholder="organization-name" maxlength="64" required;
                    button type="submit" { "Create" }
                }
            },
        ))
    })
}

#[derive(Deserialize)]
pub struct NameForm {
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: String,
}

pub async fn org_create(State(st): St, User(user): User, Form(form): Form<NameForm>) -> ActionResult {
    blocking(|| {
        let name = form.name.trim();
        if !auth::valid_slug(name, 1, 64) {
            return Err(AppError::Bad("Name: letters, digits, '-', '_' or '.' only.".into()));
        }
        st.db()?.create_org(name, user.id).map_err(AppError::bad)?;
        Ok(redirect(format!("/orgs/{}", enc(name))))
    })
}

pub async fn org_detail(State(st): St, User(user): User, Path(org): Path<String>) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        let members = db.list_members(org.id)?;
        let projects = db.list_org_projects(org.id)?;
        let base = format!("/orgs/{}", enc(&org.name));
        let manage_members = org.can(Permission::ManageMembers);
        let requires_mfa = db.org_requires_mfa(org.id)?;
        let audit_integrity = db.check_audit_log(org.id)?;
        let fingerprint = db.log_key_fingerprint()?;
        Ok(views::layout(
            views::Nav::PRODUCTS,
            &org.name,
            Some(&user),
            html! {
                p { a href="/orgs" { "← Organizations" } }
                h1 { (org.name) }
                p.muted { "Your role: " (org.role) }

                h2 { "Audit of decisions" }
                p.muted { "Every decision taken on the CVEs of this organization's projects — who, when, why — as one chained log." }
                (super::admin::log_integrity(&audit_integrity, &fingerprint, &format!("{base}/audit/export")))

                h2 { "Projects" }
                table.list {
                    thead { tr { th { "Project" } th { "Description" } th { "Subscriptions" } } }
                    tbody {
                        @for p in &projects {
                            tr {
                                td { a href={ (base) "/projects/" (enc(&p.name)) } { (p.name) } }
                                td { (p.description.as_deref().unwrap_or("")) }
                                td { (p.subscriptions) }
                            }
                        }
                        @if projects.is_empty() { tr { td colspan="3" .muted { "No project yet." } } }
                    }
                }
                @if org.can(Permission::ManageProjects) {
                    form.row method="post" action={ (base) "/projects" } {
                        input type="text" name="name" placeholder="project-name" maxlength="64" required;
                        input type="text" name="description" placeholder="Description (optional)" maxlength="200";
                        button type="submit" { "Create project" }
                    }
                }

                h2 { "Members" }
                table.list {
                    thead { tr { th { "User" } th { "Role" } th {} } }
                    tbody {
                        @for m in &members {
                            tr {
                                td { (m.username) }
                                td {
                                    @if manage_members {
                                        form.inline method="post" action={ (base) "/members" } {
                                            input type="hidden" name="username" value=(m.username);
                                            select name="role" {
                                                @for role in Role::ALL {
                                                    option value=(role.as_str()) selected[m.role == role.as_str()] { (role.as_str()) }
                                                }
                                            }
                                            " " button.small.secondary type="submit" { "Change" }
                                        }
                                    } @else { (m.role) }
                                }
                                td.right {
                                    @if manage_members {
                                        form.inline method="post" action={ (base) "/members/" (m.user_id) "/delete" } {
                                            button.small.danger type="submit" { "Remove" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                p.muted {
                    @for role in Role::ALL { strong { (role.as_str()) } ": " (role.description()) ". " }
                }
                @if manage_members {
                    form.row method="post" action={ (base) "/mfa" } {
                        label.check {
                            input type="checkbox" name="required" value="1" checked[requires_mfa];
                            " Require two-step sign-in from everyone who has a role in this organization"
                        }
                        button.small.secondary type="submit" { "Save" }
                    }
                    p.muted { "Members who sign in with a password cannot open this organization until they set up a second factor; the rest of their account is not affected. Single sign-on accounts rely on their identity provider." }
                } @else if requires_mfa {
                    p.muted { "This organization requires two-step sign-in." }
                }
                @if manage_members {
                    form.row method="post" action={ (base) "/members" } {
                        input type="text" name="username" placeholder="username" required;
                        select name="role" {
                            @for role in Role::ALL.iter().rev() {
                                option value=(role.as_str()) { (role.as_str()) }
                            }
                        }
                        button type="submit" { "Add member" }
                    }
                }
                @if org.can(Permission::DeleteOrganization) {
                    h2 { "Danger zone" }
                    form.row method="post" action={ (base) "/delete" } {
                        input type="text" name="name" placeholder="Type the organization name to confirm" size="36" required;
                        button.danger type="submit" { "Delete organization" }
                    }
                }
            },
        ))
    })
}

pub async fn org_delete(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Form(form): Form<NameForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        require(&org, Permission::DeleteOrganization)?;
        if form.name.trim() != org.name {
            return Err(AppError::Bad("Confirmation does not match the organization name.".into()));
        }
        db.delete_org(org.id)?;
        Ok(redirect("/orgs".into()))
    })
}

#[derive(Deserialize)]
pub struct MemberForm {
    username: String,
    #[serde(default)]
    role: String,
}

pub async fn member_add(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Form(form): Form<MemberForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        require(&org, Permission::ManageMembers)?;
        if let Some(account) = db.get_credentials_or_sso(form.username.trim())? {
            if !db.may_hold_right(account.id, crate::db::Scope::Organization(org.id))? {
                return Err(AppError::Bad("This account belongs to another project or organization.".into()));
            }
        }
        db.add_member(org.id, form.username.trim(), &form.role)
            .map_err(AppError::bad)?;
        Ok(redirect(format!("/orgs/{}", enc(&org.name))))
    })
}

pub async fn member_remove(
    State(st): St,
    User(user): User,
    Path((org, user_id)): Path<(String, i64)>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        require(&org, Permission::ManageMembers)?;
        db.remove_member(org.id, user_id).map_err(AppError::bad)?;
        Ok(redirect(format!("/orgs/{}", enc(&org.name))))
    })
}

/// Signed export of the audit of an organization, for whoever can read the organization
pub async fn org_audit_export(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Query(q): Query<super::admin::ExportQuery>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        super::admin::export_response(&db.export_audit_log(org.id, &org.name)?, &q.format, &format!("audit-{}", org.name))
    })
}

/// Logo, also the icon of the site
pub async fn logo() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        include_str!("logo.svg"),
    )
}

pub async fn stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        views::STYLESHEET,
    )
}
