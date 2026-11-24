//! Read-only REST API (authenticated with an API token or HTTP Basic).

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::pages::{build_filter, load_project, CveQuery, PAGE_SIZE};
use super::{blocking, ApiError, ApiUser, AppError, St};

type ApiResult = Result<Json<Value>, ApiError>;

#[derive(Deserialize, Default)]
pub struct PageQuery {
    search: Option<String>,
    page: Option<i64>,
}

fn offset(page: Option<i64>, size: i64) -> i64 {
    (page.unwrap_or(1).clamp(1, super::pages::MAX_PAGE) - 1) * size
}

pub async fn cve_list(State(st): St, ApiUser(user): ApiUser, Query(q): Query<CveQuery>) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let filter = build_filter(&db, &q, Some(&user))?;
        let page = q.page.as_deref().and_then(|p| p.parse().ok());
        let cves = db.list_cves(&filter, PAGE_SIZE, offset(page, PAGE_SIZE))?;
        Ok(Json(json!(cves)))
    })
}

pub async fn cve_detail(State(st): St, ApiUser(_): ApiUser, Path(id): Path<String>) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let id = id.to_uppercase();
        let cve = db.get_cve(&id)?.ok_or(AppError::NotFound)?;
        let changes = db.list_cve_changes(&id)?;
        let mut value = serde_json::to_value(&cve).map_err(anyhow::Error::from)?;
        value["changes"] = json!(changes
            .iter()
            .map(|c| json!({ "created_at": c.created_at, "events": c.events }))
            .collect::<Vec<_>>());
        Ok(Json(value))
    })
}

pub async fn vendors(State(st): St, ApiUser(_): ApiUser, Query(q): Query<PageQuery>) -> ApiResult {
    blocking(|| {
        let search = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let vendors = st.db()?.list_vendors(search, 50, offset(q.page, 50))?;
        Ok(Json(json!(vendors)))
    })
}

pub async fn products(State(st): St, ApiUser(_): ApiUser, Path(vendor): Path<String>) -> ApiResult {
    blocking(|| {
        let products = st.db()?.list_products(&vendor)?;
        if products.is_empty() {
            return Err(AppError::NotFound.into());
        }
        Ok(Json(json!(products)))
    })
}

pub async fn weaknesses(State(st): St, ApiUser(_): ApiUser, Query(q): Query<PageQuery>) -> ApiResult {
    blocking(|| Ok(Json(json!(st.db()?.list_weaknesses(50, offset(q.page, 50))?))))
}

pub async fn organizations(State(st): St, ApiUser(user): ApiUser) -> ApiResult {
    blocking(|| Ok(Json(json!(st.db()?.list_orgs(user.id)?))))
}

pub async fn projects(State(st): St, ApiUser(user): ApiUser, Path(org): Path<String>) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let org = db.get_org(&org, user.id)?.ok_or(AppError::NotFound)?;
        Ok(Json(json!(db.list_org_projects(org.id)?)))
    })
}

pub async fn project(
    State(st): St,
    ApiUser(user): ApiUser,
    Path((org, project)): Path<(String, String)>,
) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let (_, project) = load_project(&db, &user, &org, &project)?;
        Ok(Json(json!({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "subscriptions": db.list_subscriptions(project.id)?,
        })))
    })
}

#[derive(Deserialize, Default)]
pub struct WatchlistQuery {
    /// untreated | accepted | treated | not_applicable; all of them when absent
    status: Option<String>,
    /// "1" or "true": only the entries to review that are past their deadline
    overdue: Option<String>,
    page: Option<i64>,
}

/// Watchlist entries of a project, 200 per page, each with where it stands
/// against its remediation deadline
pub async fn watchlist(
    State(st): St,
    ApiUser(user): ApiUser,
    Path((org, project)): Path<(String, String)>,
    Query(q): Query<WatchlistQuery>,
) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let (_, project) = load_project(&db, &user, &org, &project)?;
        let status = match q.status.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => Some(crate::models::CveStatus::from_str(s).ok_or_else(|| AppError::Bad(format!("invalid status '{s}'")))?),
            None => None,
        };
        let overdue = matches!(q.overdue.as_deref(), Some("1" | "true"));
        let entries = db.list_watchlist_entries(None, Some(project.id), None, status)?;
        let entries = crate::deadlines::entries_json(entries, &db.deadline_policies()?, overdue, None);
        let total = entries.len();
        let page: Vec<&Value> = entries.iter().skip(offset(q.page, 200) as usize).take(200).collect();
        Ok(Json(json!({ "total": total, "entries": page })))
    })
}

#[derive(Deserialize, Default)]
pub struct SummaryQuery {
    /// Length in days of the period the resolution figures are taken over (default 90)
    days: Option<String>,
    /// All readable projects: only those of this organization
    org: Option<String>,
}

fn summary_period(days: Option<&str>) -> Result<i64, AppError> {
    match days.filter(|d| !d.is_empty()) {
        None => Ok(90),
        Some(d) => d
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=365).contains(n))
            .ok_or_else(|| AppError::Bad("days must be a whole number from 1 to 365".into())),
    }
}

/// The projects the caller may ask the figures of: every project it holds a
/// role on, executive included. Names and role only.
pub async fn summary_projects(State(st): St, ApiUser(user): ApiUser) -> ApiResult {
    blocking(|| {
        let held = st.db()?.held_projects(user.id)?;
        Ok(Json(json!(held.iter().map(|p| json!({ "org": p.org, "project": p.name, "role": p.role })).collect::<Vec<_>>())))
    })
}

/// Executive figures of every project the caller holds a role on (executive
/// or more), or of those of one organization: figures only (see
/// `crate::deadlines::Figures`). An organization the caller holds nothing in
/// answers as one without anything.
pub async fn summary(State(st): St, ApiUser(user): ApiUser, Query(q): Query<SummaryQuery>) -> ApiResult {
    blocking(|| {
        let days = summary_period(q.days.as_deref())?;
        let org = q.org.as_deref().filter(|o| !o.is_empty());
        Ok(Json(json!(st.db()?.figures(Some(user.id), None, org, days)?)))
    })
}

/// Executive figures of one project
pub async fn project_summary(
    State(st): St,
    ApiUser(user): ApiUser,
    Path((org, project)): Path<(String, String)>,
    Query(q): Query<SummaryQuery>,
) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let (_, project) = super::pages::load_summary_project(&db, &user, &org, &project)?;
        let days = summary_period(q.days.as_deref())?;
        Ok(Json(json!(db.figures(Some(user.id), Some(project.id), None, days)?)))
    })
}

pub async fn reports(
    State(st): St,
    ApiUser(user): ApiUser,
    Path((org, project)): Path<(String, String)>,
) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let (_, project) = load_project(&db, &user, &org, &project)?;
        Ok(Json(json!(db.list_reports(project.id, 365)?)))
    })
}

pub async fn report(
    State(st): St,
    ApiUser(user): ApiUser,
    Path((org, project, day)): Path<(String, String, String)>,
) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let (_, project) = load_project(&db, &user, &org, &project)?;
        let changes = db.get_report(project.id, &day)?.ok_or(AppError::NotFound)?;
        Ok(Json(json!({ "day": day, "changes": changes })))
    })
}

/// Signed export of the security log (instance administrators)
pub async fn security_log(State(st): St, ApiUser(user): ApiUser) -> ApiResult {
    if !user.is_admin {
        return Err(AppError::Forbidden.into());
    }
    blocking(|| Ok(Json(json!(st.db()?.export_security_log()?))))
}

/// Signed export of the audit of decisions of an organization
pub async fn audit_log(State(st): St, ApiUser(user): ApiUser, Path(org): Path<String>) -> ApiResult {
    blocking(|| {
        let db = st.db()?;
        let org = super::pages::load_org(&db, &user, &org)?;
        Ok(Json(json!(db.export_audit_log(org.id, &org.name)?)))
    })
}
