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
