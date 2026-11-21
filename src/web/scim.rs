//! SCIM 2.0 provisioning API (RFC 7643 / 7644), under `/scim/v2`.
//!
//! An identity provider creates, updates, deactivates and removes users and
//! groups with a bearer token created in the administration. A token belongs
//! to the instance, an organization or a project, and only sees — and
//! creates — users and groups of that scope.
//!
//! Supported: Users and Groups (GET, POST, PUT, PATCH, DELETE), filtering
//! (`eq`, `ne`, `co`, `sw`, `ew`, `pr`, combined with `and`), pagination, and the
//! discovery endpoints. Bulk, sorting, ETags and password change are declared
//! unsupported, as the specification allows.

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use super::{blocking, AppState, St};
use crate::auth;
use crate::db::{Database, ScimGroup, ScimUser, Scope};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const MAX_RESULTS: usize = 200;

// ==========================================
// Responses and errors
// ==========================================

fn scim(status: StatusCode, body: Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/scim+json")], body.to_string()).into_response()
}

#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "Resource not found")
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some("invalidValue"), detail)
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, Some("uniqueness"), detail)
    }
}

impl From<anyhow::Error> for ScimError {
    fn from(e: anyhow::Error) -> Self {
        // Messages of the storage layer meant for the client
        let text = e.to_string();
        match text.as_str() {
            "Username already taken" | "Group name already used" => ScimError::conflict(text),
            "Unknown member" => ScimError::invalid("A member does not exist in this scope"),
            _ => {
                tracing::error!("SCIM request failed: {e:#}");
                ScimError::new(StatusCode::INTERNAL_SERVER_ERROR, None, "Internal error")
            }
        }
    }
}

impl From<super::AppError> for ScimError {
    fn from(_: super::AppError) -> Self {
        ScimError::new(StatusCode::INTERNAL_SERVER_ERROR, None, "Internal error")
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        let mut response = scim(self.status, body);
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer realm=\"vulnizard-scim\""));
        }
        response
    }
}

type ScimResult = Result<Response, ScimError>;

// ==========================================
// Authentication
// ==========================================

/// Scope of the SCIM token of the request
pub struct ScimAuth(Scope);

impl FromRequestParts<Arc<AppState>> for ScimAuth {
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, ScimError> {
        let unauthorized = || ScimError::new(StatusCode::UNAUTHORIZED, None, "A valid SCIM bearer token is required");
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or_else(unauthorized)?;
        let scope = blocking(|| -> Result<Option<Scope>, ScimError> {
            Ok(state.db()?.scim_token_scope(&auth::hash_token(token))?)
        })?;
        scope.map(ScimAuth).ok_or_else(unauthorized)
    }
}

// ==========================================
// Resources
// ==========================================

fn timestamp(sqlite: &str) -> String {
    // "2026-11-20 10:00:00" -> "2026-11-20T10:00:00Z"
    format!("{}Z", sqlite.replacen(' ', "T", 1))
}

fn base_url(st: &AppState) -> String {
    format!("{}/scim/v2", st.config.web.base_url.trim_end_matches('/'))
}

fn user_json(st: &AppState, u: &ScimUser) -> Value {
    let mut body = json!({
        "schemas": [USER_SCHEMA],
        "id": u.id.to_string(),
        "userName": u.user_name,
        "displayName": u.username,
        "active": u.active,
        "groups": u.groups.iter().map(|(id, name)| json!({
            "value": id.to_string(),
            "display": name,
            "$ref": format!("{}/Groups/{id}", base_url(st)),
        })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "User",
            "created": timestamp(&u.created_at),
            "lastModified": timestamp(&u.updated_at),
            "location": format!("{}/Users/{}", base_url(st), u.id),
        },
    });
    if let Some(external_id) = &u.external_id {
        body["externalId"] = json!(external_id);
    }
    if let Some(email) = &u.email {
        body["emails"] = json!([{ "value": email, "type": "work", "primary": true }]);
    }
    body
}

fn group_json(st: &AppState, g: &ScimGroup) -> Value {
    let mut body = json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.id.to_string(),
        "displayName": g.display_name,
        "members": g.members.iter().map(|(id, name)| json!({
            "value": id.to_string(),
            "display": name,
            "type": "User",
            "$ref": format!("{}/Users/{id}", base_url(st)),
        })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "created": timestamp(&g.created_at),
            "lastModified": timestamp(&g.updated_at),
            "location": format!("{}/Groups/{}", base_url(st), g.id),
        },
    });
    if let Some(external_id) = &g.external_id {
        body["externalId"] = json!(external_id);
    }
    body
}

fn parse_id(raw: &str) -> Result<i64, ScimError> {
    raw.parse().map_err(|_| ScimError::not_found())
}

// ==========================================
// Filters and pagination
// ==========================================

#[derive(Deserialize, Default)]
pub struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<String>,
    count: Option<String>,
}

#[derive(Debug, PartialEq)]
struct Clause {
    attribute: String,
    operator: String,
    value: Option<String>,
}

/// Parses `attr op "value"` clauses joined by `and`. Anything else (`or`,
/// parentheses, complex value paths) is refused with `invalidFilter`.
fn parse_filter(filter: &str) -> Result<Vec<Clause>, ScimError> {
    let invalid = || ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), "Unsupported filter");
    let mut clauses = Vec::new();
    let mut rest = filter.trim();
    while !rest.is_empty() {
        let (attribute, after) = rest.split_once(' ').ok_or_else(invalid)?;
        let after = after.trim_start();
        let (operator, after) = match after.split_once(' ') {
            Some((op, tail)) => (op, tail.trim_start()),
            None => (after, ""),
        };
        let operator = operator.to_lowercase();
        let (value, after) = if operator == "pr" {
            (None, after)
        } else if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted.find('"').ok_or_else(invalid)?;
            (Some(quoted[..end].to_string()), quoted[end + 1..].trim_start())
        } else {
            // Unquoted literal: true, false, a number
            let (literal, tail) = after.split_once(' ').unwrap_or((after, ""));
            if literal.is_empty() {
                return Err(invalid());
            }
            (Some(literal.to_string()), tail.trim_start())
        };
        if !matches!(operator.as_str(), "eq" | "ne" | "co" | "sw" | "ew" | "pr")
            || attribute.contains(['(', ')', '['])
        {
            return Err(invalid());
        }
        clauses.push(Clause {
            attribute: attribute.to_lowercase(),
            operator,
            value,
        });
        rest = match after.split_once(' ') {
            Some((and, tail)) if and.eq_ignore_ascii_case("and") => tail.trim_start(),
            None if after.is_empty() => "",
            _ => return Err(invalid()),
        };
    }
    Ok(clauses)
}

fn compare(actual: Option<&str>, clause: &Clause) -> bool {
    let expected = clause.value.as_deref().unwrap_or("").to_lowercase();
    let actual_lower = actual.map(str::to_lowercase);
    match (clause.operator.as_str(), actual_lower.as_deref()) {
        ("pr", value) => value.is_some_and(|v| !v.is_empty()),
        ("eq", Some(v)) => v == expected,
        ("ne", Some(v)) => v != expected,
        ("ne", None) => true,
        ("co", Some(v)) => v.contains(&expected),
        ("sw", Some(v)) => v.starts_with(&expected),
        ("ew", Some(v)) => v.ends_with(&expected),
        _ => false,
    }
}

fn user_matches(user: &ScimUser, clauses: &[Clause]) -> Result<bool, ScimError> {
    for clause in clauses {
        let id = user.id.to_string();
        let active = user.active.to_string();
        let actual = match clause.attribute.as_str() {
            "username" => Some(user.user_name.as_str()),
            "displayname" => Some(user.username.as_str()),
            "externalid" => user.external_id.as_deref(),
            "id" => Some(id.as_str()),
            "active" => Some(active.as_str()),
            "emails" | "emails.value" => user.email.as_deref(),
            _ => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), "Unsupported filter attribute")),
        };
        if !compare(actual, clause) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn group_matches(group: &ScimGroup, clauses: &[Clause]) -> Result<bool, ScimError> {
    for clause in clauses {
        let id = group.id.to_string();
        let ok = match clause.attribute.as_str() {
            "displayname" => compare(Some(&group.display_name), clause),
            "externalid" => compare(group.external_id.as_deref(), clause),
            "id" => compare(Some(&id), clause),
            // Groups a user belongs to
            "members" | "members.value" => {
                let wanted = clause.value.as_deref().unwrap_or("");
                clause.operator == "eq" && group.members.iter().any(|(id, _)| id.to_string() == wanted)
            }
            _ => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), "Unsupported filter attribute")),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

fn list_response(resources: Vec<Value>, q: &ListQuery) -> Response {
    let total = resources.len();
    // startIndex is 1-based; values below 1 mean 1
    let start = q.start_index.as_deref().and_then(|s| s.parse::<i64>().ok()).unwrap_or(1).max(1) as usize;
    let count = q
        .count
        .as_deref()
        .and_then(|c| c.parse::<i64>().ok())
        .map(|c| c.max(0) as usize)
        .unwrap_or(MAX_RESULTS)
        .min(MAX_RESULTS);
    let page: Vec<Value> = resources.into_iter().skip(start - 1).take(count).collect();
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": page.len(),
            "Resources": page,
        }),
    )
}

// ==========================================
// Attribute parsing
// ==========================================

/// Booleans are sometimes sent as strings ("True") by identity providers
fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Primary (or first) email of an `emails` value: an array, an object or a string
fn email_of(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("value").and_then(Value::as_str).map(String::from),
        Value::Array(list) => list
            .iter()
            .find(|e| e.get("primary").and_then(as_bool) == Some(true))
            .or_else(|| list.first())
            .and_then(email_of),
        _ => None,
    }
}

fn check_email(email: &str) -> Result<(), ScimError> {
    if email.len() > 254 || email.parse::<lettre::Address>().is_err() {
        return Err(ScimError::invalid("Invalid email address"));
    }
    Ok(())
}

fn check_user_name(user_name: &str) -> Result<(), ScimError> {
    if user_name.is_empty() || user_name.chars().count() > 200 || user_name.chars().any(char::is_control) {
        return Err(ScimError::invalid("userName is required (200 characters at most)"));
    }
    Ok(())
}

fn check_text(label: &str, value: &str, max: usize) -> Result<(), ScimError> {
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(ScimError::invalid(format!("{label} is required ({max} characters at most)")));
    }
    Ok(())
}

/// Member ids of a `members` value (array of `{value}` objects)
fn member_ids(value: &Value) -> Result<Vec<i64>, ScimError> {
    let list = match value {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![value.clone()],
        Value::Null => Vec::new(),
        _ => return Err(ScimError::invalid("members must be a list")),
    };
    if list.len() > 5000 {
        return Err(ScimError::invalid("Too many members in one request"));
    }
    list.iter()
        .map(|m| {
            m.get("value")
                .and_then(Value::as_str)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| ScimError::invalid("A member does not exist in this scope"))
        })
        .collect()
}

/// Changes to apply to a user (None = untouched)
#[derive(Default)]
struct UserChanges {
    user_name: Option<String>,
    email: Option<Option<String>>,
    external_id: Option<Option<String>>,
    active: Option<bool>,
}

impl UserChanges {
    /// Reads the attributes present in a (partial or full) user object
    fn absorb(&mut self, object: &serde_json::Map<String, Value>) -> Result<(), ScimError> {
        for (key, value) in object {
            match key.to_lowercase().as_str() {
                "username" => {
                    let name = value.as_str().ok_or_else(|| ScimError::invalid("userName must be a string"))?;
                    check_user_name(name)?;
                    self.user_name = Some(name.to_string());
                }
                "active" => self.active = Some(as_bool(value).ok_or_else(|| ScimError::invalid("active must be a boolean"))?),
                "externalid" => self.external_id = Some(value.as_str().map(String::from)),
                "emails" => {
                    let email = email_of(value);
                    if let Some(email) = &email {
                        check_email(email)?;
                    }
                    self.email = Some(email);
                }
                // name, displayName, password, enterprise extension…: accepted and ignored
                _ => {}
            }
        }
        Ok(())
    }

    fn apply(&self, db: &Database, id: i64) -> Result<(), ScimError> {
        Ok(db.scim_update_user(
            id,
            self.user_name.as_deref(),
            self.email.as_ref().map(|e| e.as_deref()),
            self.external_id.as_ref().map(|e| e.as_deref()),
            self.active,
        )?)
    }
}

#[derive(Deserialize)]
struct PatchBody {
    #[serde(rename = "Operations", alias = "operations")]
    operations: Vec<PatchOperation>,
}

#[derive(Deserialize)]
struct PatchOperation {
    op: String,
    path: Option<String>,
    value: Option<Value>,
}

fn parse_patch(body: &Value) -> Result<Vec<PatchOperation>, ScimError> {
    let patch: PatchBody = serde_json::from_value(body.clone())
        .map_err(|_| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Invalid PATCH body"))?;
    if patch.operations.len() > 1000 {
        return Err(ScimError::invalid("Too many operations"));
    }
    Ok(patch.operations)
}

// ==========================================
// Users
// ==========================================

async fn users_list(State(st): St, ScimAuth(scope): ScimAuth, Query(q): Query<ListQuery>) -> ScimResult {
    blocking(|| {
        let clauses = match q.filter.as_deref() {
            Some(filter) => parse_filter(filter)?,
            None => Vec::new(),
        };
        let mut resources = Vec::new();
        for user in st.db()?.scim_list_users(scope)? {
            if user_matches(&user, &clauses)? {
                resources.push(user_json(&st, &user));
            }
        }
        Ok(list_response(resources, &q))
    })
}

async fn users_create(State(st): St, ScimAuth(scope): ScimAuth, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let object = body.as_object().ok_or_else(|| ScimError::invalid("A user object is expected"))?;
        let mut changes = UserChanges::default();
        changes.absorb(object)?;
        let user_name = changes.user_name.clone().ok_or_else(|| ScimError::invalid("userName is required"))?;
        let db = st.db()?;
        let id = db.scim_create_user(
            scope,
            &user_name,
            changes.email.clone().flatten().as_deref(),
            changes.external_id.clone().flatten().as_deref(),
            changes.active.unwrap_or(true),
        )?;
        let user = db.scim_get_user(scope, id)?.ok_or_else(ScimError::not_found)?;
        let mut response = scim(StatusCode::CREATED, user_json(&st, &user));
        if let Ok(location) = header::HeaderValue::from_str(&format!("{}/Users/{id}", base_url(&st))) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    })
}

fn load_user(db: &Database, scope: Scope, raw_id: &str) -> Result<ScimUser, ScimError> {
    db.scim_get_user(scope, parse_id(raw_id)?)?.ok_or_else(ScimError::not_found)
}

async fn user_get(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>) -> ScimResult {
    blocking(|| Ok(scim(StatusCode::OK, user_json(&st, &load_user(&st.db()?, scope, &id)?))))
}

/// PUT replaces the user: attributes absent from the body are cleared
async fn user_replace(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let user = load_user(&db, scope, &id)?;
        let object = body.as_object().ok_or_else(|| ScimError::invalid("A user object is expected"))?;
        let mut changes = UserChanges {
            email: Some(None),
            external_id: Some(None),
            active: Some(true),
            ..Default::default()
        };
        changes.absorb(object)?;
        if changes.user_name.is_none() {
            return Err(ScimError::invalid("userName is required"));
        }
        changes.apply(&db, user.id)?;
        Ok(scim(StatusCode::OK, user_json(&st, &load_user(&db, scope, &id)?)))
    })
}

async fn user_patch(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let user = load_user(&db, scope, &id)?;
        let mut changes = UserChanges::default();
        for operation in parse_patch(&body)? {
            let op = operation.op.to_lowercase();
            if !matches!(op.as_str(), "add" | "replace" | "remove") {
                return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Unknown operation"));
            }
            match operation.path.as_deref().map(str::to_lowercase) {
                // No path: the value is an object of attributes
                None => {
                    let object = operation
                        .value
                        .as_ref()
                        .and_then(Value::as_object)
                        .ok_or_else(|| ScimError::invalid("An object of attributes is expected"))?;
                    changes.absorb(object)?;
                }
                Some(path) => {
                    // "emails[type eq \"work\"].value" and "emails" both mean the email
                    let attribute = path.split(['[', '.']).next().unwrap_or("").to_string();
                    if op == "remove" {
                        match attribute.as_str() {
                            "emails" => changes.email = Some(None),
                            "externalid" => changes.external_id = Some(None),
                            "username" | "active" => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "This attribute cannot be removed")),
                            _ => {}
                        }
                    } else {
                        let value = operation.value.unwrap_or(Value::Null);
                        let mut object = serde_json::Map::new();
                        object.insert(attribute, value);
                        changes.absorb(&object)?;
                    }
                }
            }
        }
        changes.apply(&db, user.id)?;
        Ok(scim(StatusCode::OK, user_json(&st, &load_user(&db, scope, &id)?)))
    })
}

async fn user_delete(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let user = load_user(&db, scope, &id)?;
        db.scim_delete_user(user.id)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
}

// ==========================================
// Groups
// ==========================================

async fn groups_list(State(st): St, ScimAuth(scope): ScimAuth, Query(q): Query<ListQuery>) -> ScimResult {
    blocking(|| {
        let clauses = match q.filter.as_deref() {
            Some(filter) => parse_filter(filter)?,
            None => Vec::new(),
        };
        let mut resources = Vec::new();
        for group in st.db()?.scim_list_groups(scope)? {
            if group_matches(&group, &clauses)? {
                resources.push(group_json(&st, &group));
            }
        }
        Ok(list_response(resources, &q))
    })
}

fn load_group(db: &Database, scope: Scope, raw_id: &str) -> Result<ScimGroup, ScimError> {
    db.scim_get_group(scope, parse_id(raw_id)?)?.ok_or_else(ScimError::not_found)
}

fn display_name_of(body: &Value) -> Result<String, ScimError> {
    let name = body
        .get("displayName")
        .and_then(Value::as_str)
        .ok_or_else(|| ScimError::invalid("displayName is required"))?;
    check_text("displayName", name, 200)?;
    Ok(name.to_string())
}

async fn groups_create(State(st): St, ScimAuth(scope): ScimAuth, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let name = display_name_of(&body)?;
        let members = member_ids(body.get("members").unwrap_or(&Value::Null))?;
        let db = st.db()?;
        let id = db.scim_create_group(scope, &name, body.get("externalId").and_then(Value::as_str))?;
        if let Err(e) = db.scim_add_members(id, &members) {
            // Nothing half-created
            db.scim_delete_group(id)?;
            return Err(e.into());
        }
        let group = db.scim_get_group(scope, id)?.ok_or_else(ScimError::not_found)?;
        let mut response = scim(StatusCode::CREATED, group_json(&st, &group));
        if let Ok(location) = header::HeaderValue::from_str(&format!("{}/Groups/{id}", base_url(&st))) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    })
}

async fn group_get(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>) -> ScimResult {
    blocking(|| Ok(scim(StatusCode::OK, group_json(&st, &load_group(&st.db()?, scope, &id)?))))
}

async fn group_replace(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let group = load_group(&db, scope, &id)?;
        let name = display_name_of(&body)?;
        let members = member_ids(body.get("members").unwrap_or(&Value::Null))?;
        if name != group.display_name && db.scim_list_groups(scope)?.iter().any(|g| g.display_name == name) {
            return Err(ScimError::conflict("Group name already used"));
        }
        db.scim_set_members(group.id, &members)?;
        db.scim_rename_group(group.id, Some(&name), Some(body.get("externalId").and_then(Value::as_str)))?;
        Ok(scim(StatusCode::OK, group_json(&st, &load_group(&db, scope, &id)?)))
    })
}

/// Member id in a path such as `members[value eq "42"]`
fn member_in_path(path: &str) -> Option<i64> {
    let inside = path.split_once('[')?.1.split_once(']')?.0;
    let (attribute, rest) = inside.trim().split_once(' ')?;
    let (operator, value) = rest.trim().split_once(' ')?;
    if !attribute.eq_ignore_ascii_case("value") || !operator.eq_ignore_ascii_case("eq") {
        return None;
    }
    value.trim().trim_matches('"').parse().ok()
}

async fn group_patch(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>, Json(body): Json<Value>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let group = load_group(&db, scope, &id)?;
        for operation in parse_patch(&body)? {
            let op = operation.op.to_lowercase();
            if !matches!(op.as_str(), "add" | "replace" | "remove") {
                return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Unknown operation"));
            }
            let path = operation.path.as_deref().unwrap_or("");
            let attribute = path.split(['[', '.']).next().unwrap_or("").to_lowercase();
            let value = operation.value.clone().unwrap_or(Value::Null);
            match (attribute.as_str(), op.as_str()) {
                // No path: an object with displayName and/or members
                ("", _) => {
                    let object = value.as_object().ok_or_else(|| ScimError::invalid("An object of attributes is expected"))?;
                    for (key, value) in object {
                        match key.to_lowercase().as_str() {
                            "displayname" => {
                                let name = value.as_str().unwrap_or("");
                                check_text("displayName", name, 200)?;
                                db.scim_rename_group(group.id, Some(name), None)?;
                            }
                            "externalid" => db.scim_rename_group(group.id, None, Some(value.as_str()))?,
                            "members" if op == "add" => db.scim_add_members(group.id, &member_ids(value)?)?,
                            "members" => db.scim_set_members(group.id, &member_ids(value)?)?,
                            _ => {}
                        }
                    }
                }
                ("displayname", "add" | "replace") => {
                    let name = value.as_str().unwrap_or("");
                    check_text("displayName", name, 200)?;
                    if name != group.display_name && db.scim_list_groups(scope)?.iter().any(|g| g.display_name == name) {
                        return Err(ScimError::conflict("Group name already used"));
                    }
                    db.scim_rename_group(group.id, Some(name), None)?;
                }
                ("externalid", "add" | "replace") => db.scim_rename_group(group.id, None, Some(value.as_str()))?,
                ("externalid", "remove") => db.scim_rename_group(group.id, None, Some(None))?,
                ("members", "add") => db.scim_add_members(group.id, &member_ids(&value)?)?,
                ("members", "replace") => db.scim_set_members(group.id, &member_ids(&value)?)?,
                ("members", "remove") => match member_in_path(path) {
                    Some(member) => db.scim_remove_members(group.id, &[member])?,
                    None if value.is_null() => db.scim_set_members(group.id, &[])?,
                    None => db.scim_remove_members(group.id, &member_ids(&value)?)?,
                },
                ("displayname", "remove") => {
                    return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "displayName cannot be removed"))
                }
                // Unknown attributes are ignored
                _ => {}
            }
        }
        Ok(scim(StatusCode::OK, group_json(&st, &load_group(&db, scope, &id)?)))
    })
}

async fn group_delete(State(st): St, ScimAuth(scope): ScimAuth, Path(id): Path<String>) -> ScimResult {
    blocking(|| {
        let db = st.db()?;
        let group = load_group(&db, scope, &id)?;
        db.scim_delete_group(group.id)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
}

// ==========================================
// Discovery
// ==========================================

async fn service_provider_config(State(st): St, ScimAuth(_): ScimAuth) -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": format!("{}/admin/sso?tab=scim", st.config.web.base_url.trim_end_matches('/')),
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_RESULTS },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "Token created in the Vulnizard administration (Single sign-on, SCIM)",
                "primary": true,
            }],
            "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{}/ServiceProviderConfig", base_url(&st)) },
        }),
    )
}

fn resource_types(st: &AppState) -> Vec<Value> {
    [("User", "/Users", USER_SCHEMA, "User account"), ("Group", "/Groups", GROUP_SCHEMA, "Group")]
        .iter()
        .map(|(name, endpoint, schema, description)| {
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": name,
                "name": name,
                "endpoint": endpoint,
                "description": description,
                "schema": schema,
                "meta": { "resourceType": "ResourceType", "location": format!("{}/ResourceTypes/{name}", base_url(st)) },
            })
        })
        .collect()
}

fn attribute(name: &str, kind: &str, multi: bool, required: bool, mutability: &str, uniqueness: &str) -> Value {
    json!({
        "name": name, "type": kind, "multiValued": multi, "required": required, "caseExact": false,
        "mutability": mutability, "returned": "default", "uniqueness": uniqueness,
    })
}

fn schemas(st: &AppState) -> Vec<Value> {
    let sub = |name: &str, kind: &str| attribute(name, kind, false, false, "readWrite", "none");
    let mut emails = attribute("emails", "complex", true, false, "readWrite", "none");
    emails["subAttributes"] = json!([sub("value", "string"), sub("type", "string"), sub("primary", "boolean")]);
    let mut groups = attribute("groups", "complex", true, false, "readOnly", "none");
    groups["subAttributes"] = json!([sub("value", "string"), sub("display", "string"), sub("$ref", "reference")]);
    let mut members = attribute("members", "complex", true, false, "readWrite", "none");
    members["subAttributes"] = json!([sub("value", "string"), sub("display", "string"), sub("type", "string"), sub("$ref", "reference")]);
    let schema = |id: &str, name: &str, attributes: Vec<Value>| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": id,
            "name": name,
            "description": format!("{name} resource"),
            "attributes": attributes,
            "meta": { "resourceType": "Schema", "location": format!("{}/Schemas/{id}", base_url(st)) },
        })
    };
    vec![
        schema(
            USER_SCHEMA,
            "User",
            vec![
                attribute("userName", "string", false, true, "readWrite", "server"),
                attribute("displayName", "string", false, false, "readOnly", "none"),
                attribute("active", "boolean", false, false, "readWrite", "none"),
                attribute("externalId", "string", false, false, "readWrite", "none"),
                emails,
                groups,
            ],
        ),
        schema(
            GROUP_SCHEMA,
            "Group",
            vec![
                attribute("displayName", "string", false, true, "readWrite", "server"),
                attribute("externalId", "string", false, false, "readWrite", "none"),
                members,
            ],
        ),
    ]
}

fn discovery_list(resources: Vec<Value>) -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": resources.len(),
            "startIndex": 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

async fn resource_types_list(State(st): St, ScimAuth(_): ScimAuth) -> Response {
    discovery_list(resource_types(&st))
}

async fn resource_type_get(State(st): St, ScimAuth(_): ScimAuth, Path(name): Path<String>) -> ScimResult {
    resource_types(&st)
        .into_iter()
        .find(|r| r["id"] == name.as_str())
        .map(|r| scim(StatusCode::OK, r))
        .ok_or_else(ScimError::not_found)
}

async fn schemas_list(State(st): St, ScimAuth(_): ScimAuth) -> Response {
    discovery_list(schemas(&st))
}

async fn schema_get(State(st): St, ScimAuth(_): ScimAuth, Path(id): Path<String>) -> ScimResult {
    schemas(&st)
        .into_iter()
        .find(|s| s["id"] == id.as_str())
        .map(|s| scim(StatusCode::OK, s))
        .ok_or_else(ScimError::not_found)
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/ResourceTypes", get(resource_types_list))
        .route("/ResourceTypes/{name}", get(resource_type_get))
        .route("/Schemas", get(schemas_list))
        .route("/Schemas/{id}", get(schema_get))
        .route("/Users", get(users_list).post(users_create))
        .route("/Users/{id}", get(user_get).put(user_replace).patch(user_patch).delete(user_delete))
        .route("/Groups", get(groups_list).post(groups_create))
        .route("/Groups/{id}", get(group_get).put(group_replace).patch(group_patch).delete(group_delete))
        .fallback(|| async { ScimError::not_found() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause(attribute: &str, operator: &str, value: Option<&str>) -> Clause {
        Clause {
            attribute: attribute.into(),
            operator: operator.into(),
            value: value.map(String::from),
        }
    }

    #[test]
    fn filters_are_parsed() {
        assert_eq!(parse_filter(r#"userName eq "jdoe@corp.example""#).unwrap(), [clause("username", "eq", Some("jdoe@corp.example"))]);
        assert_eq!(
            parse_filter(r#"userName sw "j" and active eq true"#).unwrap(),
            [clause("username", "sw", Some("j")), clause("active", "eq", Some("true"))]
        );
        assert_eq!(parse_filter("externalId pr").unwrap(), [clause("externalid", "pr", None)]);
        assert_eq!(parse_filter(r#"displayName eq "Dev Ops""#).unwrap(), [clause("displayname", "eq", Some("Dev Ops"))]);
        for unsupported in [
            r#"userName eq "a" or userName eq "b""#,
            r#"(userName eq "a")"#,
            r#"emails[type eq "work"].value eq "a""#,
            r#"userName gt "a""#,
            "userName",
            r#"userName eq "unterminated"#,
        ] {
            assert!(parse_filter(unsupported).is_err(), "{unsupported}");
        }
    }

    #[test]
    fn values_sent_by_common_providers_are_understood() {
        // Booleans as strings
        assert_eq!(as_bool(&json!("False")), Some(false));
        assert_eq!(as_bool(&json!(true)), Some(true));
        assert_eq!(as_bool(&json!("yes")), None);
        // Email: primary first, else the first one
        let emails = json!([{ "value": "a@example.org" }, { "value": "b@example.org", "primary": true }]);
        assert_eq!(email_of(&emails).as_deref(), Some("b@example.org"));
        assert_eq!(email_of(&json!("c@example.org")).as_deref(), Some("c@example.org"));
        // Member removed through its path
        assert_eq!(member_in_path(r#"members[value eq "42"]"#), Some(42));
        assert_eq!(member_in_path(r#"members[display eq "x"]"#), None);
        assert_eq!(member_in_path("members"), None);
    }
}
