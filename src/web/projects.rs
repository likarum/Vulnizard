//! Project management and the actions of the "products" side (triage,
//! tracked applications, notifications). The views are in `product.rs`.

use axum::extract::{Form, Path, State};
use maud::{html, Markup};
use serde::Deserialize;

use super::pages::{load_project, redirect, require, ActionResult, HtmlResult, NameForm};
use super::views::{self, layout, product_url, Nav};
use super::{blocking, AppError, St, User};
use crate::auth;
use crate::db::{Actor, Database, Org, OrgProject};
use crate::models::{Application, CveStatus};
use crate::rbac::Permission;

/// Page to come back to after an action: only a local products page is
/// accepted (never an arbitrary URL), otherwise the given default.
fn back_or(back: &str, default: String) -> String {
    let local = (back == "/" || back.starts_with("/product") || back.starts_with("/projects"))
        && !back.contains("//")
        && !back.contains('\\')
        && !back.chars().any(|c| c.is_control());
    if local {
        back.to_string()
    } else {
        default
    }
}

fn project_table(projects: &[crate::db::ProjectSummary], listing: &views::Listing) -> Markup {
    html! {
        table.list {
            thead {
                tr {
                    (listing.th("project", "Project")) (listing.th("review", "To review"))
                    (listing.th("apps", "Applications")) (listing.th("subs", "Subscriptions"))
                    (listing.th("last", "Last change")) (listing.th("role", "Your role"))
                }
            }
            tbody {
                @for p in projects {
                    tr {
                        td {
                            a href=(product_url(Some((&p.org, &p.name)), "overview")) { strong { (p.name) } }
                            " " span.muted { (p.org) }
                            @if let Some(d) = &p.description { div.muted { (d) } }
                        }
                        td { @if p.untreated > 0 { strong { (p.untreated) } } @else { span.muted { "0" } } }
                        td { (p.applications) }
                        td { (p.subscriptions) }
                        td.nowrap { (p.last_report.as_deref().unwrap_or("—")) }
                        td { (p.role) }
                    }
                }
                @if projects.is_empty() { tr { td colspan="6" .muted { "No project yet." } } }
            }
        }
    }
}

// ==========================================
// Projects list & creation
// ==========================================

pub async fn projects(State(st): St, User(user): User) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let mut projects = db.project_summaries(user.id)?;
        let total = projects.len();
        let listing = views::Listing::from_page("project", false);
        listing.apply(
            &mut projects,
            |p| format!("{} {} {}", p.name, p.org, p.description.as_deref().unwrap_or("")),
            |p, column| match column {
                "project" => Some(views::SortKey::text(&p.name)),
                "review" => Some(views::SortKey::num(p.untreated as f64)),
                "apps" => Some(views::SortKey::num(p.applications as f64)),
                "subs" => Some(views::SortKey::num(p.subscriptions as f64)),
                "last" => Some(views::SortKey::text(p.last_report.as_deref().unwrap_or(""))),
                "role" => Some(views::SortKey::text(&p.role)),
                _ => None,
            },
        );
        let orgs: Vec<Org> = db
            .list_orgs(user.id)?
            .into_iter()
            .filter(|o| o.can(Permission::ManageProjects))
            .collect();
        Ok(layout(
            Nav::PRODUCTS,
            "Projects",
            Some(&user),
            html! {
                div.head {
                    h1 { "Projects" }
                    a href="/orgs" { "Organizations & members →" }
                }
                (listing.filter_box("Filter: project, organization…", projects.len(), total))
                (project_table(&projects, &listing))

                h2 { "New project" }
                @if orgs.is_empty() {
                    p.muted { "You need the owner or editor role in an organization to create projects. " a href="/orgs" { "Create an organization" } "." }
                } @else {
                    form.row method="post" action="/projects" {
                        select name="org" {
                            @for o in &orgs { option value=(o.name) { (o.name) } }
                        }
                        input type="text" name="name" placeholder="project-name" maxlength="64" required;
                        input type="text" name="description" placeholder="Description (optional)" maxlength="200";
                        button type="submit" { "Create project" }
                    }
                }
            },
        ))
    })
}

fn create_project(db: &Database, user_id: i64, org: &Org, form: &NameForm) -> ActionResult {
    require(org, Permission::ManageProjects)?;
    let name = form.name.trim();
    if !auth::valid_slug(name, 1, 64) {
        return Err(AppError::Bad("Name: letters, digits, '-', '_' or '.' only.".into()));
    }
    let description = Some(form.description.trim()).filter(|d| !d.is_empty());
    db.create_org_project(org.id, user_id, name, description)
        .map_err(AppError::bad)?;
    Ok(redirect(product_url(Some((&org.name, name)), "applications")))
}

#[derive(Deserialize)]
pub struct NewProjectForm {
    org: String,
    #[serde(flatten)]
    project: NameForm,
}

pub async fn project_create_any(State(st): St, User(user): User, Form(form): Form<NewProjectForm>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = db.get_org(&form.org, user.id)?.ok_or(AppError::NotFound)?;
        create_project(&db, user.id, &org, &form.project)
    })
}

pub async fn project_create(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Form(form): Form<NameForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = db.get_org(&org, user.id)?.ok_or(AppError::NotFound)?;
        create_project(&db, user.id, &org, &form)
    })
}

// ==========================================
// Project actions
// ==========================================

#[derive(Deserialize)]
pub struct StatusForm {
    status: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    back: String,
}

pub async fn watchlist_status(
    State(st): St,
    User(user): User,
    Path((org, project, entry_id)): Path<(String, String, i64)>,
    Form(form): Form<StatusForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::Triage)?;
        let status = CveStatus::from_str(&form.status).ok_or_else(|| AppError::Bad("Invalid status".into()))?;
        let actor = Actor::user(user.id, &user.username);
        let comment = Some(form.comment.trim()).filter(|c| !c.is_empty());
        if status == CveStatus::Accepted && comment.is_none() {
            return Err(AppError::Bad("Accepting a risk requires a justification.".into()));
        }
        if comment.is_some_and(|c| c.chars().count() > 500) {
            return Err(AppError::Bad("Comment is too long.".into()));
        }
        if !db.set_watchlist_status(project.id, entry_id, status, &actor, comment)? {
            return Err(AppError::NotFound);
        }
        Ok(redirect(back_or(
            &form.back,
            product_url(Some((&org.name, &project.name)), "review"),
        )))
    })
}

#[derive(Deserialize)]
pub struct ApplicationForm {
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    back: String,
}

pub async fn application_add(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(form): Form<ApplicationForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let name = form.name.trim();
        if name.is_empty() || name.len() > 100 || form.version.len() > 64 || form.vendor.len() > 100 {
            return Err(AppError::Bad("Invalid application name, version or vendor.".into()));
        }
        let mut app = Application::new(project.id, name.to_string());
        app.version = Some(form.version.trim().to_string()).filter(|v| !v.is_empty());
        app.vendor = Some(form.vendor.trim().to_string()).filter(|v| !v.is_empty());
        if !form.ecosystem.is_empty() && !crate::db::watchlist::PACKAGE_ECOSYSTEMS.contains(&form.ecosystem.as_str()) {
            return Err(AppError::Bad("Unknown package ecosystem.".into()));
        }
        app.ecosystem = Some(form.ecosystem.clone()).filter(|e| !e.is_empty());
        if db
            .get_application_by_name(project.id, &app.name, app.version.as_deref())?
            .is_some()
        {
            return Err(AppError::Bad("This application is already tracked with this version.".into()));
        }
        if !crate::db::watchlist::is_matchable_name(&app.name) {
            return Err(AppError::Bad("The application name needs at least two letters or digits.".into()));
        }
        db.add_application_scanned(&mut app)?;
        Ok(redirect(back_or(
            &form.back,
            product_url(Some((&org.name, &project.name)), "applications"),
        )))
    })
}

/// Loads an application and checks that it belongs to the project
fn project_application(db: &Database, project: &OrgProject, app_id: i64) -> Result<Application, AppError> {
    db.get_application(app_id)?
        .filter(|a| a.project_id == project.id)
        .ok_or(AppError::NotFound)
}

#[derive(Deserialize)]
pub struct VersionForm {
    version: String,
    #[serde(default)]
    back: String,
}

#[derive(Deserialize, Default)]
pub struct BackForm {
    #[serde(default)]
    back: String,
}

pub async fn application_version(
    State(st): St,
    User(user): User,
    Path((org, project, app_id)): Path<(String, String, i64)>,
    Form(form): Form<VersionForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        let app = project_application(&db, &project, app_id)?;
        let version = form.version.trim();
        if version.is_empty() || version.len() > 64 {
            return Err(AppError::Bad("Invalid version.".into()));
        }
        if app.version.as_deref() != Some(version) {
            if db.get_application_by_name(project.id, &app.name, Some(version))?.is_some() {
                return Err(AppError::Bad("This application is already tracked with this version.".into()));
            }
            db.change_application_version(app_id, version, &Actor::user(user.id, &user.username))?;
        }
        Ok(redirect(back_or(
            &form.back,
            product_url(Some((&org.name, &project.name)), "applications"),
        )))
    })
}

pub async fn application_delete(
    State(st): St,
    User(user): User,
    Path((org, project, app_id)): Path<(String, String, i64)>,
    Form(form): Form<BackForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageProjects)?;
        if !db.delete_application_by_id(project.id, app_id, &Actor::user(user.id, &user.username))? {
            return Err(AppError::NotFound);
        }
        Ok(redirect(back_or(
            &form.back,
            product_url(Some((&org.name, &project.name)), "applications"),
        )))
    })
}

pub async fn project_delete(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(form): Form<NameForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::DeleteProject)?;
        if form.name.trim() != project.name {
            return Err(AppError::Bad("Confirmation does not match the project name.".into()));
        }
        db.delete_project_by_id(project.id, &Actor::user(user.id, &user.username))?;
        Ok(redirect("/projects".into()))
    })
}

pub async fn report_detail(
    State(st): St,
    User(user): User,
    Path((org, project, day)): Path<(String, String, String)>,
) -> HtmlResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        let changes = db.get_report(project.id, &day)?.ok_or(AppError::NotFound)?;
        let scope = Some((org.name.as_str(), project.name.as_str()));
        Ok(layout(
            Nav::Product { scope, view: "evolution" },
            &format!("Report {day}"),
            Some(&user),
            html! {
                p { a href=(product_url(scope, "evolution")) { "← " (project.name) " evolution" } }
                h1 { "Report of " (day) }
                p.muted { (changes.len()) " change(s) on subscribed CVEs" }
                (views::report_changes(&changes))
            },
        ))
    })
}

// ==========================================
// Members of one project
// ==========================================

#[derive(Deserialize)]
pub struct ProjectMemberForm {
    username: String,
    role: String,
}

/// Gives a user a role on this project only
pub async fn project_member_set(
    State(st): St,
    User(user): User,
    Path((org, project)): Path<(String, String)>,
    Form(form): Form<ProjectMemberForm>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageMembers)?;
        let role = crate::rbac::Role::parse(&form.role).ok_or_else(|| AppError::Bad("Unknown role.".into()))?;
        let account = db
            .get_credentials_or_sso(form.username.trim())?
            .ok_or_else(|| AppError::Bad("Unknown user.".into()))?;
        if !db.may_hold_right(account.id, crate::db::Scope::Project(project.id))? {
            return Err(AppError::Bad("This account belongs to another project or organization.".into()));
        }
        db.set_project_member(project.id, account.id, role)?;
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}

pub async fn project_member_remove(
    State(st): St,
    User(user): User,
    Path((org, project, user_id)): Path<(String, String, i64)>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageMembers)?;
        db.remove_project_member(project.id, user_id)?;
        Ok(redirect(product_url(Some((&org.name, &project.name)), "settings")))
    })
}
