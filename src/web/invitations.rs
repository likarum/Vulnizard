//! Invitations: a member is added by name, and the name answers.
//!
//! The member forms of an organization and of a project no longer give a
//! role to a name: they record an invitation, with one answer — the same
//! page, the same words — whether an account bears the name or not. See
//! `db::invitations` for what an invitation is tied to.

use axum::extract::{Path, State};
use maud::{html, Markup};

use super::pages::{load_org, load_project, redirect, require, ActionResult};
use super::views::{self, enc, product_url};
use super::{blocking, AppError, St, User};
use crate::db::{Account, Actor, Database, Scope, INVITATION_DAYS};
use crate::rbac::{Permission, Role};

/// Mark, in the address of the page, that an invitation was just recorded.
/// The words shown are fixed: an address cannot put a text in the page.
const INVITED: &str = "notice=invited";

/// The name typed in a member form, as usernames are written: no space
/// around it, the characters a username may hold. Refused on its spelling
/// alone, before anything is looked up.
pub(super) fn typed_name(raw: &str) -> Result<&str, AppError> {
    let name = raw.trim();
    if !crate::auth::valid_slug(name, 1, 64) {
        return Err(AppError::Bad("Name: letters, digits, '-', '_' or '.' only.".into()));
    }
    Ok(name)
}

/// Records the invitation and answers the page it was typed on. Nothing here
/// depends on whether the name is one of an account.
pub(super) fn invite(db: &Database, user: &Account, scope: Scope, name: &str, role: Role, page: String) -> ActionResult {
    db.invite(scope, name, role, &Actor::user(user.id, &user.username)).map_err(AppError::bad)?;
    let mark = if page.contains('?') { '&' } else { '?' };
    Ok(redirect(format!("{page}{mark}{INVITED}#invitations")))
}

fn just_invited() -> bool {
    views::PAGE
        .try_with(|c| c.path.split_once('?').is_some_and(|(_, query)| query.split('&').any(|p| p == INVITED)))
        .unwrap_or(false)
}

/// Pending invitations of an organization or of a project, for whoever
/// manages its members: names as they were typed, never whether they are accounts.
pub(super) fn pending_section(db: &Database, scope: Scope, base: &str) -> Result<Markup, AppError> {
    let pending = db.pending_invitations(scope)?;
    Ok(html! {
        h3 #invitations { "Pending invitations" }
        @if just_invited() {
            div.card.notice {
                "Invitation recorded. If an account bears this name, it finds the invitation when it signs in, and decides. "
                "Nothing is granted until then, and nothing here tells whether the name is one of an account."
            }
        }
        p.muted {
            "A name typed above is invited: the role is given when the person accepts, from their settings. "
            "An invitation expires after " (INVITATION_DAYS) " days, and only an account that existed when it was made can accept it."
        }
        table.list.fit {
            (views::columns("- kind who day day act", true))
            thead { tr { th { "Name typed" } th { "Role" } th { "Invited by" } th { "Sent" } th { "Expires" } th {} } }
            tbody {
                @for p in &pending {
                    tr {
                        td { (p.name) }
                        td data-label="Role" { (p.role) }
                        td data-label="Invited by" { (p.invited_by) }
                        td data-label="Sent" { (views::short_date(Some(&p.created_at))) }
                        td data-label="Expires" { (views::short_date(Some(&p.expires_at))) }
                        td.right {
                            form.inline method="post" action={ (base) "/invitations/" (p.id) "/cancel" } {
                                button.small.danger type="submit" { "Cancel" }
                            }
                        }
                    }
                }
                @if pending.is_empty() { tr { td colspan="6" .muted { "No pending invitation." } } }
            }
        }
    })
}

/// Invitations waiting for the answer of the signed-in account (settings page)
pub(super) fn received_section(db: &Database, user: &Account) -> Result<Markup, AppError> {
    let received = db.received_invitations(user.id)?;
    Ok(html! {
        @if !received.is_empty() {
            h2 #invitations { "Invitations" }
            p.muted { "You were offered these roles. Nothing is given until you accept; declining removes the invitation." }
            table.list.fit {
                (views::columns("- kind who day actions", true))
                thead { tr { th { "To" } th { "Role" } th { "Invited by" } th { "Expires" } th {} } }
                tbody {
                    @for i in &received {
                        tr {
                            td { (i.target()) }
                            td data-label="Role" { (i.role.as_str()) }
                            td data-label="Invited by" { (i.invited_by) }
                            td data-label="Expires" { (views::short_date(Some(&i.expires_at))) }
                            td.right.actions {
                                form.inline method="post" action={ "/invitations/" (i.id) "/accept" } {
                                    button.small type="submit" { "Accept" }
                                }
                                " "
                                form.inline method="post" action={ "/invitations/" (i.id) "/decline" } {
                                    button.small.secondary type="submit" { "Decline" }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// The invited account accepts: it gets the role offered, where it was
/// offered. An id that is not an invitation of this account — unknown, of
/// someone else, expired, void — is not found, in one answer.
pub async fn accept(State(st): St, User(user): User, Path(id): Path<i64>) -> ActionResult {
    blocking(|| {
        let invitation = st.db()?.accept_invitation(user.id, id).map_err(AppError::bad)?.ok_or(AppError::NotFound)?;
        Ok(redirect(match &invitation.project {
            Some(project) => product_url(Some((&invitation.org, project)), "overview"),
            None => format!("/orgs/{}", enc(&invitation.org)),
        }))
    })
}

pub async fn decline(State(st): St, User(user): User, Path(id): Path<i64>) -> ActionResult {
    blocking(|| {
        if !st.db()?.decline_invitation(user.id, id)? {
            return Err(AppError::NotFound);
        }
        Ok(redirect("/settings".into()))
    })
}

pub async fn org_cancel(State(st): St, User(user): User, Path((org, id)): Path<(String, i64)>) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        require(&org, Permission::ManageMembers)?;
        if !db.cancel_invitation(Scope::Organization(org.id), id, &Actor::user(user.id, &user.username))? {
            return Err(AppError::NotFound);
        }
        Ok(redirect(format!("/orgs/{}#invitations", enc(&org.name))))
    })
}

pub async fn project_cancel(
    State(st): St,
    User(user): User,
    Path((org, project, id)): Path<(String, String, i64)>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let (org, project) = load_project(&db, &user, &org, &project)?;
        require(&org, Permission::ManageMembers)?;
        if !db.cancel_invitation(Scope::Project(project.id), id, &Actor::user(user.id, &user.username))? {
            return Err(AppError::NotFound);
        }
        Ok(redirect(format!("{}#invitations", product_url(Some((&org.name, &project.name)), "settings"))))
    })
}
