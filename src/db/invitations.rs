//! Invitations (schema v30): a role offered to a name, which the person
//! accepts or declines.
//!
//! Whoever manages the members of an organization or of a project types a
//! name. Nothing is granted then, and nothing tells whether the name is one
//! of an account: an invitation is recorded for the name as typed, by the
//! same statement whether an account bears it or not.
//!
//! The invitation is tied, when it is made, to the account that bore the name
//! at that moment (`invitee_id`), and to nothing when nobody did. Only that
//! account sees it and may accept it: an account created afterwards with the
//! invited name (registration, single sign-on, SCIM) never can, and an
//! invitation that matched nobody stays unclaimable until it expires.
//!
//! An invitation is void — neither shown to the invited account nor
//! acceptable — once it expired, once whoever made it was disabled or lost
//! the right to manage the members there, when the invited account may not
//! hold a right there (accounts coming from another project or organization)
//! or already holds one given directly. It goes with its organization or
//! project (cascade).

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::db::{Actor, Database, Scope};
use crate::rbac::{Permission, Role};

const INVITATIONS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- exactly one of the two: the level the role is offered at
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    -- the name as typed
    name TEXT NOT NULL COLLATE NOCASE,
    role TEXT NOT NULL CHECK(role IN ('owner', 'editor', 'viewer')),
    invited_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- the account that bore the name when the invitation was made; NULL when none did
    invitee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    CHECK ((organization_id IS NULL) != (project_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_organization ON invitations(organization_id, name) WHERE organization_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_project ON invitations(project_id, name) WHERE project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invitations_invitee ON invitations(invitee_id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '30');
"#;

/// Days an invitation can be accepted
pub const INVITATION_DAYS: i64 = 14;
/// Invitations one organization, or one project, may have pending at a time
pub const MAX_PENDING_INVITATIONS: i64 = 50;

/// An invitation as whoever manages the members sees it: the name as typed,
/// and nothing about the account behind it, if any
#[derive(Debug, Clone)]
pub struct PendingInvitation {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub invited_by: String,
    pub created_at: String,
    pub expires_at: String,
}

/// An invitation as the invited account sees it
#[derive(Debug, Clone)]
pub struct ReceivedInvitation {
    pub id: i64,
    pub scope: Scope,
    pub org: String,
    /// Name of the project, for a role offered on one project only
    pub project: Option<String>,
    pub role: Role,
    pub invited_by: String,
    pub expires_at: String,
}

impl ReceivedInvitation {
    /// "organization acme" or "project acme / infra"
    pub fn target(&self) -> String {
        match &self.project {
            Some(project) => format!("project {} / {project}", self.org),
            None => format!("organization {}", self.org),
        }
    }
}

/// Columns holding the level of an invitation: (organization, project)
fn target(scope: Scope) -> Result<(Option<i64>, Option<i64>)> {
    match scope {
        Scope::Organization(id) => Ok((Some(id), None)),
        Scope::Project(id) => Ok((None, Some(id))),
        Scope::Instance => Err(anyhow!("Invitations are for an organization or a project")),
    }
}

impl Database {
    pub(super) fn migrate_invitations(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(INVITATIONS_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// "organization acme" or "project acme / infra", for the trail
    fn scope_name(&self, scope: Scope) -> Result<String> {
        let name: Option<String> = match scope {
            Scope::Organization(id) => self
                .conn()
                .query_row("SELECT 'organization ' || name FROM organizations WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?,
            Scope::Project(id) => self
                .conn()
                .query_row(
                    "SELECT 'project ' || COALESCE(o.name, '') || ' / ' || p.name FROM projects p
                     LEFT JOIN organizations o ON o.id = p.organization_id WHERE p.id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()?,
            Scope::Instance => None,
        };
        name.ok_or_else(|| anyhow!("Unknown organization or project"))
    }

    /// May this account, today, give a role at this level? The rule of the
    /// member forms (enabled, and the right to manage members there).
    fn may_invite(&self, user_id: i64, scope: Scope) -> Result<bool> {
        let view = match scope {
            Scope::Organization(_) => "org_access a ON a.organization_id = ?2",
            Scope::Project(_) => "project_access a ON a.project_id = ?2",
            Scope::Instance => return Ok(false),
        };
        let role: Option<String> = self
            .conn()
            .query_row(
                &format!(
                    "SELECT {role} FROM users u JOIN {view} AND a.user_id = u.id WHERE u.id = ?1 AND u.disabled = 0",
                    role = super::roles::role_of("a.rank")
                ),
                params![user_id, scope.id()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(role.as_deref().and_then(Role::parse).is_some_and(|r| r.allows(Permission::ManageMembers)))
    }

    /// Whether the account holds a role given directly at this level
    fn is_direct_member(&self, user_id: i64, scope: Scope) -> Result<bool> {
        let sql = match scope {
            Scope::Organization(_) => "SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id = ?1 AND user_id = ?2)",
            Scope::Project(_) => "SELECT EXISTS(SELECT 1 FROM project_memberships WHERE project_id = ?1 AND user_id = ?2)",
            Scope::Instance => return Ok(false),
        };
        Ok(self.conn().query_row(sql, params![scope.id(), user_id], |r| r.get(0))?)
    }

    /// Records an invitation for a name. One statement whatever the name: the
    /// account bearing it now, if any, is the only one that will ever see it.
    /// A pending invitation for the same name at the same level is replaced.
    pub fn invite(&self, scope: Scope, name: &str, role: Role, inviter: &Actor) -> Result<()> {
        let (org, project) = target(scope)?;
        let inviter_id = inviter.user_id.ok_or_else(|| anyhow!("An invitation is made by an account"))?;
        let label = self.scope_name(scope)?;
        let tx = self.write_tx()?;
        // What can no longer be accepted makes room: expired, or made by someone who may no longer invite
        tx.execute(
            "DELETE FROM invitations WHERE organization_id IS ?1 AND project_id IS ?2
               AND (expires_at <= datetime('now') OR name = ?3)",
            params![org, project, name],
        )?;
        let others: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT DISTINCT invited_by FROM invitations WHERE organization_id IS ?1 AND project_id IS ?2")?;
            let rows = stmt.query_map(params![org, project], |r| r.get(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for other in others {
            if !self.may_invite(other, scope)? {
                tx.execute(
                    "DELETE FROM invitations WHERE organization_id IS ?1 AND project_id IS ?2 AND invited_by = ?3",
                    params![org, project, other],
                )?;
            }
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM invitations WHERE organization_id IS ?1 AND project_id IS ?2",
            params![org, project],
            |r| r.get(0),
        )?;
        if pending >= MAX_PENDING_INVITATIONS {
            return Err(anyhow!(
                "Too many pending invitations ({MAX_PENDING_INVITATIONS}): cancel some, or wait for them to expire"
            ));
        }
        tx.execute(
            &format!(
                "INSERT INTO invitations (organization_id, project_id, name, role, invited_by, invitee_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5,
                         (SELECT id FROM users WHERE username = ?3 COLLATE NOCASE
                            AND (password_hash IS NOT NULL OR oidc_subject IS NOT NULL OR provisioned != 0)),
                         datetime('now', '+{INVITATION_DAYS} days'))"
            ),
            params![org, project, name, role.as_str(), inviter_id],
        )?;
        // About the level, not about an account: the trail says no more than the form did
        self.log_security_event(inviter, None, "invitation_sent", Some(&format!("{label}: “{name}” as {}", role.as_str())))?;
        tx.commit()?;
        Ok(())
    }

    /// Invitations pending at this level, for whoever manages its members
    pub fn pending_invitations(&self, scope: Scope) -> Result<Vec<PendingInvitation>> {
        let (org, project) = target(scope)?;
        let rows: Vec<(i64, PendingInvitation)> = {
            let mut stmt = self.conn().prepare(
                "SELECT i.invited_by, i.id, i.name, i.role, u.username, i.created_at, i.expires_at
                 FROM invitations i JOIN users u ON u.id = i.invited_by
                 WHERE i.organization_id IS ?1 AND i.project_id IS ?2 AND i.expires_at > datetime('now')
                 ORDER BY i.id",
            )?;
            let rows = stmt
                .query_map(params![org, project], |r| {
                    Ok((
                        r.get(0)?,
                        PendingInvitation {
                            id: r.get(1)?,
                            name: r.get(2)?,
                            role: r.get(3)?,
                            invited_by: r.get(4)?,
                            created_at: r.get(5)?,
                            expires_at: r.get(6)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut out = Vec::new();
        let mut inviters: std::collections::HashMap<i64, bool> = Default::default();
        for (inviter, invitation) in rows {
            let valid = match inviters.get(&inviter) {
                Some(valid) => *valid,
                None => {
                    let valid = self.may_invite(inviter, scope)?;
                    inviters.insert(inviter, valid);
                    valid
                }
            };
            if valid {
                out.push(invitation);
            }
        }
        Ok(out)
    }

    /// Invitations this account can accept (all of them, or the one of this id)
    fn claimable_invitations(&self, user_id: i64, id: Option<i64>) -> Result<Vec<ReceivedInvitation>> {
        let rows: Vec<(i64, Option<i64>, Option<i64>, String, ReceivedInvitation)> = {
            let mut stmt = self.conn().prepare(
                "SELECT i.invited_by, i.organization_id, i.project_id, i.role,
                        i.id, COALESCE(o.name, po.name, ''), p.name, u.username, i.expires_at
                 FROM invitations i
                 JOIN users u ON u.id = i.invited_by
                 JOIN users me ON me.id = i.invitee_id AND me.disabled = 0
                 LEFT JOIN organizations o ON o.id = i.organization_id
                 LEFT JOIN projects p ON p.id = i.project_id
                 LEFT JOIN organizations po ON po.id = p.organization_id
                 WHERE i.invitee_id = ?1 AND (?2 IS NULL OR i.id = ?2) AND i.expires_at > datetime('now')
                 ORDER BY i.id",
            )?;
            let rows = stmt
                .query_map(params![user_id, id], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        ReceivedInvitation {
                            id: r.get(4)?,
                            scope: Scope::Instance,
                            org: r.get(5)?,
                            project: r.get(6)?,
                            role: Role::Viewer,
                            invited_by: r.get(7)?,
                            expires_at: r.get(8)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut out = Vec::new();
        for (inviter, org, project, role, mut invitation) in rows {
            let (Some(scope), Some(role)) = (
                match (org, project) {
                    (Some(id), None) => Some(Scope::Organization(id)),
                    (None, Some(id)) => Some(Scope::Project(id)),
                    _ => None,
                },
                Role::parse(&role),
            ) else {
                continue;
            };
            if self.may_invite(inviter, scope)? && self.may_hold_right(user_id, scope)? && !self.is_direct_member(user_id, scope)? {
                invitation.scope = scope;
                invitation.role = role;
                out.push(invitation);
            }
        }
        Ok(out)
    }

    /// Invitations waiting for this account's answer
    pub fn received_invitations(&self, user_id: i64) -> Result<Vec<ReceivedInvitation>> {
        self.claimable_invitations(user_id, None)
    }

    /// Accepts an invitation: the role it offers, at its level, is given the
    /// way the member forms give one. `None` when there is no such invitation
    /// for this account — unknown, addressed to someone else, expired or void
    /// are one answer.
    pub fn accept_invitation(&self, user_id: i64, id: i64) -> Result<Option<ReceivedInvitation>> {
        let tx = self.write_tx()?;
        let Some(invitation) = self.claimable_invitations(user_id, Some(id))?.pop() else {
            return Ok(None);
        };
        match invitation.scope {
            Scope::Organization(org) => super::platform::grant_org_role(&tx, org, user_id, invitation.role)?,
            Scope::Project(project) => super::roles::grant_project_role(&tx, project, user_id, invitation.role)?,
            Scope::Instance => return Ok(None),
        }
        tx.execute("DELETE FROM invitations WHERE id = ?1", params![id])?;
        let name: String = tx.query_row("SELECT username FROM users WHERE id = ?1", params![user_id], |r| r.get(0))?;
        self.log_security_event(
            &Actor::user(user_id, &name),
            Some(user_id),
            "invitation_accepted",
            Some(&format!("{} as {}, invited by {}", invitation.target(), invitation.role.as_str(), invitation.invited_by)),
        )?;
        tx.commit()?;
        Ok(Some(invitation))
    }

    /// Declines an invitation: it is removed. False when there is no such
    /// invitation for this account.
    pub fn decline_invitation(&self, user_id: i64, id: i64) -> Result<bool> {
        let tx = self.write_tx()?;
        let Some(invitation) = self.claimable_invitations(user_id, Some(id))?.pop() else {
            return Ok(false);
        };
        tx.execute("DELETE FROM invitations WHERE id = ?1", params![id])?;
        let name: String = tx.query_row("SELECT username FROM users WHERE id = ?1", params![user_id], |r| r.get(0))?;
        self.log_security_event(
            &Actor::user(user_id, &name),
            Some(user_id),
            "invitation_declined",
            Some(&format!("{} as {}, invited by {}", invitation.target(), invitation.role.as_str(), invitation.invited_by)),
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Cancels a pending invitation of this level. False when it has none of this id.
    pub fn cancel_invitation(&self, scope: Scope, id: i64, actor: &Actor) -> Result<bool> {
        let (org, project) = target(scope)?;
        let label = self.scope_name(scope)?;
        let tx = self.write_tx()?;
        let found: Option<(String, String)> = tx
            .query_row(
                "SELECT name, role FROM invitations WHERE id = ?1 AND organization_id IS ?2 AND project_id IS ?3",
                params![id, org, project],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((name, role)) = found else {
            return Ok(false);
        };
        tx.execute("DELETE FROM invitations WHERE id = ?1", params![id])?;
        self.log_security_event(actor, None, "invitation_cancelled", Some(&format!("{label}: “{name}” as {role}")))?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct World {
        db: Database,
        owner: i64,
        org: i64,
        infra: i64,
    }

    fn world() -> World {
        let db = Database::open_in_memory().unwrap();
        db.conn().execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let owner = db.create_account("owner", None, "h", false).unwrap();
        let org = db.create_org("acme", owner).unwrap();
        let infra = db.create_org_project(org, owner, "infra", None).unwrap();
        World { db, owner, org, infra }
    }

    fn by(id: i64, name: &str) -> Actor {
        Actor::user(id, name)
    }

    /// Makes an invitation older, as the passing of time does
    fn age(db: &Database, days: i64) {
        db.conn()
            .execute(
                &format!("UPDATE invitations SET created_at = datetime(created_at, '-{days} days'), expires_at = datetime(expires_at, '-{days} days')"),
                [],
            )
            .unwrap();
    }

    #[test]
    fn an_invitation_grants_nothing_until_the_account_it_was_made_for_accepts_it() {
        let World { db, owner, org, infra } = world();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        let carol = db.create_account("carol", None, "h", false).unwrap();
        db.invite(Scope::Organization(org), "Bob", Role::Editor, &by(owner, "owner")).unwrap();
        db.invite(Scope::Project(infra), "bob", Role::Viewer, &by(owner, "owner")).unwrap();
        db.invite(Scope::Project(infra), "nobody", Role::Owner, &by(owner, "owner")).unwrap();
        assert!(db.invite(Scope::Instance, "bob", Role::Viewer, &by(owner, "owner")).is_err());

        // Nothing is granted, and whoever manages sees names as typed
        assert_eq!(db.project_role(bob, infra).unwrap(), None);
        assert!(db.list_members(org).unwrap().iter().all(|m| m.username != "bob"));
        let pending = db.pending_invitations(Scope::Project(infra)).unwrap();
        assert_eq!(pending.iter().map(|p| (p.name.as_str(), p.role.as_str())).collect::<Vec<_>>(), [("bob", "viewer"), ("nobody", "owner")]);
        assert_eq!(db.pending_invitations(Scope::Organization(org)).unwrap()[0].name, "Bob");
        assert!(pending.iter().all(|p| p.invited_by == "owner" && p.expires_at > p.created_at));

        // Only the invited account sees them, and only it can answer
        let received = db.received_invitations(bob).unwrap();
        assert_eq!(received.iter().map(|r| r.target()).collect::<Vec<_>>(), ["organization acme", "project acme / infra"]);
        assert!(db.received_invitations(carol).unwrap().is_empty());
        let (to_org, to_project) = (received[0].id, received[1].id);
        assert!(db.accept_invitation(carol, to_org).unwrap().is_none());
        assert!(!db.decline_invitation(carol, to_project).unwrap());
        assert!(db.accept_invitation(bob, 9999).unwrap().is_none());

        // Accepting gives exactly the role offered, at the level offered
        let accepted = db.accept_invitation(bob, to_project).unwrap().unwrap();
        assert_eq!((accepted.scope, accepted.role), (Scope::Project(infra), Role::Viewer));
        assert_eq!(db.project_role(bob, infra).unwrap(), Some(Role::Viewer));
        assert!(db.get_org("acme", bob).unwrap().is_none());
        assert!(db.accept_invitation(bob, to_project).unwrap().is_none());
        // Declining removes it
        assert!(db.decline_invitation(bob, to_org).unwrap());
        assert!(db.received_invitations(bob).unwrap().is_empty());
        assert!(db.pending_invitations(Scope::Organization(org)).unwrap().is_empty());
        assert!(db.get_org("acme", bob).unwrap().is_none());

        // Cancelling belongs to the level the invitation was made at
        let nobody = db.pending_invitations(Scope::Project(infra)).unwrap()[0].id;
        assert!(!db.cancel_invitation(Scope::Organization(org), nobody, &by(owner, "owner")).unwrap());
        assert!(db.cancel_invitation(Scope::Project(infra), nobody, &by(owner, "owner")).unwrap());
        assert!(db.pending_invitations(Scope::Project(infra)).unwrap().is_empty());

        let mut trail: Vec<(String, String)> =
            db.list_security_events(None, 20).unwrap().into_iter().map(|e| (e.event, e.detail.unwrap_or_default())).collect();
        trail.reverse();
        let events: Vec<&str> = trail.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(events, ["invitation_sent", "invitation_sent", "invitation_sent", "invitation_accepted", "invitation_declined", "invitation_cancelled"]);
        assert_eq!(trail[0].1, "organization acme: “Bob” as editor");
        assert_eq!(trail[3].1, "project acme / infra as viewer, invited by owner");
        assert_eq!(trail[5].1, "project acme / infra: “nobody” as owner");
        // The trail of the invitation names the level, never an account: the same entry for any name
        assert!(db.list_security_events(Some(bob), 20).unwrap().iter().all(|e| e.event != "invitation_sent"));
    }

    #[test]
    fn an_account_created_after_the_invitation_never_claims_it() {
        let World { db, owner, org, .. } = world();
        db.invite(Scope::Organization(org), "late", Role::Owner, &by(owner, "owner")).unwrap();
        let late = db.create_account("late", None, "h", false).unwrap();
        assert!(db.received_invitations(late).unwrap().is_empty());
        let id = db.pending_invitations(Scope::Organization(org)).unwrap()[0].id;
        assert!(db.accept_invitation(late, id).unwrap().is_none());
        assert!(!db.decline_invitation(late, id).unwrap());
        assert!(db.get_org("acme", late).unwrap().is_none());
        // Inviting the name again is a new invitation, made now: it replaces the former one
        db.invite(Scope::Organization(org), "LATE", Role::Viewer, &by(owner, "owner")).unwrap();
        let pending = db.pending_invitations(Scope::Organization(org)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(db.received_invitations(late).unwrap()[0].role, Role::Viewer);
        // An account that cannot sign in (the one of the command line) is nobody
        db.invite(Scope::Organization(org), "default", Role::Viewer, &by(owner, "owner")).unwrap();
        let default: i64 = db.conn().query_row("SELECT id FROM users WHERE username = 'default'", [], |r| r.get(0)).unwrap();
        assert!(db.received_invitations(default).unwrap().is_empty());
    }

    #[test]
    fn invitations_expire_are_capped_and_follow_who_made_them() {
        let World { db, owner, org, infra } = world();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        let second = db.create_account("second", None, "h", false).unwrap();
        db.set_org_member(org, second, Role::Owner).unwrap();
        let invite = |name: &str, from: i64| db.invite(Scope::Organization(org), name, Role::Viewer, &by(from, "x"));

        // Expiry: fourteen days, after which it is neither listed nor acceptable
        invite("bob", owner).unwrap();
        let id = db.received_invitations(bob).unwrap()[0].id;
        age(&db, INVITATION_DAYS - 1);
        assert_eq!(db.received_invitations(bob).unwrap().len(), 1);
        age(&db, 1);
        assert!(db.received_invitations(bob).unwrap().is_empty());
        assert!(db.pending_invitations(Scope::Organization(org)).unwrap().is_empty());
        assert!(db.accept_invitation(bob, id).unwrap().is_none());
        assert!(db.get_org("acme", bob).unwrap().is_none());

        // The cap counts what is pending at one level; the expired one above made room
        for i in 0..MAX_PENDING_INVITATIONS {
            invite(&format!("name-{i}"), second).unwrap();
        }
        let refused = invite("one-too-many", owner).unwrap_err().to_string();
        assert!(refused.contains("Too many pending invitations"), "{refused}");
        // ... the same answer for a name that is an account, and replacing one is not one more
        assert_eq!(invite("bob", owner).unwrap_err().to_string(), refused);
        invite("name-3", owner).unwrap();
        db.invite(Scope::Project(infra), "bob", Role::Editor, &by(second, "second")).unwrap();

        // Whoever invited loses the right, or the account: the invitations are void
        let to_project = db.received_invitations(bob).unwrap()[0].id;
        db.set_org_member(org, second, Role::Editor).unwrap();
        assert!(db.received_invitations(bob).unwrap().is_empty());
        assert!(db.accept_invitation(bob, to_project).unwrap().is_none());
        assert_eq!(db.pending_invitations(Scope::Organization(org)).unwrap().len(), 1);
        db.set_org_member(org, second, Role::Owner).unwrap();
        assert_eq!(db.received_invitations(bob).unwrap().len(), 1);
        db.create_account("root", None, "h", true).unwrap();
        db.set_disabled(second, true).unwrap();
        assert!(db.accept_invitation(bob, to_project).unwrap().is_none());
        assert_eq!(db.project_role(bob, infra).unwrap(), None);
        // ... and the next invitation clears them away
        invite("bob", owner).unwrap();
        let left: i64 = db.conn().query_row("SELECT COUNT(*) FROM invitations WHERE organization_id = ?1", params![org], |r| r.get(0)).unwrap();
        assert_eq!(left, 2);

        // A role given directly meanwhile makes the invitation pointless: it does not lower it
        db.set_org_member(org, bob, Role::Owner).unwrap();
        assert!(db.received_invitations(bob).unwrap().is_empty());
        assert_eq!(db.get_org("acme", bob).unwrap().unwrap().role, "owner");
    }

    #[test]
    fn invitations_go_with_their_organization_or_project() {
        let World { db, owner, org, infra } = world();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        db.invite(Scope::Organization(org), "bob", Role::Viewer, &by(owner, "owner")).unwrap();
        db.invite(Scope::Project(infra), "bob", Role::Viewer, &by(owner, "owner")).unwrap();
        let count = |db: &Database| -> i64 { db.conn().query_row("SELECT COUNT(*) FROM invitations", [], |r| r.get(0)).unwrap() };
        assert_eq!(count(&db), 2);
        db.delete_project_by_id(infra, &by(owner, "owner")).unwrap();
        assert_eq!(count(&db), 1);
        db.delete_org(org).unwrap();
        assert_eq!(count(&db), 0);
        assert!(db.received_invitations(bob).unwrap().is_empty());
    }
}
