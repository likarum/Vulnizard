//! Three levels of rights (schema v12):
//! - **instance**: a role on every organization and project (`users.instance_role`),
//!   besides the administrator flag which governs the instance itself;
//! - **organization**: a role on every project of the organization (`memberships`);
//! - **project**: a role on one project only (`project_memberships`).
//!
//! The effective role is the highest of the three. Two SQL views compute it,
//! so every query scopes its rows with one join.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::db::{Database, Org, OrgProject};
use crate::rbac::Role;

const ROLES_SCHEMA: &str = r#"
ALTER TABLE users ADD COLUMN instance_role TEXT CHECK(instance_role IN ('owner', 'editor', 'viewer'));

CREATE TABLE IF NOT EXISTS project_memberships (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('owner', 'editor', 'viewer')),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_project_memberships_user ON project_memberships(user_id);

-- Effective role of a user on an organization: its membership or its instance role
CREATE VIEW IF NOT EXISTS org_access AS
SELECT user_id, organization_id, MAX(rank) AS rank FROM (
    SELECT user_id, organization_id,
           CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END AS rank
    FROM memberships
    UNION ALL
    SELECT u.id, o.id, CASE u.instance_role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
    FROM users u JOIN organizations o WHERE u.instance_role IS NOT NULL
) GROUP BY user_id, organization_id;

-- Effective role of a user on a project: organization-level access or a project membership
CREATE VIEW IF NOT EXISTS project_access AS
SELECT user_id, project_id, MAX(rank) AS rank FROM (
    SELECT a.user_id, p.id AS project_id, a.rank
    FROM org_access a JOIN projects p ON p.organization_id = a.organization_id
    UNION ALL
    SELECT user_id, project_id, CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
    FROM project_memberships
) GROUP BY user_id, project_id;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '12');
"#;

/// SQL expression turning a rank of the access views into a role name
pub(super) const ROLE_OF_RANK: &str = "CASE {rank} WHEN 3 THEN 'owner' WHEN 2 THEN 'editor' ELSE 'viewer' END";

pub(super) fn role_of(rank_column: &str) -> String {
    ROLE_OF_RANK.replace("{rank}", rank_column)
}

/// One right of a user, at one of the three levels
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Assignment {
    /// instance | organization | project
    pub level: String,
    /// Organization name (organization and project levels)
    pub org: Option<String>,
    /// Project name (project level)
    pub project: Option<String>,
    pub role: String,
}

/// A member of a project with the level the right comes from
#[derive(Debug, Clone, Serialize)]
pub struct ProjectMember {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    /// project | organization | instance
    pub level: String,
}

/// Gives (or changes) a role on one project: the one way a member form or an
/// accepted invitation gives one.
pub(super) fn grant_project_role(conn: &rusqlite::Connection, project_id: i64, user_id: i64, role: Role) -> Result<()> {
    conn.execute(
        "INSERT INTO project_memberships (project_id, user_id, role) VALUES (?1, ?2, ?3)
         ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role",
        params![project_id, user_id, role.as_str()],
    )?;
    Ok(())
}

impl Database {
    pub(super) fn migrate_roles(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(ROLES_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// A project the user can access, looked up by names, with the user's
    /// effective role in it (returned in the `Org` for permission checks).
    pub fn get_project_for_user(&self, org: &str, project: &str, user_id: i64) -> Result<Option<(Org, OrgProject)>> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT o.id, o.name, {role}, p.id, p.name, p.description,
                            (SELECT COUNT(*) FROM subscriptions s WHERE s.project_id = p.id)
                     FROM projects p
                     JOIN organizations o ON o.id = p.organization_id
                     JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?3
                     WHERE o.name = ?1 AND p.name = ?2",
                    role = role_of("pa.rank")
                ),
                params![org, project, user_id],
                |r| {
                    Ok((
                        Org {
                            id: r.get(0)?,
                            name: r.get(1)?,
                            role: r.get(2)?,
                        },
                        OrgProject {
                            id: r.get(3)?,
                            name: r.get(4)?,
                            description: r.get(5)?,
                            subscriptions: r.get(6)?,
                        },
                    ))
                },
            )
            .optional()?)
    }

    /// Instance-wide role (None removes it). The administrator flag is separate.
    pub fn set_instance_role(&self, user_id: i64, role: Option<Role>) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE users SET instance_role = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![role.map(Role::as_str), user_id],
        )?;
        if changed == 0 {
            return Err(anyhow!("Unknown account"));
        }
        Ok(())
    }

    /// Gives (or changes) a role on one project
    pub fn set_project_member(&self, project_id: i64, user_id: i64, role: Role) -> Result<()> {
        grant_project_role(self.conn(), project_id, user_id, role)
    }

    pub fn remove_project_member(&self, project_id: i64, user_id: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM project_memberships WHERE project_id = ?1 AND user_id = ?2",
            params![project_id, user_id],
        )? > 0)
    }

    /// Gives (or changes) a role on an organization, without the last-owner
    /// guard of `add_member` (administrators manage the instance).
    pub fn set_org_member(&self, org_id: i64, user_id: i64, role: Role) -> Result<()> {
        self.conn().execute(
            "INSERT INTO memberships (organization_id, user_id, role) VALUES (?1, ?2, ?3)
             ON CONFLICT(organization_id, user_id) DO UPDATE SET role = excluded.role",
            params![org_id, user_id, role.as_str()],
        )?;
        Ok(())
    }

    pub fn remove_org_member(&self, org_id: i64, user_id: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM memberships WHERE organization_id = ?1 AND user_id = ?2",
            params![org_id, user_id],
        )? > 0)
    }

    /// Everyone who can access the project, with where the right comes from
    pub fn list_project_members(&self, project_id: i64) -> Result<Vec<ProjectMember>> {
        let mut stmt = self.conn().prepare(
            "SELECT u.id, u.username, pm.role, 'project' FROM project_memberships pm
               JOIN users u ON u.id = pm.user_id WHERE pm.project_id = ?1
             UNION ALL
             SELECT u.id, u.username, m.role, 'organization' FROM memberships m
               JOIN users u ON u.id = m.user_id
               JOIN projects p ON p.organization_id = m.organization_id WHERE p.id = ?1
             UNION ALL
             SELECT u.id, u.username, u.instance_role, 'instance' FROM users u WHERE u.instance_role IS NOT NULL
             ORDER BY 2, 4",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| {
                Ok(ProjectMember {
                    user_id: r.get(0)?,
                    username: r.get(1)?,
                    role: r.get(2)?,
                    level: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every right of a user, from the widest to the narrowest
    pub fn user_assignments(&self, user_id: i64) -> Result<Vec<Assignment>> {
        let mut out = Vec::new();
        let instance: Option<String> = self
            .conn()
            .query_row("SELECT instance_role FROM users WHERE id = ?1", params![user_id], |r| r.get(0))
            .optional()?
            .flatten();
        if let Some(role) = instance {
            out.push(Assignment {
                level: "instance".into(),
                org: None,
                project: None,
                role,
            });
        }
        let mut stmt = self.conn().prepare(
            "SELECT 'organization', o.name, NULL, m.role FROM memberships m
               JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ?1
             UNION ALL
             SELECT 'project', o.name, p.name, pm.role FROM project_memberships pm
               JOIN projects p ON p.id = pm.project_id
               JOIN organizations o ON o.id = p.organization_id WHERE pm.user_id = ?1
             ORDER BY 1, 2, 3",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(Assignment {
                    level: r.get(0)?,
                    org: r.get(1)?,
                    project: r.get(2)?,
                    role: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        out.extend(rows);
        Ok(out)
    }

    /// Every organization (administration UI)
    pub fn list_all_orgs(&self) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn().prepare("SELECT id, name FROM organizations ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Permission;

    #[test]
    fn effective_role_is_the_highest_of_the_three_levels() {
        let db = Database::open_in_memory().unwrap();
        let owner = db.create_account("owner", None, "h", false).unwrap();
        let org = db.create_org("acme", owner).unwrap();
        let infra = db.create_org_project(org, owner, "infra", None).unwrap();
        let web = db.create_org_project(org, owner, "web", None).unwrap();
        let other_org = db.create_org("other", owner).unwrap();
        let misc = db.create_org_project(other_org, owner, "misc", None).unwrap();

        // Project level: one project only, nothing else is visible
        let dev = db.create_account("dev", None, "h", false).unwrap();
        db.set_project_member(infra, dev, Role::Editor).unwrap();
        assert_eq!(db.project_role(dev, infra).unwrap(), Some(Role::Editor));
        assert_eq!(db.project_role(dev, web).unwrap(), None);
        let names: Vec<String> = db.list_user_projects(dev).unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["infra"]);
        assert!(db.list_orgs(dev).unwrap().is_empty());
        assert!(db.get_org("acme", dev).unwrap().is_none());
        let (as_org, _) = db.get_project_for_user("acme", "infra", dev).unwrap().unwrap();
        assert!(as_org.can(Permission::ManageProjects) && !as_org.can(Permission::ManageMembers));
        assert!(db.get_project_for_user("acme", "web", dev).unwrap().is_none());
        assert_eq!(db.project_summaries(dev).unwrap().len(), 1);

        // Organization level: every project of the organization, not the others
        let lead = db.create_account("lead", None, "h", false).unwrap();
        db.set_org_member(org, lead, Role::Viewer).unwrap();
        assert_eq!(db.project_role(lead, web).unwrap(), Some(Role::Viewer));
        assert_eq!(db.project_role(lead, misc).unwrap(), None);
        // A higher project role wins over the organization role
        db.set_project_member(web, lead, Role::Owner).unwrap();
        assert_eq!(db.project_role(lead, web).unwrap(), Some(Role::Owner));
        assert_eq!(db.project_role(lead, infra).unwrap(), Some(Role::Viewer));

        // Instance level: every organization and project
        let auditor = db.create_account("auditor", None, "h", false).unwrap();
        db.set_instance_role(auditor, Some(Role::Viewer)).unwrap();
        assert_eq!(db.project_role(auditor, misc).unwrap(), Some(Role::Viewer));
        assert_eq!(db.list_orgs(auditor).unwrap().len(), 3); // acme, other and the CLI default
        db.set_instance_role(auditor, None).unwrap();
        assert_eq!(db.project_role(auditor, misc).unwrap(), None);

        assert_eq!(
            db.user_assignments(lead).unwrap(),
            vec![
                Assignment { level: "organization".into(), org: Some("acme".into()), project: None, role: "viewer".into() },
                Assignment { level: "project".into(), org: Some("acme".into()), project: Some("web".into()), role: "owner".into() },
            ]
        );
        let members = db.list_project_members(web).unwrap();
        assert!(members.iter().any(|m| m.username == "lead" && m.level == "project" && m.role == "owner"));
        assert!(members.iter().any(|m| m.username == "lead" && m.level == "organization"));
        assert!(db.remove_project_member(web, lead).unwrap());
        assert_eq!(db.project_role(lead, web).unwrap(), Some(Role::Viewer));
    }
}
