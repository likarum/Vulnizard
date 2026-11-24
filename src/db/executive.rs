//! The executive role (schema v31): the figures of the Overview and nothing else.
//!
//! It is held like the other roles, at the three levels, and ranks below
//! viewer. What it gives is a right of its own (`Permission::Summary`), which
//! reading a project (`Permission::View`) does not come with.
//!
//! The access views are split in two so that nothing has to remember it:
//! - `org_access` and `project_access` keep meaning "may read": a viewer or
//!   more. An executive is not in them, so every query that scopes its rows
//!   with them (lists, pages, exports, tools) leaves it out without a change;
//! - `org_summary_access` and `project_summary_access` mean "at least
//!   executive". Only what serves the Overview reads them: the figures, and
//!   the names of the projects they are about.
//!
//! Where an account holds several roles for a project the highest wins, as
//! before: an executive of an organization who is viewer of one of its
//! projects reads that project.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::db::{Database, Org, OrgProject};
use crate::rbac::{Permission, Role};

/// Tables whose `role` column lists the roles it accepts
const ROLE_TABLES: [&str; 6] = ["users", "memberships", "project_memberships", "oidc_providers", "scim_group_roles", "invitations"];
const ROLES_BEFORE: &str = "IN ('owner', 'editor', 'viewer')";
const ROLES_AFTER: &str = "IN ('owner', 'editor', 'viewer', 'executive')";

const EXECUTIVE_VIEWS: &str = r#"
DROP VIEW IF EXISTS project_access;
DROP VIEW IF EXISTS org_access;
DROP VIEW IF EXISTS project_summary_access;
DROP VIEW IF EXISTS org_summary_access;

-- At least executive on the organization. A role nobody knows gives nothing.
CREATE VIEW org_summary_access AS
SELECT a.user_id, a.organization_id, a.rank FROM (
    SELECT user_id, organization_id, MAX(rank) AS rank FROM (
        SELECT user_id, organization_id,
               CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 WHEN 'executive' THEN 0 END AS rank
        FROM memberships
        UNION ALL
        SELECT u.id, o.id,
               CASE u.instance_role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 WHEN 'executive' THEN 0 END
        FROM users u JOIN organizations o WHERE u.instance_role IS NOT NULL
        UNION ALL
        SELECT gm.user_id, o.id,
               CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 WHEN 'executive' THEN 0 END
        FROM scim_group_members gm
        JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        JOIN organizations o ON gr.level = 'instance' OR (gr.level = 'organization' AND gr.target_id = o.id)
        WHERE gr.level IN ('instance', 'organization')
    ) WHERE rank IS NOT NULL GROUP BY user_id, organization_id
) a
WHERE NOT EXISTS (
    SELECT 1 FROM organizations o JOIN users u ON u.id = a.user_id
    WHERE o.id = a.organization_id AND o.require_mfa = 1 AND u.password_hash IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.confirmed = 1)
      AND NOT EXISTS (SELECT 1 FROM mfa_passkeys k WHERE k.user_id = u.id)
);

-- May read the organization: viewer or more
CREATE VIEW org_access AS
SELECT user_id, organization_id, rank FROM org_summary_access WHERE rank >= 1;

-- At least executive on the project
CREATE VIEW project_summary_access AS
SELECT a.user_id, a.project_id, a.rank FROM (
    SELECT user_id, project_id, MAX(rank) AS rank FROM (
        SELECT a.user_id, p.id AS project_id, a.rank
        FROM org_summary_access a JOIN projects p ON p.organization_id = a.organization_id
        UNION ALL
        SELECT user_id, project_id,
               CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 WHEN 'executive' THEN 0 END
        FROM project_memberships
        UNION ALL
        SELECT gm.user_id, gr.target_id,
               CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 WHEN 'viewer' THEN 1 WHEN 'executive' THEN 0 END
        FROM scim_group_members gm JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        WHERE gr.level = 'project'
    ) WHERE rank IS NOT NULL GROUP BY user_id, project_id
) a
WHERE NOT EXISTS (
    SELECT 1 FROM projects p
    JOIN organizations o ON o.id = p.organization_id
    JOIN users u ON u.id = a.user_id
    WHERE p.id = a.project_id AND o.require_mfa = 1 AND u.password_hash IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.confirmed = 1)
      AND NOT EXISTS (SELECT 1 FROM mfa_passkeys k WHERE k.user_id = u.id)
);

-- May read the project: viewer or more
CREATE VIEW project_access AS
SELECT user_id, project_id, rank FROM project_summary_access WHERE rank >= 1;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '31');
"#;

/// Whose rights reach a row: those who may read the project, or everyone
/// who may at least read its figures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Viewer or more: lists, pages, exports, tools
    View,
    /// Executive or more: the figures of the Overview, and nothing else
    Summary,
}

impl Reach {
    pub(super) fn org_view(self) -> &'static str {
        match self {
            Reach::View => "org_access",
            Reach::Summary => "org_summary_access",
        }
    }

    pub(super) fn project_view(self) -> &'static str {
        match self {
            Reach::View => "project_access",
            Reach::Summary => "project_summary_access",
        }
    }
}

/// A project the account holds a role on, whatever the role
#[derive(Debug, Clone)]
pub struct HeldProject {
    pub id: i64,
    pub org: String,
    pub name: String,
    pub role: String,
}

impl HeldProject {
    /// May read the project, beyond its figures
    pub fn can_view(&self) -> bool {
        Role::parse(&self.role).is_some_and(|r| r.allows(Permission::View))
    }
}

/// Rebuilds a table with its definition changed by `change`, keeping its
/// rows, their identifiers, its indexes, its triggers and the next identifier
/// it will give. To be called with foreign keys off, inside a transaction.
pub(super) fn rebuild_table(conn: &rusqlite::Connection, table: &str, change: impl Fn(&str) -> String) -> Result<bool> {
    let sql: String = conn.query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1", params![table], |r| r.get(0))?;
    let changed = change(&sql);
    if changed == sql {
        return Ok(false);
    }
    let columns = changed.find('(').ok_or_else(|| anyhow!("unexpected definition of {table}"))?;
    let attached: Vec<String> = conn
        .prepare("SELECT sql FROM sqlite_master WHERE tbl_name = ?1 AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY rowid")?
        .query_map(params![table], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    let next = format!("{table}_rebuilt");
    conn.execute_batch(&format!(
        "CREATE TABLE {next} {definition};
         INSERT INTO {next} SELECT * FROM {table};",
        definition = &changed[columns..]
    ))?;
    // An identifier that was given once is never given again
    let sequences: bool =
        conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence')", [], |r| r.get(0))?;
    if sequences {
        conn.execute("DELETE FROM sqlite_sequence WHERE name = ?1", params![next])?;
        conn.execute("INSERT INTO sqlite_sequence (name, seq) SELECT ?1, seq FROM sqlite_sequence WHERE name = ?2", params![next, table])?;
    }
    conn.execute_batch(&format!("DROP TABLE {table}; ALTER TABLE {next} RENAME TO {table};"))?;
    for statement in attached {
        conn.execute_batch(&statement)?;
    }
    Ok(true)
}

impl Database {
    /// v31: the tables holding a role accept `executive`, and the access views
    /// tell "may read" from "may read the figures".
    pub(super) fn migrate_executive(&self) -> Result<()> {
        // Rebuilding a table must not cascade to the rows that reference it,
        // and renaming one must not look into the views dropped meanwhile
        self.conn().execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
        let result = (|| -> Result<()> {
            let tx = self.write_tx()?;
            tx.execute_batch(
                "DROP VIEW IF EXISTS project_access; DROP VIEW IF EXISTS org_access;
                 DROP VIEW IF EXISTS project_summary_access; DROP VIEW IF EXISTS org_summary_access;",
            )?;
            for table in ROLE_TABLES {
                let rebuilt = rebuild_table(&tx, table, |sql| sql.replace(ROLES_BEFORE, ROLES_AFTER))?;
                let accepts: bool = tx.query_row(
                    "SELECT instr(sql, ?2) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table, ROLES_AFTER],
                    |r| r.get(0),
                )?;
                if !accepts {
                    anyhow::bail!("schema v31: the roles of {table} are not where they were expected (rebuilt: {rebuilt})");
                }
            }
            tx.execute_batch(EXECUTIVE_VIEWS)?;
            let broken: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
            if broken > 0 {
                anyhow::bail!("schema v31: {broken} broken references after rebuilding the role tables");
            }
            tx.commit()?;
            Ok(())
        })();
        self.conn().execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;")?;
        result
    }

    /// Every project the account holds a role on, executive included: what
    /// the Overview can be asked for
    pub fn held_projects(&self, user_id: i64) -> Result<Vec<HeldProject>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT p.id, o.name, p.name, {role} FROM projects p
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_summary_access pa ON pa.project_id = p.id
             WHERE pa.user_id = ?1 ORDER BY o.name, p.name",
            role = super::roles::role_of("pa.rank")
        ))?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(HeldProject {
                    id: r.get(0)?,
                    org: r.get(1)?,
                    name: r.get(2)?,
                    role: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// A project the account may read the figures of, looked up by names,
    /// with its effective role there. Nothing but the names comes with it for
    /// who may not read the project.
    pub fn get_project_for_summary(&self, org: &str, project: &str, user_id: i64) -> Result<Option<(Org, OrgProject)>> {
        self.project_reached(org, project, user_id, Reach::Summary)
    }

    pub(super) fn project_reached(&self, org: &str, project: &str, user_id: i64, reach: Reach) -> Result<Option<(Org, OrgProject)>> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT o.id, o.name, {role}, p.id, p.name,
                            CASE WHEN pa.rank >= 1 THEN p.description END,
                            CASE WHEN pa.rank >= 1 THEN (SELECT COUNT(*) FROM subscriptions s WHERE s.project_id = p.id) ELSE 0 END
                     FROM projects p
                     JOIN organizations o ON o.id = p.organization_id
                     JOIN {view} pa ON pa.project_id = p.id AND pa.user_id = ?3
                     WHERE o.name = ?1 AND p.name = ?2",
                    role = super::roles::role_of("pa.rank"),
                    view = reach.project_view(),
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

    /// Effective role of the user on the organization, executive included
    pub fn org_role(&self, user_id: i64, org_id: i64) -> Result<Option<Role>> {
        let role: Option<String> = self
            .conn()
            .query_row(
                &format!(
                    "SELECT {role} FROM org_summary_access a WHERE a.organization_id = ?1 AND a.user_id = ?2",
                    role = super::roles::role_of("a.rank")
                ),
                params![org_id, user_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(role.as_deref().and_then(Role::parse))
    }

    /// Whether the account is confined to the Overview: it holds at least one
    /// role, none above executive, and does not administer the instance.
    ///
    /// The roles are counted as they were given (instance, organizations,
    /// projects, groups), not as the access views apply them: one role above
    /// executive anywhere opens the reference database and the rest of what
    /// an account without any role has, even where a second factor is still
    /// missing to use that role.
    pub fn summary_only(&self, user_id: i64) -> Result<bool> {
        let confined: Option<bool> = self
            .conn()
            .query_row(
                "SELECT u.is_admin = 0 AND COUNT(r.role) > 0 AND COALESCE(SUM(r.role != 'executive'), 0) = 0
                 FROM users u LEFT JOIN (
                     SELECT id AS user_id, instance_role AS role FROM users WHERE instance_role IS NOT NULL
                     UNION ALL SELECT user_id, role FROM memberships
                     UNION ALL SELECT user_id, role FROM project_memberships
                     UNION ALL SELECT gm.user_id, gr.role FROM scim_group_members gm
                               JOIN scim_group_roles gr ON gr.group_id = gm.group_id
                 ) r ON r.user_id = u.id
                 WHERE u.id = ?1 GROUP BY u.id",
                params![user_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(confined.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Actor, Provider, Scope};

    /// The access views as schema v20 made them: any role reads
    const VIEWS_V30: &str = r#"
DROP VIEW project_access; DROP VIEW org_access; DROP VIEW project_summary_access; DROP VIEW org_summary_access;
CREATE VIEW org_access AS
SELECT a.user_id, a.organization_id, a.rank FROM (
    SELECT user_id, organization_id, MAX(rank) AS rank FROM (
        SELECT user_id, organization_id,
               CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END AS rank
        FROM memberships
        UNION ALL
        SELECT u.id, o.id, CASE u.instance_role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM users u JOIN organizations o WHERE u.instance_role IS NOT NULL
        UNION ALL
        SELECT gm.user_id, o.id, CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM scim_group_members gm
        JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        JOIN organizations o ON gr.level = 'instance' OR (gr.level = 'organization' AND gr.target_id = o.id)
        WHERE gr.level IN ('instance', 'organization')
    ) GROUP BY user_id, organization_id
) a;
CREATE VIEW project_access AS
SELECT a.user_id, a.project_id, a.rank FROM (
    SELECT user_id, project_id, MAX(rank) AS rank FROM (
        SELECT a.user_id, p.id AS project_id, a.rank
        FROM org_access a JOIN projects p ON p.organization_id = a.organization_id
        UNION ALL
        SELECT user_id, project_id, CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM project_memberships
        UNION ALL
        SELECT gm.user_id, gr.target_id, CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM scim_group_members gm JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        WHERE gr.level = 'project'
    ) GROUP BY user_id, project_id
) a;
INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '30');
"#;

    /// A version 30 database: the role tables refuse `executive`
    fn back_to_v30(db: &Database) {
        db.conn().execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;").unwrap();
        db.conn()
            .execute_batch(
                "DROP VIEW project_access; DROP VIEW org_access; DROP VIEW project_summary_access; DROP VIEW org_summary_access;",
            )
            .unwrap();
        for table in ROLE_TABLES {
            assert!(rebuild_table(db.conn(), table, |sql| sql.replace(ROLES_AFTER, ROLES_BEFORE)).unwrap(), "{table}");
        }
        db.conn()
            .execute_batch(
                "CREATE VIEW org_access AS SELECT 1; CREATE VIEW project_access AS SELECT 1;
                 CREATE VIEW org_summary_access AS SELECT 1; CREATE VIEW project_summary_access AS SELECT 1;",
            )
            .unwrap();
        db.conn().execute_batch(VIEWS_V30).unwrap();
        db.conn().execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;").unwrap();
    }

    /// Everything of the role tables that a rebuild could lose
    fn snapshot(db: &Database) -> Vec<String> {
        let rows = |sql: &str| -> Vec<String> {
            db.conn().prepare(sql).unwrap().query_map([], |r| r.get::<_, String>(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        let mut out = Vec::new();
        for table in ROLE_TABLES {
            let columns = rows(&format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid"));
            let quoted: Vec<String> = columns.iter().map(|c| format!("quote({c})")).collect();
            out.extend(
                rows(&format!("SELECT {} FROM {table} ORDER BY rowid", quoted.join(" || '|' || ")))
                    .into_iter()
                    .map(|row| format!("{table}: {row}")),
            );
            out.extend(rows(&format!(
                "SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE tbl_name = '{table}' AND type IN ('index', 'trigger') ORDER BY name"
            )));
            out.extend(rows(&format!("SELECT name || ' next ' || seq FROM sqlite_sequence WHERE name = '{table}'")));
        }
        // What references the rebuilt tables is still there
        for child in ["sessions", "api_tokens", "scim_group_members"] {
            out.extend(rows(&format!("SELECT '{child} ' || COUNT(*) FROM {child}")));
        }
        out
    }

    fn provider(slug: &str, default_role: Option<&str>) -> Provider {
        Provider {
            slug: slug.into(),
            name: "Example".into(),
            issuer: "https://id.example.org".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            scopes: "openid email".into(),
            auto_create: true,
            link_existing_accounts: false,
            admin_group: None,
            allowed_domains: Vec::new(),
            enabled: true,
            from_config: false,
            scope: Scope::Instance,
            scope_label: String::new(),
            default_role: default_role.map(String::from),
        }
    }

    #[test]
    fn version_30_roles_are_kept_and_executive_is_accepted_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v30.db");
        let (owner, lead, dev, auditor, grouped, org, infra, web, group, before, next_user);
        {
            let db = Database::open(&path).unwrap();
            owner = db.create_account("owner", None, "h", true).unwrap();
            lead = db.create_account("lead", None, "h", false).unwrap();
            dev = db.create_account("dev", None, "h", false).unwrap();
            auditor = db.create_account("auditor", None, "h", false).unwrap();
            grouped = db.create_account("grouped", None, "h", false).unwrap();
            // The last account given was deleted: its identifier must not be given again
            let gone = db.create_account("gone", None, "h", false).unwrap();
            db.conn().execute("DELETE FROM users WHERE id = ?1", [gone]).unwrap();
            next_user = gone + 1;
            org = db.create_org("acme", owner).unwrap();
            infra = db.create_org_project(org, owner, "infra", None).unwrap();
            web = db.create_org_project(org, owner, "web", None).unwrap();
            // Roles at the three levels, through a group, offered by an invitation and given by a provider
            db.set_instance_role(auditor, Some(Role::Viewer)).unwrap();
            db.set_org_member(org, lead, Role::Editor).unwrap();
            db.set_project_member(infra, dev, Role::Viewer).unwrap();
            group = db.scim_create_group(Scope::Instance, "ops", None).unwrap();
            db.conn().execute("UPDATE users SET provisioned = 1 WHERE id = ?1", [grouped]).unwrap();
            db.scim_add_members(group, &[grouped]).unwrap();
            db.set_group_role(group, Scope::Project(web), Role::Editor).unwrap();
            db.invite(Scope::Project(web), "dev", Role::Editor, &Actor::user(owner, "owner")).unwrap();
            db.save_sso_provider(&provider("corp", Some("viewer"))).unwrap();
            // Rows that reference the accounts: a rebuild must not take them away
            db.create_session(dev, "session", 3600).unwrap();
            db.create_api_token(dev, "ci", "token").unwrap();

            back_to_v30(&db);
            assert_eq!(db.schema_version().unwrap(), 30);
            // As before this version: the role does not exist
            for refused in [
                format!("UPDATE users SET instance_role = 'executive' WHERE id = {dev}"),
                format!("INSERT INTO memberships (organization_id, user_id, role) VALUES ({org}, {dev}, 'executive')"),
                format!("INSERT INTO project_memberships (project_id, user_id, role) VALUES ({web}, {dev}, 'executive')"),
                "UPDATE oidc_providers SET default_role = 'executive'".to_string(),
                "UPDATE scim_group_roles SET role = 'executive'".to_string(),
                "UPDATE invitations SET role = 'executive'".to_string(),
            ] {
                assert!(db.conn().execute(&refused, []).is_err(), "{refused}");
            }
            before = snapshot(&db);
            assert!(before.iter().any(|row| row.starts_with("memberships: ")) && before.iter().any(|row| row.starts_with("index idx_memberships_user")));
            assert!(before.iter().any(|row| row.starts_with("invitations next ")), "{before:?}");
        }

        // Opening it upgrades it
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 31);
        // Rows, identifiers, indexes, triggers and the next identifiers are what they were
        assert_eq!(snapshot(&db), before);
        let count = |sql: &str| -> i64 { db.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
        assert_eq!(count("PRAGMA foreign_keys"), 1);
        assert_eq!(count("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_rebuilt'"), 0);
        assert!(db.get_session_account("session").unwrap().is_some());
        assert!(db.get_token_account("token").unwrap().is_some());
        // The roles held before still give what they gave
        assert_eq!(db.project_role(auditor, web).unwrap(), Some(Role::Viewer));
        assert_eq!(db.project_role(lead, infra).unwrap(), Some(Role::Editor));
        assert_eq!(db.project_role(dev, infra).unwrap(), Some(Role::Viewer));
        assert_eq!(db.project_role(dev, web).unwrap(), None);
        assert_eq!(db.project_role(grouped, web).unwrap(), Some(Role::Editor));
        assert_eq!(db.project_role(owner, web).unwrap(), Some(Role::Owner));
        assert!(db.get_org("acme", lead).unwrap().is_some() && db.get_org("acme", dev).unwrap().is_none());
        assert_eq!(db.list_user_projects(dev).unwrap().len(), 1);
        assert_eq!(db.received_invitations(dev).unwrap().len(), 1);
        assert_eq!(db.get_sso_provider("corp").unwrap().unwrap().default_role.as_deref(), Some("viewer"));
        // A new account does not take the identifier of a deleted one
        assert_eq!(db.create_account("new", None, "h", false).unwrap(), next_user);

        // The new role is accepted wherever a role is held, and an unknown one still is not
        db.set_instance_role(auditor, Some(Role::Executive)).unwrap();
        db.set_org_member(org, lead, Role::Executive).unwrap();
        db.set_project_member(infra, dev, Role::Executive).unwrap();
        db.set_group_role(group, Scope::Project(web), Role::Executive).unwrap();
        db.save_sso_provider(&provider("corp", Some("executive"))).unwrap();
        db.conn().execute("UPDATE invitations SET role = 'executive'", []).unwrap();
        assert_eq!(db.received_invitations(dev).unwrap()[0].role, Role::Executive);
        assert!(db.conn().execute("UPDATE memberships SET role = 'manager'", []).is_err());
        assert!(db.conn().execute("UPDATE users SET instance_role = 'manager'", []).is_err());

        // And opening it again changes nothing
        let after = snapshot(&db);
        drop(db);
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 31);
        assert_eq!(snapshot(&db), after);
    }

    #[test]
    fn an_executive_holds_a_project_without_reading_it() {
        let db = Database::open_in_memory().unwrap();
        let owner = db.create_account("owner", None, "h", false).unwrap();
        let org = db.create_org("acme", owner).unwrap();
        let infra = db.create_org_project(org, owner, "infra", Some("the servers")).unwrap();
        let web = db.create_org_project(org, owner, "web", None).unwrap();
        let other = db.create_org("other", owner).unwrap();
        let misc = db.create_org_project(other, owner, "misc", None).unwrap();
        let held = |user: i64| -> Vec<(String, String)> {
            db.held_projects(user).unwrap().into_iter().map(|p| (format!("{}/{}", p.org, p.name), p.role)).collect()
        };
        let pair = |project: &str, role: &str| (project.to_string(), role.to_string());

        // On one project: held, never read
        let exec = db.create_account("exec", None, "h", false).unwrap();
        assert!(!db.summary_only(exec).unwrap(), "an account without any role is not confined");
        db.set_project_member(infra, exec, Role::Executive).unwrap();
        assert!(db.summary_only(exec).unwrap());
        assert_eq!(db.project_role(exec, infra).unwrap(), Some(Role::Executive));
        assert_eq!(db.project_role(exec, web).unwrap(), None);
        assert_eq!(held(exec), [pair("acme/infra", "executive")]);
        assert!(db.list_user_projects(exec).unwrap().is_empty());
        assert!(db.project_summaries(exec).unwrap().is_empty());
        assert!(db.get_project_for_user("acme", "infra", exec).unwrap().is_none());
        assert!(db.list_orgs(exec).unwrap().is_empty() && db.get_org("acme", exec).unwrap().is_none());
        assert!(db.scoped_applications(exec, None).unwrap().is_empty());
        // What comes with the project for its figures: its names and the role, nothing else
        let (access, project) = db.get_project_for_summary("acme", "infra", exec).unwrap().unwrap();
        assert_eq!((access.role.as_str(), project.name.as_str(), project.description, project.subscriptions), ("executive", "infra", None, 0));
        assert!(access.can(Permission::Summary) && !access.can(Permission::View));
        assert!(db.get_project_for_summary("acme", "web", exec).unwrap().is_none());

        // On an organization: each of its projects, not the organization itself nor the others
        let board = db.create_account("board", None, "h", false).unwrap();
        db.set_org_member(org, board, Role::Executive).unwrap();
        assert_eq!(held(board), [pair("acme/infra", "executive"), pair("acme/web", "executive")]);
        assert_eq!(db.org_role(board, org).unwrap(), Some(Role::Executive));
        assert!(db.get_org("acme", board).unwrap().is_none() && db.list_orgs(board).unwrap().is_empty());
        assert!(db.summary_only(board).unwrap());
        // The highest role wins on a project, and the other projects are not touched
        db.set_project_member(web, board, Role::Viewer).unwrap();
        assert_eq!(held(board), [pair("acme/infra", "executive"), pair("acme/web", "viewer")]);
        assert_eq!(db.list_user_projects(board).unwrap().len(), 1);
        assert!(!db.summary_only(board).unwrap(), "one role above executive lifts the confinement");
        // And the other way round: executive on a project adds nothing to a viewer of the organization
        let lead = db.create_account("lead", None, "h", false).unwrap();
        db.set_org_member(org, lead, Role::Viewer).unwrap();
        db.set_project_member(infra, lead, Role::Executive).unwrap();
        assert_eq!(held(lead), [pair("acme/infra", "viewer"), pair("acme/web", "viewer")]);

        // On the instance: every project
        let chair = db.create_account("chair", None, "h", false).unwrap();
        db.set_instance_role(chair, Some(Role::Executive)).unwrap();
        assert_eq!(held(chair).len(), 4, "acme/infra, acme/web, other/misc and the project of the CLI");
        assert!(db.list_user_projects(chair).unwrap().is_empty() && db.summary_only(chair).unwrap());
        assert_eq!(db.project_role(chair, misc).unwrap(), Some(Role::Executive));
        // An administrator is never confined
        db.set_admin(chair, true).unwrap();
        assert!(!db.summary_only(chair).unwrap());

        // Through a group
        let grouped = db.create_account("grouped", None, "h", false).unwrap();
        let group = db.scim_create_group(Scope::Instance, "board", None).unwrap();
        db.conn().execute("UPDATE users SET provisioned = 1 WHERE id = ?1", [grouped]).unwrap();
        db.scim_add_members(group, &[grouped]).unwrap();
        db.set_group_role(group, Scope::Organization(other), Role::Executive).unwrap();
        assert_eq!(held(grouped), [pair("other/misc", "executive")]);
        assert!(db.summary_only(grouped).unwrap() && db.list_user_projects(grouped).unwrap().is_empty());

        // An executive manages nobody: what it would invite to is void (the forms refuse it before)
        db.invite(Scope::Project(web), "exec2", Role::Viewer, &Actor::user(exec, "exec")).unwrap();
        let exec2 = db.create_account("exec2", None, "h", false).unwrap();
        db.invite(Scope::Project(infra), "exec2", Role::Owner, &Actor::user(exec, "exec")).unwrap();
        assert!(db.received_invitations(exec2).unwrap().is_empty());
        // Invited as executive by who manages the members, it holds the role once it accepts
        let guest = db.create_account("guest", None, "h", false).unwrap();
        db.invite(Scope::Organization(org), "guest", Role::Executive, &Actor::user(owner, "owner")).unwrap();
        assert!(held(guest).is_empty());
        let invitation = db.received_invitations(guest).unwrap().remove(0);
        assert_eq!(invitation.role, Role::Executive);
        assert!(db.accept_invitation(guest, invitation.id).unwrap().is_some());
        assert_eq!(held(guest).len(), 2);
        assert!(db.summary_only(guest).unwrap());
    }
}
