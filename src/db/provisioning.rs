//! Scoped identity (schema v14).
//!
//! - **Origin of an account.** An account created through an SSO provider or
//!   a SCIM token of a project (or an organization) belongs to that scope and
//!   can never receive a right outside it; only instance accounts can hold
//!   rights anywhere and be administrators.
//! - **Scoped SSO providers.** A provider belongs to the instance, an
//!   organization or a project, and gives a default role there.
//! - **SCIM 2.0 provisioning.** Tokens, provisioned users, groups, and the
//!   rights a group gives (computed by the access views, never copied).

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::db::Database;
use crate::rbac::Role;

const PROVISIONING_SCHEMA: &str = r#"
ALTER TABLE users ADD COLUMN origin_scope TEXT NOT NULL DEFAULT 'instance'
    CHECK(origin_scope IN ('instance', 'organization', 'project'));
ALTER TABLE users ADD COLUMN origin_scope_id INTEGER;
-- Created by SCIM: may sign in through SSO once the provider vouches for the same name
ALTER TABLE users ADD COLUMN provisioned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN scim_external_id TEXT;
-- userName as the identity provider knows it (often an email address); the
-- local username is derived from it once and then stays stable
ALTER TABLE users ADD COLUMN scim_username TEXT;

ALTER TABLE oidc_providers ADD COLUMN scope TEXT NOT NULL DEFAULT 'instance'
    CHECK(scope IN ('instance', 'organization', 'project'));
ALTER TABLE oidc_providers ADD COLUMN scope_id INTEGER;
ALTER TABLE oidc_providers ADD COLUMN default_role TEXT CHECK(default_role IN ('owner', 'editor', 'viewer'));

CREATE TABLE IF NOT EXISTS scim_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('instance', 'organization', 'project')),
    scope_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name TEXT NOT NULL,
    external_id TEXT,
    scope TEXT NOT NULL CHECK(scope IN ('instance', 'organization', 'project')),
    scope_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id INTEGER NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
-- Right given to every member of a group, at one of the three levels
CREATE TABLE IF NOT EXISTS scim_group_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    level TEXT NOT NULL CHECK(level IN ('instance', 'organization', 'project')),
    target_id INTEGER,
    role TEXT NOT NULL CHECK(role IN ('owner', 'editor', 'viewer')),
    UNIQUE (group_id, level, target_id)
);

-- The access views also count the rights given through groups
DROP VIEW project_access;
DROP VIEW org_access;
CREATE VIEW org_access AS
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
) GROUP BY user_id, organization_id;
CREATE VIEW project_access AS
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
) GROUP BY user_id, project_id;

-- What belongs to a project or an organization disappears with it
CREATE TRIGGER IF NOT EXISTS identity_project_deleted AFTER DELETE ON projects BEGIN
    DELETE FROM oidc_providers WHERE scope = 'project' AND scope_id = OLD.id;
    DELETE FROM scim_tokens WHERE scope = 'project' AND scope_id = OLD.id;
    DELETE FROM scim_groups WHERE scope = 'project' AND scope_id = OLD.id;
    DELETE FROM scim_group_roles WHERE level = 'project' AND target_id = OLD.id;
    UPDATE users SET disabled = 1 WHERE origin_scope = 'project' AND origin_scope_id = OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS identity_organization_deleted AFTER DELETE ON organizations BEGIN
    DELETE FROM oidc_providers WHERE scope = 'organization' AND scope_id = OLD.id;
    DELETE FROM scim_tokens WHERE scope = 'organization' AND scope_id = OLD.id;
    DELETE FROM scim_groups WHERE scope = 'organization' AND scope_id = OLD.id;
    DELETE FROM scim_group_roles WHERE level = 'organization' AND target_id = OLD.id;
    UPDATE users SET disabled = 1 WHERE origin_scope = 'organization' AND origin_scope_id = OLD.id;
END;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '14');
"#;

/// Where something belongs: the instance, an organization or a project
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Instance,
    Organization(i64),
    Project(i64),
}

impl Scope {
    pub fn level(&self) -> &'static str {
        match self {
            Scope::Instance => "instance",
            Scope::Organization(_) => "organization",
            Scope::Project(_) => "project",
        }
    }

    pub fn id(&self) -> Option<i64> {
        match self {
            Scope::Instance => None,
            Scope::Organization(id) | Scope::Project(id) => Some(*id),
        }
    }

    pub fn from_parts(level: &str, id: Option<i64>) -> Option<Scope> {
        match (level, id) {
            ("instance", _) => Some(Scope::Instance),
            ("organization", Some(id)) => Some(Scope::Organization(id)),
            ("project", Some(id)) => Some(Scope::Project(id)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScimToken {
    pub id: i64,
    pub name: String,
    pub scope: Scope,
    pub scope_label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScimUser {
    pub id: i64,
    /// userName of the identity provider, returned verbatim
    pub user_name: String,
    /// Local username (shown in Vulnizard, author of decisions)
    pub username: String,
    pub email: Option<String>,
    pub active: bool,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// (group id, display name)
    pub groups: Vec<(i64, String)>,
}

#[derive(Debug, Clone)]
pub struct ScimGroup {
    pub id: i64,
    pub display_name: String,
    pub external_id: Option<String>,
    pub scope: Scope,
    pub scope_label: String,
    pub created_at: String,
    pub updated_at: String,
    /// (user id, username)
    pub members: Vec<(i64, String)>,
}

/// A right a group gives to its members
#[derive(Debug, Clone)]
pub struct GroupRole {
    pub id: i64,
    pub label: String,
    pub role: String,
}

const SCOPE_LABEL: &str = "CASE {t}.scope
    WHEN 'organization' THEN COALESCE((SELECT name FROM organizations WHERE id = {t}.scope_id), '?')
    WHEN 'project' THEN COALESCE((SELECT o.name || ' / ' || p.name FROM projects p
                                  LEFT JOIN organizations o ON o.id = p.organization_id
                                  WHERE p.id = {t}.scope_id), '?')
    ELSE '' END";

fn scope_label(table: &str) -> String {
    SCOPE_LABEL.replace("{t}", table)
}

impl Database {
    pub(super) fn migrate_provisioning(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(PROVISIONING_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    // ---------- origin of accounts ----------

    pub fn user_origin(&self, user_id: i64) -> Result<Scope> {
        let (level, id): (String, Option<i64>) = self.conn().query_row(
            "SELECT origin_scope, origin_scope_id FROM users WHERE id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Scope::from_parts(&level, id).ok_or_else(|| anyhow!("invalid account origin"))
    }

    fn project_org(&self, project_id: i64) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row("SELECT organization_id FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))
            .optional()?
            .flatten())
    }

    /// True if `target` is inside `origin`: an instance origin contains
    /// everything, an organization contains itself and its projects, a
    /// project only itself.
    pub fn scope_contains(&self, origin: Scope, target: Scope) -> Result<bool> {
        Ok(match (origin, target) {
            (Scope::Instance, _) => true,
            (Scope::Organization(o), Scope::Organization(t)) => o == t,
            (Scope::Organization(o), Scope::Project(p)) => self.project_org(p)? == Some(o),
            (Scope::Project(o), Scope::Project(t)) => o == t,
            _ => false,
        })
    }

    /// May this account receive a right on `target`? An account coming from
    /// a project (or an organization) can only hold rights inside it.
    pub fn may_hold_right(&self, user_id: i64, target: Scope) -> Result<bool> {
        self.scope_contains(self.user_origin(user_id)?, target)
    }

    // ---------- SCIM tokens ----------

    pub fn create_scim_token(&self, name: &str, token_hash: &str, scope: Scope) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO scim_tokens (name, token_hash, scope, scope_id) VALUES (?1, ?2, ?3, ?4)",
            params![name, token_hash, scope.level(), scope.id()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn list_scim_tokens(&self) -> Result<Vec<ScimToken>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT t.id, t.name, t.scope, t.scope_id, {label}, t.created_at, t.last_used_at
             FROM scim_tokens t ORDER BY t.id",
            label = scope_label("t")
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(id, name, level, scope_id, scope_label, created_at, last_used_at)| {
                Some(ScimToken {
                    id,
                    name,
                    scope: Scope::from_parts(&level, scope_id)?,
                    scope_label,
                    created_at,
                    last_used_at,
                })
            })
            .collect())
    }

    pub fn delete_scim_token(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM scim_tokens WHERE id = ?1", params![id])? > 0)
    }

    /// Scope of a SCIM bearer token
    pub fn scim_token_scope(&self, token_hash: &str) -> Result<Option<Scope>> {
        let row: Option<(String, Option<i64>)> = self
            .conn()
            .query_row(
                "SELECT scope, scope_id FROM scim_tokens WHERE token_hash = ?1",
                params![token_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let scope = row.and_then(|(level, id)| Scope::from_parts(&level, id));
        if scope.is_some() {
            self.conn().execute(
                "UPDATE scim_tokens SET last_used_at = datetime('now') WHERE token_hash = ?1",
                params![token_hash],
            )?;
        }
        Ok(scope)
    }

    // ---------- SCIM users ----------

    fn scim_user_groups(&self, user_id: i64) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn().prepare(
            "SELECT g.id, g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id = m.group_id
             WHERE m.user_id = ?1 ORDER BY g.display_name",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Accounts provisioned by SCIM in the given scope
    pub fn scim_list_users(&self, scope: Scope) -> Result<Vec<ScimUser>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, COALESCE(scim_username, username), username, email, disabled, scim_external_id,
                    created_at, updated_at FROM users
             WHERE provisioned = 1 AND origin_scope = ?1 AND origin_scope_id IS ?2 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![scope.level(), scope.id()], |r| {
                Ok(ScimUser {
                    id: r.get(0)?,
                    user_name: r.get(1)?,
                    username: r.get(2)?,
                    email: r.get(3)?,
                    active: r.get::<_, i64>(4)? == 0,
                    external_id: r.get(5)?,
                    created_at: r.get(6)?,
                    updated_at: r.get(7)?,
                    groups: Vec::new(),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut users = rows;
        for user in &mut users {
            user.groups = self.scim_user_groups(user.id)?;
        }
        Ok(users)
    }

    pub fn scim_get_user(&self, scope: Scope, id: i64) -> Result<Option<ScimUser>> {
        Ok(self.scim_list_users(scope)?.into_iter().find(|u| u.id == id))
    }

    /// Creates a provisioned account in the scope. `user_name` is the
    /// provider's name (unique in the scope); the local username is derived
    /// from it and made unique.
    pub fn scim_create_user(
        &self,
        scope: Scope,
        user_name: &str,
        email: Option<&str>,
        external_id: Option<&str>,
        active: bool,
    ) -> Result<i64> {
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let exists: bool = self.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE scim_username = ?1 COLLATE NOCASE
                               AND provisioned = 1 AND origin_scope = ?2 AND origin_scope_id IS ?3)",
                params![user_name, scope.level(), scope.id()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(anyhow!("Username already taken"));
            }
            let derived = crate::auth::derive_username(user_name)
                .unwrap_or_else(|| format!("user-{}", &crate::auth::hash_token(user_name)[..8]));
            // An account provisioned for one organization or project carries a mark of it:
            // a plain name stays free for whoever holds it on the instance.
            let base = match scope {
                Scope::Instance => derived,
                Scope::Organization(id) => format!("{}.o{id}", derived.chars().take(24).collect::<String>()),
                Scope::Project(id) => format!("{}.p{id}", derived.chars().take(24).collect::<String>()),
            };
            let mut local = base.clone();
            let mut suffix = 2;
            loop {
                let taken: bool = self.conn().query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
                    params![local],
                    |r| r.get(0),
                )?;
                if !taken {
                    break;
                }
                if suffix > 200 {
                    return Err(anyhow!("Username already taken"));
                }
                local = format!("{}-{suffix}", &base[..base.len().min(28)]);
                suffix += 1;
            }
            self.conn().execute(
                "INSERT INTO users (username, scim_username, email, provisioned, scim_external_id, disabled,
                                    origin_scope, origin_scope_id)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
                params![local, user_name, email, external_id, (!active) as i32, scope.level(), scope.id()],
            )?;
            Ok(self.conn().last_insert_rowid())
        })();
        match &result {
            Ok(_) => self.conn().execute_batch("COMMIT")?,
            Err(_) => self.conn().execute_batch("ROLLBACK")?,
        }
        result
    }

    /// Updates the given attributes of a provisioned account. Deactivating
    /// closes its sessions at once. Renaming changes the provider's name only:
    /// the local username stays, so past decisions keep their author.
    pub fn scim_update_user(
        &self,
        id: i64,
        user_name: Option<&str>,
        email: Option<Option<&str>>,
        external_id: Option<Option<&str>>,
        active: Option<bool>,
    ) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        if let Some(user_name) = user_name {
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users u, users me
                               WHERE me.id = ?2 AND u.id != me.id AND u.scim_username = ?1 COLLATE NOCASE
                                 AND u.provisioned = 1 AND u.origin_scope = me.origin_scope
                                 AND u.origin_scope_id IS me.origin_scope_id)",
                params![user_name, id],
                |r| r.get(0),
            )?;
            if taken {
                return Err(anyhow!("Username already taken"));
            }
            tx.execute("UPDATE users SET scim_username = ?1 WHERE id = ?2", params![user_name, id])?;
        }
        if let Some(email) = email {
            tx.execute("UPDATE users SET email = ?1 WHERE id = ?2", params![email, id])?;
        }
        if let Some(external_id) = external_id {
            tx.execute("UPDATE users SET scim_external_id = ?1 WHERE id = ?2", params![external_id, id])?;
        }
        if let Some(active) = active {
            // The identity provider activates and deactivates its accounts, except
            // one an administrator of Vulnizard disabled: that one stays disabled.
            tx.execute(
                "UPDATE users SET disabled = ?1 WHERE id = ?2 AND (?1 = 1 OR disabled_by_admin = 0)",
                params![(!active) as i32, id],
            )?;
            if !active {
                tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
            }
        }
        tx.execute("UPDATE users SET updated_at = datetime('now') WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }

    /// Deprovisions an account: disabled, signed out, tokens revoked, removed
    /// from its groups and no longer visible to SCIM. The account itself and
    /// the history of its decisions are kept.
    pub fn scim_delete_user(&self, id: i64) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute(
            // provisioned = 2: deprovisioned, still listed for administrators, gone for SCIM
            "UPDATE users SET disabled = 1, provisioned = 2, updated_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
        tx.execute("DELETE FROM api_tokens WHERE user_id = ?1", params![id])?;
        tx.execute("DELETE FROM scim_group_members WHERE user_id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }

    /// Provisioned account of the scope whose SCIM `userName` is one of these
    /// names, not yet linked to an SSO identity. Used at the first SSO sign-in.
    /// The derived local username is never matched: nobody vouches for it.
    pub fn find_provisioned_account(&self, scope: Scope, names: &[&str]) -> Result<Option<i64>> {
        for name in names {
            let found: Option<i64> = self
                .conn()
                .query_row(
                    "SELECT id FROM users
                     WHERE scim_username = ?1 COLLATE NOCASE
                       AND provisioned = 1 AND oidc_subject IS NULL
                       AND origin_scope = ?2 AND origin_scope_id IS ?3",
                    params![name, scope.level(), scope.id()],
                    |r| r.get(0),
                )
                .optional()?;
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub fn set_oidc_subject(&self, user_id: i64, subject: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET oidc_subject = ?1, updated_at = datetime('now') WHERE id = ?2 AND oidc_subject IS NULL",
            params![subject, user_id],
        )?;
        Ok(())
    }

    // ---------- SCIM groups ----------

    fn scim_group_members(&self, group_id: i64) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn().prepare(
            "SELECT u.id, u.username FROM scim_group_members m JOIN users u ON u.id = m.user_id
             WHERE m.group_id = ?1 ORDER BY u.username",
        )?;
        let rows = stmt
            .query_map(params![group_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn scim_groups_where(&self, filter: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<ScimGroup>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT g.id, g.display_name, g.external_id, g.scope, g.scope_id, {label}, g.created_at, g.updated_at
             FROM scim_groups g WHERE {filter} ORDER BY g.id",
            label = scope_label("g")
        ))?;
        let rows = stmt
            .query_map(args, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut groups = Vec::new();
        for (id, display_name, external_id, level, scope_id, scope_label, created_at, updated_at) in rows {
            let Some(scope) = Scope::from_parts(&level, scope_id) else {
                continue;
            };
            groups.push(ScimGroup {
                id,
                display_name,
                external_id,
                scope,
                scope_label,
                created_at,
                updated_at,
                members: self.scim_group_members(id)?,
            });
        }
        Ok(groups)
    }

    /// Groups of one scope (what a SCIM token sees)
    pub fn scim_list_groups(&self, scope: Scope) -> Result<Vec<ScimGroup>> {
        self.scim_groups_where("g.scope = ?1 AND g.scope_id IS ?2", &[&scope.level(), &scope.id()])
    }

    /// Every group (administration UI)
    pub fn scim_all_groups(&self) -> Result<Vec<ScimGroup>> {
        self.scim_groups_where("1 = 1", &[])
    }

    pub fn scim_get_group(&self, scope: Scope, id: i64) -> Result<Option<ScimGroup>> {
        Ok(self.scim_list_groups(scope)?.into_iter().find(|g| g.id == id))
    }

    pub fn scim_create_group(&self, scope: Scope, display_name: &str, external_id: Option<&str>) -> Result<i64> {
        let taken: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM scim_groups WHERE scope = ?1 AND scope_id IS ?2 AND display_name = ?3)",
            params![scope.level(), scope.id(), display_name],
            |r| r.get(0),
        )?;
        if taken {
            return Err(anyhow!("Group name already used"));
        }
        self.conn().execute(
            "INSERT INTO scim_groups (display_name, external_id, scope, scope_id) VALUES (?1, ?2, ?3, ?4)",
            params![display_name, external_id, scope.level(), scope.id()],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn scim_rename_group(&self, id: i64, display_name: Option<&str>, external_id: Option<Option<&str>>) -> Result<()> {
        if let Some(name) = display_name {
            self.conn()
                .execute("UPDATE scim_groups SET display_name = ?1 WHERE id = ?2", params![name, id])?;
        }
        if let Some(external_id) = external_id {
            self.conn()
                .execute("UPDATE scim_groups SET external_id = ?1 WHERE id = ?2", params![external_id, id])?;
        }
        self.touch_group(id)
    }

    fn touch_group(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Adds members; only provisioned accounts of the group's own scope are accepted
    pub fn scim_add_members(&self, group_id: i64, user_ids: &[i64]) -> Result<()> {
        for user_id in user_ids {
            let allowed = self.conn().execute(
                "INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
                 SELECT g.id, u.id FROM scim_groups g, users u
                 WHERE g.id = ?1 AND u.id = ?2 AND u.provisioned = 1
                   AND u.origin_scope = g.scope AND u.origin_scope_id IS g.scope_id",
                params![group_id, user_id],
            )?;
            let present: bool = self.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM scim_group_members WHERE group_id = ?1 AND user_id = ?2)",
                params![group_id, user_id],
                |r| r.get(0),
            )?;
            if allowed == 0 && !present {
                return Err(anyhow!("Unknown member"));
            }
        }
        self.touch_group(group_id)
    }

    pub fn scim_remove_members(&self, group_id: i64, user_ids: &[i64]) -> Result<()> {
        for user_id in user_ids {
            self.conn().execute(
                "DELETE FROM scim_group_members WHERE group_id = ?1 AND user_id = ?2",
                params![group_id, user_id],
            )?;
        }
        self.touch_group(group_id)
    }

    /// Replaces the members of a group
    pub fn scim_set_members(&self, group_id: i64, user_ids: &[i64]) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute("DELETE FROM scim_group_members WHERE group_id = ?1", params![group_id])?;
        self.scim_add_members(group_id, user_ids)?;
        tx.commit()?;
        Ok(())
    }

    pub fn scim_delete_group(&self, id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM scim_groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---------- rights given by groups ----------

    /// Gives a role to the members of a group. The right must be inside the
    /// scope the group belongs to.
    pub fn set_group_role(&self, group_id: i64, target: Scope, role: Role) -> Result<()> {
        let (level, id): (String, Option<i64>) = self
            .conn()
            .query_row("SELECT scope, scope_id FROM scim_groups WHERE id = ?1", params![group_id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .ok_or_else(|| anyhow!("Unknown group"))?;
        let group_scope = Scope::from_parts(&level, id).ok_or_else(|| anyhow!("Unknown group"))?;
        if !self.scope_contains(group_scope, target)? {
            return Err(anyhow!("This group cannot give a right outside what it belongs to"));
        }
        self.conn().execute(
            "DELETE FROM scim_group_roles WHERE group_id = ?1 AND level = ?2 AND target_id IS ?3",
            params![group_id, target.level(), target.id()],
        )?;
        self.conn().execute(
            "INSERT INTO scim_group_roles (group_id, level, target_id, role) VALUES (?1, ?2, ?3, ?4)",
            params![group_id, target.level(), target.id(), role.as_str()],
        )?;
        Ok(())
    }

    pub fn remove_group_role(&self, group_id: i64, role_id: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM scim_group_roles WHERE id = ?1 AND group_id = ?2",
            params![role_id, group_id],
        )? > 0)
    }

    pub fn list_group_roles(&self, group_id: i64) -> Result<Vec<GroupRole>> {
        let mut stmt = self.conn().prepare(
            "SELECT r.id, r.level, r.target_id, r.role,
                    CASE r.level
                      WHEN 'organization' THEN COALESCE((SELECT name FROM organizations WHERE id = r.target_id), '?')
                      WHEN 'project' THEN COALESCE((SELECT o.name || ' / ' || p.name FROM projects p
                                                    LEFT JOIN organizations o ON o.id = p.organization_id
                                                    WHERE p.id = r.target_id), '?')
                      ELSE 'whole instance' END
             FROM scim_group_roles r WHERE r.group_id = ?1 ORDER BY r.level, 5",
        )?;
        let rows = stmt
            .query_map(params![group_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(id, level, target_id, role, label)| {
                // Rows whose target no longer exists are skipped
                Scope::from_parts(&level, target_id)?;
                Some(GroupRole { id, label, role })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Database, i64, i64, i64, i64) {
        let db = Database::open_in_memory().unwrap();
        let owner = db.create_account("owner", None, "h", false).unwrap();
        let org = db.create_org("acme", owner).unwrap();
        let infra = db.create_org_project(org, owner, "infra", None).unwrap();
        let web = db.create_org_project(org, owner, "web", None).unwrap();
        (db, owner, org, infra, web)
    }

    #[test]
    fn an_account_only_holds_rights_inside_its_origin() {
        let (db, owner, org, infra, web) = setup();
        let other_org = db.create_org("other", owner).unwrap();
        let misc = db.create_org_project(other_org, owner, "misc", None).unwrap();

        let from_project = db.scim_create_user(Scope::Project(infra), "pdev", None, None, true).unwrap();
        assert!(db.may_hold_right(from_project, Scope::Project(infra)).unwrap());
        for outside in [Scope::Project(web), Scope::Organization(org), Scope::Instance, Scope::Project(misc)] {
            assert!(!db.may_hold_right(from_project, outside).unwrap(), "{outside:?}");
        }
        let from_org = db.scim_create_user(Scope::Organization(org), "odev", None, None, true).unwrap();
        assert!(db.may_hold_right(from_org, Scope::Organization(org)).unwrap());
        assert!(db.may_hold_right(from_org, Scope::Project(web)).unwrap());
        for outside in [Scope::Instance, Scope::Organization(other_org), Scope::Project(misc)] {
            assert!(!db.may_hold_right(from_org, outside).unwrap(), "{outside:?}");
        }
        // A local account belongs to the instance
        assert!(db.may_hold_right(owner, Scope::Instance).unwrap());
        assert!(db.may_hold_right(owner, Scope::Project(misc)).unwrap());
    }

    #[test]
    fn scim_users_are_scoped_updated_and_deprovisioned() {
        let (db, _, org, infra, _) = setup();
        let scope = Scope::Project(infra);
        let id = db.scim_create_user(scope, "jdoe", Some("j@example.org"), Some("ext-1"), true).unwrap();
        assert!(db.scim_create_user(scope, "JDoe", None, None, true).is_err());
        // A reserved or already used local name gets another local username
        let sys = db.scim_create_user(scope, "system", None, None, true).unwrap();
        assert!(db.scim_get_user(scope, sys).unwrap().unwrap().username.starts_with("user-"));
        let same_local = db.scim_create_user(scope, "jdoe@corp.example", None, None, true).unwrap();
        let user = db.scim_get_user(scope, same_local).unwrap().unwrap();
        assert_eq!((user.user_name.as_str(), user.username.as_str()), ("jdoe@corp.example", format!("jdoe.p{infra}-2").as_str()));
        // The plain name stays free for an account of the instance
        assert_eq!(db.scim_get_user(scope, id).unwrap().unwrap().username, format!("jdoe.p{infra}"));
        assert!(db.scim_get_user(Scope::Organization(org), id).unwrap().is_none());
        assert!(db.scim_get_user(Scope::Instance, id).unwrap().is_none());

        // A provisioned account is known but has no way to sign in until SSO links it
        assert!(db.get_credentials("jdoe").unwrap().is_none());
        assert_eq!(db.find_provisioned_account(scope, &["jdoe"]).unwrap(), Some(id));
        assert_eq!(db.find_provisioned_account(scope, &["nope", "jdoe@corp.example"]).unwrap(), Some(same_local));
        assert_eq!(db.find_provisioned_account(Scope::Instance, &["jdoe"]).unwrap(), None);
        assert!(db.list_accounts().unwrap().iter().any(|a| a.username == format!("jdoe.p{infra}")));
        assert!(!db.list_accounts().unwrap().iter().any(|a| a.username == "jdoe"));

        db.create_session(id, "sess", 60).unwrap();
        db.scim_update_user(id, Some("john"), Some(None), None, Some(false)).unwrap();
        let user = db.scim_get_user(scope, id).unwrap().unwrap();
        // Renamed for the provider; the local username (author of decisions) is unchanged
        assert_eq!(
            (user.user_name.as_str(), user.username.as_str(), user.email.as_deref(), user.active, user.external_id.as_deref()),
            ("john", format!("jdoe.p{infra}").as_str(), None, false, Some("ext-1"))
        );
        assert!(db.get_session_account("sess").unwrap().is_none());
        assert!(db.scim_update_user(id, Some("jdoe@corp.example"), None, None, None).is_err());

        db.scim_update_user(id, None, None, None, Some(true)).unwrap();
        let disabled = |db: &Database| db.list_accounts().unwrap().iter().find(|a| a.id == id).unwrap().disabled;
        assert!(!disabled(&db));
        // An administrator's decision to disable the account holds against the identity provider
        db.create_account("root", None, "h", true).unwrap();
        db.set_disabled(id, true).unwrap();
        db.scim_update_user(id, None, None, None, Some(true)).unwrap();
        assert!(disabled(&db));
        db.set_disabled(id, false).unwrap();
        db.scim_update_user(id, None, None, None, Some(false)).unwrap();
        db.scim_update_user(id, None, None, None, Some(true)).unwrap();
        assert!(!disabled(&db));
        db.scim_delete_user(id).unwrap();
        assert!(db.scim_get_user(scope, id).unwrap().is_none());
        assert!(db.list_accounts().unwrap().iter().any(|a| a.username == format!("jdoe.p{infra}") && a.disabled));
    }

    #[test]
    fn groups_give_rights_through_the_access_views() {
        let (db, _, org, infra, web) = setup();
        let scope = Scope::Organization(org);
        let alice = db.scim_create_user(scope, "alice", None, None, true).unwrap();
        let bob = db.scim_create_user(scope, "bob", None, None, true).unwrap();
        let stranger = db.scim_create_user(Scope::Project(infra), "stranger", None, None, true).unwrap();
        let group = db.scim_create_group(scope, "devs", Some("g-1")).unwrap();
        assert!(db.scim_create_group(scope, "devs", None).is_err());

        db.scim_add_members(group, &[alice, bob]).unwrap();
        // Accounts of another scope cannot join
        assert!(db.scim_add_members(group, &[stranger]).is_err());
        assert_eq!(db.project_role(alice, infra).unwrap(), None);

        // A group right is computed, not copied: it follows the membership
        db.set_group_role(group, Scope::Project(infra), Role::Editor).unwrap();
        assert_eq!(db.project_role(alice, infra).unwrap(), Some(Role::Editor));
        assert_eq!(db.project_role(alice, web).unwrap(), None);
        db.set_group_role(group, Scope::Organization(org), Role::Viewer).unwrap();
        assert_eq!(db.project_role(bob, web).unwrap(), Some(Role::Viewer));
        assert_eq!(db.project_role(bob, infra).unwrap(), Some(Role::Editor));
        assert!(db.get_org("acme", bob).unwrap().is_some());
        // Never outside what the group belongs to
        assert!(db.set_group_role(group, Scope::Instance, Role::Owner).is_err());
        assert_eq!(db.list_group_roles(group).unwrap().len(), 2);

        db.scim_remove_members(group, &[bob]).unwrap();
        assert_eq!(db.project_role(bob, infra).unwrap(), None);
        db.scim_set_members(group, &[bob]).unwrap();
        assert_eq!(db.project_role(alice, infra).unwrap(), None);
        assert_eq!(db.project_role(bob, infra).unwrap(), Some(Role::Editor));

        let role_id = db.list_group_roles(group).unwrap()[0].id;
        assert!(db.remove_group_role(group, role_id).unwrap());
        db.scim_delete_group(group).unwrap();
        assert_eq!(db.project_role(bob, web).unwrap(), None);
    }

    #[test]
    fn tokens_are_scoped_and_cleaned_with_their_project() {
        let (db, owner, _, infra, _) = setup();
        db.create_scim_token("idp", "hash-1", Scope::Project(infra)).unwrap();
        db.create_scim_token("corp", "hash-2", Scope::Instance).unwrap();
        assert_eq!(db.scim_token_scope("hash-1").unwrap(), Some(Scope::Project(infra)));
        assert_eq!(db.scim_token_scope("nope").unwrap(), None);
        let user = db.scim_create_user(Scope::Project(infra), "tmp", None, None, true).unwrap();
        let tokens = db.list_scim_tokens().unwrap();
        assert_eq!(tokens[0].scope_label, "acme / infra");
        assert!(tokens[0].last_used_at.is_some());

        // Deleting the project removes its token and disables its accounts
        db.delete_project_by_id(infra, &crate::db::Actor::user(owner, "owner")).unwrap();
        assert_eq!(db.scim_token_scope("hash-1").unwrap(), None);
        assert_eq!(db.scim_token_scope("hash-2").unwrap(), Some(Scope::Instance));
        assert!(db.list_accounts().unwrap().iter().any(|a| a.id == user && a.disabled));
    }

    #[test]
    fn scoped_accounts_stay_inside_their_origin() {
        let db = Database::open_in_memory().unwrap();
        let root = db.create_account("root", None, "h", false).unwrap();
        let org = db.create_org("acme", root).unwrap();
        let project = db.create_org_project(org, root, "infra", None).unwrap();
        let scope = Scope::Project(project);

        // An account created by a project provider belongs to the project, is never an administrator
        let dev = db.create_oidc_account("dev", None, "iss|dev", true, scope).unwrap();
        assert_eq!(db.user_origin(dev).unwrap(), scope);
        assert!(!db.get_account(dev).unwrap().unwrap().is_admin);
        // ... and cannot make itself owner of a new organization
        assert!(db.create_org("mine", dev).is_err());

        // A project provider cannot take an account of the instance by naming itself after it,
        // and nothing is written in the attempt
        db.create_account("bob", None, "h", false).unwrap();
        assert!(db.link_oidc_account("bob", "iss|evil", scope).unwrap().is_none());
        assert!(db.find_oidc_account("iss|evil").unwrap().is_none());
        assert!(db.link_oidc_account("bob", "iss|bob", Scope::Instance).unwrap().is_some());

        // A provisioned account is matched on its SCIM userName only, never on the derived local name
        let id = db.scim_create_user(scope, "jane.doe@corp.example", None, None, true).unwrap();
        let local = db.get_account(id).unwrap().unwrap().username;
        assert_eq!(db.find_provisioned_account(scope, &[&local]).unwrap(), None);
        assert_eq!(db.find_provisioned_account(scope, &["jane.doe@corp.example"]).unwrap(), Some(id));
        assert!(db.link_oidc_account(&local, "iss|squat", Scope::Instance).unwrap().is_none());
    }
}
