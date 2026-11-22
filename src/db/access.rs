//! Schema v7 and the operations built on it: account administration,
//! SSO (OIDC) account linking, dashboard queries and watchlist triage.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::changes::Event;
use crate::db::{Account, Database};

const ACCESS_SCHEMA: &str = r#"
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
ALTER TABLE users ADD COLUMN last_login_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc ON users(oidc_subject) WHERE oidc_subject IS NOT NULL;

-- Roles become owner / editor / viewer ('member' was an editor)
CREATE TABLE memberships_v7 (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('owner', 'editor', 'viewer')),
    PRIMARY KEY (organization_id, user_id)
);
INSERT INTO memberships_v7 (organization_id, user_id, role)
SELECT organization_id, user_id, CASE role WHEN 'owner' THEN 'owner' ELSE 'editor' END FROM memberships;
DROP TABLE memberships;
ALTER TABLE memberships_v7 RENAME TO memberships;
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);

-- Pending SSO logins (state -> PKCE verifier and nonce)
CREATE TABLE IF NOT EXISTS oidc_states (
    state_hash TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '7');
"#;

/// Account as seen by an administrator
#[derive(Debug, Clone, Serialize)]
pub struct AccountInfo {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub is_admin: bool,
    pub disabled: bool,
    pub has_password: bool,
    pub sso: bool,
    pub last_login_at: Option<String>,
    pub organizations: i64,
    /// Role on every organization and project, if any
    pub instance_role: Option<String>,
    /// Number of rights at organization and project level
    pub assignments: i64,
}

/// Untreated (or handled) watchlist entry with its project context
#[derive(Debug, Clone, Serialize)]
pub struct TriageItem {
    pub entry_id: i64,
    pub cve_id: String,
    pub status: String,
    pub priority: Option<String>,
    pub app_name: String,
    pub app_version: Option<String>,
    pub org: String,
    pub project: String,
    pub cvss: Option<f64>,
    pub kev: bool,
    pub description: Option<String>,
    /// Group of inventory sources the application is tracked for (empty: added by hand)
    pub group: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    pub id: i64,
    pub org: String,
    pub name: String,
    pub description: Option<String>,
    pub role: String,
    pub applications: i64,
    pub subscriptions: i64,
    pub untreated: i64,
    pub last_report: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Breakdown {
    pub project_id: i64,
    pub status: String,
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedApplication {
    pub org: String,
    pub project: String,
    pub id: i64,
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub untreated: i64,
    /// Group of inventory sources it is tracked for (empty: added by hand)
    pub group: String,
    /// Names of the sources reporting it
    pub sources: Vec<String>,
    /// CVEs the sources hold under this name, whatever the version; 0: unknown to the sources
    pub known_cves: Option<i64>,
    pub ecosystem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedSubscription {
    pub org: String,
    pub project: String,
    pub project_id: i64,
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectChange {
    pub org: String,
    pub project: String,
    pub cve_id: String,
    pub created_at: String,
    pub events: Vec<Event>,
    pub cvss: Option<f64>,
}

/// Pending SSO logins kept at once (each lives 10 minutes at most)
const MAX_PENDING_LOGINS: i64 = 10_000;

/// Accounts of people (not the CLI `default` user): they can sign in, or
/// were provisioned and will sign in through SSO.
const CAN_LOG_IN: &str = "(password_hash IS NOT NULL OR oidc_subject IS NOT NULL OR provisioned != 0)";

// ==========================================
// Migration
// ==========================================

impl Database {
    pub(super) fn migrate_access(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(ACCESS_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }
}

// ==========================================
// Account administration
// ==========================================

impl Database {
    pub fn list_accounts(&self) -> Result<Vec<AccountInfo>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT u.id, u.username, u.email, u.is_admin, u.disabled,
                    u.password_hash IS NOT NULL, u.oidc_subject IS NOT NULL, u.last_login_at,
                    (SELECT COUNT(*) FROM memberships m WHERE m.user_id = u.id),
                    u.instance_role,
                    (SELECT COUNT(*) FROM memberships m WHERE m.user_id = u.id)
                      + (SELECT COUNT(*) FROM project_memberships pm WHERE pm.user_id = u.id)
             FROM users u WHERE {CAN_LOG_IN} ORDER BY u.username COLLATE NOCASE"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AccountInfo {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    email: r.get(2)?,
                    is_admin: r.get::<_, i64>(3)? != 0,
                    disabled: r.get::<_, i64>(4)? != 0,
                    has_password: r.get(5)?,
                    sso: r.get(6)?,
                    last_login_at: r.get(7)?,
                    organizations: r.get(8)?,
                    instance_role: r.get(9)?,
                    assignments: r.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Runs an account change and refuses it (rolled back) if it leaves the
    /// instance without any enabled administrator.
    fn guarded_account_change(&self, sql: &str, user_id: i64, value: bool) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        let changed = tx.execute(sql, params![value as i32, user_id])?;
        if changed == 0 {
            return Err(anyhow!("Unknown account"));
        }
        let admins: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0 AND {CAN_LOG_IN}"),
            [],
            |r| r.get(0),
        )?;
        if admins == 0 {
            return Err(anyhow!("At least one enabled administrator is required"));
        }
        // Close the sessions so the change applies immediately
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        tx.commit()?;
        Ok(())
    }

    /// Grants or removes instance administration. Sessions are closed so the
    /// change applies immediately.
    pub fn set_admin(&self, user_id: i64, is_admin: bool) -> Result<()> {
        self.guarded_account_change(
            &format!("UPDATE users SET is_admin = ?1, updated_at = datetime('now') WHERE id = ?2 AND {CAN_LOG_IN}"),
            user_id,
            is_admin,
        )
    }

    /// Disables or re-enables an account. A disabled account cannot log in and
    /// its sessions and API tokens stop working at once (tokens are kept and
    /// work again if the account is re-enabled).
    pub fn set_disabled(&self, user_id: i64, disabled: bool) -> Result<()> {
        self.guarded_account_change(
            // Remembered as an administrator's decision: provisioning cannot enable the account again
            &format!("UPDATE users SET disabled = ?1, disabled_by_admin = ?1, updated_at = datetime('now') WHERE id = ?2 AND {CAN_LOG_IN}"),
            user_id,
            disabled,
        )
    }

    pub fn get_account(&self, user_id: i64) -> Result<Option<Account>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT id, username, is_admin FROM users WHERE id = ?1 AND {CAN_LOG_IN}"),
                params![user_id],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        is_admin: r.get::<_, i64>(2)? != 0,
                    })
                },
            )
            .optional()?)
    }
}

// ==========================================
// SSO (OIDC)
// ==========================================

impl Database {
    pub fn save_oidc_state(
        &self,
        provider: &str,
        state_hash: &str,
        code_verifier: &str,
        nonce: &str,
        ttl_secs: i64,
    ) -> Result<()> {
        self.conn().execute(
            "DELETE FROM oidc_states WHERE expires_at < CAST(strftime('%s','now') AS INTEGER)",
            [],
        )?;
        // Unauthenticated endpoint: bound the number of pending logins
        let pending: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM oidc_states", [], |r| r.get(0))?;
        if pending >= MAX_PENDING_LOGINS {
            // Starting a sign-in needs no account: refusing new ones when the table is
            // full would let anyone lock everybody out. The oldest make room instead.
            self.conn().execute(
                "DELETE FROM oidc_states WHERE state_hash IN (
                     SELECT state_hash FROM oidc_states ORDER BY expires_at LIMIT ?1)",
                params![pending - MAX_PENDING_LOGINS + 1],
            )?;
        }
        self.conn().execute(
            "INSERT INTO oidc_states (state_hash, code_verifier, nonce, expires_at, provider)
             VALUES (?1, ?2, ?3, CAST(strftime('%s','now') AS INTEGER) + ?4, ?5)",
            params![state_hash, code_verifier, nonce, ttl_secs, provider],
        )?;
        Ok(())
    }

    /// Consumes a pending login started with this provider: returns
    /// (code verifier, nonce) once. A state of another provider is refused
    /// (and consumed).
    pub fn take_oidc_state(&self, provider: &str, state_hash: &str) -> Result<Option<(String, String)>> {
        let row: Option<(String, String, String)> = self
            .conn()
            .query_row(
                "DELETE FROM oidc_states
                 WHERE state_hash = ?1 AND expires_at > CAST(strftime('%s','now') AS INTEGER)
                 RETURNING code_verifier, nonce, provider",
                params![state_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.filter(|(_, _, p)| p == provider).map(|(verifier, nonce, _)| (verifier, nonce)))
    }

    /// Account linked to an identity-provider subject, with its disabled flag
    pub fn find_oidc_account(&self, subject: &str) -> Result<Option<(Account, bool)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, username, is_admin, disabled FROM users WHERE oidc_subject = ?1",
                params![subject],
                |r| {
                    Ok((
                        Account {
                            id: r.get(0)?,
                            username: r.get(1)?,
                            is_admin: r.get::<_, i64>(2)? != 0,
                        },
                        r.get::<_, i64>(3)? != 0,
                    ))
                },
            )
            .optional()?)
    }

    /// Creates the account of a user seen for the first time through SSO.
    /// Fails if the username is already used (no implicit takeover).
    pub fn create_oidc_account(
        &self,
        username: &str,
        email: Option<&str>,
        subject: &str,
        is_admin: bool,
        origin: super::Scope,
    ) -> Result<i64> {
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let exists: bool = self.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
                params![username],
                |r| r.get(0),
            )?;
            if exists || crate::auth::is_reserved_username(username) {
                return Err(anyhow!("Username already taken"));
            }
            let is_admin = is_admin && origin == super::Scope::Instance;
            self.conn().execute(
                "INSERT INTO users (username, email, oidc_subject, is_admin, origin_scope, origin_scope_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![username, email, subject, is_admin as i32, origin.level(), origin.id()],
            )?;
            let id = self.conn().last_insert_rowid();
            if is_admin {
                self.conn().execute(
                    "INSERT OR IGNORE INTO memberships (organization_id, user_id, role)
                     SELECT id, ?1, 'owner' FROM organizations WHERE name = 'default'",
                    params![id],
                )?;
            }
            Ok(id)
        })();
        match &result {
            Ok(_) => self.conn().execute_batch("COMMIT")?,
            Err(_) => self.conn().execute_batch("ROLLBACK")?,
        }
        result
    }

    /// Links an existing local account (matched by username) to an SSO subject.
    /// Only enabled, non-administrator accounts that are not linked yet can be
    /// linked: an administrator account is never obtained through a name match.
    ///
    /// The account must belong to what the provider (`scope`) covers, which is
    /// checked before anything is written, and accounts provisioned by SCIM
    /// are never linked through their local name.
    pub fn link_oidc_account(&self, username: &str, subject: &str, scope: super::Scope) -> Result<Option<(Account, bool)>> {
        let candidate: Option<i64> = self
            .conn()
            .query_row(
                &format!(
                    "SELECT id FROM users WHERE username = ?1 COLLATE NOCASE AND oidc_subject IS NULL
                       AND is_admin = 0 AND disabled = 0 AND provisioned = 0 AND {CAN_LOG_IN}"
                ),
                params![username],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = candidate else {
            return Ok(None);
        };
        if !self.scope_contains(scope, self.user_origin(id)?)? {
            return Ok(None);
        }
        let changed = self.conn().execute(
            "UPDATE users SET oidc_subject = ?1, updated_at = datetime('now') WHERE id = ?2 AND oidc_subject IS NULL",
            params![subject, id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        self.find_oidc_account(subject)
    }

    /// Aligns the administrator flag with the identity provider's group
    /// (never removes the last enabled administrator).
    pub fn sync_admin_flag(&self, user_id: i64, is_admin: bool) -> Result<()> {
        let current: bool = self.conn().query_row(
            "SELECT is_admin FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )?;
        if current == is_admin {
            return Ok(());
        }
        let tx = self.conn().unchecked_transaction()?;
        tx.execute(
            "UPDATE users SET is_admin = ?1 WHERE id = ?2",
            params![is_admin as i32, user_id],
        )?;
        let admins: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0 AND {CAN_LOG_IN}"),
            [],
            |r| r.get(0),
        )?;
        if admins == 0 {
            return Ok(()); // rolled back: keep the last administrator
        }
        if is_admin {
            tx.execute(
                "INSERT OR IGNORE INTO memberships (organization_id, user_id, role)
                 SELECT id, ?1, 'owner' FROM organizations WHERE name = 'default'",
                params![user_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ==========================================
// Dashboard and triage
// ==========================================

const TRIAGE_SELECT: &str = "
    SELECT w.id, w.cve_id, w.status, w.priority, a.name, a.version, o.name, p.name,
           c.cvss_v3_score, COALESCE(c.kev_known_exploited, 0), c.description, a.grp
    FROM watchlist_entries w
    JOIN applications a ON a.id = w.app_id
    JOIN projects p ON p.id = a.project_id
    JOIN organizations o ON o.id = p.organization_id
    LEFT JOIN cves c ON c.cve_id = w.cve_id";

const TRIAGE_ORDER: &str =
    " ORDER BY COALESCE(c.kev_known_exploited, 0) DESC, c.cvss_v3_score DESC NULLS LAST, w.cve_id DESC";

fn triage_row(r: &rusqlite::Row) -> rusqlite::Result<TriageItem> {
    Ok(TriageItem {
        entry_id: r.get(0)?,
        cve_id: r.get(1)?,
        status: r.get(2)?,
        priority: r.get(3)?,
        app_name: r.get(4)?,
        app_version: r.get(5)?,
        org: r.get(6)?,
        project: r.get(7)?,
        cvss: r.get(8)?,
        kev: r.get::<_, i64>(9)? != 0,
        description: r.get(10)?,
        group: r.get(11)?,
    })
}

impl Database {
    /// Watchlist entries of one project: untreated ones, or the handled ones
    #[cfg(test)]
    pub fn project_triage(&self, project_id: i64, handled: bool) -> Result<Vec<TriageItem>> {
        let filter = if handled { "w.status != 'untreated'" } else { "w.status = 'untreated'" };
        let sql = format!("{TRIAGE_SELECT} WHERE p.id = ?1 AND {filter} {TRIAGE_ORDER}");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt
            .query_map(params![project_id], triage_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Watchlist counts per (project id, status, severity level) for the
    /// user's projects, or one project.
    pub fn watch_breakdown(&self, user_id: i64, project_id: Option<i64>) -> Result<Vec<Breakdown>> {
        let mut stmt = self.conn().prepare(
            "SELECT p.id, w.status,
                    CASE WHEN c.cvss_v3_score >= 9.0 THEN 'critical'
                         WHEN c.cvss_v3_score >= 7.0 THEN 'high'
                         WHEN c.cvss_v3_score >= 4.0 THEN 'medium'
                         WHEN c.cvss_v3_score > 0 THEN 'low'
                         ELSE 'none' END,
                    COUNT(*)
             FROM watchlist_entries w
             JOIN applications a ON a.id = w.app_id
             JOIN projects p ON p.id = a.project_id
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             LEFT JOIN cves c ON c.cve_id = w.cve_id
             WHERE (?2 IS NULL OR p.id = ?2)
             GROUP BY 1, 2, 3",
        )?;
        let rows = stmt
            .query_map(params![user_id, project_id], |r| {
                Ok(Breakdown {
                    project_id: r.get(0)?,
                    status: r.get(1)?,
                    severity: r.get(2)?,
                    count: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Untreated entries of the user's projects, optionally for one project
    pub fn scoped_triage(&self, user_id: i64, project_id: Option<i64>, handled: bool, limit: i64) -> Result<Vec<TriageItem>> {
        let filter = if handled { "w.status != 'untreated'" } else { "w.status = 'untreated'" };
        let sql = format!(
            "{TRIAGE_SELECT}
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             WHERE {filter} AND (?2 IS NULL OR p.id = ?2) {TRIAGE_ORDER} LIMIT ?3"
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt
            .query_map(params![user_id, project_id, limit], triage_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Applications of the user's projects (or one project): (org, project, application)
    pub fn scoped_applications(&self, user_id: i64, project_id: Option<i64>) -> Result<Vec<ScopedApplication>> {
        let mut stmt = self.conn().prepare(
            "SELECT o.name, p.name, a.id, a.name, a.version, a.vendor,
                    (SELECT COUNT(*) FROM watchlist_entries w WHERE w.app_id = a.id AND w.status = 'untreated'),
                    a.grp,
                    (SELECT GROUP_CONCAT(s.name, char(10)) FROM inventory_components c
                     JOIN inventory_sources s ON s.id = c.source_id WHERE c.application_id = a.id),
                    a.known_cves, a.ecosystem
             FROM applications a
             JOIN projects p ON p.id = a.project_id
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             WHERE (?2 IS NULL OR p.id = ?2)
             ORDER BY o.name, p.name, a.name, a.version",
        )?;
        let rows = stmt
            .query_map(params![user_id, project_id], |r| {
                Ok(ScopedApplication {
                    org: r.get(0)?,
                    project: r.get(1)?,
                    id: r.get(2)?,
                    name: r.get(3)?,
                    version: r.get(4)?,
                    vendor: r.get(5)?,
                    untreated: r.get(6)?,
                    group: r.get(7)?,
                    sources: r
                        .get::<_, Option<String>>(8)?
                        .map(|names| names.lines().map(String::from).collect())
                        .unwrap_or_default(),
                    known_cves: r.get(9)?,
                    ecosystem: r.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Subscriptions of the user's projects (or one project)
    pub fn scoped_subscriptions(&self, user_id: i64, project_id: Option<i64>) -> Result<Vec<ScopedSubscription>> {
        let mut stmt = self.conn().prepare(
            "SELECT o.name, p.name, p.id, s.vendor, s.product
             FROM subscriptions s
             JOIN projects p ON p.id = s.project_id
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             WHERE (?2 IS NULL OR p.id = ?2)
             ORDER BY o.name, p.name, s.vendor, s.product",
        )?;
        let rows = stmt
            .query_map(params![user_id, project_id], |r| {
                Ok(ScopedSubscription {
                    org: r.get(0)?,
                    project: r.get(1)?,
                    project_id: r.get(2)?,
                    vendor: r.get(3)?,
                    product: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Latest run of each source
    pub fn last_sync_runs(&self) -> Result<Vec<crate::db::SyncRun>> {
        let mut stmt = self.conn().prepare(
            "SELECT source, started_at, completed_at, status, cves_added, cves_updated, error_message
             FROM sync_history WHERE id IN (SELECT MAX(id) FROM sync_history GROUP BY source)",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(crate::db::SyncRun {
                    source: r.get(0)?,
                    started_at: r.get(1)?,
                    completed_at: r.get(2)?,
                    status: r.get(3)?,
                    added: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    updated: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    error: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks the runs left in the `running` state by a stopped process as
    /// interrupted. Called when the server starts, before its first sync.
    pub fn fail_interrupted_syncs(&self) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE sync_history SET status = 'failed', completed_at = datetime('now'),
                    error_message = 'interrupted' WHERE status = 'running'",
            [],
        )?)
    }

    /// Last completed sync (UTC, `YYYY-MM-DD HH:MM:SS`) and whether one is running
    /// Sources that are running, or that started less than `minutes` ago
    pub fn recently_synced_sources(&self, minutes: u64) -> Result<Vec<String>> {
        let mut stmt = self.conn().prepare(
            "SELECT DISTINCT source FROM sync_history
             WHERE (status = 'running' AND started_at > datetime('now', '-3 hours'))
                OR (?1 > 0 AND started_at > datetime('now', '-' || ?1 || ' minutes'))",
        )?;
        let rows = stmt
            .query_map(params![minutes as i64], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    pub fn sync_status(&self) -> Result<(Option<String>, bool)> {
        let last: Option<String> = self.conn().query_row(
            "SELECT MAX(completed_at) FROM sync_history WHERE status = 'completed'",
            [],
            |r| r.get(0),
        )?;
        // A crashed run stays 'running': ignore the old ones
        let running: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_history
                           WHERE status = 'running' AND started_at > datetime('now', '-3 hours'))",
            [],
            |r| r.get(0),
        )?;
        Ok((last, running))
    }

    /// Every project the user can access, with its counters
    pub fn project_summaries(&self, user_id: i64) -> Result<Vec<ProjectSummary>> {
        let mut stmt = self.conn().prepare(
            "SELECT p.id, o.name, p.name, p.description,
                    CASE pa.rank WHEN 3 THEN 'owner' WHEN 2 THEN 'editor' ELSE 'viewer' END,
                    (SELECT COUNT(*) FROM applications a WHERE a.project_id = p.id),
                    (SELECT COUNT(*) FROM subscriptions s WHERE s.project_id = p.id),
                    (SELECT COUNT(*) FROM watchlist_entries w JOIN applications a ON a.id = w.app_id
                      WHERE a.project_id = p.id AND w.status = 'untreated'),
                    (SELECT MAX(day) FROM reports r WHERE r.project_id = p.id)
             FROM projects p
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             ORDER BY o.name, p.name",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(ProjectSummary {
                    id: r.get(0)?,
                    org: r.get(1)?,
                    name: r.get(2)?,
                    description: r.get(3)?,
                    role: r.get(4)?,
                    applications: r.get(5)?,
                    subscriptions: r.get(6)?,
                    untreated: r.get(7)?,
                    last_report: r.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Latest changes on CVEs matching the subscriptions of the user's
    /// projects (or of one project).
    pub fn recent_project_changes(
        &self,
        user_id: i64,
        project_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<ProjectChange>> {
        let mut stmt = self.conn().prepare(
            "SELECT o.name, p.name, ch.cve_id, ch.created_at, ch.events, c.cvss_v3_score
             FROM report_changes rc
             JOIN reports r ON r.id = rc.report_id
             JOIN cve_changes ch ON ch.id = rc.change_id
             JOIN projects p ON p.id = r.project_id
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_access pa ON pa.project_id = p.id AND pa.user_id = ?1
             LEFT JOIN cves c ON c.cve_id = ch.cve_id
             WHERE (?2 IS NULL OR p.id = ?2)
             ORDER BY ch.id DESC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![user_id, project_id, limit], |r| {
                Ok(ProjectChange {
                    org: r.get(0)?,
                    project: r.get(1)?,
                    cve_id: r.get(2)?,
                    created_at: r.get(3)?,
                    events: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                    cvss: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AffectedProduct, Application, Cve, CveStatus};
    use crate::rbac::Role;

    #[test]
    fn migration_from_v6_maps_member_to_editor() {
        // Rebuild a v6-shaped memberships table, then run the v7 migration again
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        db.conn()
            .execute_batch(
                "DROP VIEW project_access; DROP VIEW org_access;
                 DROP INDEX idx_users_oidc; DROP TABLE oidc_states;
                 DROP TRIGGER identity_project_deleted; DROP TRIGGER identity_organization_deleted;
                 ALTER TABLE users DROP COLUMN disabled; ALTER TABLE users DROP COLUMN oidc_subject;
                 ALTER TABLE users DROP COLUMN last_login_at;
                 DROP TABLE memberships;
                 CREATE TABLE memberships (organization_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','member')), PRIMARY KEY (organization_id, user_id));",
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO memberships VALUES (?1, ?2, 'owner'), (?1, ?3, 'member')",
                params![org, alice, bob],
            )
            .unwrap();
        db.migrate_access().unwrap();
        db.conn()
            .execute_batch(
                "CREATE VIEW org_access AS SELECT user_id, organization_id,
                    CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END AS rank FROM memberships;",
            )
            .unwrap();
        assert_eq!(db.get_org("acme", alice).unwrap().unwrap().role, "owner");
        assert_eq!(db.get_org("acme", bob).unwrap().unwrap().role, "editor");
    }

    #[test]
    fn disabled_accounts_lose_access_and_last_admin_is_protected() {
        let db = Database::open_in_memory().unwrap();
        let admin = db.create_account("root", None, "h", true).unwrap();
        let user = db.create_account("user", None, "h", false).unwrap();
        db.create_session(user, "s", 60).unwrap();
        db.create_api_token(user, "ci", "t").unwrap();

        db.set_disabled(user, true).unwrap();
        assert!(db.get_session_account("s").unwrap().is_none());
        assert!(db.get_token_account("t").unwrap().is_none());
        assert!(db.get_credentials("user").unwrap().is_none());
        db.set_disabled(user, false).unwrap();
        assert!(db.get_token_account("t").unwrap().is_some());
        assert!(db.get_credentials("user").unwrap().is_some());

        // The only administrator can be neither disabled nor demoted
        assert!(db.set_disabled(admin, true).is_err());
        assert!(db.set_admin(admin, false).is_err());
        assert!(db.get_credentials("root").unwrap().unwrap().0.is_admin);
        db.set_admin(user, true).unwrap();
        db.set_admin(admin, false).unwrap();
        assert!(db.set_admin(9999, true).is_err());

        let accounts = db.list_accounts().unwrap();
        assert_eq!(accounts.len(), 2); // the CLI `default` user is not an account
        assert!(accounts.iter().all(|a| a.has_password && !a.sso));
    }

    #[test]
    fn oidc_state_is_single_use_and_accounts_are_not_taken_over() {
        let db = Database::open_in_memory().unwrap();
        db.save_oidc_state("a", "st", "verifier", "nonce", 60).unwrap();
        assert_eq!(db.take_oidc_state("a", "st").unwrap(), Some(("verifier".into(), "nonce".into())));
        assert_eq!(db.take_oidc_state("a", "st").unwrap(), None);
        db.save_oidc_state("a", "old", "v", "n", -1).unwrap();
        assert_eq!(db.take_oidc_state("a", "old").unwrap(), None);
        // A state started with one provider cannot complete at another
        db.save_oidc_state("a", "mixed", "v", "n", 60).unwrap();
        assert_eq!(db.take_oidc_state("b", "mixed").unwrap(), None);
        assert_eq!(db.take_oidc_state("a", "mixed").unwrap(), None);

        db.create_account("alice", None, "h", false).unwrap();
        assert!(db.create_oidc_account("Alice", None, "sub-1", false, crate::db::Scope::Instance).is_err());
        assert!(db.find_oidc_account("sub-1").unwrap().is_none());

        let id = db.create_oidc_account("carol", Some("c@example.org"), "sub-2", false, crate::db::Scope::Instance).unwrap();
        let (account, disabled) = db.find_oidc_account("sub-2").unwrap().unwrap();
        assert_eq!((account.id, disabled), (id, false));
        assert!(db.get_credentials("carol").unwrap().is_none()); // no password login
        assert_eq!(db.count_accounts().unwrap(), 2);
        for i in 0..MAX_PENDING_LOGINS {
            db.save_oidc_state("a", &format!("s{i}"), "v", "n", 60).unwrap();
        }
        // A full table makes room instead of refusing: nobody can lock sign-in for everyone
        db.save_oidc_state("a", "overflow", "v", "n", 120).unwrap();
        let pending: i64 = db.conn().query_row("SELECT COUNT(*) FROM oidc_states", [], |r| r.get(0)).unwrap();
        assert_eq!(pending, MAX_PENDING_LOGINS);
        assert!(db.take_oidc_state("a", "overflow").unwrap().is_some());
        db.conn().execute("DELETE FROM oidc_states", []).unwrap();

        // Explicit linking of a local account, once; never an admin or a disabled one
        let root = db.create_account("root", None, "h", true).unwrap();
        assert!(db.link_oidc_account("root", "sub-r", crate::db::Scope::Instance).unwrap().is_none());
        let off = db.create_account("off", None, "h", false).unwrap();
        db.set_disabled(off, true).unwrap();
        assert!(db.link_oidc_account("off", "sub-o", crate::db::Scope::Instance).unwrap().is_none());
        assert!(db.find_oidc_account("sub-o").unwrap().is_none());
        assert!(db.link_oidc_account("alice", "sub-1", crate::db::Scope::Instance).unwrap().is_some());
        assert!(db.link_oidc_account("alice", "sub-9", crate::db::Scope::Instance).unwrap().is_none());
        assert!(db.link_oidc_account("default", "sub-8", crate::db::Scope::Instance).unwrap().is_none());

        db.sync_admin_flag(id, true).unwrap();
        assert!(db.get_account(id).unwrap().unwrap().is_admin);
        db.sync_admin_flag(id, false).unwrap();
        assert!(!db.get_account(id).unwrap().unwrap().is_admin);
        // The last administrator is kept whatever the provider says
        db.sync_admin_flag(root, false).unwrap();
        assert!(db.get_account(root).unwrap().unwrap().is_admin);
    }

    #[test]
    fn triage_is_scoped_to_member_projects() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        let other_org = db.create_org("other", bob).unwrap();
        let other_project = db.create_org_project(other_org, bob, "misc", None).unwrap();

        let mut cve = Cve::new("CVE-2024-7000".into());
        cve.description = Some("Flaw".into());
        cve.cvss_v3_score = Some(9.8);
        cve.kev_known_exploited = true;
        cve.affected_products.push(AffectedProduct {
            vendor: Some("acme".into()),
            product: Some("widget".into()),
            version: Some("*".into()),
            version_start: None,
            version_end: None,
            cpe: Some("cpe".into()),
            ..Default::default()
        });
        db.upsert_cve(&cve).unwrap();

        let mut app = Application::new(project, "widget".into());
        app.id = Some(db.create_application(&app).unwrap());
        assert_eq!(db.scan_app_for_cves(&app).unwrap().0, 1);

        let items = db.scoped_triage(alice, None, false, 10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].project.as_str(), items[0].kev), ("infra", true));
        let breakdown = db.watch_breakdown(alice, None).unwrap();
        assert_eq!(breakdown.len(), 1);
        assert_eq!(
            (breakdown[0].project_id, breakdown[0].status.as_str(), breakdown[0].severity.as_str(), breakdown[0].count),
            (project, "untreated", "critical", 1)
        );
        assert!(db.scoped_triage(bob, None, false, 10).unwrap().is_empty());
        assert!(db.watch_breakdown(bob, None).unwrap().is_empty());
        assert!(db.scoped_triage(alice, Some(other_project), false, 10).unwrap().is_empty());
        assert_eq!(db.scoped_applications(alice, None).unwrap()[0].untreated, 1);
        // A run left "running" by a stopped process no longer shows as in progress
        db.start_sync("nvd").unwrap();
        assert!(db.sync_status().unwrap().1);
        assert_eq!(db.fail_interrupted_syncs().unwrap(), 1);
        assert_eq!(db.sync_status().unwrap(), (None, false));
        assert!(db.scoped_applications(bob, Some(project)).unwrap().is_empty());
        assert_eq!(db.project_role(bob, project).unwrap(), None::<Role>);

        // An entry can only be changed through its own project
        let entry = items[0].entry_id;
        let actor = crate::db::Actor::user(alice, "alice");
        assert!(!db.set_watchlist_status(other_project, entry, CveStatus::Treated, &actor, None).unwrap());
        assert!(db.set_watchlist_status(project, entry, CveStatus::NotApplicable, &actor, None).unwrap());
        assert!(db.project_triage(project, false).unwrap().is_empty());
        assert_eq!(db.project_triage(project, true).unwrap()[0].status, "not_applicable");
        assert_eq!(db.watch_breakdown(alice, None).unwrap()[0].status, "not_applicable");

        let summary = &db.project_summaries(alice).unwrap()[0];
        assert_eq!((summary.applications, summary.untreated, summary.role.as_str()), (1, 0, "owner"));
        assert!(!db.delete_application_by_id(other_project, app.id.unwrap(), &actor).unwrap());
        assert!(db.delete_application_by_id(project, app.id.unwrap(), &actor).unwrap());
    }
}
