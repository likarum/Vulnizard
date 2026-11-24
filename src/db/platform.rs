//! Web platform database operations:
//! accounts, sessions, API tokens, organizations, project subscriptions,
//! notifications, change history, reports, tags and the vendor/CWE catalog.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::changes::Event;
use crate::db::Database;
use crate::rbac::{Permission, Role};

const PLATFORM_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS memberships (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner', 'member')),
    PRIMARY KEY (organization_id, user_id)
);

ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE projects ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(organization_id);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL DEFAULT '',
    UNIQUE (project_id, vendor, product)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('webhook', 'slack', 'email')),
    target TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    min_cvss REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS cve_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    events TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_cve ON cve_changes(cve_id);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    UNIQUE (project_id, day)
);

CREATE TABLE IF NOT EXISTS report_changes (
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    change_id INTEGER NOT NULL REFERENCES cve_changes(id) ON DELETE CASCADE,
    PRIMARY KEY (report_id, change_id)
);

CREATE TABLE IF NOT EXISTS cve_tags (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (user_id, cve_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_user_tag ON cve_tags(user_id, tag);

CREATE TABLE IF NOT EXISTS cve_cwes (
    cve_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe ON cve_cwes(cwe_id);

CREATE TABLE IF NOT EXISTS products (
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    cve_count INTEGER NOT NULL,
    PRIMARY KEY (vendor, product)
);

CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified_at);

-- Backfill weaknesses from the JSON column
INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id)
SELECT c.cve_id, j.value FROM cves c, json_each(c.cwe_ids) j
WHERE c.cwe_ids IS NOT NULL AND c.cwe_ids != '[]';

-- Existing CLI users owning projects get an organization of the same name
INSERT OR IGNORE INTO organizations (name)
SELECT username FROM users WHERE id IN (SELECT user_id FROM projects);
INSERT OR IGNORE INTO memberships (organization_id, user_id, role)
SELECT o.id, u.id, 'owner' FROM users u JOIN organizations o ON o.name = u.username
WHERE u.id IN (SELECT user_id FROM projects);
UPDATE projects SET organization_id = (
    SELECT o.id FROM organizations o JOIN users u ON u.username = o.name WHERE u.id = projects.user_id
) WHERE organization_id IS NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '6');
"#;

// ==========================================
// Types
// ==========================================

#[derive(Debug, Clone, Serialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Org {
    pub id: i64,
    pub name: String,
    pub role: String,
}

impl Org {
    /// Permission check; an unknown stored role grants nothing.
    pub fn can(&self, permission: Permission) -> bool {
        Role::parse(&self.role).is_some_and(|r| r.allows(permission))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Member {
    pub user_id: i64,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrgProject {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub subscriptions: i64,
}

#[derive(Debug, Clone)]
pub struct UserProject {
    pub id: i64,
    pub org: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subscription {
    pub id: i64,
    pub vendor: String,
    /// Empty string = whole vendor
    pub product: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    /// Id of the destination
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    /// Event types to notify; empty = none
    pub events: Vec<String>,
    pub min_cvss: Option<f64>,
    pub enabled: bool,
    /// What the destination belongs to: instance | organization | project
    pub scope: String,
    /// Settings of the destination (may hold an SMTP password): never serialized
    #[serde(skip)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeRow {
    pub id: i64,
    pub cve_id: String,
    pub created_at: String,
    pub events: Vec<Event>,
    pub cvss: Option<f64>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportInfo {
    pub day: String,
    pub changes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveSummary {
    pub cve_id: String,
    pub description: Option<String>,
    pub cvss: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
}


/// Shortest keyword searched in descriptions
pub const MIN_KEYWORD_CHARS: usize = 3;
/// Keyword searches running at once: each one reads every description
const MAX_KEYWORD_SEARCHES: usize = 4;
static KEYWORD_SEARCHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The server is doing as many costly operations of this kind as it accepts
#[derive(Debug)]
pub struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Too many searches are running, try again in a moment.")
    }
}

impl std::error::Error for Busy {}

/// One of the few places for a running keyword search, given back on drop
pub(crate) struct KeywordSlot(&'static std::sync::atomic::AtomicUsize);

impl KeywordSlot {
    fn take() -> Result<Self> {
        Self::take_from(&KEYWORD_SEARCHES)
    }

    pub(crate) fn take_from(running: &'static std::sync::atomic::AtomicUsize) -> Result<Self> {
        use std::sync::atomic::Ordering;
        let taken = running.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_KEYWORD_SEARCHES).then_some(n + 1));
        match taken {
            Ok(_) => Ok(KeywordSlot(running)),
            Err(_) => Err(Busy.into()),
        }
    }
}

impl Drop for KeywordSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Sources a CVE list can be narrowed to, with their label
pub const CVE_SOURCES: [(&str, &str); 8] = [
    ("nvd", "NVD"),
    ("cisa_kev", "CISA KEV"),
    ("epss", "EPSS"),
    ("vulnrichment", "Vulnrichment (SSVC)"),
    ("osv", "OSV packages"),
    ("exploitdb", "Exploit-DB"),
    ("metasploit", "Metasploit"),
    ("nuclei", "Nuclei templates"),
];

/// SQL condition selecting the CVEs a source has data on. Which source wrote
/// what is not recorded: it is told from the fields only that source fills.
/// `table` prefixes the columns of `cves` ("c." or "cves.").
pub fn source_condition(source: &str, table: &str) -> Option<String> {
    Some(match source {
        "nvd" => format!("{table}published_at IS NOT NULL"),
        "cisa_kev" => format!("{table}kev_known_exploited = 1"),
        "epss" => format!("{table}epss_score IS NOT NULL"),
        "vulnrichment" => format!(
            "({table}ssvc_exploitation IS NOT NULL OR {table}ssvc_automatable IS NOT NULL OR {table}ssvc_technical_impact IS NOT NULL)"
        ),
        "osv" => format!("EXISTS (SELECT 1 FROM affected_packages pkg WHERE pkg.cve_id = {table}cve_id)"),
        "exploitdb" => format!("({table}exploit_urls IS NOT NULL AND {table}exploit_urls NOT IN ('', '[]'))"),
        "metasploit" => format!("{table}metasploit_module IS NOT NULL"),
        "nuclei" => format!("{table}nuclei_template IS NOT NULL"),
        _ => return None,
    })
}

pub fn unknown_source(source: &str) -> String {
    let known: Vec<&str> = CVE_SOURCES.iter().map(|(key, _)| *key).collect();
    format!("Unknown source '{source}': one of {}.", known.join(", "))
}

#[derive(Debug, Clone, Default)]
pub struct CveFilter {
    pub search: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    /// none | low | medium | high | critical
    pub cvss: Option<String>,
    pub cwe: Option<String>,
    pub kev: bool,
    /// Only CVEs a given source has data on (see `source_condition`)
    pub source: Option<String>,
    /// (user id, tag)
    pub tag: Option<(i64, String)>,
    pub project_id: Option<i64>,
    /// Sort column: id | cvss | epss | published | updated (default)
    pub sort: Option<String>,
    /// Descending order (when a sort column is given)
    pub desc: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRun {
    pub source: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: String,
    pub added: i64,
    pub updated: i64,
    /// CVEs read again and found as they were
    pub same: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VendorInfo {
    pub vendor: String,
    pub products: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductInfo {
    pub product: String,
    pub cves: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WeaknessInfo {
    pub cwe_id: String,
    pub cves: i64,
}

/// A batch of changes to send through one notification channel
#[derive(Debug, Clone)]
pub struct Dispatch {
    pub notification: Notification,
    pub org: String,
    pub project: String,
    pub changes: Vec<ChangeRow>,
}

fn parse_events(json: &str) -> Vec<Event> {
    serde_json::from_str(json).unwrap_or_default()
}

// ==========================================
// Migration
// ==========================================

impl Database {
    /// Schema v6: web platform tables. Runs once (fresh DB or upgrade from v5).
    pub(super) fn migrate_platform(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(PLATFORM_SCHEMA)?;
        tx.commit()?;
        self.rebuild_catalog()?;
        Ok(())
    }

    /// Rebuilds the vendor/product catalog from the normalized products table
    pub fn rebuild_catalog(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(
            r#"
            DELETE FROM products;
            INSERT INTO products (vendor, product, cve_count)
            SELECT vendor, product, COUNT(DISTINCT cve_id)
            FROM affected_products_normalized
            WHERE vendor IS NOT NULL AND vendor != '' AND product IS NOT NULL AND product != ''
            GROUP BY vendor, product;
            "#,
        )?;
        tx.commit()?;
        Ok(())
    }
}

// ==========================================
// Accounts, sessions, API tokens
// ==========================================

impl Database {
    /// Number of accounts able to log in
    pub fn count_accounts(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM users WHERE password_hash IS NOT NULL OR oidc_subject IS NOT NULL OR provisioned != 0",
            [],
            |r| r.get(0),
        )?)
    }

    /// Creates a login account. Admins also become owners of the CLI
    /// `default` organization so its projects are reachable from the web UI.
    pub fn create_account(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        is_admin: bool,
    ) -> Result<i64> {
        let exists: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
            params![username],
            |r| r.get(0),
        )?;
        if exists || crate::auth::is_reserved_username(username) {
            return Err(anyhow!("Username already taken"));
        }
        self.conn().execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?1, ?2, ?3, ?4)",
            params![username, email, password_hash, is_admin as i32],
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
    }

    /// Self-registration: the first account able to log in becomes admin.
    /// Runs under a write lock so that two concurrent first registrations
    /// cannot both be granted administrator rights.
    pub fn register_account(&self, username: &str, email: Option<&str>, password_hash: &str) -> Result<i64> {
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        // Registration never creates the first account, hence never an administrator: the
        // first account takes the setup code or the command line
        let result = self.count_accounts().and_then(|n| {
            if n == 0 {
                return Err(anyhow::Error::new(super::watchlist::UserFacing(
                    "This instance is not set up yet: create its administrator first.".into(),
                )));
            }
            self.create_account(username, email, password_hash, false)
        });
        match &result {
            Ok(_) => self.conn().execute_batch("COMMIT")?,
            Err(_) => self.conn().execute_batch("ROLLBACK")?,
        }
        result
    }

    pub fn set_password(&self, user_id: i64, password_hash: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET password_hash = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![password_hash, user_id],
        )?;
        // Changing the password invalidates every session and API token
        self.conn()
            .execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        self.conn()
            .execute("DELETE FROM api_tokens WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }

    /// Returns the account and its password hash
    pub fn get_credentials(&self, username: &str) -> Result<Option<(Account, String)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, username, is_admin, password_hash FROM users
                 WHERE username = ?1 COLLATE NOCASE AND password_hash IS NOT NULL AND disabled = 0",
                params![username],
                |r| {
                    Ok((
                        Account {
                            id: r.get(0)?,
                            username: r.get(1)?,
                            is_admin: r.get::<_, i64>(2)? != 0,
                        },
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?)
    }

    pub fn create_session(&self, user_id: i64, token_hash: &str, ttl_secs: i64) -> Result<()> {
        self.conn().execute(
            "DELETE FROM sessions WHERE expires_at < CAST(strftime('%s','now') AS INTEGER)",
            [],
        )?;
        self.conn().execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at)
             VALUES (?1, ?2, CAST(strftime('%s','now') AS INTEGER) + ?3)",
            params![token_hash, user_id, ttl_secs],
        )?;
        self.conn().execute(
            "UPDATE users SET last_login_at = datetime('now') WHERE id = ?1",
            params![user_id],
        )?;
        Ok(())
    }

    pub fn get_session_account(&self, token_hash: &str) -> Result<Option<Account>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT u.id, u.username, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND u.disabled = 0
                   AND s.expires_at > CAST(strftime('%s','now') AS INTEGER)",
                params![token_hash],
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

    pub fn delete_session(&self, token_hash: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM sessions WHERE token_hash = ?1", params![token_hash])?;
        Ok(())
    }

    pub fn create_api_token(&self, user_id: i64, name: &str, token_hash: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO api_tokens (user_id, name, token_hash) VALUES (?1, ?2, ?3)",
            params![user_id, name, token_hash],
        )?;
        Ok(())
    }

    pub fn list_api_tokens(&self, user_id: i64) -> Result<Vec<ApiToken>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, created_at, last_used_at FROM api_tokens WHERE user_id = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(ApiToken {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    created_at: r.get(2)?,
                    last_used_at: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_api_token(&self, user_id: i64, id: i64) -> Result<()> {
        self.conn().execute(
            "DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        Ok(())
    }

    pub fn get_token_account(&self, token_hash: &str) -> Result<Option<Account>> {
        let account = self
            .conn()
            .query_row(
                "SELECT u.id, u.username, u.is_admin FROM api_tokens t JOIN users u ON u.id = t.user_id
                 WHERE t.token_hash = ?1 AND u.disabled = 0",
                params![token_hash],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        is_admin: r.get::<_, i64>(2)? != 0,
                    })
                },
            )
            .optional()?;
        if account.is_some() {
            self.conn().execute(
                "UPDATE api_tokens SET last_used_at = datetime('now') WHERE token_hash = ?1",
                params![token_hash],
            )?;
        }
        Ok(account)
    }
}

// ==========================================
// Organizations & projects
// ==========================================

impl Database {
    pub fn create_org(&self, name: &str, owner_id: i64) -> Result<i64> {
        // An account coming from an organization or a project holds no right outside it
        if self.user_origin(owner_id)? != super::Scope::Instance {
            return Err(anyhow!("This account cannot create organizations"));
        }
        let tx = self.write_tx()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM organizations WHERE name = ?1 COLLATE NOCASE)",
            params![name],
            |r| r.get(0),
        )?;
        // CLI projects are attached to the organization named after their
        // user: such a name must never be claimable from the web UI.
        let shadows_user: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
            params![name],
            |r| r.get(0),
        )?;
        if exists || shadows_user {
            return Err(anyhow!("Organization name already taken"));
        }
        tx.execute("INSERT INTO organizations (name) VALUES (?1)", params![name])?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO memberships (organization_id, user_id, role) VALUES (?1, ?2, 'owner')",
            params![id, owner_id],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Organizations the user has a role on (membership or instance role)
    pub fn list_orgs(&self, user_id: i64) -> Result<Vec<Org>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT o.id, o.name, {role} FROM organizations o
             JOIN org_access a ON a.organization_id = o.id
             WHERE a.user_id = ?1 ORDER BY o.name",
            role = super::roles::role_of("a.rank")
        ))?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(Org {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    role: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the organization only if the user has a role on it. A role
    /// limited to one of its projects does not give access to the organization.
    pub fn get_org(&self, name: &str, user_id: i64) -> Result<Option<Org>> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT o.id, o.name, {role} FROM organizations o
                     JOIN org_access a ON a.organization_id = o.id
                     WHERE o.name = ?1 AND a.user_id = ?2",
                    role = super::roles::role_of("a.rank")
                ),
                params![name, user_id],
                |r| {
                    Ok(Org {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        role: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn delete_org(&self, org_id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM organizations WHERE id = ?1", params![org_id])?;
        Ok(())
    }

    pub fn list_members(&self, org_id: i64) -> Result<Vec<Member>> {
        let mut stmt = self.conn().prepare(
            "SELECT u.id, u.username, m.role FROM memberships m JOIN users u ON u.id = m.user_id
             WHERE m.organization_id = ?1 ORDER BY u.username",
        )?;
        let rows = stmt
            .query_map(params![org_id], |r| {
                Ok(Member {
                    user_id: r.get(0)?,
                    username: r.get(1)?,
                    role: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn add_member(&self, org_id: i64, username: &str, role: &str) -> Result<()> {
        // One transaction: a refused change (last owner demoted) is rolled back
        let tx = self.write_tx()?;
        let user_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM users WHERE username = ?1 COLLATE NOCASE
                   AND (password_hash IS NOT NULL OR oidc_subject IS NOT NULL OR provisioned != 0)",
                params![username],
                |r| r.get(0),
            )
            .optional()?;
        let user_id = user_id.ok_or_else(|| anyhow!("Unknown user"))?;
        let role = Role::parse(role).ok_or_else(|| anyhow!("Unknown role"))?;
        grant_org_role(&tx, org_id, user_id, role)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_member(&self, org_id: i64, user_id: i64) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute(
            "DELETE FROM memberships WHERE organization_id = ?1 AND user_id = ?2",
            params![org_id, user_id],
        )?;
        let owners: i64 = tx.query_row(
            "SELECT COUNT(*) FROM memberships WHERE organization_id = ?1 AND role = 'owner'",
            params![org_id],
            |r| r.get(0),
        )?;
        if owners == 0 {
            return Err(anyhow!("An organization must keep at least one owner"));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn create_org_project(
        &self,
        org_id: i64,
        user_id: i64,
        name: &str,
        description: Option<&str>,
    ) -> Result<i64> {
        let exists: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE name = ?1 AND (organization_id = ?2 OR user_id = ?3))",
            params![name, org_id, user_id],
            |r| r.get(0),
        )?;
        if exists {
            return Err(anyhow!("Project name already used"));
        }
        self.conn().execute(
            "INSERT INTO projects (user_id, organization_id, name, description) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, org_id, name, description],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn list_org_projects(&self, org_id: i64) -> Result<Vec<OrgProject>> {
        let mut stmt = self.conn().prepare(
            "SELECT p.id, p.name, p.description,
                    (SELECT COUNT(*) FROM subscriptions s WHERE s.project_id = p.id)
             FROM projects p WHERE p.organization_id = ?1 ORDER BY p.name",
        )?;
        let rows = stmt
            .query_map(params![org_id], |r| {
                Ok(OrgProject {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    subscriptions: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every project the user can access, across organizations
    pub fn list_user_projects(&self, user_id: i64) -> Result<Vec<UserProject>> {
        let mut stmt = self.conn().prepare(
            "SELECT p.id, o.name, p.name FROM projects p
             JOIN organizations o ON o.id = p.organization_id
             JOIN project_access pa ON pa.project_id = p.id
             WHERE pa.user_id = ?1 ORDER BY o.name, p.name",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(UserProject {
                    id: r.get(0)?,
                    org: r.get(1)?,
                    name: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every project of every organization (local, unauthenticated access: MCP)
    pub fn list_all_projects(&self) -> Result<Vec<UserProject>> {
        let mut stmt = self.conn().prepare(
            "SELECT p.id, o.name, p.name FROM projects p
             JOIN organizations o ON o.id = p.organization_id ORDER BY o.name, p.name",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(UserProject {
                    id: r.get(0)?,
                    org: r.get(1)?,
                    name: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Project id from its organization and name, without membership check
    pub fn find_project(&self, org: &str, name: &str) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT p.id FROM projects p JOIN organizations o ON o.id = p.organization_id
                 WHERE o.name = ?1 AND p.name = ?2",
                params![org, name],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Effective role of the user on the project (instance, organization or project level)
    pub fn project_role(&self, user_id: i64, project_id: i64) -> Result<Option<Role>> {
        let role: Option<String> = self
            .conn()
            .query_row(
                &format!(
                    "SELECT {role} FROM project_access pa WHERE pa.project_id = ?1 AND pa.user_id = ?2",
                    role = super::roles::role_of("pa.rank")
                ),
                params![project_id, user_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(role.as_deref().and_then(Role::parse))
    }
}

/// Gives (or changes) the role of an account on an organization, inside the
/// transaction of the caller: refused, for the caller to roll back, when it
/// would leave the organization without an owner. The one way a member form
/// or an accepted invitation gives a role.
pub(super) fn grant_org_role(conn: &rusqlite::Connection, org_id: i64, user_id: i64, role: Role) -> Result<()> {
    conn.execute(
        "INSERT INTO memberships (organization_id, user_id, role) VALUES (?1, ?2, ?3)
         ON CONFLICT(organization_id, user_id) DO UPDATE SET role = excluded.role",
        params![org_id, user_id, role.as_str()],
    )?;
    let owners: i64 = conn.query_row(
        "SELECT COUNT(*) FROM memberships WHERE organization_id = ?1 AND role = 'owner'",
        params![org_id],
        |r| r.get(0),
    )?;
    if owners == 0 {
        return Err(anyhow!("An organization must keep at least one owner"));
    }
    Ok(())
}

// ==========================================
// Subscriptions & notifications
// ==========================================

impl Database {
    pub fn subscribe(&self, project_id: i64, vendor: &str, product: &str) -> Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO subscriptions (project_id, vendor, product) VALUES (?1, ?2, ?3)",
            params![project_id, vendor, product],
        )?;
        Ok(())
    }

    pub fn unsubscribe(&self, project_id: i64, vendor: &str, product: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM subscriptions WHERE project_id = ?1 AND vendor = ?2 AND product = ?3",
            params![project_id, vendor, product],
        )?;
        Ok(())
    }

    pub fn list_subscriptions(&self, project_id: i64) -> Result<Vec<Subscription>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, vendor, product FROM subscriptions WHERE project_id = ?1 ORDER BY vendor, product",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| {
                Ok(Subscription {
                    id: r.get(0)?,
                    vendor: r.get(1)?,
                    product: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

// ==========================================
// Change history, reports, notification pipeline
// ==========================================

const CHANGES_MARKER: &str = "changes_marker";

impl Database {
    pub fn list_cve_changes(&self, cve_id: &str) -> Result<Vec<ChangeRow>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, cve_id, created_at, events FROM cve_changes WHERE cve_id = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt
            .query_map(params![cve_id], |r| {
                Ok(ChangeRow {
                    id: r.get(0)?,
                    cve_id: r.get(1)?,
                    created_at: r.get(2)?,
                    events: parse_events(&r.get::<_, String>(3)?),
                    cvss: None,
                    description: None,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_reports(&self, project_id: i64, limit: i64) -> Result<Vec<ReportInfo>> {
        let mut stmt = self.conn().prepare(
            "SELECT r.day, (SELECT COUNT(*) FROM report_changes rc WHERE rc.report_id = r.id)
             FROM reports r WHERE r.project_id = ?1 ORDER BY r.day DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![project_id, limit], |r| {
                Ok(ReportInfo {
                    day: r.get(0)?,
                    changes: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_report(&self, project_id: i64, day: &str) -> Result<Option<Vec<ChangeRow>>> {
        let report_id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM reports WHERE project_id = ?1 AND day = ?2",
                params![project_id, day],
                |r| r.get(0),
            )
            .optional()?;
        let Some(report_id) = report_id else {
            return Ok(None);
        };
        let mut stmt = self.conn().prepare(
            "SELECT ch.id, ch.cve_id, ch.created_at, ch.events, c.cvss_v3_score, c.description
             FROM report_changes rc
             JOIN cve_changes ch ON ch.id = rc.change_id
             LEFT JOIN cves c ON c.cve_id = ch.cve_id
             WHERE rc.report_id = ?1 ORDER BY ch.id DESC",
        )?;
        let rows = stmt
            .query_map(params![report_id], |r| {
                Ok(ChangeRow {
                    id: r.get(0)?,
                    cve_id: r.get(1)?,
                    created_at: r.get(2)?,
                    events: parse_events(&r.get::<_, String>(3)?),
                    cvss: r.get(4)?,
                    description: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Some(rows))
    }

    /// Routes the changes recorded since the last run to the subscribed
    /// projects: fills the daily reports and returns the notifications to send.
    ///
    /// The first run only sets the marker, so that the history imported before
    /// the platform was enabled never triggers notifications.
    pub fn process_changes(&self) -> Result<Vec<Dispatch>> {
        let max_id: i64 =
            self.conn()
                .query_row("SELECT COALESCE(MAX(id), 0) FROM cve_changes", [], |r| r.get(0))?;
        let marker = match self.get_metadata(CHANGES_MARKER)? {
            Some(m) => m.parse::<i64>().unwrap_or(0),
            None => {
                self.set_metadata(CHANGES_MARKER, &max_id.to_string())?;
                return Ok(Vec::new());
            }
        };
        if max_id <= marker {
            return Ok(Vec::new());
        }

        let tx = self.write_tx()?;
        let mut per_project: BTreeMap<i64, Vec<ChangeRow>> = BTreeMap::new();
        {
            let mut changes = tx.prepare(
                "SELECT ch.id, ch.cve_id, ch.created_at, ch.events, c.cvss_v3_score, c.description
                 FROM cve_changes ch LEFT JOIN cves c ON c.cve_id = ch.cve_id
                 WHERE ch.id > ?1 AND ch.id <= ?2 ORDER BY ch.id",
            )?;
            let mut projects = tx.prepare(
                "SELECT DISTINCT s.project_id FROM subscriptions s
                 JOIN affected_products_normalized ap
                   ON ap.vendor = s.vendor AND (s.product = '' OR ap.product = s.product)
                 WHERE ap.cve_id = ?1",
            )?;
            let mut upsert_report = tx.prepare(
                "INSERT INTO reports (project_id, day) VALUES (?1, ?2)
                 ON CONFLICT(project_id, day) DO UPDATE SET day = excluded.day RETURNING id",
            )?;
            let mut link =
                tx.prepare("INSERT OR IGNORE INTO report_changes (report_id, change_id) VALUES (?1, ?2)")?;

            let rows = changes
                .query_map(params![marker, max_id], |r| {
                    Ok(ChangeRow {
                        id: r.get(0)?,
                        cve_id: r.get(1)?,
                        created_at: r.get(2)?,
                        events: parse_events(&r.get::<_, String>(3)?),
                        cvss: r.get(4)?,
                        description: r.get(5)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            for change in rows {
                let project_ids = projects
                    .query_map(params![change.cve_id], |r| r.get::<_, i64>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let day = change.created_at.get(..10).unwrap_or(&change.created_at).to_string();
                for project_id in project_ids {
                    let report_id: i64 =
                        upsert_report.query_row(params![project_id, day], |r| r.get(0))?;
                    link.execute(params![report_id, change.id])?;
                    per_project.entry(project_id).or_default().push(change.clone());
                }
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![CHANGES_MARKER, max_id.to_string()],
        )?;
        tx.commit()?;

        let mut dispatches = Vec::new();
        for (project_id, changes) in per_project {
            let (org, project): (String, String) = self.conn().query_row(
                "SELECT COALESCE(o.name, ''), p.name FROM projects p
                 LEFT JOIN organizations o ON o.id = p.organization_id WHERE p.id = ?1",
                params![project_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            // Each destination covering the project, once: a change leaves once per destination
            for notification in self.list_notifications(project_id)? {
                if !notification.enabled {
                    continue;
                }
                let matching: Vec<ChangeRow> = changes
                    .iter()
                    .filter(|c| notification_matches(&notification, c))
                    .cloned()
                    .collect();
                if !matching.is_empty() {
                    dispatches.push(Dispatch {
                        notification,
                        org: org.clone(),
                        project: project.clone(),
                        changes: matching,
                    });
                }
            }
        }
        Ok(dispatches)
    }
}

fn notification_matches(n: &Notification, change: &ChangeRow) -> bool {
    // No event type chosen: the destination sends nothing
    let event_ok = change.events.iter().any(|e| n.events.iter().any(|k| k == e.kind()));
    let cvss_ok = match n.min_cvss {
        Some(min) if min > 0.0 => change.cvss.is_some_and(|s| s >= min),
        _ => true,
    };
    event_ok && cvss_ok
}

// ==========================================
// Tags
// ==========================================

impl Database {
    pub fn add_tag(&self, user_id: i64, cve_id: &str, tag: &str) -> Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO cve_tags (user_id, cve_id, tag) VALUES (?1, ?2, ?3)",
            params![user_id, cve_id, tag],
        )?;
        Ok(())
    }

    pub fn remove_tag(&self, user_id: i64, cve_id: &str, tag: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM cve_tags WHERE user_id = ?1 AND cve_id = ?2 AND tag = ?3",
            params![user_id, cve_id, tag],
        )?;
        Ok(())
    }

    pub fn list_cve_tags(&self, user_id: i64, cve_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT tag FROM cve_tags WHERE user_id = ?1 AND cve_id = ?2 ORDER BY tag")?;
        let rows = stmt
            .query_map(params![user_id, cve_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    pub fn list_user_tags(&self, user_id: i64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT DISTINCT tag FROM cve_tags WHERE user_id = ?1 ORDER BY tag")?;
        let rows = stmt
            .query_map(params![user_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }
}

// ==========================================
// Catalog & CVE listing
// ==========================================

impl Database {
    pub fn list_vendors(&self, search: Option<&str>, limit: i64, offset: i64) -> Result<Vec<VendorInfo>> {
        self.list_vendors_sorted(search, "vendor", false, limit, offset)
    }

    /// Vendors sorted by name (`vendor`) or number of products (`products`)
    pub fn list_vendors_sorted(
        &self,
        search: Option<&str>,
        sort: &str,
        desc: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<VendorInfo>> {
        let direction = if desc { "DESC" } else { "ASC" };
        let order = match sort {
            "products" => format!("COUNT(*) {direction}, vendor"),
            _ => format!("vendor {direction}"),
        };
        let mut stmt = self.conn().prepare(&format!(
            "SELECT vendor, COUNT(*) FROM products
             WHERE (?1 IS NULL OR instr(vendor, ?1) > 0)
             GROUP BY vendor ORDER BY {order} LIMIT ?2 OFFSET ?3"
        ))?;
        let search = search.map(|s| s.to_lowercase());
        let rows = stmt
            .query_map(params![search, limit, offset], |r| {
                Ok(VendorInfo {
                    vendor: r.get(0)?,
                    products: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_products(&self, vendor: &str) -> Result<Vec<ProductInfo>> {
        let mut stmt = self.conn().prepare(
            "SELECT product, cve_count FROM products WHERE vendor = ?1 ORDER BY cve_count DESC, product",
        )?;
        let rows = stmt
            .query_map(params![vendor], |r| {
                Ok(ProductInfo {
                    product: r.get(0)?,
                    cves: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_weaknesses(&self, limit: i64, offset: i64) -> Result<Vec<WeaknessInfo>> {
        self.list_weaknesses_sorted(None, "cves", true, limit, offset)
    }

    /// Weaknesses sorted by identifier (`cwe`) or number of CVEs (`cves`)
    pub fn list_weaknesses_sorted(
        &self,
        search: Option<&str>,
        sort: &str,
        desc: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WeaknessInfo>> {
        let direction = if desc { "DESC" } else { "ASC" };
        let order = match sort {
            // Numeric order of the identifier: CWE-79 before CWE-100
            "cwe" => format!("CAST(substr(cwe_id, 5) AS INTEGER) {direction}, cwe_id"),
            _ => format!("n {direction}, cwe_id"),
        };
        let mut stmt = self.conn().prepare(&format!(
            "SELECT cwe_id, COUNT(*) AS n FROM cve_cwes
             WHERE (?1 IS NULL OR instr(lower(cwe_id), ?1) > 0)
             GROUP BY cwe_id ORDER BY {order} LIMIT ?2 OFFSET ?3"
        ))?;
        let search = search.map(|s| s.to_lowercase());
        let rows = stmt
            .query_map(params![search, limit, offset], |r| {
                Ok(WeaknessInfo {
                    cwe_id: r.get(0)?,
                    cves: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists CVEs (most recently modified first). Stub entries without
    /// description (EPSS-only) are never listed.
    pub fn list_cves(&self, filter: &CveFilter, limit: i64, offset: i64) -> Result<Vec<CveSummary>> {
        let mut sql = String::from(
            "SELECT c.cve_id, c.description, c.cvss_v3_score, c.epss_score, c.kev_known_exploited,
                    c.published_at, c.modified_at
             FROM cves c WHERE c.description IS NOT NULL",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        // Held until the query has run
        let mut _keyword_slot: Option<KeywordSlot> = None;

        if let Some(search) = filter.search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let upper = search.to_uppercase();
            let is_id_prefix = upper.starts_with("CVE-")
                && upper.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
            if is_id_prefix {
                sql.push_str(" AND c.cve_id GLOB ?");
                args.push(Box::new(format!("{}*", upper)));
            } else {
                // No index serves a keyword: every description is read. Keep it rare and short.
                if search.chars().count() < MIN_KEYWORD_CHARS {
                    return Err(super::watchlist::UserFacing(format!("A keyword needs at least {MIN_KEYWORD_CHARS} characters.")).into());
                }
                _keyword_slot = Some(KeywordSlot::take()?);
                sql.push_str(" AND instr(lower(c.description), ?) > 0");
                args.push(Box::new(search.to_lowercase()));
            }
        }
        match (filter.vendor.as_deref(), filter.product.as_deref()) {
            (Some(vendor), Some(product)) => {
                sql.push_str(
                    " AND c.cve_id IN (SELECT cve_id FROM affected_products_normalized WHERE vendor = ? AND product = ?)",
                );
                args.push(Box::new(vendor.to_string()));
                args.push(Box::new(product.to_string()));
            }
            (Some(vendor), None) => {
                sql.push_str(" AND c.cve_id IN (SELECT cve_id FROM affected_products_normalized WHERE vendor = ?)");
                args.push(Box::new(vendor.to_string()));
            }
            // A product alone: whatever its vendor
            (None, Some(product)) => {
                sql.push_str(" AND c.cve_id IN (SELECT cve_id FROM affected_products_normalized WHERE product = ?)");
                args.push(Box::new(product.to_string()));
            }
            (None, None) => {}
        }
        match filter.cvss.as_deref() {
            Some("none") => sql.push_str(" AND c.cvss_v3_score IS NULL"),
            Some("low") => sql.push_str(" AND c.cvss_v3_score > 0 AND c.cvss_v3_score < 4.0"),
            Some("medium") => sql.push_str(" AND c.cvss_v3_score >= 4.0 AND c.cvss_v3_score < 7.0"),
            Some("high") => sql.push_str(" AND c.cvss_v3_score >= 7.0 AND c.cvss_v3_score < 9.0"),
            Some("critical") => sql.push_str(" AND c.cvss_v3_score >= 9.0"),
            _ => {}
        }
        if let Some(cwe) = &filter.cwe {
            sql.push_str(" AND c.cve_id IN (SELECT cve_id FROM cve_cwes WHERE cwe_id = ?)");
            args.push(Box::new(cwe.clone()));
        }
        if filter.kev {
            sql.push_str(" AND c.kev_known_exploited = 1");
        }
        if let Some(source) = &filter.source {
            let condition = source_condition(source, "c.").ok_or_else(|| anyhow::Error::new(super::watchlist::UserFacing(unknown_source(source))))?;
            sql.push_str(" AND ");
            sql.push_str(&condition);
        }
        if let Some((user_id, tag)) = &filter.tag {
            sql.push_str(" AND c.cve_id IN (SELECT cve_id FROM cve_tags WHERE user_id = ? AND tag = ?)");
            args.push(Box::new(*user_id));
            args.push(Box::new(tag.clone()));
        }
        if let Some(project_id) = filter.project_id {
            sql.push_str(
                " AND c.cve_id IN (SELECT ap.cve_id FROM subscriptions s
                    JOIN affected_products_normalized ap
                      ON ap.vendor = s.vendor AND (s.product = '' OR ap.product = s.product)
                    WHERE s.project_id = ?)",
            );
            args.push(Box::new(project_id));
        }
        // The column is chosen among constants: nothing from the request reaches the SQL
        let column = match filter.sort.as_deref() {
            Some("id") => Some("c.cve_id"),
            Some("cvss") => Some("c.cvss_v3_score"),
            Some("epss") => Some("c.epss_score"),
            Some("published") => Some("c.published_at"),
            Some("updated") => Some("c.modified_at"),
            _ => None,
        };
        match column {
            Some(column) => {
                let direction = if filter.desc { "DESC" } else { "ASC" };
                sql.push_str(&format!(" ORDER BY {column} {direction} NULLS LAST, c.cve_id DESC"));
            }
            None => sql.push_str(" ORDER BY c.modified_at DESC, c.cve_id DESC"),
        }
        sql.push_str(" LIMIT ? OFFSET ?");
        args.push(Box::new(limit));
        args.push(Box::new(offset));

        let mut stmt = self.conn().prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |r| {
                Ok(CveSummary {
                    cve_id: r.get(0)?,
                    description: r.get(1)?,
                    cvss: r.get(2)?,
                    epss: r.get(3)?,
                    kev: r.get::<_, Option<i64>>(4)?.unwrap_or(0) != 0,
                    published_at: r.get(5)?,
                    modified_at: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn recent_syncs(&self, limit: i64) -> Result<Vec<SyncRun>> {
        let mut stmt = self.conn().prepare(
            "SELECT source, started_at, completed_at, status, cves_added, cves_updated, error_message, cves_unchanged
             FROM sync_history ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(SyncRun {
                    source: r.get(0)?,
                    started_at: r.get(1)?,
                    completed_at: r.get(2)?,
                    status: r.get(3)?,
                    added: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    updated: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    same: r.get::<_, Option<i64>>(7)?.unwrap_or(0),
                    error: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AffectedProduct, Cve};

    fn product(vendor: &str, product: &str, cpe: bool) -> AffectedProduct {
        AffectedProduct {
            vendor: Some(vendor.into()),
            product: Some(product.into()),
            version: Some("*".into()),
            version_start: None,
            version_end: None,
            cpe: cpe.then(|| format!("cpe:2.3:a:{vendor}:{product}:*")),
            ..Default::default()
        }
    }

    fn cve(id: &str, cvss: Option<f64>) -> Cve {
        let mut cve = Cve::new(id.into());
        cve.description = Some(format!("Description of {id}"));
        cve.cvss_v3_score = cvss;
        cve.affected_products.push(product("apache", "httpd", true));
        cve
    }

    fn kinds(db: &Database, id: &str) -> Vec<Vec<&'static str>> {
        let mut changes = db.list_cve_changes(id).unwrap();
        changes.reverse();
        changes
            .iter()
            .map(|c| c.events.iter().map(|e| e.kind()).collect())
            .collect()
    }

    #[test]
    fn upsert_records_changes_only_when_something_changed() {
        let db = Database::open_in_memory().unwrap();
        db.upsert_cve(&cve("CVE-2024-0001", Some(5.0))).unwrap();
        db.upsert_cve(&cve("CVE-2024-0001", Some(5.0))).unwrap();
        assert_eq!(kinds(&db, "CVE-2024-0001"), vec![vec!["created"]]);

        db.upsert_cve(&cve("CVE-2024-0001", Some(9.8))).unwrap();
        assert_eq!(kinds(&db, "CVE-2024-0001"), vec![vec!["created"], vec!["metrics"]]);
    }

    #[test]
    fn epss_only_stub_is_not_a_change() {
        let db = Database::open_in_memory().unwrap();
        let mut stub = Cve::new("CVE-2024-0002".into());
        stub.epss_score = Some(0.5);
        db.upsert_cve(&stub).unwrap();
        assert!(kinds(&db, "CVE-2024-0002").is_empty());

        // The stub becoming a real CVE is its creation
        db.upsert_cve(&cve("CVE-2024-0002", None)).unwrap();
        assert_eq!(kinds(&db, "CVE-2024-0002"), vec![vec!["created"]]);
    }

    #[test]
    fn kev_flag_is_tracked_and_keeps_cpe_products() {
        let db = Database::open_in_memory().unwrap();
        db.upsert_cve(&cve("CVE-2024-0003", Some(7.0))).unwrap();

        let mut kev = Cve::new("CVE-2024-0003".into());
        kev.kev_known_exploited = true;
        kev.affected_products.push(product("apache_foundation", "http_server", false));
        db.upsert_cve(&kev).unwrap();

        assert_eq!(kinds(&db, "CVE-2024-0003"), vec![vec!["created"], vec!["kev"]]);
        let stored = db.get_cve("CVE-2024-0003").unwrap().unwrap();
        assert_eq!(stored.affected_products.len(), 1);
        assert_eq!(stored.affected_products[0].vendor.as_deref(), Some("apache"));
    }

    #[test]
    fn organizations_are_isolated_between_users() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "hash", true).unwrap();
        let bob = db.create_account("bob", None, "hash", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();

        assert!(db.get_org("acme", alice).unwrap().is_some());
        assert!(db.get_org("acme", bob).unwrap().is_none());
        assert_eq!(db.project_role(alice, project).unwrap(), Some(Role::Owner));
        assert_eq!(db.project_role(bob, project).unwrap(), None);
        assert!(db.list_user_projects(bob).unwrap().is_empty());

        assert!(db.create_org("ACME", bob).is_err());
        assert!(db.create_account("Alice", None, "hash", false).is_err());
        assert!(db.create_account("System", None, "hash", false).is_err());

        // The last owner cannot be removed nor demoted
        assert!(db.remove_member(org, alice).is_err());
        assert!(db.add_member(org, "alice", "editor").is_err());
        assert!(db.get_org("acme", alice).unwrap().unwrap().can(Permission::ManageMembers));
        // An organization cannot take the name of an existing user
        assert!(db.create_org("bob", alice).is_err());
        assert!(db.create_org("default", alice).is_err());
        db.add_member(org, "bob", "viewer").unwrap();
        assert!(db.add_member(org, "bob", "member").is_err());
        assert_eq!(db.project_role(bob, project).unwrap(), Some(Role::Viewer));
        assert!(db.get_org("acme", bob).unwrap().is_some_and(|o| !o.can(Permission::Triage)));
    }

    #[test]
    fn registration_never_makes_an_administrator_and_password_change_revokes_tokens() {
        let db = Database::open_in_memory().unwrap();
        // Nobody registers into an instance that has no administrator yet
        assert!(db.register_account("eve", None, "hash").unwrap_err().to_string().contains("not set up"));
        assert_eq!(db.count_accounts().unwrap(), 0);
        let first = db.create_first_administrator("first", None, "hash").unwrap();
        let second = db.register_account("second", None, "hash").unwrap();
        assert!(db.get_credentials("first").unwrap().unwrap().0.is_admin);
        assert!(!db.get_credentials("second").unwrap().unwrap().0.is_admin);
        assert!(db.register_account("FIRST", None, "hash").is_err());

        db.create_api_token(first, "ci", "tokenhash").unwrap();
        db.create_session(first, "sessionhash", 60).unwrap();
        db.create_api_token(second, "ci", "other").unwrap();
        db.set_password(first, "newhash").unwrap();
        assert!(db.get_token_account("tokenhash").unwrap().is_none());
        assert!(db.get_session_account("sessionhash").unwrap().is_none());
        assert!(db.get_token_account("other").unwrap().is_some());
    }

    #[test]
    fn admin_gets_access_to_cli_default_organization() {
        let db = Database::open_in_memory().unwrap();
        let admin = db.create_account("root", None, "hash", true).unwrap();
        let orgs = db.list_orgs(admin).unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].name, "default");
        assert_eq!(db.list_org_projects(orgs[0].id).unwrap()[0].name, "default");
    }

    /// (organization/project, destination, CVEs) of each batch, in the order they leave
    fn sent(dispatches: &[Dispatch]) -> Vec<(String, String, Vec<String>)> {
        dispatches
            .iter()
            .map(|d| (format!("{}/{}", d.org, d.project), d.notification.name.clone(), d.changes.iter().map(|c| c.cve_id.clone()).collect()))
            .collect()
    }

    #[test]
    fn destinations_receive_the_changes_of_the_projects_they_cover_without_any_rule() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "hash", false).unwrap();
        let acme = db.create_org("acme", alice).unwrap();
        let infra = db.create_org_project(acme, alice, "infra", None).unwrap();
        let beta = db.create_org("beta", alice).unwrap();
        let edge = db.create_org_project(beta, alice, "edge", None).unwrap();
        db.subscribe(infra, "apache", "").unwrap();
        db.subscribe(edge, "apache", "").unwrap();
        let hook = serde_json::json!({ "url": "https://example.org/h" });
        let everyone = db.create_destination("instance", None, "everyone", "webhook", &hook, false).unwrap();
        let team = db.create_destination("organization", Some(acme), "team", "webhook", &hook, false).unwrap();
        let solo = db.create_destination("project", Some(edge), "solo", "webhook", &hook, false).unwrap();
        assert!(db.process_changes().unwrap().is_empty());

        // One change, two projects of two organizations: the instance destination gets it for
        // both, the organization one for its organization only, the project one for its project only
        db.upsert_cve(&cve("CVE-2024-0201", Some(5.0))).unwrap();
        let dispatches = db.process_changes().unwrap();
        let one = |name: &str| vec![name.to_string()];
        assert_eq!(
            sent(&dispatches),
            [
                ("acme/infra".to_string(), "team".to_string(), one("CVE-2024-0201")),
                ("acme/infra".to_string(), "everyone".to_string(), one("CVE-2024-0201")),
                ("beta/edge".to_string(), "solo".to_string(), one("CVE-2024-0201")),
                ("beta/edge".to_string(), "everyone".to_string(), one("CVE-2024-0201")),
            ]
        );
        // Never twice through the same destination for the same project
        let mut pairs: Vec<(String, i64)> = dispatches.iter().map(|d| (format!("{}/{}", d.org, d.project), d.notification.id)).collect();
        pairs.sort();
        pairs.dedup();
        assert_eq!(pairs.len(), dispatches.len());
        // Nothing is left to send again
        assert!(db.process_changes().unwrap().is_empty());

        // What each destination says it sends is obeyed: event types, minimum CVSS, enabled
        db.update_destination_settings(everyone, &["created".into()], Some(7.0), true, None).unwrap();
        db.update_destination_settings(team, &crate::db::all_events(), None, false, None).unwrap();
        db.update_destination_settings(solo, &[], None, true, None).unwrap();
        // Under the minimum CVSS: nobody; a disabled destination and one without any event send nothing
        db.upsert_cve(&cve("CVE-2024-0202", Some(5.0))).unwrap();
        assert!(db.process_changes().unwrap().is_empty());
        db.upsert_cve(&cve("CVE-2024-0203", Some(9.0))).unwrap();
        assert_eq!(
            sent(&db.process_changes().unwrap()),
            [
                ("acme/infra".to_string(), "everyone".to_string(), one("CVE-2024-0203")),
                ("beta/edge".to_string(), "everyone".to_string(), one("CVE-2024-0203")),
            ]
        );
        // A score change is not a new CVE: the event type is not one it sends
        db.upsert_cve(&cve("CVE-2024-0203", Some(9.5))).unwrap();
        assert!(db.process_changes().unwrap().is_empty());
        // The reports of the projects hold every change all the same
        assert_eq!(db.list_reports(edge, 10).unwrap()[0].changes, 4);
    }

    #[test]
    fn changes_are_routed_to_reports_and_notifications() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "hash", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        db.subscribe(project, "apache", "").unwrap();
        db.create_notification(project, "critical", "webhook", "https://example.org/h", &[], Some(9.0))
            .unwrap();
        db.create_notification(project, "new", "webhook", "https://example.org/n", &["created".into()], None)
            .unwrap();

        // History imported before the first run never notifies
        db.upsert_cve(&cve("CVE-2024-0100", Some(9.9))).unwrap();
        assert!(db.process_changes().unwrap().is_empty());
        assert!(db.list_reports(project, 10).unwrap().is_empty());

        // A new subscribed CVE (low score) and an unrelated one
        db.upsert_cve(&cve("CVE-2024-0101", Some(5.0))).unwrap();
        let mut other = cve("CVE-2024-0102", Some(9.9));
        other.affected_products = vec![product("nginx", "nginx", true)];
        db.upsert_cve(&other).unwrap();
        // A score bump on the first one
        db.upsert_cve(&cve("CVE-2024-0100", Some(10.0))).unwrap();

        let dispatches = db.process_changes().unwrap();
        let summary: Vec<(String, Vec<String>)> = dispatches
            .iter()
            .map(|d| {
                (
                    d.notification.name.clone(),
                    d.changes.iter().map(|c| c.cve_id.clone()).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("critical".to_string(), vec!["CVE-2024-0100".to_string()]),
                ("new".to_string(), vec!["CVE-2024-0101".to_string()]),
            ]
        );
        assert_eq!(dispatches[0].org, "acme");

        let reports = db.list_reports(project, 10).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].changes, 2);
        assert_eq!(db.get_report(project, &reports[0].day).unwrap().unwrap().len(), 2);

        // Nothing is sent twice
        assert!(db.process_changes().unwrap().is_empty());
    }

    #[test]
    fn keyword_searches_are_few_and_not_too_short() {
        static RUNNING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let held: Vec<KeywordSlot> = (0..MAX_KEYWORD_SEARCHES).map(|_| KeywordSlot::take_from(&RUNNING).unwrap()).collect();
        let refused = KeywordSlot::take_from(&RUNNING).err().unwrap();
        assert!(refused.is::<Busy>());
        drop(held);
        assert!(KeywordSlot::take_from(&RUNNING).is_ok());

        // One or two characters would match about every description
        let db = Database::open_in_memory().unwrap();
        let short = db.list_cves(&CveFilter { search: Some("ab".into()), ..Default::default() }, 10, 0).err().unwrap();
        assert!(short.is::<crate::db::watchlist::UserFacing>());
        // An identifier prefix is served by the index, whatever its length
        assert!(db.list_cves(&CveFilter { search: Some("CVE-2".into()), ..Default::default() }, 10, 0).is_ok());
    }

    #[test]
    fn list_cves_filters() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "hash", false).unwrap();
        db.upsert_cve(&cve("CVE-2024-0200", Some(9.5))).unwrap();
        let mut other = cve("CVE-2023-0201", Some(3.0));
        other.affected_products = vec![product("nginx", "nginx", true)];
        other.cwe_ids = vec!["CWE-79".into()];
        db.upsert_cve(&other).unwrap();
        let mut stub = Cve::new("CVE-2024-0299".into());
        stub.epss_score = Some(0.1);
        db.upsert_cve(&stub).unwrap();
        db.add_tag(alice, "CVE-2023-0201", "todo").unwrap();
        db.rebuild_catalog().unwrap();

        let ids = |f: CveFilter| -> Vec<String> {
            let mut ids: Vec<String> =
                db.list_cves(&f, 50, 0).unwrap().into_iter().map(|c| c.cve_id).collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(CveFilter::default()), ["CVE-2023-0201", "CVE-2024-0200"]);
        assert_eq!(ids(CveFilter { search: Some("cve-2024".into()), ..Default::default() }), ["CVE-2024-0200"]);
        assert_eq!(ids(CveFilter { search: Some("DESCRIPTION OF".into()), ..Default::default() }).len(), 2);
        assert_eq!(ids(CveFilter { vendor: Some("nginx".into()), ..Default::default() }), ["CVE-2023-0201"]);
        // A product alone filters too, whatever the vendor; a vendor and a product must both match
        assert_eq!(ids(CveFilter { product: Some("nginx".into()), ..Default::default() }), ["CVE-2023-0201"]);
        assert!(ids(CveFilter { product: Some("nope".into()), ..Default::default() }).is_empty());
        assert!(ids(CveFilter { vendor: Some("nginx".into()), product: Some("nope".into()), ..Default::default() }).is_empty());
        assert_eq!(ids(CveFilter { cvss: Some("critical".into()), ..Default::default() }), ["CVE-2024-0200"]);
        assert_eq!(ids(CveFilter { cwe: Some("CWE-79".into()), ..Default::default() }), ["CVE-2023-0201"]);
        assert_eq!(ids(CveFilter { tag: Some((alice, "todo".into())), ..Default::default() }), ["CVE-2023-0201"]);

        assert_eq!(db.list_vendors(Some("ngi"), 10, 0).unwrap()[0].vendor, "nginx");
        assert_eq!(db.list_products("apache").unwrap()[0].cves, 1);
        assert_eq!(db.list_weaknesses(10, 0).unwrap()[0].cwe_id, "CWE-79");
        // Sorting is done by the database, on a fixed set of columns
        let sorted = |sort: &str, desc: bool| -> Vec<String> {
            let filter = CveFilter { sort: Some(sort.into()), desc, ..Default::default() };
            db.list_cves(&filter, 50, 0).unwrap().into_iter().map(|c| c.cve_id).collect()
        };
        assert_eq!(sorted("cvss", true), ["CVE-2024-0200", "CVE-2023-0201"]);
        assert_eq!(sorted("cvss", false), ["CVE-2023-0201", "CVE-2024-0200"]);
        assert_eq!(sorted("id", false), ["CVE-2023-0201", "CVE-2024-0200"]);
        assert_eq!(sorted("id; DROP TABLE cves", true).len(), 2);
        assert_eq!(db.list_vendors_sorted(None, "vendor", true, 10, 0).unwrap()[0].vendor, "nginx");
        assert_eq!(db.list_vendors_sorted(None, "products", true, 10, 0).unwrap().len(), 2);
        assert!(db.list_weaknesses_sorted(Some("cwe-7"), "cwe", false, 10, 0).unwrap().len() == 1);
        assert!(db.list_weaknesses_sorted(Some("zzz"), "cwe", false, 10, 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::models::{AffectedPackage, Cve};

    /// One CVE per source, plus one nobody but EPSS knows: the filter of the
    /// lists, the CLI search and `Cve::sources` must agree on every one.
    #[test]
    fn a_list_narrowed_to_a_source_holds_what_that_source_filled() {
        let db = Database::open_in_memory().unwrap();
        let fill: [(&str, fn(&mut Cve)); 8] = [
            ("nvd", |c| c.published_at = Some(chrono::Utc::now())),
            ("cisa_kev", |c| c.kev_known_exploited = true),
            ("epss", |c| c.epss_score = Some(0.5)),
            ("vulnrichment", |c| c.ssvc_automatable = Some("yes".into())),
            ("osv", |c| {
                c.affected_packages.push(AffectedPackage {
                    ecosystem: "npm".into(),
                    name: "left-pad".into(),
                    vulnerable_range: None,
                    fixed_version: None,
                })
            }),
            ("exploitdb", |c| {
                c.exploit_public = true;
                c.exploit_urls.push("https://www.exploit-db.com/exploits/1".into());
            }),
            ("metasploit", |c| {
                c.exploit_public = true;
                c.metasploit_module = Some("exploit/x".into());
            }),
            ("nuclei", |c| c.nuclei_template = Some("http/cves/2024/x.yaml".into())),
        ];
        assert_eq!(fill.map(|(key, _)| key), CVE_SOURCES.map(|(key, _)| key));
        for (n, (_, set)) in fill.iter().enumerate() {
            let mut cve = Cve::new(format!("CVE-2024-100{n}"));
            // Lists leave out CVEs nobody described yet
            cve.description = Some("described".into());
            set(&mut cve);
            db.upsert_cve(&cve).unwrap();
        }
        for (n, (source, _)) in fill.iter().enumerate() {
            let expected = format!("CVE-2024-100{n}");
            let filter = CveFilter { source: Some(source.to_string()), ..Default::default() };
            let listed: Vec<String> = db.list_cves(&filter, 50, 0).unwrap().into_iter().map(|c| c.cve_id).collect();
            assert_eq!(listed, [expected.clone()], "{source}");
            assert_eq!(db.get_cve(&expected).unwrap().unwrap().sources(), [*source], "{source}");
            let query = crate::db::SearchQuery { source: Some(source.to_string()), limit: 50, ..Default::default() };
            let found: Vec<String> = db.search(&query).unwrap().into_iter().map(|c| c.cve_id).collect();
            assert_eq!(found, [expected], "{source} (search)");
        }
        // An unknown source is refused, not ignored
        let filter = CveFilter { source: Some("bogus".into()), ..Default::default() };
        assert!(db.list_cves(&filter, 50, 0).unwrap_err().to_string().contains("Unknown source"));
        assert!(source_condition("x' OR 1=1 --", "c.").is_none());
    }
}
