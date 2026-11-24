pub mod watchlist;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

mod access;
mod admin_ops;
mod destinations;
mod distro;
mod inventory;
mod lifecycle;
mod mfa;
mod osv;
mod platform;
mod provisioning;
mod roles;
mod setup;
mod sso;
mod trail;
pub use access::*;
pub use destinations::*;
pub use distro::*;
pub use inventory::*;
pub use lifecycle::*;
pub use mfa::*;
pub use osv::*;
pub use sso::*;
pub use trail::*;
pub use setup::SetupClosed;
pub use platform::*;
pub use provisioning::*;

use crate::changes::{self, Snapshot};
use crate::extraction;
use crate::models::{AffectedPackage, AffectedProduct, Cve, Reference};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    epss_score REAL,
    epss_percentile REAL,
    cwe_ids TEXT,
    affected_products TEXT,
    references_json TEXT,
    kev_known_exploited INTEGER DEFAULT 0,
    kev_date_added TEXT,
    published_at TEXT,
    modified_at TEXT,
    -- Enrichissement: Exploitabilité
    exploit_public INTEGER DEFAULT 0,
    exploit_urls TEXT DEFAULT '[]',
    metasploit_module TEXT,
    nuclei_template TEXT,
    -- Enrichissement: SSVC (Vulnrichment)
    ssvc_exploitation TEXT,
    ssvc_automatable TEXT,
    ssvc_technical_impact TEXT,
    -- Timestamps
    created_in_db TEXT DEFAULT (datetime('now')),
    updated_in_db TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_v3_score);
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev_known_exploited);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at);
CREATE INDEX IF NOT EXISTS idx_cves_exploit ON cves(exploit_public);
CREATE INDEX IF NOT EXISTS idx_cves_ssvc_exploitation ON cves(ssvc_exploitation);

CREATE TABLE IF NOT EXISTS affected_products_normalized (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version TEXT,
    version_start TEXT,
    version_end TEXT,
    cpe TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ap_cve_id ON affected_products_normalized(cve_id);
CREATE INDEX IF NOT EXISTS idx_ap_product ON affected_products_normalized(product);
CREATE INDEX IF NOT EXISTS idx_ap_vendor_product ON affected_products_normalized(vendor, product);

CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    vulnerable_range TEXT,
    fixed_version TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pkg_cve_id ON affected_packages(cve_id);
CREATE INDEX IF NOT EXISTS idx_pkg_ecosystem ON affected_packages(ecosystem);
CREATE INDEX IF NOT EXISTS idx_pkg_name ON affected_packages(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pkg_unique ON affected_packages(cve_id, ecosystem, name);

CREATE TABLE IF NOT EXISTS sync_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    cves_added INTEGER DEFAULT 0,
    cves_updated INTEGER DEFAULT 0,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Watchlist tables (v4)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    vendor TEXT,
    ecosystem TEXT,
    cpe_pattern TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, name, version)
);

CREATE TABLE IF NOT EXISTS watchlist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'untreated',
    priority TEXT DEFAULT 'medium',
    assigned_to TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    treated_at TEXT,
    FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
    UNIQUE(app_id, cve_id),
    CHECK(status IN ('untreated', 'treated', 'not_applicable')),
    CHECK(priority IN ('critical', 'high', 'medium', 'low'))
);

CREATE INDEX IF NOT EXISTS idx_watchlist_status ON watchlist_entries(status);
CREATE INDEX IF NOT EXISTS idx_watchlist_cve ON watchlist_entries(cve_id);
CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);
CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
"#;

/// What storing a CVE did
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// The CVE was not known
    Created,
    /// It was known and something of it changed
    Changed,
    /// It was known and is as it was: nothing was written
    Same,
}

pub struct Database {
    conn: Connection,
    /// Key of the secrets stored in this database (see `crate::secrets`)
    key: crate::secrets::Key,
}

/// The database holds secrets (second-factor seeds, SMTP passwords, SSO client
/// secrets, tokens of Git sources): its files are for their owner only.
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let file = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if file.exists() {
                if let Err(e) = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
                    tracing::warn!("cannot restrict {} to its owner: {e}", file.display());
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// SQL functions of the application, available on every connection
fn register_functions(conn: &Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    // version_affects(asked, version, start, start_excluded, end, end_included, cpe)
    conn.create_scalar_function("version_affects", 7, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        let text = |i: usize| ctx.get::<Option<String>>(i);
        let flag = |i: usize| ctx.get::<Option<bool>>(i).map(|v| v.unwrap_or(false));
        let version = crate::versions::cpe_version(text(1)?.as_deref(), text(6)?.as_deref());
        Ok(crate::versions::product_affects(text(0)?.as_deref(), version.as_deref(), text(2)?.as_deref(), flag(3)?, text(4)?.as_deref(), flag(5)?))
    })?;
    // name_variant(product, name): `versions::is_name_variant`
    conn.create_scalar_function("name_variant", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        Ok(match (ctx.get::<Option<String>>(0)?, ctx.get::<Option<String>>(1)?) {
            (Some(product), Some(name)) => crate::versions::is_name_variant(&product, &name),
            _ => false,
        })
    })?;
    // name_key(text): a product name as it is compared (`versions::name_key`)
    conn.create_scalar_function("name_key", 1, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        Ok(ctx.get::<Option<String>>(0)?.map(|text| crate::versions::name_key(&text)))
    })?;
    Ok(())
}

impl Database {
    /// Get a reference to the underlying connection (for watchlist module)
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// A transaction that writes: it takes the write lock when it opens, and
    /// waits its turn for it. A deferred one that reads first is refused at
    /// once on its first write when another connection (a synchronization)
    /// committed meanwhile: "database is locked", whatever the time allowed.
    pub(crate) fn write_tx(&self) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        rusqlite::Transaction::new_unchecked(&self.conn, rusqlite::TransactionBehavior::Immediate)
    }
}

impl Database {
    /// Encrypts a secret for storage
    pub(crate) fn seal(&self, plain: &str) -> String {
        crate::secrets::seal(&self.key, plain)
    }

    /// Reads a stored secret back (values stored before encryption are returned as they are)
    pub(crate) fn unseal(&self, stored: &str) -> Result<String> {
        crate::secrets::open(&self.key, stored)
    }

    /// Runs writes as one unit: a transaction taken for writing at once when
    /// none is open (a deferred one that reads first can fail on its first
    /// write if another connection committed meanwhile), a savepoint inside
    /// a caller's transaction. Rolled back on error.
    pub(crate) fn write_scope<T>(&self, name: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
        let outermost = self.conn.is_autocommit();
        self.conn.execute_batch(&if outermost { "BEGIN IMMEDIATE".to_string() } else { format!("SAVEPOINT {name}") })?;
        let result = work();
        let end = match (&result, outermost) {
            (Ok(_), true) => "COMMIT".to_string(),
            (Err(_), true) => "ROLLBACK".to_string(),
            (Ok(_), false) => format!("RELEASE {name}"),
            (Err(_), false) => format!("ROLLBACK TO {name}; RELEASE {name}"),
        };
        match self.conn.execute_batch(&end) {
            Ok(()) => result,
            // The work failed and so did the rollback: report the first failure
            Err(e) => result.and(Err(e.into())),
        }
    }

    /// Keyed hash (HMAC-SHA256) under the key of this database: proves a
    /// value was issued by this instance.
    pub(crate) fn mac(&self, data: &str) -> String {
        use hmac::{Hmac, Mac};
        // An HMAC key of any length is accepted
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// A secret kept in the settings table
    pub fn get_secret(&self, key: &str) -> Result<Option<String>> {
        self.get_metadata(key)?.map(|stored| self.unseal(&stored)).transpose()
    }

    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.set_metadata(key, &self.seal(value))
    }

    /// Ouvre ou crée la base de données
    pub fn open(path: &Path) -> Result<Self> {
        let exists = path.exists();
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        // Configure SQLite for better concurrent access
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;

        // A database that already holds encrypted secrets needs its own key: starting
        // with a new one would leave them unreadable and mix two keys in the file
        let key_file = crate::secrets::key_path(path);
        if exists && !key_file.exists() {
            let version: i32 = conn
                .query_row("SELECT COALESCE(CAST(value AS INTEGER), 1) FROM metadata WHERE key = 'schema_version'", [], |r| r.get(0))
                .unwrap_or(1);
            if version >= 21 {
                anyhow::bail!(
                    "the key file {} is missing: this database holds secrets encrypted with it. \
                     Restore the key file (or point VULNIZARD_KEY_FILE at it).",
                    key_file.display()
                );
            }
        }
        register_functions(&conn)?;
        let db = Self { conn, key: crate::secrets::key_for(path)? };
        restrict_to_owner(path);

        if !exists {
            tracing::info!("Creating new database at {}", path.display());
            db.init()?;
        } else {
            db.ensure_schema_updated()?;
        }

        Ok(db)
    }

    /// Opens an existing, already-migrated database without running the
    /// (costly) schema checks. Used for per-request connections in server mode.
    pub fn connect(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
        register_functions(&conn)?;
        Ok(Self { conn, key: crate::secrets::key_for(path)? })
    }

    /// Vérifie et met à jour le schéma si nécessaire
    fn ensure_schema_updated(&self) -> Result<()> {
        // Get current schema version
        let schema_version: i32 = self.conn.query_row(
            "SELECT COALESCE(CAST(value AS INTEGER), 1) FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        ).unwrap_or(1);

        // Migration v1 -> v2: affected_products_normalized table
        if schema_version < 2 {
            tracing::info!("Upgrading database schema to v2");
            self.conn.execute_batch(r#"
                CREATE TABLE IF NOT EXISTS affected_products_normalized (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    version_start TEXT,
                    version_end TEXT,
                    cpe TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_ap_cve_id ON affected_products_normalized(cve_id);
                CREATE INDEX IF NOT EXISTS idx_ap_product ON affected_products_normalized(product);
                CREATE INDEX IF NOT EXISTS idx_ap_vendor_product ON affected_products_normalized(vendor, product);
            "#)?;
        }

        // Migration v2 -> v3: enrichment columns + affected_packages table
        if schema_version < 3 {
            tracing::info!("Upgrading database schema to v3 (enrichment fields)");
            self.conn.execute_batch(r#"
                ALTER TABLE cves ADD COLUMN exploit_public INTEGER DEFAULT 0;
                ALTER TABLE cves ADD COLUMN exploit_urls TEXT DEFAULT '[]';
                ALTER TABLE cves ADD COLUMN metasploit_module TEXT;
                ALTER TABLE cves ADD COLUMN nuclei_template TEXT;

                CREATE TABLE IF NOT EXISTS affected_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    name TEXT NOT NULL,
                    vulnerable_range TEXT,
                    fixed_version TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_cves_exploit ON cves(exploit_public);
                CREATE INDEX IF NOT EXISTS idx_pkg_cve_id ON affected_packages(cve_id);
                CREATE INDEX IF NOT EXISTS idx_pkg_ecosystem ON affected_packages(ecosystem);
                CREATE INDEX IF NOT EXISTS idx_pkg_name ON affected_packages(name);
                CREATE INDEX IF NOT EXISTS idx_pkg_ecosystem_name ON affected_packages(ecosystem, name);
            "#)?;

            self.conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '3')",
                [],
            )?;
        }

        // Migration v3 -> v4: watchlist tables
        if schema_version < 4 {
            tracing::info!("Upgrading database schema to v4 (watchlist tables)");
            self.conn.execute_batch(r#"
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, name)
                );

                CREATE TABLE IF NOT EXISTS applications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    vendor TEXT,
                    ecosystem TEXT,
                    cpe_pattern TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                    UNIQUE(project_id, name, version)
                );

                CREATE TABLE IF NOT EXISTS watchlist_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'untreated',
                    priority TEXT DEFAULT 'medium',
                    assigned_to TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    treated_at TEXT,
                    FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
                    UNIQUE(app_id, cve_id),
                    CHECK(status IN ('untreated', 'treated', 'not_applicable')),
                    CHECK(priority IN ('critical', 'high', 'medium', 'low'))
                );

                CREATE INDEX IF NOT EXISTS idx_watchlist_status ON watchlist_entries(status);
                CREATE INDEX IF NOT EXISTS idx_watchlist_cve ON watchlist_entries(cve_id);
                CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);
                CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
            "#)?;

            // Create default user for CLI mode
            self.conn.execute(
                "INSERT OR IGNORE INTO users (username, email) VALUES ('default', NULL)",
                [],
            )?;

            // Create default project for CLI mode
            self.conn.execute(
                "INSERT OR IGNORE INTO projects (user_id, name, description)
                 SELECT id, 'default', 'Default project' FROM users WHERE username = 'default'",
                [],
            )?;

            self.conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '4')",
                [],
            )?;
        }

        // Migration v4 -> v5: SSVC columns (Vulnrichment)
        if schema_version < 5 {
            tracing::info!("Upgrading database schema to v5 (SSVC columns)");
            self.conn.execute_batch(r#"
                ALTER TABLE cves ADD COLUMN ssvc_exploitation TEXT;
                ALTER TABLE cves ADD COLUMN ssvc_automatable TEXT;
                ALTER TABLE cves ADD COLUMN ssvc_technical_impact TEXT;

                CREATE INDEX IF NOT EXISTS idx_cves_ssvc_exploitation ON cves(ssvc_exploitation);
            "#)?;

            self.conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '5')",
                [],
            )?;
        }

        // Migration v5 -> v6: web platform (accounts, organizations, change tracking)
        if schema_version < 6 {
            tracing::info!("Upgrading database schema to v6 (web platform)");
            self.migrate_platform()?;
        }

        // Migration v6 -> v7: roles (owner/editor/viewer), account status, SSO
        if schema_version < 7 {
            tracing::info!("Upgrading database schema to v7 (roles, SSO)");
            self.migrate_access()?;
        }

        // Migration v7 -> v8: watchlist lifecycle (accepted status, event log)
        if schema_version < 8 {
            tracing::info!("Upgrading database schema to v8 (watchlist lifecycle)");
            self.migrate_lifecycle()?;
        }

        // Migration v8 -> v9: SSO providers managed from the UI
        if schema_version < 9 {
            tracing::info!("Upgrading database schema to v9 (SSO providers)");
            self.migrate_sso()?;
        }

        // Migration v9 -> v10: decision history outlives deleted projects
        if schema_version < 10 {
            tracing::info!("Upgrading database schema to v10 (durable history)");
            self.migrate_history()?;
        }

        // Migration v10 -> v11: ntfy notification type
        if schema_version < 11 {
            tracing::info!("Upgrading database schema to v11 (ntfy notifications)");
            self.migrate_notifications()?;
        }

        // Migration v11 -> v12: rights at instance, organization and project level
        if schema_version < 12 {
            tracing::info!("Upgrading database schema to v12 (three levels of rights)");
            self.migrate_roles()?;
        }

        // Migration v12 -> v13: notification destinations, Web Push
        if schema_version < 13 {
            tracing::info!("Upgrading database schema to v13 (notification destinations)");
            self.migrate_destinations()?;
        }

        // Migration v13 -> v14: scoped identity (SSO per scope, SCIM)
        if schema_version < 14 {
            tracing::info!("Upgrading database schema to v14 (scoped identity, SCIM)");
            self.migrate_provisioning()?;
        }

        // Migration v14 -> v15: inventory sources and discovered components
        if schema_version < 15 {
            tracing::info!("Upgrading database schema to v15 (inventory)");
            self.migrate_inventory()?;
        }

        // Migration v15 -> v16: distribution advisories, groups of inventory sources
        if schema_version < 16 {
            tracing::info!("Upgrading database schema to v16 (distribution packages, groups)");
            self.migrate_distro()?;
        }

        // Migration v16 -> v17: second factors
        if schema_version < 17 {
            tracing::info!("Upgrading database schema to v17 (second factors)");
            self.migrate_mfa()?;
        }

        // Migration v17 -> v18: trail of account security events
        if schema_version < 18 {
            tracing::info!("Upgrading database schema to v18 (security events)");
            self.migrate_security()?;
        }

        // Migration v18 -> v19: sign-in with a passkey alone
        if schema_version < 19 {
            tracing::info!("Upgrading database schema to v19 (passkey sign-in)");
            self.migrate_passkey_login()?;
        }

        // Migration v19 -> v20: an organization's second-factor requirement closes that organization only
        if schema_version < 20 {
            tracing::info!("Upgrading database schema to v20 (access views, admin-disabled accounts)");
            self.migrate_access_v20()?;
        }

        // Migration v20 -> v21: secrets encrypted at rest
        if schema_version < 21 {
            tracing::info!("Upgrading database schema to v21 (secrets encrypted at rest)");
            if self.migrate_seal_secrets()? > 0 {
                // The values just replaced are still in freed pages and in the journal:
                // rewrite the file so that a copy taken from now on does not hold them
                tracing::info!("Rewriting the database to erase the secrets that were stored in clear (may take a while)");
                self.conn.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
            }
        }

        // Migration v21 -> v22: chained logs
        if schema_version < 22 {
            tracing::info!("Upgrading database schema to v22 (chained logs)");
            self.migrate_trail()?;
        }

        // Migration v22 -> v23: each bound of a version range is included or not
        if schema_version < 23 {
            tracing::info!("Upgrading database schema to v23 (inclusive and exclusive version bounds)");
            self.migrate_bounds()?;
        }

        // Migration v23 -> v24: entries kept without a version from the sources
        if schema_version < 24 {
            tracing::info!("Upgrading database schema to v24 (entries whose version no source gives)");
            self.migrate_version_unknown()?;
        }

        // Migration v24 -> v25: advisories of package ecosystems kept one by one
        if schema_version < 25 {
            tracing::info!("Upgrading database schema to v25 (package advisories kept one by one)");
            self.migrate_osv_advisories()?;
        }

        // Migration v25 -> v26: how many CVEs a run read again and found as they were
        if schema_version < 26 {
            tracing::info!("Upgrading database schema to v26 (unchanged CVEs counted apart)");
            self.migrate_sync_unchanged()?;
        }

        // Migration v26 -> v27: a destination receives by its scope, and holds what it sends
        if schema_version < 27 {
            tracing::info!("Upgrading database schema to v27 (destinations receive by their scope; the per-project rules are gone)");
            self.migrate_destination_settings()?;
        }

        // Check if normalized table needs to be populated
        let normalized_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM affected_products_normalized",
            [],
            |row| row.get(0),
        )?;

        let cves_with_products: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE affected_products != '[]'",
            [],
            |row| row.get(0),
        )?;

        // If we have CVEs with products but normalized table is mostly empty, populate it
        if cves_with_products > 0 && normalized_count < cves_with_products / 2 {
            self.populate_normalized_products()?;
        }

        Ok(())
    }

    /// v23: whether the start of a range is excluded and its end included,
    /// and how many CVEs the sources hold for each application.
    /// What is already stored keeps the former reading (start included, end
    /// excluded) until the NVD is read again, which the import does by itself
    /// (see `sources::nvd`).
    fn migrate_bounds(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             ALTER TABLE affected_products_normalized ADD COLUMN start_excluded INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE affected_products_normalized ADD COLUMN end_included INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE applications ADD COLUMN known_cves INTEGER;
             DELETE FROM metadata WHERE key IN ('nvd.history_from', 'nvd.backfill_until');
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '23');
             COMMIT;",
        )?;
        Ok(())
    }

    /// v24: whether an entry is kept without any source giving the affected
    /// versions. Filled in by the next scan.
    fn migrate_version_unknown(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             ALTER TABLE watchlist_entries ADD COLUMN version_unknown INTEGER NOT NULL DEFAULT 0;
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '24');
             COMMIT;",
        )?;
        Ok(())
    }

    /// v26: a run counts apart the CVEs it created, those it changed and
    /// those it read again and found as they were. Earlier runs counted every
    /// CVE read as added: their figures stay as they were written.
    fn migrate_sync_unchanged(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             ALTER TABLE sync_history ADD COLUMN cves_unchanged INTEGER DEFAULT 0;
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '26');
             COMMIT;",
        )?;
        Ok(())
    }

    /// Peuple la table normalisée depuis le JSON existant
    fn populate_normalized_products(&self) -> Result<()> {
        tracing::info!("Populating normalized products table from existing data...");

        let mut stmt = self.conn.prepare("SELECT cve_id, affected_products FROM cves WHERE affected_products != '[]'")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut count = 0;
        for row in rows {
            let (cve_id, json): (String, String) = row?;
            let products: Vec<AffectedProduct> = serde_json::from_str(&json).unwrap_or_default();

            for product in products {
                self.conn.execute(
                    "INSERT INTO affected_products_normalized (cve_id, vendor, product, version, version_start, version_end, cpe, start_excluded, end_included) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![cve_id, product.vendor, product.product, product.version, product.version_start, product.version_end, product.cpe, product.version_start_excluded, product.version_end_included],
                )?;
                count += 1;
            }
        }

        tracing::info!("Populated {} product entries", count);
        Ok(())
    }

    /// Ouvre une base de données en mémoire (pour tests)
    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        register_functions(&conn)?;
        let db = Self { conn, key: crate::secrets::random_key() };
        db.init()?;
        Ok(db)
    }

    /// Initialise le schéma de la base
    fn init(&self) -> Result<()> {
        self.conn
            .execute_batch(SCHEMA)
            .with_context(|| "Failed to initialize database schema")?;

        // Version du schéma
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '5')",
            [],
        )?;

        // Create default user for CLI mode
        self.conn.execute(
            "INSERT OR IGNORE INTO users (username, email) VALUES ('default', NULL)",
            [],
        )?;

        // Create default project for CLI mode
        self.conn.execute(
            "INSERT OR IGNORE INTO projects (user_id, name, description)
             SELECT id, 'default', 'Default project' FROM users WHERE username = 'default'",
            [],
        )?;

        self.migrate_platform()?;
        self.migrate_access()?;
        self.migrate_lifecycle()?;
        self.migrate_sso()?;
        self.migrate_history()?;
        self.migrate_notifications()?;
        self.migrate_roles()?;
        self.migrate_destinations()?;
        self.migrate_provisioning()?;
        self.migrate_inventory()?;
        self.migrate_distro()?;
        self.migrate_mfa()?;
        self.migrate_security()?;
        self.migrate_passkey_login()?;
        self.migrate_access_v20()?;
        self.migrate_seal_secrets()?;
        self.migrate_trail()?;
        self.migrate_bounds()?;
        self.migrate_version_unknown()?;
        self.migrate_osv_advisories()?;
        self.migrate_sync_unchanged()?;
        self.migrate_destination_settings()?;

        tracing::info!("Database initialized successfully");
        Ok(())
    }

    /// Insère ou met à jour une CVE
    pub fn upsert_cve(&self, cve: &Cve) -> Result<Stored> {
        self.upsert(cve, true)
    }

    /// Whether a description is stored for this CVE
    pub fn has_description(&self, cve_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM cves WHERE cve_id = ?1 AND description IS NOT NULL AND description != '')")?
            .query_row(params![cve_id], |r| r.get(0))?)
    }

    /// Same, without recording anything as a change of the CVE: for the
    /// history read long after the fact, which is not news
    pub fn upsert_cve_untracked(&self, cve: &Cve) -> Result<Stored> {
        self.upsert(cve, false)
    }

    fn upsert(&self, cve: &Cve, record_changes: bool) -> Result<Stored> {
        let existed: bool =
            self.conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM cves WHERE cve_id = ?1)")?.query_row(params![cve.cve_id], |r| r.get(0))?;
        // Only upserts touching tracked fields can produce change events
        // (an EPSS-only update skips the before/after comparison entirely).
        let touches_tracked = cve.description.is_some()
            || cve.cvss_v3_score.is_some()
            || !cve.cwe_ids.is_empty()
            || !cve.affected_products.is_empty()
            || !cve.references.is_empty()
            || cve.kev_known_exploited;
        let before = if touches_tracked { self.snapshot(&cve.cve_id)? } else { None };
        let tracked = touches_tracked && record_changes;

        // Products without CPE (KEV catalog, description heuristics) must not
        // replace products already known for this CVE.
        let keep_products = before.as_ref().is_some_and(|b| !b.products.is_empty())
            && cve.affected_products.iter().all(|p| p.cpe.is_none());
        let incoming_products: &[AffectedProduct] = if keep_products {
            &[]
        } else {
            &cve.affected_products
        };

        let cwe_ids = serde_json::to_string(&cve.cwe_ids)?;
        let affected_products = serde_json::to_string(incoming_products)?;
        let references = serde_json::to_string(&cve.references)?;
        let exploit_urls = serde_json::to_string(&cve.exploit_urls)?;

        let published_at = cve.published_at.map(|d| d.to_rfc3339());
        let modified_at = cve.modified_at.map(|d| d.to_rfc3339());

        let rows_affected = self.conn.execute(
            r#"
            INSERT INTO cves (
                cve_id, description, cvss_v3_score, cvss_v3_vector,
                epss_score, epss_percentile, cwe_ids, affected_products,
                references_json, kev_known_exploited, kev_date_added,
                published_at, modified_at,
                exploit_public, exploit_urls, metasploit_module, nuclei_template,
                ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
                updated_in_db
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
                description = COALESCE(excluded.description, description),
                cvss_v3_score = COALESCE(excluded.cvss_v3_score, cvss_v3_score),
                cvss_v3_vector = COALESCE(excluded.cvss_v3_vector, cvss_v3_vector),
                epss_score = COALESCE(excluded.epss_score, epss_score),
                epss_percentile = COALESCE(excluded.epss_percentile, epss_percentile),
                cwe_ids = CASE WHEN excluded.cwe_ids != '[]' THEN excluded.cwe_ids ELSE cwe_ids END,
                affected_products = CASE WHEN excluded.affected_products != '[]' THEN excluded.affected_products ELSE affected_products END,
                references_json = CASE WHEN excluded.references_json != '[]' THEN excluded.references_json ELSE references_json END,
                kev_known_exploited = MAX(kev_known_exploited, excluded.kev_known_exploited),
                kev_date_added = COALESCE(excluded.kev_date_added, kev_date_added),
                published_at = COALESCE(excluded.published_at, published_at),
                modified_at = COALESCE(excluded.modified_at, modified_at),
                exploit_public = MAX(exploit_public, excluded.exploit_public),
                exploit_urls = CASE WHEN excluded.exploit_urls != '[]' THEN excluded.exploit_urls ELSE exploit_urls END,
                metasploit_module = COALESCE(excluded.metasploit_module, metasploit_module),
                nuclei_template = COALESCE(excluded.nuclei_template, nuclei_template),
                ssvc_exploitation = COALESCE(excluded.ssvc_exploitation, ssvc_exploitation),
                ssvc_automatable = COALESCE(excluded.ssvc_automatable, ssvc_automatable),
                ssvc_technical_impact = COALESCE(excluded.ssvc_technical_impact, ssvc_technical_impact),
                updated_in_db = datetime('now')
            -- Only a row that would really differ is written: what follows repeats the
            -- assignments above, one by one. A row left alone counts as unchanged.
            WHERE description IS NOT COALESCE(excluded.description, description)
                OR cvss_v3_score IS NOT COALESCE(excluded.cvss_v3_score, cvss_v3_score)
                OR cvss_v3_vector IS NOT COALESCE(excluded.cvss_v3_vector, cvss_v3_vector)
                OR epss_score IS NOT COALESCE(excluded.epss_score, epss_score)
                OR epss_percentile IS NOT COALESCE(excluded.epss_percentile, epss_percentile)
                OR (excluded.cwe_ids != '[]' AND cwe_ids IS NOT excluded.cwe_ids)
                OR (excluded.affected_products != '[]' AND affected_products IS NOT excluded.affected_products)
                OR (excluded.references_json != '[]' AND references_json IS NOT excluded.references_json)
                OR kev_known_exploited IS NOT MAX(kev_known_exploited, excluded.kev_known_exploited)
                OR kev_date_added IS NOT COALESCE(excluded.kev_date_added, kev_date_added)
                OR published_at IS NOT COALESCE(excluded.published_at, published_at)
                OR modified_at IS NOT COALESCE(excluded.modified_at, modified_at)
                OR exploit_public IS NOT MAX(exploit_public, excluded.exploit_public)
                OR (excluded.exploit_urls != '[]' AND exploit_urls IS NOT excluded.exploit_urls)
                OR metasploit_module IS NOT COALESCE(excluded.metasploit_module, metasploit_module)
                OR nuclei_template IS NOT COALESCE(excluded.nuclei_template, nuclei_template)
                OR ssvc_exploitation IS NOT COALESCE(excluded.ssvc_exploitation, ssvc_exploitation)
                OR ssvc_automatable IS NOT COALESCE(excluded.ssvc_automatable, ssvc_automatable)
                OR ssvc_technical_impact IS NOT COALESCE(excluded.ssvc_technical_impact, ssvc_technical_impact)
            "#,
            params![
                cve.cve_id,
                cve.description,
                cve.cvss_v3_score,
                cve.cvss_v3_vector,
                cve.epss_score,
                cve.epss_percentile,
                cwe_ids,
                affected_products,
                references,
                cve.kev_known_exploited as i32,
                cve.kev_date_added,
                published_at,
                modified_at,
                cve.exploit_public as i32,
                exploit_urls,
                cve.metasploit_module,
                cve.nuclei_template,
                cve.ssvc_exploitation,
                cve.ssvc_automatable,
                cve.ssvc_technical_impact,
            ],
        )?;

        // Insert affected products into normalized table
        if !incoming_products.is_empty() {
            // Delete existing entries for this CVE
            self.conn.execute(
                "DELETE FROM affected_products_normalized WHERE cve_id = ?1",
                params![cve.cve_id],
            )?;

            // Insert new entries
            for product in incoming_products {
                self.conn.execute(
                    r#"
                    INSERT INTO affected_products_normalized (cve_id, vendor, product, version, version_start, version_end, cpe, start_excluded, end_included)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                    "#,
                    params![
                        cve.cve_id,
                        product.vendor,
                        product.product,
                        product.version,
                        product.version_start,
                        product.version_end,
                        product.cpe,
                        product.version_start_excluded,
                        product.version_end_included,
                    ],
                )?;
            }
        }

        // Insert affected packages into normalized table
        if !cve.affected_packages.is_empty() {
            self.conn.execute(
                "DELETE FROM affected_packages WHERE cve_id = ?1",
                params![cve.cve_id],
            )?;

            for pkg in &cve.affected_packages {
                self.conn.execute(
                    r#"
                    INSERT INTO affected_packages (cve_id, ecosystem, name, vulnerable_range, fixed_version)
                    VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    params![
                        cve.cve_id,
                        pkg.ecosystem,
                        pkg.name,
                        pkg.vulnerable_range,
                        pkg.fixed_version,
                    ],
                )?;
            }
        }

        // Normalized weaknesses
        if !cve.cwe_ids.is_empty() {
            self.conn.execute("DELETE FROM cve_cwes WHERE cve_id = ?1", params![cve.cve_id])?;
            for cwe in &cve.cwe_ids {
                self.conn.execute(
                    "INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id) VALUES (?1, ?2)",
                    params![cve.cve_id, cwe],
                )?;
            }
        }

        // Change tracking
        if tracked {
            if let Some(after) = self.snapshot(&cve.cve_id)? {
                let events = changes::diff(before.as_ref(), &after);
                if !events.is_empty() {
                    self.conn.execute(
                        "INSERT INTO cve_changes (cve_id, created_at, events) VALUES (?1, ?2, ?3)",
                        params![
                            cve.cve_id,
                            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            serde_json::to_string(&events)?
                        ],
                    )?;
                }
            }
        }

        Ok(match (existed, rows_affected > 0) {
            (false, _) => Stored::Created,
            (true, true) => Stored::Changed,
            (true, false) => Stored::Same,
        })
    }

    /// Tracked state of a CVE, used for change detection
    fn snapshot(&self, cve_id: &str) -> Result<Option<Snapshot>> {
        let row = self
            .conn
            .query_row(
                "SELECT description, cvss_v3_score, cwe_ids, affected_products, references_json, kev_known_exploited
                 FROM cves WHERE cve_id = ?1",
                params![cve_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<f64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;

        Ok(row.map(|(description, cvss, cwes, products, references, kev)| {
            let cwes: Vec<String> = cwes.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let products: Vec<AffectedProduct> =
                products.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let references: Vec<Reference> =
                references.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            Snapshot {
                description,
                cvss,
                cwes: cwes.into_iter().collect(),
                products: products
                    .into_iter()
                    .filter_map(|p| match (p.vendor, p.product) {
                        (Some(v), Some(p)) => Some(format!("{}:{}", v, p)),
                        _ => None,
                    })
                    .collect(),
                references: references.into_iter().map(|r| r.url).collect(),
                kev: kev.unwrap_or(0) != 0,
            }
        }))
    }

    /// Recherche des CVE
    pub fn search(&self, query: &SearchQuery) -> Result<Vec<Cve>> {
        let use_product_join = query.product.is_some() || query.version.is_some();
        let use_package_join = query.ecosystem.is_some() || query.package_name.is_some();

        let mut sql = if use_product_join || use_package_join {
            let mut base = String::from(
                r#"
                SELECT DISTINCT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_vector,
                       c.epss_score, c.epss_percentile, c.cwe_ids, c.affected_products,
                       c.references_json, c.kev_known_exploited, c.kev_date_added,
                       c.published_at, c.modified_at,
                       c.exploit_public, c.exploit_urls, c.metasploit_module, c.nuclei_template,
                       c.ssvc_exploitation, c.ssvc_automatable, c.ssvc_technical_impact
                FROM cves c
                "#,
            );
            if use_product_join {
                base.push_str("JOIN affected_products_normalized ap ON c.cve_id = ap.cve_id\n");
            }
            if use_package_join {
                base.push_str("JOIN affected_packages pkg ON c.cve_id = pkg.cve_id\n");
            }
            base.push_str("WHERE 1=1");
            base
        } else {
            String::from(
                r#"
                SELECT cve_id, description, cvss_v3_score, cvss_v3_vector,
                       epss_score, epss_percentile, cwe_ids, affected_products,
                       references_json, kev_known_exploited, kev_date_added,
                       published_at, modified_at,
                       exploit_public, exploit_urls, metasploit_module, nuclei_template,
                       ssvc_exploitation, ssvc_automatable, ssvc_technical_impact
                FROM cves
                WHERE 1=1
                "#,
            )
        };
        let use_aliased = use_product_join || use_package_join;

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(ref text) = query.text {
            if use_aliased {
                sql.push_str(&format!(
                    " AND (c.cve_id LIKE '%' || ?{idx} || '%' OR c.description LIKE '%' || ?{idx} || '%' OR c.affected_products LIKE '%' || ?{idx} || '%')",
                    idx = param_idx
                ));
            } else {
                sql.push_str(&format!(
                    " AND (cve_id LIKE '%' || ?{idx} || '%' OR description LIKE '%' || ?{idx} || '%' OR affected_products LIKE '%' || ?{idx} || '%')",
                    idx = param_idx
                ));
            }
            params.push(Box::new(text.clone()));
            param_idx += 1;
        }

        if let Some(min_cvss) = query.min_cvss {
            let col = if use_aliased { "c.cvss_v3_score" } else { "cvss_v3_score" };
            sql.push_str(&format!(" AND {} >= ?{}", col, param_idx));
            params.push(Box::new(min_cvss));
            param_idx += 1;
        }

        if let Some(min_epss) = query.min_epss {
            let col = if use_aliased { "c.epss_score" } else { "epss_score" };
            sql.push_str(&format!(" AND {} >= ?{}", col, param_idx));
            params.push(Box::new(min_epss));
            param_idx += 1;
        }

        if query.only_kev {
            let col = if use_aliased { "c.kev_known_exploited" } else { "kev_known_exploited" };
            sql.push_str(&format!(" AND {} = 1", col));
        }

        if query.has_exploit {
            let col = if use_aliased { "c.exploit_public" } else { "exploit_public" };
            sql.push_str(&format!(" AND {} = 1", col));
        }

        if let Some(ref source) = query.source {
            let condition = source_condition(source, if use_aliased { "c." } else { "cves." })
                .ok_or_else(|| anyhow::anyhow!(unknown_source(source)))?;
            sql.push_str(&format!(" AND {condition}"));
        }

        if let Some(ref vendor) = query.vendor {
            let col = if use_aliased { "c.affected_products" } else { "affected_products" };
            sql.push_str(&format!(
                " AND {} LIKE '%' || ?{} || '%'",
                col, param_idx
            ));
            params.push(Box::new(vendor.clone()));
            param_idx += 1;
        }

        // Product filtering (uses normalized table via JOIN)
        if let Some(ref product) = query.product {
            sql.push_str(&format!(" AND ap.product LIKE ?{}", param_idx));
            params.push(Box::new(format!("%{}%", product)));
            param_idx += 1;
        }

        // Version filtering
        if let Some(ref version) = query.version {
            // Same judgement as for tracked applications (`versions::product_affects`)
            sql.push_str(&format!(
                " AND version_affects(?{idx}, ap.version, ap.version_start, ap.start_excluded, ap.version_end, ap.end_included, ap.cpe)",
                idx = param_idx
            ));
            params.push(Box::new(version.clone()));
            param_idx += 1;
        }

        // Ecosystem filtering (via affected_packages table)
        if let Some(ref ecosystem) = query.ecosystem {
            sql.push_str(&format!(" AND pkg.ecosystem = ?{}", param_idx));
            params.push(Box::new(ecosystem.clone()));
            param_idx += 1;
        }

        // Package name filtering (via affected_packages table)
        if let Some(ref package_name) = query.package_name {
            sql.push_str(&format!(" AND pkg.name LIKE ?{}", param_idx));
            params.push(Box::new(format!("%{}%", package_name)));
            param_idx += 1;
        }

        // SSVC filtering
        if let Some(ref ssvc_exploitation) = query.ssvc_exploitation {
            let col = if use_aliased { "c.ssvc_exploitation" } else { "ssvc_exploitation" };
            sql.push_str(&format!(" AND {} = ?{}", col, param_idx));
            params.push(Box::new(ssvc_exploitation.clone()));
            param_idx += 1;
        }

        if let Some(ref ssvc_automatable) = query.ssvc_automatable {
            let col = if use_aliased { "c.ssvc_automatable" } else { "ssvc_automatable" };
            sql.push_str(&format!(" AND {} = ?{}", col, param_idx));
            params.push(Box::new(ssvc_automatable.clone()));
            #[allow(unused_assignments)]
            { param_idx += 1; }
        }

        sql.push_str(" ORDER BY ");
        let order_prefix = if use_aliased { "c." } else { "" };
        match query.sort_by {
            SortBy::Cvss => sql.push_str(&format!("{}cvss_v3_score DESC NULLS LAST", order_prefix)),
            SortBy::Epss => sql.push_str(&format!("{}epss_score DESC NULLS LAST", order_prefix)),
            SortBy::Published => sql.push_str(&format!("{}published_at DESC NULLS LAST", order_prefix)),
            SortBy::Modified => sql.push_str(&format!("{}modified_at DESC NULLS LAST", order_prefix)),
        }

        sql.push_str(&format!(" LIMIT {}", query.limit));

        let mut stmt = self.conn.prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let cwe_ids: String = row.get(6)?;
            let affected_products: String = row.get(7)?;
            let references: String = row.get(8)?;
            let exploit_urls: String = row.get(14)?;

            Ok(CveRow {
                cve_id: row.get(0)?,
                description: row.get(1)?,
                cvss_v3_score: row.get(2)?,
                cvss_v3_vector: row.get(3)?,
                epss_score: row.get(4)?,
                epss_percentile: row.get(5)?,
                cwe_ids,
                affected_products,
                references,
                kev_known_exploited: row.get(9)?,
                kev_date_added: row.get(10)?,
                published_at: row.get(11)?,
                modified_at: row.get(12)?,
                exploit_public: row.get(13)?,
                exploit_urls,
                metasploit_module: row.get(15)?,
                nuclei_template: row.get(16)?,
                ssvc_exploitation: row.get(17)?,
                ssvc_automatable: row.get(18)?,
                ssvc_technical_impact: row.get(19)?,
            })
        })?;

        let mut cves = Vec::new();
        for row in rows {
            let row = row?;
            cves.push(row.into_cve());
        }

        Ok(cves)
    }

    /// Récupère une CVE par son ID
    pub fn get_cve(&self, cve_id: &str) -> Result<Option<Cve>> {
        let row: Option<CveRow> = self
            .conn
            .query_row(
                r#"
            SELECT cve_id, description, cvss_v3_score, cvss_v3_vector,
                   epss_score, epss_percentile, cwe_ids, affected_products,
                   references_json, kev_known_exploited, kev_date_added,
                   published_at, modified_at,
                   exploit_public, exploit_urls, metasploit_module, nuclei_template,
                   ssvc_exploitation, ssvc_automatable, ssvc_technical_impact
            FROM cves WHERE cve_id = ?1
            "#,
                params![cve_id],
                |row| {
                    Ok(CveRow {
                        cve_id: row.get(0)?,
                        description: row.get(1)?,
                        cvss_v3_score: row.get(2)?,
                        cvss_v3_vector: row.get(3)?,
                        epss_score: row.get(4)?,
                        epss_percentile: row.get(5)?,
                        cwe_ids: row.get(6)?,
                        affected_products: row.get(7)?,
                        references: row.get(8)?,
                        kev_known_exploited: row.get(9)?,
                        kev_date_added: row.get(10)?,
                        published_at: row.get(11)?,
                        modified_at: row.get(12)?,
                        exploit_public: row.get(13)?,
                        exploit_urls: row.get(14)?,
                        metasploit_module: row.get(15)?,
                        nuclei_template: row.get(16)?,
                        ssvc_exploitation: row.get(17)?,
                        ssvc_automatable: row.get(18)?,
                        ssvc_technical_impact: row.get(19)?,
                    })
                },
            )
            .optional()?;

        match row {
            Some(r) => {
                let mut cve = r.into_cve();
                // Load affected packages
                cve.affected_packages = self.get_affected_packages(&cve.cve_id)?;
                Ok(Some(cve))
            }
            None => Ok(None),
        }
    }

    /// Récupère les packages affectés pour une CVE
    pub fn get_affected_packages(&self, cve_id: &str) -> Result<Vec<AffectedPackage>> {
        let mut stmt = self.conn.prepare(
            "SELECT ecosystem, name, vulnerable_range, fixed_version FROM affected_packages WHERE cve_id = ?1"
        )?;

        let packages = stmt.query_map(params![cve_id], |row| {
            Ok(AffectedPackage {
                ecosystem: row.get(0)?,
                name: row.get(1)?,
                vulnerable_range: row.get(2)?,
                fixed_version: row.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(packages)
    }

    /// Compte le nombre total de CVE
    pub fn count_cves(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Enregistre le début d'une synchronisation
    pub fn start_sync(&self, source: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO sync_history (source, started_at, status) VALUES (?1, datetime('now'), 'running')",
            params![source],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Marque une synchronisation comme terminée
    pub fn complete_sync(
        &self,
        sync_id: i64,
        cves_added: i64,
        cves_updated: i64,
        cves_unchanged: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_history SET completed_at = datetime('now'), status = 'completed', cves_added = ?2, cves_updated = ?3, cves_unchanged = ?4 WHERE id = ?1",
            params![sync_id, cves_added, cves_updated, cves_unchanged],
        )?;
        Ok(())
    }

    /// Marque une synchronisation comme échouée
    pub fn fail_sync(&self, sync_id: i64, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_history SET completed_at = datetime('now'), status = 'failed', error_message = ?2 WHERE id = ?1",
            params![sync_id, error],
        )?;
        Ok(())
    }

    /// The source was asked and has nothing new: nothing was downloaded. It
    /// counts as a run for the time to wait before asking again.
    pub fn unchanged_sync(&self, sync_id: i64) -> Result<()> {
        self.conn.execute("UPDATE sync_history SET completed_at = datetime('now'), status = 'unchanged' WHERE id = ?1", params![sync_id])?;
        Ok(())
    }

    /// Forgets a run that turned out to have nothing to do
    pub fn discard_sync(&self, sync_id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM sync_history WHERE id = ?1 AND status = 'running'", params![sync_id])?;
        Ok(())
    }

    /// When the last successful sync of a source **started**: what changed
    /// upstream while it was running is then covered by the next one.
    pub fn get_last_sync(&self, source: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let result: Option<String> = self.conn.query_row(
            "SELECT started_at FROM sync_history WHERE source = ?1 AND status IN ('completed', 'unchanged') ORDER BY started_at DESC LIMIT 1",
            params![source],
            |row| row.get(0),
        ).optional()?;

        match result {
            Some(s) => {
                // Parse the SQLite datetime format
                let dt = chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|d| d.and_utc());
                Ok(dt)
            }
            None => Ok(None),
        }
    }

    /// Statistiques de la base
    pub fn stats(&self) -> Result<DbStats> {
        let total_cves = self.count_cves()?;

        let with_cvss: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE cvss_v3_score IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let with_epss: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE epss_score IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let kev_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE kev_known_exploited = 1",
            [],
            |row| row.get(0),
        )?;

        let critical_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cves WHERE cvss_v3_score >= 9.0",
            [],
            |row| row.get(0),
        )?;

        Ok(DbStats {
            total_cves,
            with_cvss,
            with_epss,
            kev_count,
            critical_count,
        })
    }

    /// Met à jour les CVEs sans affected_products en extrayant depuis la description
    pub fn update_products_from_descriptions(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, description FROM cves WHERE affected_products = '[]' AND description IS NOT NULL"
        )?;

        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        let total = rows.len();
        let mut updated = 0i64;

        for (cve_id, description) in rows {
            let products = extraction::extract_from_description(&description);

            if !products.is_empty() {
                // Mettre à jour le JSON dans la table cves
                let json = serde_json::to_string(&products)?;
                self.conn.execute(
                    "UPDATE cves SET affected_products = ?1, updated_in_db = datetime('now') WHERE cve_id = ?2",
                    params![json, cve_id],
                )?;

                // Insérer dans la table normalisée
                for product in &products {
                    self.conn.execute(
                        r#"
                        INSERT INTO affected_products_normalized (cve_id, vendor, product, version, version_start, version_end, cpe, start_excluded, end_included)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                        "#,
                        params![
                            cve_id,
                            product.vendor,
                            product.product,
                            product.version,
                            product.version_start,
                            product.version_end,
                            product.cpe,
                            product.version_start_excluded,
                            product.version_end_included,
                        ],
                    )?;
                }

                updated += 1;
            }
        }

        tracing::info!(
            "Extracted products for {}/{} CVEs with empty affected_products",
            updated,
            total
        );

        Ok(updated)
    }

    /// Get metadata value by key
    /// Version of the schema this database is at
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.get_metadata("schema_version")?.and_then(|v| v.parse().ok()).unwrap_or(1))
    }

    pub fn get_metadata(&self, key: &str) -> Result<Option<String>> {
        let result: Option<String> = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        ).optional()?;
        Ok(result)
    }

    /// Set metadata value
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Remove a metadata value
    pub fn delete_metadata(&self, key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM metadata WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Update SSVC fields for existing CVEs (batch optimized)
    pub fn batch_update_ssvc(&self, updates: &[(String, Option<String>, Option<String>, Option<String>)]) -> Result<i64> {
        let mut updated = 0i64;

        self.conn.execute("BEGIN TRANSACTION", [])?;

        for (cve_id, exploitation, automatable, technical_impact) in updates {
            let rows = self.conn.execute(
                r#"
                UPDATE cves SET
                    ssvc_exploitation = COALESCE(?2, ssvc_exploitation),
                    ssvc_automatable = COALESCE(?3, ssvc_automatable),
                    ssvc_technical_impact = COALESCE(?4, ssvc_technical_impact),
                    updated_in_db = datetime('now')
                WHERE cve_id = ?1
                    AND (ssvc_exploitation IS NOT COALESCE(?2, ssvc_exploitation)
                        OR ssvc_automatable IS NOT COALESCE(?3, ssvc_automatable)
                        OR ssvc_technical_impact IS NOT COALESCE(?4, ssvc_technical_impact))
                "#,
                params![cve_id, exploitation, automatable, technical_impact],
            )?;
            if rows > 0 {
                updated += 1;
            }
        }

        self.conn.execute("COMMIT", [])?;

        Ok(updated)
    }
}

/// Row intermédiaire pour la conversion depuis SQLite
struct CveRow {
    cve_id: String,
    description: Option<String>,
    cvss_v3_score: Option<f64>,
    cvss_v3_vector: Option<String>,
    epss_score: Option<f64>,
    epss_percentile: Option<f64>,
    cwe_ids: String,
    affected_products: String,
    references: String,
    kev_known_exploited: i32,
    kev_date_added: Option<String>,
    published_at: Option<String>,
    modified_at: Option<String>,
    // Enrichissement
    exploit_public: i32,
    exploit_urls: String,
    metasploit_module: Option<String>,
    nuclei_template: Option<String>,
    // SSVC
    ssvc_exploitation: Option<String>,
    ssvc_automatable: Option<String>,
    ssvc_technical_impact: Option<String>,
}

impl CveRow {
    fn into_cve(self) -> Cve {
        use chrono::DateTime;

        let cwe_ids: Vec<String> = serde_json::from_str(&self.cwe_ids).unwrap_or_default();
        let affected_products: Vec<AffectedProduct> =
            serde_json::from_str(&self.affected_products).unwrap_or_default();
        let references: Vec<Reference> = serde_json::from_str(&self.references).unwrap_or_default();
        let exploit_urls: Vec<String> = serde_json::from_str(&self.exploit_urls).unwrap_or_default();

        let published_at = self
            .published_at
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));

        let modified_at = self
            .modified_at
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));

        Cve {
            cve_id: self.cve_id,
            description: self.description,
            cvss_v3_score: self.cvss_v3_score,
            cvss_v3_vector: self.cvss_v3_vector,
            epss_score: self.epss_score,
            epss_percentile: self.epss_percentile,
            cwe_ids,
            affected_products,
            references,
            kev_known_exploited: self.kev_known_exploited != 0,
            kev_date_added: self.kev_date_added,
            published_at,
            modified_at,
            // Enrichissement
            exploit_public: self.exploit_public != 0,
            exploit_urls,
            metasploit_module: self.metasploit_module,
            nuclei_template: self.nuclei_template,
            affected_packages: Vec::new(), // Loaded separately if needed
            // SSVC
            ssvc_exploitation: self.ssvc_exploitation,
            ssvc_automatable: self.ssvc_automatable,
            ssvc_technical_impact: self.ssvc_technical_impact,
        }
    }
}

#[derive(Debug, Default)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub min_cvss: Option<f64>,
    pub min_epss: Option<f64>,
    pub only_kev: bool,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub has_exploit: bool,
    /// Only CVEs this source has data on
    pub source: Option<String>,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub ssvc_exploitation: Option<String>,
    pub ssvc_automatable: Option<String>,
    pub sort_by: SortBy,
    pub limit: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum SortBy {
    Cvss,
    Epss,
    #[default]
    Published,
    Modified,
}

#[derive(Debug)]
pub struct DbStats {
    pub total_cves: i64,
    pub with_cvss: i64,
    pub with_epss: i64,
    pub kev_count: i64,
    pub critical_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = Database::open(&db_path).unwrap();
        (db, temp_dir)
    }

    #[test]
    fn a_writing_transaction_waits_its_turn_instead_of_failing() {
        let (db, dir) = create_test_db();
        let other = Database::connect(&dir.path().join("test.db")).unwrap();
        other.conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        db.conn.busy_timeout(std::time::Duration::ZERO).unwrap();

        // What used to happen: a transaction reads, a synchronization commits, the transaction's
        // first write is refused at once, with or without time to wait
        let deferred = db.conn.unchecked_transaction().unwrap();
        let _: i64 = deferred.query_row("SELECT COUNT(*) FROM metadata", [], |r| r.get(0)).unwrap();
        other.set_metadata("sync", "wrote meanwhile").unwrap();
        let refused = deferred.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('k', 'v')", []);
        assert!(refused.unwrap_err().to_string().contains("locked"));
        drop(deferred);

        // A writing transaction holds the lock from its opening: the other side waits for it
        // (here, with no time to wait, it is told to come back), and its own writes pass
        let tx = db.write_tx().unwrap();
        let _: i64 = tx.query_row("SELECT COUNT(*) FROM metadata", [], |r| r.get(0)).unwrap();
        assert!(other.set_metadata("sync", "second").is_err());
        tx.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('k', 'v')", []).unwrap();
        tx.commit().unwrap();
        other.set_metadata("sync", "third").unwrap();
        assert_eq!(db.get_metadata("k").unwrap().as_deref(), Some("v"));
    }

    #[test]
    fn test_database_initialization() {
        let (db, _temp_dir) = create_test_db();

        // Check schema version is 27
        let version: String = db.conn.query_row(
            "SELECT value FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0)
        ).unwrap();

        assert_eq!(version, "27");
    }

    #[test]
    fn test_ssvc_columns_exist() {
        let (db, _temp_dir) = create_test_db();

        // Verify SSVC columns exist in schema
        let sql = "PRAGMA table_info(cves)";
        let mut stmt = db.conn.prepare(sql).unwrap();
        let columns: Vec<String> = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        }).unwrap().filter_map(Result::ok).collect();

        assert!(columns.contains(&"ssvc_exploitation".to_string()));
        assert!(columns.contains(&"ssvc_automatable".to_string()));
        assert!(columns.contains(&"ssvc_technical_impact".to_string()));
    }

    #[test]
    fn test_upsert_cve_with_ssvc() {
        let (db, _temp_dir) = create_test_db();

        let mut cve = Cve::new("CVE-2024-12345".to_string());
        cve.description = Some("Test vulnerability".to_string());
        cve.cvss_v3_score = Some(9.8);
        cve.ssvc_exploitation = Some("active".to_string());
        cve.ssvc_automatable = Some("yes".to_string());
        cve.ssvc_technical_impact = Some("total".to_string());

        let is_new = db.upsert_cve(&cve).unwrap();
        assert_eq!(is_new, Stored::Created);

        // Retrieve and verify
        let retrieved = db.get_cve("CVE-2024-12345").unwrap().unwrap();
        assert_eq!(retrieved.ssvc_exploitation, Some("active".to_string()));
        assert_eq!(retrieved.ssvc_automatable, Some("yes".to_string()));
        assert_eq!(retrieved.ssvc_technical_impact, Some("total".to_string()));
    }

    #[test]
    fn storing_a_cve_says_whether_it_was_created_changed_or_left_alone() {
        let (db, _temp_dir) = create_test_db();
        let mut cve = Cve::new("CVE-2024-11111".to_string());
        cve.description = Some("Test vulnerability".to_string());
        cve.cvss_v3_score = Some(7.5);
        cve.cwe_ids = vec!["CWE-79".to_string()];
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Created);
        let written = |db: &Database| -> String {
            db.conn.query_row("SELECT updated_in_db FROM cves WHERE cve_id = 'CVE-2024-11111'", [], |r| r.get(0)).unwrap()
        };
        db.conn.execute("UPDATE cves SET updated_in_db = 'before'", []).unwrap();

        // Read again as it is: nothing is written
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Same);
        assert_eq!(db.upsert_cve_untracked(&cve).unwrap(), Stored::Same);
        // A source that knows less than what is stored changes nothing either
        assert_eq!(db.upsert_cve(&Cve::new("CVE-2024-11111".to_string())).unwrap(), Stored::Same);
        assert_eq!(written(&db), "before");

        // Each kind of field, once new, is a change, and only once
        let mut scored = Cve::new("CVE-2024-11111".to_string());
        scored.epss_score = Some(0.42);
        assert_eq!(db.upsert_cve(&scored).unwrap(), Stored::Changed);
        assert_eq!(db.upsert_cve(&scored).unwrap(), Stored::Same);
        assert_ne!(written(&db), "before");
        let mut exploited = Cve::new("CVE-2024-11111".to_string());
        exploited.kev_known_exploited = true;
        exploited.exploit_public = true;
        assert_eq!(db.upsert_cve(&exploited).unwrap(), Stored::Changed);
        assert_eq!(db.upsert_cve(&exploited).unwrap(), Stored::Same);
        // A flag once raised is not lowered by a source that does not raise it
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Same);
        let mut template = Cve::new("CVE-2024-11111".to_string());
        template.nuclei_template = Some("http/cves/2024/CVE-2024-11111.yaml".to_string());
        assert_eq!(db.upsert_cve(&template).unwrap(), Stored::Changed);
        assert_eq!(db.upsert_cve(&template).unwrap(), Stored::Same);
        cve.cwe_ids = vec!["CWE-79".to_string(), "CWE-80".to_string()];
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Changed);
        cve.cvss_v3_score = Some(9.8);
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Changed);
        assert_eq!(db.upsert_cve(&cve).unwrap(), Stored::Same);

        // What was stored along the way is all there
        let stored = db.get_cve("CVE-2024-11111").unwrap().unwrap();
        assert_eq!(stored.cvss_v3_score, Some(9.8));
        assert_eq!(stored.epss_score, Some(0.42));
        assert!(stored.kev_known_exploited && stored.exploit_public);
        assert_eq!(stored.nuclei_template.as_deref(), Some("http/cves/2024/CVE-2024-11111.yaml"));
        assert_eq!(stored.cwe_ids.len(), 2);
    }

    #[test]
    fn a_run_keeps_created_changed_and_unchanged_apart() {
        let (db, _temp_dir) = create_test_db();
        let run = db.start_sync("nvd").unwrap();
        db.complete_sync(run, 3, 12, 340).unwrap();
        let last = &db.recent_syncs(1).unwrap()[0];
        assert_eq!((last.added, last.updated, last.same), (3, 12, 340));
        let latest = &db.last_sync_runs().unwrap()[0];
        assert_eq!((latest.added, latest.updated, latest.same), (3, 12, 340));
    }

    #[test]
    fn test_upsert_cve_updates_ssvc() {
        let (db, _temp_dir) = create_test_db();

        // Insert initial CVE without SSVC
        let mut cve = Cve::new("CVE-2024-67890".to_string());
        cve.description = Some("Test vulnerability".to_string());
        db.upsert_cve(&cve).unwrap();

        // Update with SSVC data
        let mut cve_updated = Cve::new("CVE-2024-67890".to_string());
        cve_updated.ssvc_exploitation = Some("poc".to_string());
        cve_updated.ssvc_automatable = Some("no".to_string());
        cve_updated.ssvc_technical_impact = Some("partial".to_string());

        db.upsert_cve(&cve_updated).unwrap();

        // Verify update - SSVC fields should be updated, description should be preserved
        let retrieved = db.get_cve("CVE-2024-67890").unwrap().unwrap();
        assert_eq!(retrieved.ssvc_exploitation, Some("poc".to_string()));
        assert_eq!(retrieved.ssvc_automatable, Some("no".to_string()));
        assert_eq!(retrieved.ssvc_technical_impact, Some("partial".to_string()));
        assert_eq!(retrieved.description, Some("Test vulnerability".to_string()));
    }

    #[test]
    fn test_batch_update_ssvc() {
        let (db, _temp_dir) = create_test_db();

        // Insert multiple CVEs
        for i in 1..=5 {
            let cve = Cve::new(format!("CVE-2024-{:05}", i));
            db.upsert_cve(&cve).unwrap();
        }

        // Batch update SSVC
        let updates = vec![
            ("CVE-2024-00001".to_string(), Some("active".to_string()), Some("yes".to_string()), Some("total".to_string())),
            ("CVE-2024-00002".to_string(), Some("poc".to_string()), Some("no".to_string()), Some("partial".to_string())),
            ("CVE-2024-00003".to_string(), Some("none".to_string()), Some("no".to_string()), Some("partial".to_string())),
        ];

        let updated = db.batch_update_ssvc(&updates).unwrap();
        assert_eq!(updated, 3);
        // The same values again change nothing
        assert_eq!(db.batch_update_ssvc(&updates).unwrap(), 0);

        // Verify updates
        let cve1 = db.get_cve("CVE-2024-00001").unwrap().unwrap();
        assert_eq!(cve1.ssvc_exploitation, Some("active".to_string()));

        let cve2 = db.get_cve("CVE-2024-00002").unwrap().unwrap();
        assert_eq!(cve2.ssvc_exploitation, Some("poc".to_string()));

        let cve3 = db.get_cve("CVE-2024-00003").unwrap().unwrap();
        assert_eq!(cve3.ssvc_exploitation, Some("none".to_string()));
    }

    #[test]
    fn test_search_with_ssvc_exploitation_filter() {
        let (db, _temp_dir) = create_test_db();

        // Insert CVEs with different exploitation levels
        let mut cve1 = Cve::new("CVE-2024-11111".to_string());
        cve1.ssvc_exploitation = Some("active".to_string());
        cve1.cvss_v3_score = Some(9.0);
        db.upsert_cve(&cve1).unwrap();

        let mut cve2 = Cve::new("CVE-2024-22222".to_string());
        cve2.ssvc_exploitation = Some("poc".to_string());
        cve2.cvss_v3_score = Some(8.0);
        db.upsert_cve(&cve2).unwrap();

        let mut cve3 = Cve::new("CVE-2024-33333".to_string());
        cve3.ssvc_exploitation = Some("none".to_string());
        cve3.cvss_v3_score = Some(7.0);
        db.upsert_cve(&cve3).unwrap();

        // Search for active exploitation
        let query = SearchQuery {
            ssvc_exploitation: Some("active".to_string()),
            limit: 10,
            ..Default::default()
        };

        let results = db.search(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-11111");
    }

    #[test]
    fn test_search_with_ssvc_automatable_filter() {
        let (db, _temp_dir) = create_test_db();

        // Insert CVEs with different automatable values
        let mut cve1 = Cve::new("CVE-2024-44444".to_string());
        cve1.ssvc_automatable = Some("yes".to_string());
        cve1.cvss_v3_score = Some(9.0);
        db.upsert_cve(&cve1).unwrap();

        let mut cve2 = Cve::new("CVE-2024-55555".to_string());
        cve2.ssvc_automatable = Some("no".to_string());
        cve2.cvss_v3_score = Some(8.0);
        db.upsert_cve(&cve2).unwrap();

        // Search for automatable
        let query = SearchQuery {
            ssvc_automatable: Some("yes".to_string()),
            limit: 10,
            ..Default::default()
        };

        let results = db.search(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-44444");
    }

    #[test]
    fn test_search_with_combined_ssvc_filters() {
        let (db, _temp_dir) = create_test_db();

        // Insert CVEs
        let mut cve1 = Cve::new("CVE-2024-66666".to_string());
        cve1.ssvc_exploitation = Some("active".to_string());
        cve1.ssvc_automatable = Some("yes".to_string());
        cve1.cvss_v3_score = Some(9.5);
        db.upsert_cve(&cve1).unwrap();

        let mut cve2 = Cve::new("CVE-2024-77777".to_string());
        cve2.ssvc_exploitation = Some("active".to_string());
        cve2.ssvc_automatable = Some("no".to_string());
        cve2.cvss_v3_score = Some(9.0);
        db.upsert_cve(&cve2).unwrap();

        let mut cve3 = Cve::new("CVE-2024-88888".to_string());
        cve3.ssvc_exploitation = Some("poc".to_string());
        cve3.ssvc_automatable = Some("yes".to_string());
        cve3.cvss_v3_score = Some(8.5);
        db.upsert_cve(&cve3).unwrap();

        // Search for active AND automatable
        let query = SearchQuery {
            ssvc_exploitation: Some("active".to_string()),
            ssvc_automatable: Some("yes".to_string()),
            limit: 10,
            ..Default::default()
        };

        let results = db.search(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-66666");
    }

    #[test]
    fn test_metadata_operations() {
        let (db, _temp_dir) = create_test_db();

        // Set metadata
        db.set_metadata("test_key", "test_value").unwrap();

        // Get metadata
        let value = db.get_metadata("test_key").unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        // Update metadata
        db.set_metadata("test_key", "new_value").unwrap();
        let updated = db.get_metadata("test_key").unwrap();
        assert_eq!(updated, Some("new_value".to_string()));

        // Non-existent key
        let none = db.get_metadata("nonexistent").unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn test_batch_update_ssvc_nonexistent_cve() {
        let (db, _temp_dir) = create_test_db();

        // Try to update non-existent CVE
        let updates = vec![
            ("CVE-9999-99999".to_string(), Some("active".to_string()), None, None),
        ];

        let updated = db.batch_update_ssvc(&updates).unwrap();
        assert_eq!(updated, 0); // No rows affected
    }

    #[test]
    fn test_ssvc_index_exists() {
        let (db, _temp_dir) = create_test_db();

        // Check that index on ssvc_exploitation exists
        let sql = "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_cves_ssvc_exploitation'";
        let index_exists: Result<String, _> = db.conn.query_row(sql, [], |row| row.get(0));

        assert!(index_exists.is_ok());
        assert_eq!(index_exists.unwrap(), "idx_cves_ssvc_exploitation");
    }
    #[test]
    fn the_history_read_after_the_fact_is_not_a_change() {
        let db = Database::open_in_memory().unwrap();
        let changes = |id: &str| -> i64 { db.conn.query_row("SELECT COUNT(*) FROM cve_changes WHERE cve_id = ?1", params![id], |r| r.get(0)).unwrap() };
        let cve = |id: &str, description: &str| {
            let mut cve = Cve::new(id.into());
            cve.description = Some(description.into());
            cve
        };
        db.upsert_cve_untracked(&cve("CVE-2014-0160", "Heartbleed")).unwrap();
        assert_eq!(changes("CVE-2014-0160"), 0);
        // A stub left by another source is completed without a word either
        let mut stub = Cve::new("CVE-2021-3156".into());
        stub.kev_known_exploited = true;
        db.upsert_cve(&stub).unwrap();
        let before = changes("CVE-2021-3156");
        db.upsert_cve_untracked(&cve("CVE-2021-3156", "Heap overflow in sudo")).unwrap();
        assert_eq!(changes("CVE-2021-3156"), before);
        // What changes afterwards is recorded as before
        db.upsert_cve(&cve("CVE-2014-0160", "Heartbleed, reworded")).unwrap();
        assert_eq!(changes("CVE-2014-0160"), 1);
    }

    #[test]
    fn the_version_filter_of_the_search_orders_versions() {
        let db = Database::open_in_memory().unwrap();
        let add = |id: &str, start: Option<&str>, end: Option<&str>, end_included: bool| {
            let mut cve = Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.affected_products.push(AffectedProduct {
                vendor: Some("acme".into()),
                product: Some("widget".into()),
                version: Some("*".into()),
                version_start: start.map(String::from),
                version_end: end.map(String::from),
                version_end_included: end_included,
                cpe: Some("cpe:2.3:a:acme:widget:*".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        };
        add("CVE-2025-0001", None, Some("3.7.3"), false);
        add("CVE-2025-0002", Some("3.7.10"), Some("3.7.20"), false);
        add("CVE-2025-0003", None, Some("10.0"), true);
        add("CVE-2025-0004", None, None, false);
        let found = |version: &str| {
            let query = SearchQuery { product: Some("widget".into()), version: Some(version.into()), limit: 50, ..Default::default() };
            let mut ids: Vec<String> = db.search(&query).unwrap().into_iter().map(|c| c.cve_id[11..].to_string()).collect();
            ids.sort();
            ids.join(" ")
        };
        // As text, 3.7.16 sorts before 3.7.3 and 10.0 before 9.0
        assert_eq!(found("3.7.16"), "02 03 04");
        assert_eq!(found("3.7.2"), "01 03 04");
        assert_eq!(found("9.0"), "03 04");
        assert_eq!(found("10.0"), "03 04");
        assert_eq!(found("10.1"), "04");
    }

}
