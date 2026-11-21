//! Watchlist database operations
//!
//! CRUD operations for users, projects, applications, and watchlist entries.
//! Designed to be completely isolated from CVE intelligence data.

use anyhow::{anyhow, Result};
use rusqlite::params;

use crate::db::Database;
use crate::models::{
    Application, CveStatus, Priority, Project, User, WatchlistEntry,
    WatchlistEntryWithContext, WatchlistSummary,
};

// ==========================================
// User Operations
// ==========================================

impl Database {
    /// Create a new user
    #[allow(dead_code)]
    pub fn create_user(&self, user: &User) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO users (username, email) VALUES (?1, ?2)",
            params![user.username, user.email],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get user by username
    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, username, email, created_at, updated_at FROM users WHERE username = ?1"
        )?;

        let user = stmt.query_row(params![username], |row| {
            Ok(User {
                id: Some(row.get(0)?),
                username: row.get(1)?,
                email: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        }).optional()?;

        Ok(user)
    }

    /// Get user by ID
    #[allow(dead_code)]
    pub fn get_user(&self, id: i64) -> Result<Option<User>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, username, email, created_at, updated_at FROM users WHERE id = ?1"
        )?;

        let user = stmt.query_row(params![id], |row| {
            Ok(User {
                id: Some(row.get(0)?),
                username: row.get(1)?,
                email: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        }).optional()?;

        Ok(user)
    }

    /// List all users
    #[allow(dead_code)]
    pub fn list_users(&self) -> Result<Vec<User>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, username, email, created_at, updated_at FROM users ORDER BY username"
        )?;

        let users = stmt.query_map([], |row| {
            Ok(User {
                id: Some(row.get(0)?),
                username: row.get(1)?,
                email: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(users)
    }

    /// Delete user by username (cascades to projects, applications, watchlist entries)
    #[allow(dead_code)]
    pub fn delete_user(&self, username: &str) -> Result<bool> {
        let rows = self.conn().execute(
            "DELETE FROM users WHERE username = ?1",
            params![username],
        )?;
        Ok(rows > 0)
    }
}

// ==========================================
// Project Operations
// ==========================================

impl Database {
    /// Create a new project
    pub fn create_project(&self, project: &Project) -> Result<i64> {
        self.conn().execute(
            "INSERT INTO projects (user_id, name, description, organization_id)
             VALUES (?1, ?2, ?3, (SELECT o.id FROM organizations o JOIN users u ON u.username = o.name WHERE u.id = ?1))",
            params![project.user_id, project.name, project.description],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get project by user and name
    pub fn get_project_by_name(&self, user_id: i64, name: &str) -> Result<Option<Project>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, user_id, name, description, created_at, updated_at
             FROM projects WHERE user_id = ?1 AND name = ?2"
        )?;

        let project = stmt.query_row(params![user_id, name], |row| {
            Ok(Project {
                id: Some(row.get(0)?),
                user_id: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        }).optional()?;

        Ok(project)
    }

    /// Get project by ID
    #[allow(dead_code)]
    pub fn get_project(&self, id: i64) -> Result<Option<Project>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, user_id, name, description, created_at, updated_at FROM projects WHERE id = ?1"
        )?;

        let project = stmt.query_row(params![id], |row| {
            Ok(Project {
                id: Some(row.get(0)?),
                user_id: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        }).optional()?;

        Ok(project)
    }

    /// List projects for a user
    pub fn list_projects(&self, user_id: i64) -> Result<Vec<Project>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, user_id, name, description, created_at, updated_at
             FROM projects WHERE user_id = ?1 ORDER BY name"
        )?;

        let projects = stmt.query_map(params![user_id], |row| {
            Ok(Project {
                id: Some(row.get(0)?),
                user_id: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(projects)
    }

    /// Delete project (cascades to applications and watchlist entries)
    pub fn delete_project(&self, user_id: i64, name: &str) -> Result<bool> {
        match self.get_project_by_name(user_id, name)?.and_then(|p| p.id) {
            Some(id) => {
                self.delete_project_by_id(id, &crate::db::Actor::system("cli"))?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

// ==========================================
// Application Operations
// ==========================================

fn application_row(row: &rusqlite::Row) -> rusqlite::Result<Application> {
    Ok(Application {
        id: Some(row.get(0)?),
        project_id: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        vendor: row.get(4)?,
        ecosystem: row.get(5)?,
        cpe_pattern: row.get(6)?,
        notes: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        group: row.get(10)?,
    })
}

impl Database {
    /// Create a new application
    pub fn create_application(&self, app: &Application) -> Result<i64> {
        let tracked: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM applications WHERE project_id = ?1",
            params![app.project_id],
            |r| r.get(0),
        )?;
        if tracked >= MAX_PROJECT_APPLICATIONS {
            return Err(UserFacing(format!("This project already tracks {MAX_PROJECT_APPLICATIONS} applications, the maximum.")).into());
        }
        self.conn().execute(
            "INSERT INTO applications (project_id, name, version, vendor, ecosystem, cpe_pattern, notes, grp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                app.project_id,
                app.name,
                app.version,
                app.vendor,
                app.ecosystem,
                app.cpe_pattern,
                app.notes,
                app.group
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get application by project, name, and version
    pub fn get_application_by_name(
        &self,
        project_id: i64,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<Application>> {
        let mut stmt = if version.is_some() {
            self.conn().prepare(
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp
                 FROM applications WHERE project_id = ?1 AND name = ?2 AND version = ?3 AND grp = ''"
            )?
        } else {
            self.conn().prepare(
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp
                 FROM applications WHERE project_id = ?1 AND name = ?2 AND version IS NULL AND grp = ''"
            )?
        };

        let app = if let Some(ver) = version {
            stmt.query_row(params![project_id, name, ver], |row| {
                application_row(row)
            }).optional()?
        } else {
            stmt.query_row(params![project_id, name], |row| {
                application_row(row)
            }).optional()?
        };

        Ok(app)
    }

    /// Application tracked for a group of inventory sources
    pub fn get_group_application(
        &self,
        project_id: i64,
        group: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<Application>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp
                 FROM applications WHERE project_id = ?1 AND grp = ?2 AND name = ?3 AND version IS ?4",
                params![project_id, group, name, version],
                application_row,
            )
            .optional()?)
    }

    /// Get application by ID
    #[allow(dead_code)]
    pub fn get_application(&self, id: i64) -> Result<Option<Application>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp
             FROM applications WHERE id = ?1"
        )?;

        let app = stmt.query_row(params![id], |row| {
            application_row(row)
        }).optional()?;

        Ok(app)
    }

    /// List applications for a project
    pub fn list_applications(&self, project_id: i64) -> Result<Vec<Application>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp
             FROM applications WHERE project_id = ?1 ORDER BY name, version"
        )?;

        let apps = stmt.query_map(params![project_id], |row| {
            application_row(row)
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(apps)
    }

    /// Rescans every application against the current CVE data.
    /// Returns the number of new watchlist entries.
    pub fn rescan_all_applications(&self) -> Result<i64> {
        let ids = {
            let mut stmt = self.conn().prepare("SELECT id FROM applications ORDER BY id")?;
            let ids = stmt
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ids
        };
        let mut new_entries = 0;
        for id in ids {
            if let Some(app) = self.get_application(id)? {
                match self.scan_app_for_cves(&app) {
                    Ok((new, _)) => new_entries += new,
                    Err(e) if is_refusal(&e) => tracing::warn!("application '{}' skipped: {e}", app.name),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(new_entries)
    }

    /// Update application version
    pub fn update_application_version(&self, app_id: i64, new_version: &str) -> Result<bool> {
        let rows = self.conn().execute(
            "UPDATE applications SET version = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![new_version, app_id],
        )?;
        Ok(rows > 0)
    }

    /// Delete application (cascades to watchlist entries)
    pub fn delete_application(&self, project_id: i64, name: &str, version: Option<&str>) -> Result<bool> {
        let app_id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM applications WHERE project_id = ?1 AND name = ?2 AND version IS ?3 AND grp = ''",
                params![project_id, name, version],
                |r| r.get(0),
            )
            .optional()?;
        match app_id {
            // Keeps the history of the removed entries
            Some(id) => self.delete_application_by_id(project_id, id, &crate::db::Actor::system("cli")),
            None => Ok(false),
        }
    }
}

// ==========================================
// Watchlist Entry Operations
// ==========================================

impl Database {
    /// Create or update a watchlist entry
    pub fn upsert_watchlist_entry(&self, entry: &WatchlistEntry) -> Result<i64> {
        self.conn().execute(
            r#"INSERT INTO watchlist_entries (app_id, cve_id, status, priority, assigned_to, notes, treated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(app_id, cve_id) DO UPDATE SET
                   status = excluded.status,
                   priority = excluded.priority,
                   assigned_to = COALESCE(excluded.assigned_to, assigned_to),
                   notes = COALESCE(excluded.notes, notes),
                   treated_at = excluded.treated_at,
                   updated_at = datetime('now')"#,
            params![
                entry.app_id,
                entry.cve_id,
                entry.status.as_str(),
                entry.priority.as_str(),
                entry.assigned_to,
                entry.notes,
                entry.treated_at
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get watchlist entry by app and CVE
    pub fn get_watchlist_entry(&self, app_id: i64, cve_id: &str) -> Result<Option<WatchlistEntry>> {
        let mut stmt = self.conn().prepare(
            "SELECT id, app_id, cve_id, status, priority, assigned_to, notes, created_at, updated_at, treated_at
             FROM watchlist_entries WHERE app_id = ?1 AND cve_id = ?2"
        )?;

        let entry = stmt.query_row(params![app_id, cve_id], |row| {
            let status_str: String = row.get(3)?;
            let priority_str: String = row.get(4)?;
            Ok(WatchlistEntry {
                id: Some(row.get(0)?),
                app_id: row.get(1)?,
                cve_id: row.get(2)?,
                status: CveStatus::from_str(&status_str).unwrap_or(CveStatus::Untreated),
                priority: Priority::from_str(&priority_str).unwrap_or(Priority::Medium),
                assigned_to: row.get(5)?,
                notes: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
                treated_at: row.get(9)?,
            })
        }).optional()?;

        Ok(entry)
    }

    /// Update watchlist entry status (CLI): recorded in the lifecycle history
    pub fn update_watchlist_status(
        &self,
        app_id: i64,
        cve_id: &str,
        status: CveStatus,
        notes: Option<&str>,
    ) -> Result<bool> {
        let entry_id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM watchlist_entries WHERE app_id = ?1 AND cve_id = ?2",
                params![app_id, cve_id],
                |r| r.get(0),
            )
            .optional()?;
        match entry_id {
            Some(id) => self.change_entry_status(id, status, &crate::db::Actor::system("cli"), notes),
            None => Ok(false),
        }
    }

    /// List watchlist entries with context
    pub fn list_watchlist_entries(
        &self,
        user_id: Option<i64>,
        project_id: Option<i64>,
        app_name: Option<&str>,
        status_filter: Option<CveStatus>,
    ) -> Result<Vec<WatchlistEntryWithContext>> {
        let mut sql = String::from(
            r#"SELECT
                w.id, w.app_id, w.cve_id, w.status, w.priority, w.assigned_to, w.notes,
                w.created_at, w.updated_at, w.treated_at,
                a.name as app_name, a.version as app_version,
                p.name as project_name,
                u.username,
                c.cvss_v3_score, c.description, c.kev_known_exploited
               FROM watchlist_entries w
               JOIN applications a ON w.app_id = a.id
               JOIN projects p ON a.project_id = p.id
               JOIN users u ON p.user_id = u.id
               LEFT JOIN cves c ON w.cve_id = c.cve_id
               WHERE 1=1"#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(uid) = user_id {
            sql.push_str(&format!(" AND u.id = ?{}", param_idx));
            params_vec.push(Box::new(uid));
            param_idx += 1;
        }

        if let Some(pid) = project_id {
            sql.push_str(&format!(" AND p.id = ?{}", param_idx));
            params_vec.push(Box::new(pid));
            param_idx += 1;
        }

        if let Some(app) = app_name {
            sql.push_str(&format!(" AND a.name = ?{}", param_idx));
            params_vec.push(Box::new(app.to_string()));
            param_idx += 1;
        }

        if let Some(status) = status_filter {
            sql.push_str(&format!(" AND w.status = ?{}", param_idx));
            params_vec.push(Box::new(status.as_str().to_string()));
            #[allow(unused_assignments)]
            { param_idx += 1; }
        }

        sql.push_str(" ORDER BY w.created_at DESC");

        let mut stmt = self.conn().prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let entries = stmt.query_map(params_refs.as_slice(), |row| {
            let status_str: String = row.get(3)?;
            let priority_str: String = row.get(4)?;
            let kev: Option<i32> = row.get(16)?;

            Ok(WatchlistEntryWithContext {
                entry: WatchlistEntry {
                    id: Some(row.get(0)?),
                    app_id: row.get(1)?,
                    cve_id: row.get(2)?,
                    status: CveStatus::from_str(&status_str).unwrap_or(CveStatus::Untreated),
                    priority: Priority::from_str(&priority_str).unwrap_or(Priority::Medium),
                    assigned_to: row.get(5)?,
                    notes: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    treated_at: row.get(9)?,
                },
                app_name: row.get(10)?,
                app_version: row.get(11)?,
                project_name: row.get(12)?,
                username: row.get(13)?,
                cve_cvss: row.get(14)?,
                cve_description: row.get(15)?,
                cve_kev: kev.unwrap_or(0) != 0,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Get watchlist summary/statistics
    pub fn get_watchlist_summary(
        &self,
        user_id: Option<i64>,
        project_id: Option<i64>,
    ) -> Result<WatchlistSummary> {
        let mut base_sql = String::from(
            r#"FROM watchlist_entries w
               JOIN applications a ON w.app_id = a.id
               JOIN projects p ON a.project_id = p.id
               WHERE 1=1"#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(uid) = user_id {
            base_sql.push_str(&format!(" AND p.user_id = ?{}", param_idx));
            params_vec.push(Box::new(uid));
            param_idx += 1;
        }

        if let Some(pid) = project_id {
            base_sql.push_str(&format!(" AND p.id = ?{}", param_idx));
            params_vec.push(Box::new(pid));
            #[allow(unused_assignments)]
            { param_idx += 1; }
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        // Total
        let total: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {}", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        // By status
        let untreated: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.status = 'untreated'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        let treated: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.status = 'treated'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        let not_applicable: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.status = 'not_applicable'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        // By priority
        let critical: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.priority = 'critical'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        let high: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.priority = 'high'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        let medium: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.priority = 'medium'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        let low: i64 = self.conn().query_row(
            &format!("SELECT COUNT(*) {} AND w.priority = 'low'", base_sql),
            params_refs.as_slice(),
            |row| row.get(0),
        )?;

        Ok(WatchlistSummary {
            total_entries: total,
            untreated,
            treated,
            not_applicable,
            critical,
            high,
            medium,
            low,
        })
    }
}

// ==========================================
// Scan Operations
// ==========================================

/// Above this many matching CVEs, a name is too generic to be one application
#[cfg(not(test))]
pub const MAX_APP_MATCHES: usize = 20_000;
#[cfg(test)]
pub const MAX_APP_MATCHES: usize = 40;
/// Applications one project may track
pub const MAX_PROJECT_APPLICATIONS: i64 = 10_000;

/// The name of an application matches too many CVEs to be tracked as such
#[derive(Debug)]
pub struct TooGeneric(pub usize);

impl std::fmt::Display for TooGeneric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "This name matches {} CVEs: it is too generic. Give a more precise name, the vendor or the version.",
            self.0
        )
    }
}

impl std::error::Error for TooGeneric {}

/// An error whose message is meant for the person who made the request
#[derive(Debug)]
pub struct UserFacing(pub String);

impl std::fmt::Display for UserFacing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UserFacing {}

/// CVE entries one project may hold (one per application and CVE)
#[cfg(not(test))]
pub const MAX_PROJECT_ENTRIES: i64 = 200_000;
#[cfg(test)]
pub const MAX_PROJECT_ENTRIES: i64 = 60;
/// Scans asked by people or programs running at once (same bound as keyword
/// searches): each one reads the whole table of affected products
static USER_SCANS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn scan_slot() -> Result<super::platform::KeywordSlot> {
    super::platform::KeywordSlot::take_from(&USER_SCANS)
}

/// A scan refused for what it would create (too generic a name, project
/// full): the application is skipped, the rest goes on
pub fn is_refusal(e: &anyhow::Error) -> bool {
    e.is::<TooGeneric>() || e.is::<UserFacing>()
}

/// A name needs two letters or digits to be matched against product names:
/// `%`, `_` or a single letter would match about everything.
pub fn is_matchable_name(name: &str) -> bool {
    name.chars().filter(|c| c.is_alphanumeric()).count() >= 2
}

/// "contains" pattern for `LIKE ... ESCAPE '\'`: the text is matched
/// literally, its `%` and `_` are not wildcards.
pub(crate) fn like_contains(text: &str) -> String {
    let mut pattern = String::with_capacity(text.len() + 2);
    pattern.push('%');
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('%');
    pattern
}

impl Database {
    /// CVE ids currently matching an application (product and package strategies)
    pub fn matching_cve_ids(&self, app: &Application) -> Result<Vec<String>> {
        // A distribution package is judged by its distribution, which backports
        // fixes: upstream version ranges would be wrong
        if let Some(ecosystem) = app.ecosystem.as_deref().filter(|e| crate::db::is_distro_ecosystem(e)) {
            return match app.version.as_deref() {
                Some(version) => self.distro_cves(ecosystem, &app.name, version),
                None => Ok(Vec::new()),
            };
        }
        // Product and package names are matched as substrings: `%`, `_` or a
        // single letter would match about everything
        if !is_matchable_name(&app.name) {
            return Ok(Vec::new());
        }
        let mut ids = self.find_cves_by_product(app.vendor.as_deref(), &app.name, app.version.as_deref())?;
        if let Some(ref ecosystem) = app.ecosystem {
            let mut seen: std::collections::HashSet<String> = ids.iter().cloned().collect();
            for id in self.find_cves_by_package(ecosystem, &app.name)? {
                if seen.insert(id.clone()) {
                    ids.push(id);
                }
            }
        }
        if ids.len() > MAX_APP_MATCHES {
            return Err(TooGeneric(ids.len()).into());
        }
        Ok(ids)
    }

    /// Scan an application for matching CVEs and create watchlist entries
    /// Returns (new_entries, existing_entries).
    ///
    /// A name without two letters or digits matches nothing (unless it is a
    /// distribution package, matched exactly), a name that matches more than
    /// `MAX_APP_MATCHES` CVEs is refused (`TooGeneric`), and so is a scan that
    /// would take the project beyond `MAX_PROJECT_ENTRIES`: one entry is
    /// created per CVE, so catch-all names would fill the database.
    pub fn scan_app_for_cves(&self, app: &Application) -> Result<(i64, i64)> {
        let app_id = app.id.ok_or_else(|| anyhow!("Application must have an ID"))?;
        let ids = self.matching_cve_ids(app)?;
        self.write_scope("scan_app", || {
            let tracked: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM watchlist_entries e JOIN applications a ON a.id = e.app_id WHERE a.project_id = ?1",
                params![app.project_id],
                |r| r.get(0),
            )?;
            let (mut new_entries, mut existing_entries) = (0i64, 0i64);
            for cve_id in &ids {
                if self.add_watchlist_entry_if_new(app_id, cve_id)? {
                    new_entries += 1;
                    if tracked + new_entries > MAX_PROJECT_ENTRIES {
                        return Err(UserFacing(format!(
                            "This project would track more than {MAX_PROJECT_ENTRIES} CVE entries: remove applications or make their names and versions more precise."
                        ))
                        .into());
                    }
                } else {
                    existing_entries += 1;
                }
            }
            Ok((new_entries, existing_entries))
        })
    }

    /// Creates an application and scans it, or leaves nothing behind if the
    /// scan is refused. Returns the number of matching CVEs. Asked by a
    /// person or a program: only a few run at once (`Busy` otherwise).
    pub fn add_application_scanned(&self, app: &mut Application) -> Result<i64> {
        let _slot = scan_slot()?;
        let result = self.write_scope("add_app", || {
            app.id = Some(self.create_application(app)?);
            Ok(self.scan_app_for_cves(app)?.0)
        });
        if result.is_err() {
            app.id = None;
        }
        result
    }

    /// Changes the version of an application and brings its entries in line
    /// (new CVEs added, those the new version is not affected by closed).
    /// The new version is matched first: if that is refused (too generic),
    /// nothing is changed. Returns (new entries, entries closed).
    pub fn change_application_version(&self, app_id: i64, version: &str, actor: &crate::db::Actor) -> Result<(i64, i64)> {
        let _slot = scan_slot()?;
        let mut app = self.get_application(app_id)?.ok_or_else(|| anyhow!("Unknown application"))?;
        app.version = Some(version.to_string());
        self.matching_cve_ids(&app)?;
        self.update_application_version(app_id, version)?;
        self.rescan_after_upgrade(&app, actor)
    }

    /// Find CVEs by product name (from affected_products_normalized)
    fn find_cves_by_product(
        &self,
        vendor: Option<&str>,
        product: &str,
        version: Option<&str>,
    ) -> Result<Vec<String>> {
        let product_lower = product.to_lowercase();

        // Build query - fetch candidates, filter versions in Rust for proper semver comparison
        let mut sql = String::from(
            "SELECT DISTINCT cve_id, version, version_start, version_end
             FROM affected_products_normalized WHERE LOWER(product) LIKE ?1 ESCAPE '\\'"
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        params_vec.push(Box::new(like_contains(&product_lower)));
        let mut param_idx = 2;

        if let Some(v) = vendor {
            sql.push_str(&format!(" AND LOWER(vendor) LIKE ?{} ESCAPE '\\'", param_idx));
            params_vec.push(Box::new(like_contains(&v.to_lowercase())));
            #[allow(unused_assignments)]
            { param_idx += 1; }
        }

        let mut stmt = self.conn().prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        // Rows are read one by one and the reading stops as soon as the name
        // proves too generic: nothing is accumulated for a catch-all name.
        // Versions are compared here, in Rust, for proper semantic comparison.
        let mut cves = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut rows = stmt.query(params_refs.as_slice())?;
        while let Some(row) = rows.next()? {
            let cve_id: String = row.get(0)?;
            if seen.contains(&cve_id) {
                continue;
            }
            let (db_version, version_start, version_end): (Option<String>, Option<String>, Option<String>) =
                (row.get(1)?, row.get(2)?, row.get(3)?);
            if is_version_affected(version, db_version.as_deref(), version_start.as_deref(), version_end.as_deref()) {
                seen.insert(cve_id.clone());
                cves.push(cve_id);
                if cves.len() > MAX_APP_MATCHES {
                    return Err(TooGeneric(cves.len()).into());
                }
            }
        }

        Ok(cves)
    }

    /// Find CVEs by ecosystem and package name (from affected_packages)
    fn find_cves_by_package(&self, ecosystem: &str, name: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn().prepare(
            "SELECT DISTINCT cve_id FROM affected_packages
             WHERE LOWER(ecosystem) = LOWER(?1) AND LOWER(name) LIKE ?2 ESCAPE '\\'"
        )?;

        let cves = stmt.query_map(params![ecosystem, like_contains(&name.to_lowercase())], |row| {
            row.get::<_, String>(0)
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(cves)
    }

    /// Add watchlist entry if it doesn't exist, returns true if new
    fn add_watchlist_entry_if_new(&self, app_id: i64, cve_id: &str) -> Result<bool> {
        // Check if entry already exists
        let exists: bool = self.conn().query_row(
            "SELECT 1 FROM watchlist_entries WHERE app_id = ?1 AND cve_id = ?2",
            params![app_id, cve_id],
            |_| Ok(true),
        ).unwrap_or(false);

        if exists {
            return Ok(false);
        }

        // Determine priority based on CVE data
        let priority = self.determine_priority(cve_id)?;

        // Create new entry
        let entry = WatchlistEntry {
            id: None,
            app_id,
            cve_id: cve_id.to_string(),
            status: CveStatus::Untreated,
            priority,
            assigned_to: None,
            notes: None,
            created_at: None,
            updated_at: None,
            treated_at: None,
        };

        let entry_id = self.upsert_watchlist_entry(&entry)?;
        self.log_detected(entry_id)?;
        Ok(true)
    }

    /// Determine priority based on CVE characteristics
    fn determine_priority(&self, cve_id: &str) -> Result<Priority> {
        let result: Option<(Option<f64>, i32)> = self.conn().query_row(
            "SELECT cvss_v3_score, kev_known_exploited FROM cves WHERE cve_id = ?1",
            params![cve_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;

        match result {
            Some((cvss, kev)) => {
                // KEV = Critical
                if kev != 0 {
                    return Ok(Priority::Critical);
                }

                // CVSS-based priority
                match cvss {
                    Some(score) if score >= 9.0 => Ok(Priority::Critical),
                    Some(score) if score >= 7.0 => Ok(Priority::High),
                    Some(score) if score >= 4.0 => Ok(Priority::Medium),
                    _ => Ok(Priority::Low),
                }
            }
            None => Ok(Priority::Medium), // CVE not in database, default to medium
        }
    }
}

// ==========================================
// Resolvers (for CLI commands)
// ==========================================

impl Database {
    /// Get the default user ID (creates if not exists)
    pub fn get_default_user_id(&self) -> Result<i64> {
        // Try to get existing default user
        if let Some(user) = self.get_user_by_username("default")? {
            return Ok(user.id.expect("User must have ID"));
        }

        // Create default user if it doesn't exist
        self.conn().execute(
            "INSERT INTO users (username, email) VALUES ('default', NULL)",
            [],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Resolve project name to project ID (uses default user)
    pub fn resolve_project(&self, project_name: &str) -> Result<i64> {
        let user_id = self.get_default_user_id()?;
        self.get_project_by_name(user_id, project_name)?
            .and_then(|p| p.id)
            .ok_or_else(|| anyhow!("Project '{}' not found", project_name))
    }

    /// Resolve application name to application (uses default user)
    pub fn resolve_application(
        &self,
        project_name: &str,
        app_name: &str,
        version: Option<&str>,
    ) -> Result<Application> {
        let project_id = self.resolve_project(project_name)?;
        self.get_application_by_name(project_id, app_name, version)?
            .ok_or_else(|| {
                let ver_str = version.map(|v| format!(" (version: {})", v)).unwrap_or_default();
                anyhow!("Application '{}'{} not found in project '{}'", app_name, ver_str, project_name)
            })
    }
}

// ==========================================
// Completions helpers (for shell autocomplete)
// ==========================================

impl Database {
    /// List all project names (for shell completion)
    pub fn list_project_names(&self) -> Result<Vec<String>> {
        let user_id = self.get_default_user_id()?;
        let mut stmt = self.conn().prepare(
            "SELECT name FROM projects WHERE user_id = ?1 ORDER BY name"
        )?;
        let names = stmt.query_map(params![user_id], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(names)
    }

    /// List all application names (for shell completion)
    pub fn list_app_names(&self, project_name: Option<&str>) -> Result<Vec<String>> {
        if let Some(proj) = project_name {
            let project_id = self.resolve_project(proj)?;
            let mut stmt = self.conn().prepare(
                "SELECT DISTINCT name FROM applications WHERE project_id = ?1 ORDER BY name"
            )?;
            let names = stmt.query_map(params![project_id], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(names)
        } else {
            // All apps across all projects
            let user_id = self.get_default_user_id()?;
            let mut stmt = self.conn().prepare(
                "SELECT DISTINCT a.name FROM applications a
                 JOIN projects p ON a.project_id = p.id
                 WHERE p.user_id = ?1 ORDER BY a.name"
            )?;
            let names = stmt.query_map(params![user_id], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(names)
        }
    }

    /// List all CVE IDs in watchlist (for shell completion)
    pub fn list_watchlist_cve_ids(&self, project_name: Option<&str>, app_name: Option<&str>) -> Result<Vec<String>> {
        let user_id = self.get_default_user_id()?;

        let mut sql = String::from(
            "SELECT DISTINCT w.cve_id FROM watchlist_entries w
             JOIN applications a ON w.app_id = a.id
             JOIN projects p ON a.project_id = p.id
             WHERE p.user_id = ?1"
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        params_vec.push(Box::new(user_id));
        let mut param_idx = 2;

        if let Some(proj) = project_name {
            sql.push_str(&format!(" AND p.name = ?{}", param_idx));
            params_vec.push(Box::new(proj.to_string()));
            param_idx += 1;
        }

        if let Some(app) = app_name {
            sql.push_str(&format!(" AND a.name = ?{}", param_idx));
            params_vec.push(Box::new(app.to_string()));
            #[allow(unused_assignments)]
            { param_idx += 1; }
        }

        sql.push_str(" ORDER BY w.cve_id");

        let mut stmt = self.conn().prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        let names = stmt.query_map(params_refs.as_slice(), |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

use rusqlite::OptionalExtension;

// ==========================================
// Version comparison helpers
// ==========================================

/// Check if a given version is affected by a CVE entry
fn is_version_affected(
    query_version: Option<&str>,
    db_version: Option<&str>,
    version_start: Option<&str>,
    version_end: Option<&str>,
) -> bool {
    // If no query version specified, include all CVEs for this product
    let query_ver = match query_version {
        Some(v) => v,
        None => return true,
    };

    let db_ver = db_version.unwrap_or("*");

    // Wildcard means all versions (unknown range) - include for safety
    if db_ver == "*" && version_end.is_none() {
        return true;
    }

    // Exact version match
    if db_ver != "*" && (db_ver == query_ver || query_ver.starts_with(&format!("{}.", db_ver))) {
        return true;
    }

    // Version range check
    if let Some(end) = version_end {
        let in_range = match version_start {
            Some(start) => {
                compare_versions(query_ver, start) >= 0 && compare_versions(query_ver, end) < 0
            }
            None => compare_versions(query_ver, end) < 0,
        };
        if in_range {
            return true;
        }
    }

    false
}

/// Compare two version strings semantically
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
fn compare_versions(a: &str, b: &str) -> i32 {
    let parse_parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| c == '.' || c == '-' || c == '_')
            .filter_map(|part| {
                // Extract leading numeric portion
                let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
                numeric.parse().ok()
            })
            .collect()
    };

    let parts_a = parse_parts(a);
    let parts_b = parse_parts(b);

    let max_len = parts_a.len().max(parts_b.len());

    for i in 0..max_len {
        let val_a = parts_a.get(i).copied().unwrap_or(0);
        let val_b = parts_b.get(i).copied().unwrap_or(0);

        if val_a < val_b {
            return -1;
        }
        if val_a > val_b {
            return 1;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AffectedProduct, Cve};

    fn seed(db: &Database, id: &str, product: &str) {
        let mut cve = Cve::new(id.into());
        cve.description = Some("Flaw".into());
        cve.affected_products.push(AffectedProduct {
            vendor: Some("acme".into()),
            product: Some(product.into()),
            version: Some("*".into()),
            version_start: None,
            version_end: None,
            cpe: Some("cpe".into()),
        });
        db.upsert_cve(&cve).unwrap();
    }

    fn project(db: &Database) -> i64 {
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        db.create_org_project(org, alice, "infra", None).unwrap()
    }

    #[test]
    fn wildcards_in_an_application_name_are_literal() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        seed(&db, "CVE-2024-0001", "widget");
        seed(&db, "CVE-2024-0002", "gadget");
        seed(&db, "CVE-2024-0003", "50%_off");

        assert_eq!(like_contains(r"50%_a\b"), r"%50\%\_a\\b%");
        let matches = |name: &str| {
            let mut app = Application::new(project, name.into());
            db.add_application_scanned(&mut app).unwrap()
        };
        // Catch-all names match nothing: no letters or digits, or wildcards between them
        for name in ["%", "_", "%%", "__", "w", "wi%et", "g_dget", "%dget"] {
            assert_eq!(matches(name), 0, "{name}");
        }
        // A name is a substring; its own % and _ are plain characters
        assert_eq!(matches("widget"), 1);
        assert_eq!(matches("dget"), 2);
        assert_eq!(matches("50%_off"), 1);
        assert!(is_matchable_name("r2") && !is_matchable_name("%a_") && !is_matchable_name(" "));
    }

    #[test]
    fn a_name_matching_too_many_cves_is_refused_and_leaves_nothing() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        for i in 0..=MAX_APP_MATCHES {
            seed(&db, &format!("CVE-2024-{:04}", 1000 + i), "widget");
        }
        let count = |table: &str| -> i64 { db.conn().query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap() };

        let mut app = Application::new(project, "widget".into());
        let refused = db.add_application_scanned(&mut app).err().unwrap();
        assert!(refused.is::<TooGeneric>() && refused.to_string().contains("too generic"));
        assert!(app.id.is_none());
        assert_eq!((count("applications"), count("watchlist_entries"), count("watchlist_events")), (0, 0, 0));

        // An application that became too broad does not stop the rescan of the others
        let mut narrow = Application::new(project, "gadget".into());
        seed(&db, "CVE-2024-9999", "gadget");
        assert_eq!(db.add_application_scanned(&mut narrow).unwrap(), 1);
        db.create_application(&Application::new(project, "widget".into())).unwrap();
        seed(&db, "CVE-2024-9998", "gadget");
        assert_eq!(db.rescan_all_applications().unwrap(), 1);
        assert_eq!(count("watchlist_entries"), 2);
    }

    #[test]
    fn a_project_holds_a_bounded_number_of_entries() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        for i in 0..MAX_APP_MATCHES {
            seed(&db, &format!("CVE-2023-{:04}", 1000 + i), "widget");
            seed(&db, &format!("CVE-2022-{:04}", 1000 + i), "gadget");
        }
        let count = |table: &str| -> i64 { db.conn().query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap() };
        let mut first = Application::new(project, "widget".into());
        assert_eq!(db.add_application_scanned(&mut first).unwrap(), MAX_APP_MATCHES as i64);
        // The second application would take the project over its limit: refused, nothing kept
        let mut second = Application::new(project, "gadget".into());
        let refused = db.add_application_scanned(&mut second).err().unwrap();
        assert!(is_refusal(&refused) && refused.to_string().contains("CVE entries"));
        assert_eq!((count("applications"), count("watchlist_entries")), (1, MAX_APP_MATCHES as i64));

        // A version change that would be refused leaves the version as it was
        let actor = crate::db::Actor::system("test");
        let app_id = first.id.unwrap();
        db.conn().execute("UPDATE applications SET name = 'dget' WHERE id = ?1", params![app_id]).unwrap();
        let refused = db.change_application_version(app_id, "2.0", &actor).err().unwrap();
        assert!(refused.is::<TooGeneric>());
        assert_eq!(db.get_application(app_id).unwrap().unwrap().version, None);
    }
}
