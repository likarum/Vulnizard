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
        known_cves: row.get(11)?,
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
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp, known_cves
                 FROM applications WHERE project_id = ?1 AND name = ?2 AND version = ?3 AND grp = ''"
            )?
        } else {
            self.conn().prepare(
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp, known_cves
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
                "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp, known_cves
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
            "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp, known_cves
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
            "SELECT id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp, known_cves
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
                match self.scan_app_for_cves(&app).and_then(|(new, _)| Ok((new, self.settle_stale_entries(&app)?))) {
                    Ok((new, (withdrawn, _))) => {
                        new_entries += new;
                        if withdrawn > 0 {
                            tracing::info!("application '{}': {withdrawn} entries no longer match and were set aside", app.name);
                        }
                    }
                    Err(e) if is_refusal(&e) => tracing::warn!("application '{}' skipped: {e}", app.name),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(new_entries)
    }

    /// Brings the entries of an application in line with what matches it
    /// now, after the data of the sources (or the matching itself) changed:
    /// entries still to review that no longer match are set aside as not
    /// applicable, and those set aside this way come back if they match
    /// again. Decisions taken by a person are never touched.
    /// Returns (entries set aside, entries brought back).
    pub fn settle_stale_entries(&self, app: &Application) -> Result<(i64, i64)> {
        let app_id = app.id.ok_or_else(|| anyhow!("Application must have an ID"))?;
        let matching: std::collections::HashSet<String> = self.matching_cve_ids(app)?.into_iter().collect();
        let entries: Vec<(i64, String, String, Option<String>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT id, cve_id, status, notes FROM watchlist_entries
                 WHERE app_id = ?1 AND status IN ('untreated', 'not_applicable')",
            )?;
            let rows = stmt
                .query_map(params![app_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let actor = crate::db::Actor::system("rescan");
        let (mut withdrawn, mut back) = (0, 0);
        for (entry_id, cve_id, status, notes) in entries {
            let matches = matching.contains(&cve_id);
            if status == "untreated" && !matches {
                self.change_entry_status(entry_id, CveStatus::NotApplicable, &actor, Some(NO_LONGER_MATCHES))?;
                withdrawn += 1;
            } else if status == "not_applicable" && matches && notes.as_deref() == Some(NO_LONGER_MATCHES) && self.set_aside_by_rescan(entry_id)? {
                self.change_entry_status(entry_id, CveStatus::Untreated, &actor, Some("matches the application again"))?;
                back += 1;
            }
        }
        Ok((withdrawn, back))
    }

    /// Whether the last decision on an entry is the rescan setting it aside
    /// (and not a person saying it does not apply)
    fn set_aside_by_rescan(&self, entry_id: i64) -> Result<bool> {
        let last: Option<(Option<i64>, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT user_id, comment FROM watchlist_events WHERE entry_id = ?1 AND kind = 'status' ORDER BY id DESC LIMIT 1",
                params![entry_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match last {
            Some((user, comment)) => user.is_none() && comment.as_deref() == Some(NO_LONGER_MATCHES),
            // No history kept (project outside an organization): the note tells
            None => true,
        })
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
                c.cvss_v3_score, c.description, c.kev_known_exploited, w.version_unknown
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
                version_unknown: row.get(17)?,
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

/// Package ecosystems whose advisories are read (OSV)
pub const PACKAGE_ECOSYSTEMS: [&str; 5] = ["Go", "npm", "PyPI", "crates.io", "Maven"];

/// Comment of an entry set aside by the rescan: it no longer matches its
/// application (the sources corrected their data, or the matching changed)
pub const NO_LONGER_MATCHES: &str = "no longer matches this application at this version, according to the sources";

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
        Ok(self.matching_cves(app)?.into_iter().map(|(id, _)| id).collect())
    }

    /// Same, each CVE with whether it is kept without any source giving its
    /// versions (`*` or `-` in the NVD, an advisory without a range): the
    /// application is matched out of caution, the CVE is to be read. Always
    /// false for an application without a version, which matches everything.
    pub fn matching_cves(&self, app: &Application) -> Result<Vec<(String, bool)>> {
        // A distribution package is judged by its distribution, which backports
        // fixes: upstream version ranges would be wrong
        if let Some(ecosystem) = app.ecosystem.as_deref().filter(|e| crate::db::is_distro_ecosystem(e)) {
            return Ok(match app.version.as_deref() {
                Some(version) => self.distro_cves(ecosystem, &app.name, version)?.into_iter().map(|id| (id, false)).collect(),
                None => Vec::new(),
            });
        }
        // `%`, `_` or a single letter is not a name
        if !is_matchable_name(&app.name) {
            return Ok(Vec::new());
        }
        // Every source says its piece on each CVE, then they decide together
        // (`versions::Verdicts`): a precise one wins over "every version"
        let mut said = Said::default();
        self.product_verdicts(app.vendor.as_deref(), &app.name, app.version.as_deref(), &mut said)?;
        if let Some(ref ecosystem) = app.ecosystem {
            self.package_verdicts(ecosystem, &app.name, app.version.as_deref(), &mut said)?;
        }
        let mut matches = said.affected();
        if matches.len() > MAX_APP_MATCHES {
            return Err(TooGeneric(matches.len()).into());
        }
        if app.version.is_none() {
            matches.iter_mut().for_each(|(_, unknown)| *unknown = false);
        }
        Ok(matches)
    }

    /// How many CVEs the sources hold for an application under its name,
    /// whatever the version: 0 means the sources do not know it (which is not
    /// "no flaw at this version"). `None` for a distribution package, judged
    /// by the advisories of its distribution.
    pub fn known_cve_count(&self, app: &Application) -> Result<Option<i64>> {
        if app.ecosystem.as_deref().is_some_and(crate::db::is_distro_ecosystem) {
            return Ok(None);
        }
        let mut any_version = app.clone();
        any_version.version = None;
        Ok(Some(match self.matching_cve_ids(&any_version) {
            Ok(ids) => ids.len() as i64,
            Err(e) => match e.downcast_ref::<TooGeneric>() {
                Some(TooGeneric(count)) => *count as i64,
                None => return Err(e),
            },
        }))
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
        let matches = self.matching_cves(app)?;
        let known = self.known_cve_count(app)?;
        self.write_scope("scan_app", || {
            self.conn().execute("UPDATE applications SET known_cves = ?1 WHERE id = ?2", params![known, app_id])?;
            let tracked: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM watchlist_entries e JOIN applications a ON a.id = e.app_id WHERE a.project_id = ?1",
                params![app.project_id],
                |r| r.get(0),
            )?;
            let (mut new_entries, mut existing_entries) = (0i64, 0i64);
            // The score of a CVE often comes after the CVE: the priority follows it
            self.conn().execute(
                "UPDATE watchlist_entries SET priority = COALESCE((
                     SELECT CASE WHEN COALESCE(c.kev_known_exploited, 0) != 0 OR c.cvss_v3_score >= 9.0 THEN 'critical'
                                 WHEN c.cvss_v3_score >= 7.0 THEN 'high'
                                 WHEN c.cvss_v3_score >= 4.0 THEN 'medium'
                                 ELSE 'low' END
                     FROM cves c WHERE c.cve_id = watchlist_entries.cve_id), 'medium')
                 WHERE app_id = ?1 AND priority IS NOT COALESCE((
                     SELECT CASE WHEN COALESCE(c.kev_known_exploited, 0) != 0 OR c.cvss_v3_score >= 9.0 THEN 'critical'
                                 WHEN c.cvss_v3_score >= 7.0 THEN 'high'
                                 WHEN c.cvss_v3_score >= 4.0 THEN 'medium'
                                 ELSE 'low' END
                     FROM cves c WHERE c.cve_id = watchlist_entries.cve_id), 'medium')",
                params![app_id],
            )?;
            for (cve_id, version_unknown) in &matches {
                let added = self.add_watchlist_entry_if_new(app_id, cve_id)?;
                // The sources are corrected over time: the mark follows them
                self.conn().execute(
                    "UPDATE watchlist_entries SET version_unknown = ?1 WHERE app_id = ?2 AND cve_id = ?3 AND version_unknown != ?1",
                    params![version_unknown, app_id, cve_id],
                )?;
                if added {
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
            if new_entries > 0 {
                self.seal_audit_events()?;
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
    fn product_verdicts(&self, vendor: Option<&str>, product: &str, version: Option<&str>, said: &mut Said) -> Result<()> {
        // The product is the application itself, whatever the case and the
        // separators: `podman` is not `podman_desktop`. With a vendor, the
        // products of that vendor named after it count too: the NVD records
        // nginx under `nginx` and `nginx_open_source`. The vendor is compared
        // like the product: `openssl` is not `openssl.js_project`.
        let mut sql = String::from(
            "SELECT DISTINCT cve_id, version, version_start, version_end, start_excluded, end_included, cpe
             FROM affected_products_normalized WHERE "
        );
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        params_vec.push(Box::new(versions::name_key(product)));
        match vendor {
            Some(v) => {
                // The NVD often names a vendor `<name>_project` (sudo_project)
                sql.push_str("name_key(vendor) IN (?2, ?2 || 'project') AND (name_key(product) = ?1 OR name_variant(product, ?3))");
                params_vec.push(Box::new(versions::name_key(v)));
                params_vec.push(Box::new(product.to_string()));
            }
            None => sql.push_str("name_key(product) = ?1"),
        }

        let mut stmt = self.conn().prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        // Rows are read one by one and the reading stops when the name proves
        // far too generic: nothing is accumulated for a catch-all name
        let mut rows = stmt.query(params_refs.as_slice())?;
        while let Some(row) = rows.next()? {
            let cve_id: String = row.get(0)?;
            let (db_version, version_start, version_end): (Option<String>, Option<String>, Option<String>) =
                (row.get(1)?, row.get(2)?, row.get(3)?);
            let (start_excluded, end_included): (bool, bool) = (row.get(4)?, row.get(5)?);
            // The version a CPE names includes its update field (1.9.17:p2)
            let cpe: Option<String> = row.get(6)?;
            let db_version = versions::cpe_version(db_version.as_deref(), cpe.as_deref());
            said.add(
                cve_id,
                versions::product_verdict(version, db_version.as_deref(), version_start.as_deref(), start_excluded, version_end.as_deref(), end_included),
            );
            if said.len() > MAX_APP_MATCHES * 10 {
                return Err(TooGeneric(said.len()).into());
            }
        }
        Ok(())
    }

    /// CVEs of the package advisories (`affected_packages`) for a package of
    /// an ecosystem, at a version when one is given.
    ///
    /// The name is the package itself or the last part of its path
    /// (`traefik` for `github.com/traefik/traefik/v3`): `n8n` is not
    /// `n8n-nodes-base`.
    fn package_verdicts(&self, ecosystem: &str, name: &str, version: Option<&str>, said: &mut Said) -> Result<()> {
        let mut stmt = self.conn().prepare(
            "SELECT cve_id, name, vulnerable_range FROM affected_packages
             WHERE LOWER(ecosystem) = LOWER(?1) AND LOWER(name) LIKE ?2 ESCAPE '\\'"
        )?;
        let wanted = name.to_lowercase();
        let rows: Vec<(String, String, Option<String>)> = stmt
            .query_map(params![ecosystem, like_contains(&wanted)], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // A Go module carries its major version in its path: /v3 is the 3.x
        // line. The path without suffix holds 0.x and 1.x only, for a
        // project that has such /vN modules; else it holds every version.
        let go = ecosystem.eq_ignore_ascii_case("go");
        let major = version.and_then(major_of);
        let versioned: std::collections::HashSet<String> = rows
            .iter()
            .filter_map(|(_, package, _)| {
                let package = package.to_lowercase();
                let (path, module_major) = split_go_major(&package, go);
                module_major.map(|_| path.to_string())
            })
            .collect();

        for (cve_id, package, range) in &rows {
            let package = package.to_lowercase();
            let (path, module_major) = split_go_major(&package, go);
            if path != wanted && path.rsplit('/').next() != Some(wanted.as_str()) {
                continue;
            }
            let verdict = range_verdict(range.as_deref(), version);
            if let (true, Some(major)) = (go, major) {
                // The line of this module: its suffix, or 0.x and 1.x without one
                let line = match module_major {
                    Some(m) => Some(m),
                    None if versioned.contains(path) => Some(1),
                    None => None,
                };
                match line {
                    // A later line says nothing of this version
                    Some(line) if line > major.max(1) => continue,
                    // An earlier line only tells when it was fixed there: the
                    // fix is in what followed. Still open, it says nothing.
                    Some(line) if line < major.max(1) && verdict != Verdict::NotAffected => continue,
                    _ => {}
                }
            }
            said.add(cve_id.clone(), verdict);
        }
        Ok(())
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
use crate::versions::{self, Verdict};

// ==========================================
// Version comparison helpers
// ==========================================

/// `github.com/acme/tool/v3` gives (`github.com/acme/tool`, 3) for a Go module
fn split_go_major(package: &str, go: bool) -> (&str, Option<u64>) {
    if go {
        if let Some((path, last)) = package.rsplit_once('/') {
            if let Some(major) = last.strip_prefix('v').and_then(|n| n.parse::<u64>().ok()) {
                return (path, Some(major));
            }
        }
    }
    (package, None)
}

/// First number of a version: 3 for `3.7.16` or `v3.7.16`
fn major_of(version: &str) -> Option<u64> {
    let version = version.trim().trim_start_matches(['v', 'V']);
    let digits: String = version.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// What the ranges of a package advisory say of a version. They are written
/// `>=1.0 <1.4 >=2.0 <=2.3`: each `>=` opens a range, the next `<` or `<=`
/// closes it, a range left open has no fix.
///
/// Nothing can be told without a version, without a range, or with a bound
/// that is not a version (a commit). "Every version, no fix" (`>=0` alone) is
/// its own answer: advisories are often left that way long after the fix,
/// so it gives way to a source that names the fix.
fn range_verdict(range: Option<&str>, version: Option<&str>) -> Verdict {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let (Some(range), Some(version)) = (range, version) else {
        return Verdict::Unknown;
    };
    if !versions::is_version(version) {
        return Verdict::Unknown;
    }
    let from_the_start = |start: &str| start == "0" || (versions::is_version(start) && versions::cmp(start, "0") == Equal);
    let mut from: Option<&str> = None;
    let mut open = false;
    // Past an included end ("last affected"), which names no fix
    let mut past_last = false;
    for event in range.split_whitespace() {
        if let Some(start) = event.strip_prefix(">=") {
            from = Some(start);
            open = true;
            continue;
        }
        let (end, inclusive) = match event.strip_prefix("<=") {
            Some(end) => (end, true),
            None => match event.strip_prefix('<') {
                Some(end) => (end, false),
                None => return Verdict::Unknown,
            },
        };
        let start = from.take().unwrap_or("0");
        open = false;
        if !versions::is_version(end) || (start != "0" && !versions::is_version(start)) {
            return Verdict::Unknown;
        }
        let after_start = from_the_start(start) || versions::cmp(version, start) != Less;
        let order = versions::cmp(version, end);
        if after_start && (order == Less || (inclusive && order != Greater)) {
            return Verdict::Affected;
        }
        past_last |= after_start && inclusive;
    }
    match from {
        Some(start) if open => {
            if !versions::is_version(start) && start != "0" {
                Verdict::Unknown
            } else if from_the_start(start) {
                Verdict::NoFix
            } else if versions::cmp(version, start) != Less {
                Verdict::Affected
            } else {
                Verdict::NotAffected
            }
        }
        _ if past_last => Verdict::PastLastAffected,
        _ => Verdict::NotAffected,
    }
}

/// What the sources said of each CVE, in the order the CVEs came
#[derive(Default)]
struct Said {
    order: Vec<String>,
    verdicts: std::collections::HashMap<String, versions::Verdicts>,
}

impl Said {
    fn add(&mut self, cve_id: String, verdict: Verdict) {
        match self.verdicts.get_mut(&cve_id) {
            Some(known) => known.add(verdict),
            None => {
                let mut first = versions::Verdicts::default();
                first.add(verdict);
                self.order.push(cve_id.clone());
                self.verdicts.insert(cve_id, first);
            }
        }
    }

    fn len(&self) -> usize {
        self.order.len()
    }

    /// The CVEs that affect the application, all things said, each with
    /// whether it is only kept because no source gives its versions
    fn affected(self) -> Vec<(String, bool)> {
        let Said { order, verdicts } = self;
        order
            .into_iter()
            .filter_map(|id| {
                let said = verdicts[&id];
                said.affected().then(|| (id, !said.in_a_range()))
            })
            .collect()
    }
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
            ..Default::default()
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
        // A name is the product itself, not a part of it; case and separators do not count
        assert_eq!(matches("widget"), 1);
        assert_eq!(matches("Wid-Get"), 1);
        assert_eq!(matches("dget"), 0);
        assert_eq!(matches("widgets"), 0);
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
        seed(&db, "CVE-2021-0001", "gadget");
        db.conn().execute("UPDATE applications SET name = 'gadget' WHERE id = ?1", params![app_id]).unwrap();
        let refused = db.change_application_version(app_id, "2.0", &actor).err().unwrap();
        assert!(refused.is::<TooGeneric>());
        assert_eq!(db.get_application(app_id).unwrap().unwrap().version, None);
    }

    #[test]
    fn a_version_is_judged_against_the_ranges_of_the_advisory() {
        let affects = |range: &str, version: &str| !matches!(range_verdict(Some(range), Some(version)), Verdict::NotAffected | Verdict::PastLastAffected);
        assert!(affects(">=0 <3.7.3", "3.7.2") && !affects(">=0 <3.7.3", "3.7.3") && !affects(">=0 <3.7.3", "3.7.16"));
        assert!(!affects(">=3.5.0 <3.6.3", "3.4.9") && affects(">=3.5.0 <3.6.3", "3.5.0"));
        // Several ranges: any of them
        let two = ">=0 <2.11.35 >=3.0.0 <3.6.7";
        assert!(affects(two, "2.11.34") && !affects(two, "2.11.35") && affects(two, "3.6.6") && !affects(two, "3.7.16"));
        // The last affected version is included, a range without fix has no end
        assert!(affects(">=1.0 <=1.4", "1.4") && !affects(">=1.0 <=1.4", "1.4.1"));
        assert!(affects(">=2.0", "9.9") && !affects(">=2.0", "1.9") && affects(">=0", "0.0.1"));
        // What cannot be told
        let unknown = |range: Option<&str>, version: Option<&str>| range_verdict(range, version) == Verdict::Unknown;
        assert!(unknown(None, Some("1.0")) && unknown(Some(">=0 <1.0"), None));
        assert_eq!(range_verdict(Some(">=0"), Some("9.9")), Verdict::NoFix);
        assert_eq!(range_verdict(Some(">=0.0.0"), Some("9.9")), Verdict::NoFix);
        assert_eq!(range_verdict(Some(">=1.0 <=1.4"), Some("1.5")), Verdict::PastLastAffected);
        assert_eq!(range_verdict(Some(">=1.0 <=1.4"), Some("0.9")), Verdict::NotAffected);
        assert_eq!(range_verdict(Some(">=1.0 <1.4"), Some("1.5")), Verdict::NotAffected);
        assert_eq!(range_verdict(Some(">=2.0"), Some("9.9")), Verdict::Affected);
        assert_eq!(range_verdict(Some(">=0 <1.0"), Some("0.5")), Verdict::Affected);
        assert!(affects(">=0 <0123456789abcdef0123456789abcdef01234567", "9.9"));
        assert!(affects(">=0 <1.0", "latest") && affects("garbage", "1.0"));
    }

    fn package(db: &Database, id: &str, ecosystem: &str, name: &str, range: Option<&str>) {
        let mut cve = Cve::new(id.into());
        cve.description = Some("Flaw".into());
        db.upsert_cve(&cve).unwrap();
        let known = crate::models::AffectedPackage {
            ecosystem: ecosystem.into(),
            name: name.into(),
            vulnerable_range: range.map(String::from),
            fixed_version: None,
        };
        db.batch_add_packages(&[(id.to_string(), vec![known])]).unwrap();
    }

    #[test]
    fn a_package_matches_at_its_version_and_under_its_own_name() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        package(&db, "CVE-2025-0001", "Go", "github.com/traefik/traefik/v3", Some(">=0 <3.7.3"));
        package(&db, "CVE-2025-0002", "Go", "github.com/traefik/traefik/v3", Some(">=3.7.0 <3.7.20"));
        package(&db, "CVE-2025-0003", "Go", "github.com/traefik/traefik/v2", Some(">=0"));
        package(&db, "CVE-2025-0004", "Go", "github.com/traefik/traefik", Some(">=0"));
        package(&db, "CVE-2025-0005", "Go", "github.com/traefik/traefik-plugin", Some(">=0"));
        package(&db, "CVE-2025-0006", "Go", "github.com/traefik/traefik/v3", None);
        package(&db, "CVE-2025-0007", "Go", "github.com/docker/docker", Some(">=0 <29.0.0"));
        package(&db, "CVE-2025-0008", "npm", "n8n", Some(">=0 <2.26.0"));
        package(&db, "CVE-2025-0009", "npm", "n8n", Some(">=3.0.0 <3.2.0"));
        package(&db, "CVE-2025-0010", "npm", "n8n-nodes-base", Some(">=0"));
        package(&db, "CVE-2025-0011", "npm", "@n8n/n8n-nodes-langchain", Some(">=0"));
        package(&db, "CVE-2025-0012", "npm", "@acme/n8n", Some(">=0"));
        package(&db, "CVE-2025-0013", "Go", "github.com/containous/traefik", Some(">=0"));
        package(&db, "CVE-2025-0014", "Go", "github.com/containous/traefik/v2", Some(">=0 <2.2.2"));

        let matching = |name: &str, ecosystem: &str, version: Option<&str>| {
            let mut app = Application::new(project, name.into());
            app.ecosystem = Some(ecosystem.into());
            app.version = version.map(String::from);
            let mut ids = db.matching_cve_ids(&app).unwrap();
            ids.sort();
            ids.iter().map(|id| id[11..].to_string()).collect::<Vec<_>>().join(" ")
        };
        // 3.7.16: past the fix of the first, inside the second; an advisory
        // without a range counts. Neither the 2.x module nor the old path.
        assert_eq!(matching("traefik", "Go", Some("3.7.16")), "02 06");
        assert_eq!(matching("traefik", "Go", Some("3.7.2")), "01 02 06");
        assert_eq!(matching("traefik", "go", Some("2.11.0")), "03");
        assert_eq!(matching("traefik", "go", Some("2.2.1")), "03 14");
        assert_eq!(matching("traefik", "Go", Some("1.7.0")), "04 13");
        // Without a version, everything said of the package
        assert_eq!(matching("traefik", "Go", None), "01 02 03 04 06 13 14");
        // A module without major suffix and without any /vN sibling holds every major
        assert_eq!(matching("docker", "Go", Some("28.5.0")), "07");
        assert_eq!(matching("docker", "Go", Some("29.1.0")), "");
        // n8n is neither n8n-nodes-base nor @n8n/…; a scoped package answers to its name
        assert_eq!(matching("n8n", "npm", Some("3.1.0")), "09 12");
        assert_eq!(matching("n8n", "npm", Some("2.25.0")), "08 12");
        assert_eq!(matching("n8n", "PyPI", Some("3.1.0")), "");
    }

    #[test]
    fn the_ranges_of_a_package_are_brought_up_to_date() {
        let db = Database::open_in_memory().unwrap();
        package(&db, "CVE-2025-0001", "npm", "widget", Some(">=0"));
        package(&db, "CVE-2025-0001", "npm", "widget", Some(">=0 <1.4.0"));
        let stored = db.get_affected_packages("CVE-2025-0001").unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].vulnerable_range.as_deref(), Some(">=0 <1.4.0"));
    }

    #[test]
    fn entries_that_no_longer_match_are_set_aside_and_come_back() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let alice = crate::db::Actor::user(db.get_user_by_username("alice").unwrap().unwrap().id.unwrap(), "alice");
        for id in ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"] {
            package(&db, id, "npm", "widget", Some(">=0"));
        }
        let mut app = Application::new(project, "widget".into());
        app.ecosystem = Some("npm".into());
        app.version = Some("2.0.0".into());
        assert_eq!(db.add_application_scanned(&mut app).unwrap(), 3);
        let entry = |cve: &str| -> (i64, String) {
            db.conn()
                .query_row("SELECT id, status FROM watchlist_entries WHERE cve_id = ?1", params![cve], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
        };
        // A person accepted the risk of the second: never touched
        db.change_entry_status(entry("CVE-2025-0002").0, CveStatus::Accepted, &alice, Some("behind the VPN")).unwrap();

        // The advisories are corrected: fixed in 1.4.0, the application runs 2.0.0
        for id in ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"] {
            package(&db, id, "npm", "widget", Some(">=0 <1.4.0"));
        }
        assert_eq!(db.rescan_all_applications().unwrap(), 0);
        assert_eq!(entry("CVE-2025-0001").1, "not_applicable");
        assert_eq!(entry("CVE-2025-0002").1, "accepted");
        assert_eq!(entry("CVE-2025-0003").1, "not_applicable");
        let (actor, comment): (String, String) = db
            .conn()
            .query_row("SELECT actor, comment FROM watchlist_events WHERE kind = 'status' ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((actor.as_str(), comment.as_str()), ("rescan", NO_LONGER_MATCHES));
        let org: i64 = db.conn().query_row("SELECT organization_id FROM projects WHERE id = ?1", params![project], |r| r.get(0)).unwrap();
        assert!(db.check_audit_log(org).unwrap().intact());

        // A person confirms the third does not apply; then the advisories change back
        db.change_entry_status(entry("CVE-2025-0003").0, CveStatus::Untreated, &alice, None).unwrap();
        db.change_entry_status(entry("CVE-2025-0003").0, CveStatus::NotApplicable, &alice, None).unwrap();
        for id in ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"] {
            package(&db, id, "npm", "widget", Some(">=0 <2.4.0"));
        }
        db.rescan_all_applications().unwrap();
        // What the rescan set aside comes back; what a person decided stays
        assert_eq!(entry("CVE-2025-0001").1, "untreated");
        assert_eq!(entry("CVE-2025-0002").1, "accepted");
        assert_eq!(entry("CVE-2025-0003").1, "not_applicable");
        // Nothing moves when nothing changed
        db.rescan_all_applications().unwrap();
        assert_eq!(entry("CVE-2025-0001").1, "untreated");
    }

    #[test]
    fn an_application_unknown_to_the_sources_is_told_from_one_not_affected() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let mut cve = Cve::new("CVE-2024-0001".into());
        cve.description = Some("Flaw".into());
        cve.affected_products.push(AffectedProduct {
            vendor: Some("acme".into()),
            product: Some("home-assistant".into()),
            version: Some("*".into()),
            version_end: Some("2024.1".into()),
            cpe: Some("cpe".into()),
            ..Default::default()
        });
        db.upsert_cve(&cve).unwrap();
        package(&db, "CVE-2024-0002", "PyPI", "ha-mcp", Some(">=0 <2.0"));
        let add = |name: &str, version: &str, ecosystem: Option<&str>| {
            let mut app = Application::new(project, name.into());
            app.version = Some(version.into());
            app.ecosystem = ecosystem.map(String::from);
            let matching = db.add_application_scanned(&mut app).unwrap();
            (matching, db.get_application(app.id.unwrap()).unwrap().unwrap().known_cves)
        };
        // Known under another spelling, fixed since: nothing to review, one CVE known
        assert_eq!(add("home_assistant", "2026.10.2", None), (0, Some(1)));
        assert_eq!(add("Home Assistant", "2023.12", None), (1, Some(1)));
        // No source knows it; with its ecosystem, its package advisories are found
        assert_eq!(add("ha-mcp", "9.1.0", None), (0, Some(0)));
        assert_eq!(add("ha-mcp", "1.9.0", Some("PyPI")), (1, Some(1)));
        // A distribution package is not judged this way
        assert_eq!(add("bash", "5.2.15-2", Some("Debian:12")), (0, None));
    }

    #[test]
    fn with_a_vendor_its_products_named_after_the_application_count() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let seed = |id: &str, vendor: &str, product: &str| {
            let mut cve = Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.affected_products.push(AffectedProduct {
                vendor: Some(vendor.into()),
                product: Some(product.into()),
                version: Some("*".into()),
                version_end: Some("1.30.7".into()),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        };
        seed("CVE-2026-0001", "f5", "nginx");
        seed("CVE-2026-0002", "f5", "nginx_open_source");
        seed("CVE-2026-0003", "f5", "nginx_plus");
        seed("CVE-2026-0004", "nginxui", "nginx_ui");
        seed("CVE-2026-0005", "kubernetes", "ingress-nginx");
        seed("CVE-2026-0006", "f5", "nginxui");
        let matching = |vendor: Option<&str>| {
            let mut app = Application::new(project, "nginx".into());
            app.vendor = vendor.map(String::from);
            app.version = Some("1.30.6".into());
            let mut ids = db.matching_cve_ids(&app).unwrap();
            ids.sort();
            ids.iter().map(|id| id[11..].to_string()).collect::<Vec<_>>().join(" ")
        };
        // Without a vendor: the product of that exact name only
        assert_eq!(matching(None), "01");
        // With it: its variants too, not those of others nor names merely starting alike
        assert_eq!(matching(Some("f5")), "01 02 03");
        assert_eq!(matching(Some("nginxui")), "04");
    }

    #[test]
    fn a_precise_source_wins_over_one_that_says_every_version() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let product = |id: &str, vendor: &str, name: &str, version: &str, end: Option<&str>| {
            let mut cve = Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.affected_products.push(AffectedProduct {
                vendor: Some(vendor.into()),
                product: Some(name.into()),
                version: Some(version.into()),
                version_end: end.map(String::from),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        };
        let add_package = |id: &str, name: &str, range: &str| {
            let known = crate::models::AffectedPackage { ecosystem: "Go".into(), name: name.into(), vulnerable_range: Some(range.into()), fixed_version: None };
            db.batch_add_packages(&[(id.to_string(), vec![known])]).unwrap();
        };
        // The NVD gives an end, the package advisory was left at "every version"
        product("CVE-2026-0001", "amirraminfar", "dozzle", "*", Some("10.5.2"));
        add_package("CVE-2026-0001", "github.com/amir20/dozzle", ">=0");
        // The NVD gives no version, the advisory a fix in the previous major line
        product("CVE-2023-0002", "podman_project", "podman", "-", None);
        add_package("CVE-2023-0002", "github.com/containers/podman/v4", ">=0 <4.4.2");
        // Nobody says more than "every version"
        product("CVE-2026-0003", "podman_project", "podman", "-", None);
        product("CVE-2026-0004", "podman_project", "podman", "*", None);
        // The previous line never fixed it: it says nothing of this one
        product("CVE-2026-0005", "podman_project", "podman", "*", None);
        add_package("CVE-2026-0005", "github.com/containers/podman/v4", ">=0");
        // The NVD names the last version known affected, the advisory says no fix exists
        let mut last = Cve::new("CVE-2024-0008".into());
        last.description = Some("Flaw".into());
        last.affected_products.push(AffectedProduct {
            vendor: Some("podman_project".into()),
            product: Some("podman".into()),
            version: Some("*".into()),
            version_end: Some("5.2.0".into()),
            version_end_included: true,
            cpe: Some("cpe".into()),
            ..Default::default()
        });
        db.upsert_cve(&last).unwrap();
        add_package("CVE-2024-0008", "github.com/containers/podman/v5", ">=0");
        add_package("CVE-2024-0008", "github.com/containers/podman/v4", ">=0");
        // Another vendor, whose name merely contains this one
        product("CVE-2017-0006", "openssl.js_project", "openssl.js", "*", None);
        product("CVE-2017-0007", "openssl", "openssl", "*", None);

        let matching = |name: &str, vendor: Option<&str>, ecosystem: Option<&str>, version: &str| {
            let mut app = Application::new(project, name.into());
            app.vendor = vendor.map(String::from);
            app.ecosystem = ecosystem.map(String::from);
            app.version = Some(version.into());
            let mut ids = db.matching_cve_ids(&app).unwrap();
            ids.sort();
            ids.iter().map(|id| id[11..].to_string()).collect::<Vec<_>>().join(" ")
        };
        assert_eq!(matching("dozzle", None, Some("Go"), "11.4.2"), "");
        assert_eq!(matching("dozzle", None, Some("Go"), "10.5.1"), "01");
        assert_eq!(matching("podman", None, Some("Go"), "5.8.9"), "08 03 04 05");
        assert_eq!(matching("podman", None, Some("Go"), "4.4.1"), "02 08 03 04 05");
        // Without the ecosystem, only the NVD speaks: past the last version it knows affected
        assert_eq!(matching("podman", None, None, "5.8.9"), "02 03 04 05");
        // A vendor is also its `_project` form in the NVD
        assert_eq!(matching("podman", Some("podman"), None, "5.1.0"), "02 08 03 04 05");
        assert_eq!(matching("podman", Some("pod"), None, "5.1.0"), "");
        assert_eq!(matching("openssl", Some("openssl"), None, "3.6.5"), "07");
    }

    #[test]
    fn an_entry_kept_without_any_version_from_the_sources_is_marked() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let product = |id: &str, version: &str, end: Option<&str>| {
            let mut cve = Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.affected_products.push(AffectedProduct {
                vendor: Some("jellyfin".into()),
                product: Some("jellyfin".into()),
                version: Some(version.into()),
                version_end: end.map(String::from),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        };
        product("CVE-2026-0001", "-", None);
        product("CVE-2026-0002", "*", Some("10.12.0"));
        let mut app = Application::new(project, "jellyfin".into());
        app.version = Some("10.11.11".into());
        assert_eq!(db.add_application_scanned(&mut app).unwrap(), 2);
        let marks = || -> Vec<(String, bool)> {
            db.project_triage(project, false).unwrap().into_iter().map(|i| (i.cve_id[9..].to_string(), i.version_unknown)).collect::<std::collections::BTreeSet<_>>().into_iter().collect()
        };
        assert_eq!(marks(), [("0001".to_string(), true), ("0002".to_string(), false)]);
        // The source gives the versions later: the mark goes
        product("CVE-2026-0001", "*", Some("10.12.0"));
        db.rescan_all_applications().unwrap();
        assert_eq!(marks(), [("0001".to_string(), false), ("0002".to_string(), false)]);
        // Without a version, everything matches and nothing is marked
        let mut any = Application::new(project, "Jellyfin".into());
        any.vendor = Some("jellyfin".into());
        product("CVE-2026-0003", "-", None);
        assert!(db.matching_cves(&any).unwrap().iter().all(|(_, unknown)| !unknown));
    }

    #[test]
    fn the_patch_level_of_a_cpe_counts_and_the_priority_follows_the_score() {
        let db = Database::open_in_memory().unwrap();
        let project = project(&db);
        let cve = |score: Option<f64>| {
            let mut cve = Cve::new("CVE-2026-35535".into());
            cve.description = Some("Flaw through 1.9.17p2".into());
            cve.cvss_v3_score = score;
            let entry = |version: &str, end: Option<&str>, cpe: &str| AffectedProduct {
                vendor: Some("sudo_project".into()),
                product: Some("sudo".into()),
                version: Some(version.into()),
                version_end: end.map(String::from),
                cpe: Some(cpe.into()),
                ..Default::default()
            };
            cve.affected_products = vec![
                entry("*", Some("1.9.17"), "cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*"),
                entry("1.9.17", None, "cpe:2.3:a:sudo_project:sudo:1.9.17:-:*:*:*:*:*:*"),
                entry("1.9.17", None, "cpe:2.3:a:sudo_project:sudo:1.9.17:p1:*:*:*:*:*:*"),
                entry("1.9.17", None, "cpe:2.3:a:sudo_project:sudo:1.9.17:p2:*:*:*:*:*:*"),
            ];
            db.upsert_cve(&cve).unwrap();
        };
        cve(None);
        let matches = |version: &str| {
            let mut app = Application::new(project, "sudo".into());
            app.vendor = Some("sudo".into());
            app.version = Some(version.into());
            db.matching_cve_ids(&app).unwrap().len()
        };
        assert_eq!((matches("1.9.16"), matches("1.9.17"), matches("1.9.17p1"), matches("1.9.17p2"), matches("1.9.17p3"), matches("1.9.18")), (1, 1, 1, 1, 0, 0));

        // Created before the score: low; the score comes, the priority follows at the next scan
        let mut app = Application::new(project, "sudo".into());
        app.version = Some("1.9.17p2".into());
        assert_eq!(db.add_application_scanned(&mut app).unwrap(), 1);
        let priority = || -> String { db.conn().query_row("SELECT priority FROM watchlist_entries", [], |r| r.get(0)).unwrap() };
        assert_eq!(priority(), "low");
        cve(Some(7.7));
        db.rescan_all_applications().unwrap();
        assert_eq!(priority(), "high");
    }
}
