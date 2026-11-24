//! Lifecycle of watchlist entries (schema v8): every detection, decision and
//! removal is recorded as an event, with its author. The event log feeds the
//! audit view, the evolution over time and the review of a past state.

use anyhow::{anyhow, Result};
use chrono::NaiveDate;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::db::Database;
use crate::models::{Application, CveStatus};

const LIFECYCLE_SCHEMA: &str = r#"
-- New status 'accepted' (risk accepted): the CHECK constraint must be rebuilt
CREATE TABLE watchlist_entries_v8 (
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
    CHECK(status IN ('untreated', 'treated', 'not_applicable', 'accepted')),
    CHECK(priority IN ('critical', 'high', 'medium', 'low'))
);
INSERT INTO watchlist_entries_v8 (id, app_id, cve_id, status, priority, assigned_to, notes, created_at, updated_at, treated_at)
SELECT id, app_id, cve_id, status, priority, assigned_to, notes, created_at, updated_at, treated_at FROM watchlist_entries;
DROP TABLE watchlist_entries;
ALTER TABLE watchlist_entries_v8 RENAME TO watchlist_entries;
CREATE INDEX IF NOT EXISTS idx_watchlist_status ON watchlist_entries(status);
CREATE INDEX IF NOT EXISTS idx_watchlist_cve ON watchlist_entries(cve_id);

CREATE TABLE IF NOT EXISTS watchlist_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- no foreign key: the event outlives the entry (application removed)
    entry_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    app_name TEXT NOT NULL,
    app_version TEXT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('detected', 'status', 'removed')),
    status TEXT,
    previous TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor TEXT NOT NULL,
    comment TEXT
);
CREATE INDEX IF NOT EXISTS idx_wevents_project ON watchlist_events(project_id, id);
CREATE INDEX IF NOT EXISTS idx_wevents_entry ON watchlist_events(entry_id, id);

-- History of the entries that already exist
INSERT INTO watchlist_events (project_id, entry_id, cve_id, app_name, app_version, at, kind, status, actor)
SELECT a.project_id, w.id, w.cve_id, a.name, a.version, w.created_at, 'detected', 'untreated', 'system'
FROM watchlist_entries w JOIN applications a ON a.id = w.app_id ORDER BY w.created_at, w.id;
INSERT INTO watchlist_events (project_id, entry_id, cve_id, app_name, app_version, at, kind, status, previous, actor, comment)
SELECT a.project_id, w.id, w.cve_id, a.name, a.version, COALESCE(w.treated_at, w.updated_at), 'status',
       w.status, 'untreated', 'unknown', w.notes
FROM watchlist_entries w JOIN applications a ON a.id = w.app_id
WHERE w.status != 'untreated' ORDER BY COALESCE(w.treated_at, w.updated_at), w.id;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '8');
"#;

/// Schema v10: the history is attached to the organization and keeps the
/// name of the project, so that deleting a project never erases who decided
/// what. Only the deletion of the whole organization removes it.
const HISTORY_SCHEMA: &str = r#"
CREATE TABLE watchlist_events_v10 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- no foreign key: the history outlives the project and the entry
    project_id INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    entry_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    app_name TEXT NOT NULL,
    app_version TEXT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('detected', 'status', 'removed')),
    status TEXT,
    previous TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor TEXT NOT NULL,
    comment TEXT
);
INSERT INTO watchlist_events_v10
    (id, organization_id, project_id, project_name, entry_id, cve_id, app_name, app_version, at, kind, status,
     previous, user_id, actor, comment)
SELECT e.id, p.organization_id, e.project_id, p.name, e.entry_id, e.cve_id, e.app_name, e.app_version, e.at, e.kind,
       e.status, e.previous, e.user_id, e.actor, e.comment
FROM watchlist_events e JOIN projects p ON p.id = e.project_id
WHERE p.organization_id IS NOT NULL ORDER BY e.id;
DROP TABLE watchlist_events;
ALTER TABLE watchlist_events_v10 RENAME TO watchlist_events;
CREATE INDEX IF NOT EXISTS idx_wevents_org ON watchlist_events(organization_id, id);
CREATE INDEX IF NOT EXISTS idx_wevents_project ON watchlist_events(project_id, id);
CREATE INDEX IF NOT EXISTS idx_wevents_entry ON watchlist_events(entry_id, id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '10');
"#;

/// Who performs a change
#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: Option<i64>,
    pub name: String,
}

impl Actor {
    pub fn user(id: i64, username: &str) -> Self {
        Self {
            user_id: Some(id),
            name: username.to_string(),
        }
    }

    /// Non-interactive origin: "cli", "mcp-stdio", "rescan", "system"
    pub fn system(name: &str) -> Self {
        Self {
            user_id: None,
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleEvent {
    pub id: i64,
    pub entry_id: i64,
    pub org: String,
    pub project: String,
    pub cve_id: String,
    pub app_name: String,
    pub app_version: Option<String>,
    pub at: String,
    /// detected | status | removed
    pub kind: String,
    pub status: Option<String>,
    pub previous: Option<String>,
    pub actor: String,
    /// Not done by a signed-in user (scan, CLI, MCP, migration)
    pub automatic: bool,
    /// The project no longer exists
    pub project_deleted: bool,
    pub comment: Option<String>,
    pub cvss: Option<f64>,
    pub kev: bool,
}

impl LifecycleEvent {
    pub fn day(&self) -> &str {
        self.at.get(..10).unwrap_or(&self.at)
    }
}

/// Activity of one day and the stock at the end of that day
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DayStats {
    pub day: String,
    pub new: i64,
    pub accepted: i64,
    pub closed: i64,
    pub not_applicable: i64,
    pub reopened: i64,
    /// Entries still to review at the end of the day
    pub open: i64,
    /// Entries whose risk is accepted at the end of the day
    pub accepted_total: i64,
    /// `open` by severity of the CVE as scored today: critical, high, medium,
    /// low, no score (the order of `crate::deadlines::BANDS`)
    pub open_by_severity: [i64; 5],
}

/// An entry as it was at a given instant
#[derive(Debug, Clone, Serialize)]
pub struct StateItem {
    pub status: String,
    /// Last event that put the entry in this status
    pub event: LifecycleEvent,
}

// ==========================================
// Migration & event writers
// ==========================================

impl Database {
    pub(super) fn migrate_lifecycle(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(LIFECYCLE_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn migrate_history(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(HISTORY_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    fn log_event(
        &self,
        entry_id: i64,
        kind: &str,
        status: Option<&str>,
        previous: Option<&str>,
        actor: &Actor,
        comment: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO watchlist_events
                (organization_id, project_id, project_name, entry_id, cve_id, app_name, app_version, at, kind,
                 status, previous, user_id, actor, comment)
             SELECT p.organization_id, p.id, p.name, w.id, w.cve_id, a.name, a.version, datetime('now'), ?2, ?3, ?4,
                    ?5, ?6, ?7
             FROM watchlist_entries w
             JOIN applications a ON a.id = w.app_id
             JOIN projects p ON p.id = a.project_id
             WHERE w.id = ?1 AND p.organization_id IS NOT NULL",
            params![entry_id, kind, status, previous, actor.user_id, actor.name, comment],
        )?;
        // Linked to the previous event of the organization at once. Detections come by
        // the thousand during a scan: the scan links them all when it ends.
        if kind == "detected" {
            return Ok(());
        }
        self.seal_audit_events()
    }

    /// Records the detection of a new entry (called by the scan)
    pub(super) fn log_detected(&self, entry_id: i64) -> Result<()> {
        self.log_event(entry_id, "detected", Some("untreated"), None, &Actor::system("system"), None)
    }

    /// Changes the status of an entry and records who did it and why.
    /// Returns false if the entry does not exist; an unchanged status is a no-op.
    pub fn change_entry_status(
        &self,
        entry_id: i64,
        status: CveStatus,
        actor: &Actor,
        comment: Option<&str>,
    ) -> Result<bool> {
        let tx = self.write_tx()?;
        let current: Option<String> = tx
            .query_row("SELECT status FROM watchlist_entries WHERE id = ?1", params![entry_id], |r| r.get(0))
            .optional()?;
        let Some(current) = current else {
            return Ok(false);
        };
        if current == status.as_str() {
            return Ok(true);
        }
        tx.execute(
            "UPDATE watchlist_entries
             SET status = ?1, updated_at = datetime('now'), notes = COALESCE(?2, notes),
                 treated_at = CASE WHEN ?1 = 'untreated' THEN NULL ELSE datetime('now') END
             WHERE id = ?3",
            params![status.as_str(), comment, entry_id],
        )?;
        self.log_event(entry_id, "status", Some(status.as_str()), Some(&current), actor, comment)?;
        tx.commit()?;
        Ok(true)
    }

    /// Same, for an entry that must belong to the given project
    pub fn set_watchlist_status(
        &self,
        project_id: i64,
        entry_id: i64,
        status: CveStatus,
        actor: &Actor,
        comment: Option<&str>,
    ) -> Result<bool> {
        let in_project: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM watchlist_entries w JOIN applications a ON a.id = w.app_id
                           WHERE w.id = ?1 AND a.project_id = ?2)",
            params![entry_id, project_id],
            |r| r.get(0),
        )?;
        if !in_project {
            return Ok(false);
        }
        self.change_entry_status(entry_id, status, actor, comment)
    }

    /// Watchlist entries of a project for one CVE: (entry id, application name)
    pub fn project_entries_for_cve(&self, project_id: i64, cve_id: &str) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn().prepare(
            "SELECT w.id, a.name FROM watchlist_entries w JOIN applications a ON a.id = w.app_id
             WHERE a.project_id = ?1 AND w.cve_id = ?2 ORDER BY a.name",
        )?;
        let rows = stmt
            .query_map(params![project_id, cve_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Records the removal of the entries of an application (or of every
    /// application of a project) about to be deleted.
    fn log_removed(&self, filter: &str, id: i64, actor: &Actor, comment: &str) -> Result<()> {
        self.conn().execute(
            &format!(
                "INSERT INTO watchlist_events
                    (organization_id, project_id, project_name, entry_id, cve_id, app_name, app_version, at, kind,
                     status, previous, user_id, actor, comment)
                 SELECT p.organization_id, p.id, p.name, w.id, w.cve_id, a.name, a.version, datetime('now'),
                        'removed', NULL, w.status, ?2, ?3, ?4
                 FROM watchlist_entries w
                 JOIN applications a ON a.id = w.app_id
                 JOIN projects p ON p.id = a.project_id
                 WHERE {filter} = ?1 AND p.organization_id IS NOT NULL"
            ),
            params![id, actor.user_id, actor.name, comment],
        )?;
        self.seal_audit_events()
    }

    /// Deletes a project. Its decision history is kept (shown as a deleted
    /// project), and its entries are recorded as removed.
    pub fn delete_project_by_id(&self, project_id: i64, actor: &Actor) -> Result<()> {
        let tx = self.write_tx()?;
        self.log_removed("p.id", project_id, actor, "project deleted")?;
        tx.execute("DELETE FROM projects WHERE id = ?1", params![project_id])?;
        tx.commit()?;
        Ok(())
    }

    /// Removes an application of the project, keeping the history of its entries
    pub fn delete_application_by_id(&self, project_id: i64, app_id: i64, actor: &Actor) -> Result<bool> {
        let tx = self.write_tx()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM applications WHERE id = ?1 AND project_id = ?2)",
            params![app_id, project_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
        self.log_removed("a.id", app_id, actor, "application removed")?;
        tx.execute("DELETE FROM applications WHERE id = ?1", params![app_id])?;
        tx.commit()?;
        Ok(true)
    }

    /// After a version change: adds the CVEs affecting the new version and
    /// closes the open entries that no longer affect it.
    /// Returns (new entries, entries closed by the upgrade).
    pub fn rescan_after_upgrade(&self, app: &Application, actor: &Actor) -> Result<(i64, i64)> {
        let app_id = app.id.ok_or_else(|| anyhow!("Application must have an ID"))?;
        let (new_entries, _) = self.scan_app_for_cves(app)?;
        let matching: std::collections::HashSet<String> = self.matching_cve_ids(app)?.into_iter().collect();
        let open: Vec<(i64, String)> = {
            let mut stmt = self
                .conn()
                .prepare("SELECT id, cve_id FROM watchlist_entries WHERE app_id = ?1 AND status = 'untreated'")?;
            let rows = stmt
                .query_map(params![app_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let comment = format!(
            "no longer affected after upgrade to {}",
            app.version.as_deref().unwrap_or("?")
        );
        let mut closed = 0;
        for (entry_id, cve_id) in open {
            if !matching.contains(&cve_id) {
                self.change_entry_status(entry_id, CveStatus::Treated, actor, Some(&comment))?;
                closed += 1;
            }
        }
        Ok((new_entries, closed))
    }
}

// ==========================================
// Reading the history
// ==========================================

impl Database {
    /// Every lifecycle event of the user's projects (or of one project),
    /// oldest first.
    pub fn lifecycle_events(&self, user_id: i64, project_id: Option<i64>) -> Result<Vec<LifecycleEvent>> {
        self.lifecycle_events_for(Some(user_id), project_id)
    }

    /// Same, for a user (`Some`) or without access filter (`None`: the local operator)
    pub fn lifecycle_events_for(&self, user_id: Option<i64>, project_id: Option<i64>) -> Result<Vec<LifecycleEvent>> {
        self.lifecycle_events_reaching(user_id, project_id, super::Reach::View)
    }

    /// The events the rights of a user reach. `Reach::Summary` also takes
    /// those of the projects the user is only executive of: for counting
    /// them (the figures), never for showing them.
    pub(super) fn lifecycle_events_reaching(
        &self,
        user_id: Option<i64>,
        project_id: Option<i64>,
        reach: super::Reach,
    ) -> Result<Vec<LifecycleEvent>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT e.id, e.entry_id, o.name, e.project_name, e.cve_id, e.app_name, e.app_version, e.at, e.kind,
                    e.status, e.previous, e.actor, e.comment, c.cvss_v3_score, COALESCE(c.kev_known_exploited, 0),
                    e.user_id IS NULL, NOT EXISTS(SELECT 1 FROM projects p WHERE p.id = e.project_id)
             FROM watchlist_events e
             JOIN organizations o ON o.id = e.organization_id
             LEFT JOIN cves c ON c.cve_id = e.cve_id
             WHERE (?2 IS NULL OR e.project_id = ?2)
               -- a role on the organization shows its whole history, deleted
               -- projects included; a project role shows that project only
               AND (?1 IS NULL
                    OR EXISTS(SELECT 1 FROM {org_view} a WHERE a.organization_id = o.id AND a.user_id = ?1)
                    OR EXISTS(SELECT 1 FROM {project_view} pa WHERE pa.project_id = e.project_id AND pa.user_id = ?1))
             ORDER BY e.id",
            org_view = reach.org_view(),
            project_view = reach.project_view(),
        ))?;
        let rows = stmt
            .query_map(params![user_id, project_id], |r| {
                Ok(LifecycleEvent {
                    id: r.get(0)?,
                    entry_id: r.get(1)?,
                    org: r.get(2)?,
                    project: r.get(3)?,
                    cve_id: r.get(4)?,
                    app_name: r.get(5)?,
                    app_version: r.get(6)?,
                    at: r.get(7)?,
                    kind: r.get(8)?,
                    status: r.get(9)?,
                    previous: r.get(10)?,
                    actor: r.get(11)?,
                    comment: r.get(12)?,
                    cvss: r.get(13)?,
                    kev: r.get::<_, i64>(14)? != 0,
                    automatic: r.get(15)?,
                    project_deleted: r.get(16)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// Day-by-day activity and stock between two dates (inclusive), computed by
/// replaying the events. Days without event are present, carrying the stock.
pub fn timeline(events: &[LifecycleEvent], from: NaiveDate, to: NaiveDate) -> Vec<DayStats> {
    /// Entries to review per severity band, and accepted risks
    #[derive(Clone, Copy, Default)]
    struct Stock {
        open: [i64; 5],
        accepted: i64,
    }
    impl Stock {
        fn count(&mut self, status: &str, band: usize, by: i64) {
            match status {
                "untreated" => self.open[band] += by,
                "accepted" => self.accepted += by,
                _ => {}
            }
        }
        fn write(&self, stats: &mut DayStats) {
            stats.open = self.open.iter().sum();
            stats.open_by_severity = self.open;
            stats.accepted_total = self.accepted;
        }
    }
    // Status and severity band of each entry
    let mut status: BTreeMap<i64, (String, usize)> = BTreeMap::new();
    let mut per_day: BTreeMap<String, DayStats> = BTreeMap::new();
    let (from_s, to_s) = (from.to_string(), to.to_string());
    let mut stock = Stock::default();
    // Stock at the end of the day before `from`
    let mut carried = Stock::default();
    for e in events {
        let day = e.day();
        if day > to_s.as_str() {
            break;
        }
        let in_range = day >= from_s.as_str();
        let stats = per_day.entry(day.to_string()).or_default();
        // The severity is the one the CVE has today, on every event of the entry
        let band = crate::deadlines::band(e.cvss);
        let before = match (e.kind.as_str(), e.status.as_deref()) {
            ("detected", _) => {
                stats.new += 1;
                stock.count("untreated", band, 1);
                status.insert(e.entry_id, ("untreated".into(), band))
            }
            ("status", Some(new)) => {
                match new {
                    "accepted" => stats.accepted += 1,
                    "treated" => stats.closed += 1,
                    "not_applicable" => stats.not_applicable += 1,
                    _ => stats.reopened += 1,
                }
                stock.count(new, band, 1);
                status.insert(e.entry_id, (new.to_string(), band))
            }
            ("removed", _) => status.remove(&e.entry_id),
            _ => None,
        };
        if let Some((previous, band)) = before {
            stock.count(&previous, band, -1);
        }
        stock.write(stats);
        if !in_range {
            carried = stock;
        }
    }

    let mut out = Vec::new();
    let mut day = from;
    while day <= to {
        let key = day.to_string();
        let mut stats = per_day.remove(&key).unwrap_or_else(|| {
            let mut quiet = DayStats::default();
            carried.write(&mut quiet);
            quiet
        });
        stats.day = key;
        carried = Stock { open: stats.open_by_severity, accepted: stats.accepted_total };
        out.push(stats);
        match day.succ_opt() {
            Some(next) => day = next,
            None => break,
        }
    }
    out
}

/// The entries as they were at the end of the given day
pub fn state_at(events: &[LifecycleEvent], day: NaiveDate) -> Vec<StateItem> {
    let limit = day.to_string();
    let mut state: BTreeMap<i64, StateItem> = BTreeMap::new();
    for e in events {
        if e.day() > limit.as_str() {
            break;
        }
        match (e.kind.as_str(), e.status.as_deref()) {
            ("removed", _) => {
                state.remove(&e.entry_id);
            }
            (_, Some(status)) => {
                state.insert(
                    e.entry_id,
                    StateItem {
                        status: status.to_string(),
                        event: e.clone(),
                    },
                );
            }
            _ => {}
        }
    }
    let mut items: Vec<StateItem> = state.into_values().collect();
    let rank = |s: &str| match s {
        "untreated" => 0,
        "accepted" => 1,
        "treated" => 2,
        _ => 3,
    };
    items.sort_by(|a, b| {
        rank(&a.status)
            .cmp(&rank(&b.status))
            .then(b.event.kev.cmp(&a.event.kev))
            .then(b.event.cvss.partial_cmp(&a.event.cvss).unwrap_or(std::cmp::Ordering::Equal))
            .then(b.event.cve_id.cmp(&a.event.cve_id))
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AffectedProduct, Cve};

    fn setup() -> (Database, i64, i64, Application) {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        for (id, end) in [("CVE-2024-8001", "2.0"), ("CVE-2024-8002", "5.0")] {
            let mut cve = Cve::new(id.into());
            cve.description = Some("Flaw".into());
            cve.cvss_v3_score = Some(8.0);
            cve.affected_products.push(AffectedProduct {
                vendor: Some("acme".into()),
                product: Some("widget".into()),
                version: Some("*".into()),
                version_start: None,
                version_end: Some(end.into()),
                cpe: Some("cpe".into()),
                ..Default::default()
            });
            db.upsert_cve(&cve).unwrap();
        }
        let mut app = Application::new(project, "widget".into());
        app.version = Some("1.0".into());
        app.id = Some(db.create_application(&app).unwrap());
        db.scan_app_for_cves(&app).unwrap();
        (db, alice, project, app)
    }

    fn set_day(db: &Database, event_id: i64, day: &str) {
        db.conn()
            .execute(
                "UPDATE watchlist_events SET at = ?1 || ' 12:00:00' WHERE id = ?2",
                params![day, event_id],
            )
            .unwrap();
    }

    #[test]
    fn decisions_are_recorded_with_their_author() {
        let (db, alice, project, _) = setup();
        let actor = Actor::user(alice, "alice");
        let entry = db.project_triage(project, false).unwrap()[0].entry_id;

        assert!(db
            .set_watchlist_status(project, entry, CveStatus::Accepted, &actor, Some("compensating control"))
            .unwrap());
        // Same status again: no new event
        db.set_watchlist_status(project, entry, CveStatus::Accepted, &actor, None).unwrap();
        // Unknown entry / wrong project
        assert!(!db.set_watchlist_status(project, 9999, CveStatus::Treated, &actor, None).unwrap());
        assert!(!db.set_watchlist_status(project + 100, entry, CveStatus::Treated, &actor, None).unwrap());

        let events = db.lifecycle_events(alice, Some(project)).unwrap();
        let kinds: Vec<(&str, Option<&str>)> = events.iter().map(|e| (e.kind.as_str(), e.status.as_deref())).collect();
        assert_eq!(
            kinds,
            [("detected", Some("untreated")), ("detected", Some("untreated")), ("status", Some("accepted"))]
        );
        let decision = events.last().unwrap();
        assert_eq!(
            (decision.actor.as_str(), decision.previous.as_deref(), decision.comment.as_deref()),
            ("alice", Some("untreated"), Some("compensating control"))
        );
        assert_eq!(db.project_triage(project, true).unwrap()[0].status, "accepted");
    }

    #[test]
    fn deleting_a_project_keeps_its_decision_history() {
        let (db, alice, project, _) = setup();
        let actor = Actor::user(alice, "alice");
        let entry = db.project_triage(project, false).unwrap()[0].entry_id;
        db.set_watchlist_status(project, entry, CveStatus::Accepted, &actor, Some("accepted for now")).unwrap();

        db.delete_project_by_id(project, &actor).unwrap();
        let events = db.lifecycle_events(alice, None).unwrap();
        let decision = events.iter().find(|e| e.kind == "status").expect("decision kept");
        assert_eq!(
            (decision.actor.as_str(), decision.comment.as_deref(), decision.project.as_str()),
            ("alice", Some("accepted for now"), "infra")
        );
        assert!(decision.project_deleted && !decision.automatic);
        assert!(events.iter().filter(|e| e.kind == "detected").all(|e| e.automatic));
        // Nothing of the deleted project counts as open any more
        assert_eq!(events.iter().filter(|e| e.kind == "removed").count(), 2);
        assert!(state_at(&events, chrono::Utc::now().date_naive()).is_empty());

        // A new project reusing the name starts with an empty history
        let org = db.get_org("acme", alice).unwrap().unwrap().id;
        let again = db.create_org_project(org, alice, "infra", None).unwrap();
        assert!(db.lifecycle_events(alice, Some(again)).unwrap().is_empty());
        // Only deleting the whole organization removes the history
        db.delete_org(org).unwrap();
        assert!(db.lifecycle_events(alice, None).unwrap().is_empty());
    }

    #[test]
    fn history_is_scoped_to_member_projects() {
        let (db, alice, _, _) = setup();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        assert_eq!(db.lifecycle_events(alice, None).unwrap().len(), 2);
        assert!(db.lifecycle_events(bob, None).unwrap().is_empty());
    }

    #[test]
    fn upgrade_closes_entries_that_no_longer_apply_and_removal_keeps_history() {
        let (db, alice, project, mut app) = setup();
        let actor = Actor::user(alice, "alice");
        db.update_application_version(app.id.unwrap(), "3.0").unwrap();
        app.version = Some("3.0".into());
        // 3.0 is past the fix of 8001 (< 2.0) but still below 5.0
        assert_eq!(db.rescan_after_upgrade(&app, &actor).unwrap(), (0, 1));
        let open: Vec<String> = db.project_triage(project, false).unwrap().into_iter().map(|i| i.cve_id).collect();
        assert_eq!(open, ["CVE-2024-8002"]);
        let closed = &db.project_triage(project, true).unwrap()[0];
        assert_eq!((closed.cve_id.as_str(), closed.status.as_str()), ("CVE-2024-8001", "treated"));

        assert!(!db.delete_application_by_id(project + 1, app.id.unwrap(), &actor).unwrap());
        assert!(db.delete_application_by_id(project, app.id.unwrap(), &actor).unwrap());
        let events = db.lifecycle_events(alice, Some(project)).unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "removed").count(), 2);
        let today = chrono::Utc::now().date_naive();
        assert!(state_at(&events, today).is_empty());
        let stats = timeline(&events, today, today);
        assert_eq!((stats[0].new, stats[0].closed, stats[0].open), (2, 1, 0));
    }

    #[test]
    fn timeline_and_past_state_are_replayed_from_events() {
        let (db, alice, project, _) = setup();
        let actor = Actor::user(alice, "alice");
        let entries = db.project_triage(project, false).unwrap();
        let (first, second) = (entries[0].entry_id, entries[1].entry_id);
        db.set_watchlist_status(project, first, CveStatus::Accepted, &actor, Some("ok")).unwrap();
        db.set_watchlist_status(project, second, CveStatus::Treated, &actor, None).unwrap();
        db.set_watchlist_status(project, second, CveStatus::Untreated, &actor, Some("regression")).unwrap();

        // Spread the five events over several days
        let ids: Vec<i64> = db.lifecycle_events(alice, None).unwrap().iter().map(|e| e.id).collect();
        for (id, day) in ids.iter().zip(["2026-01-01", "2026-01-01", "2026-01-03", "2026-01-03", "2026-01-06"]) {
            set_day(&db, *id, day);
        }
        let events = db.lifecycle_events(alice, None).unwrap();
        let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();

        let stats = timeline(&events, d("2026-01-01"), d("2026-01-07"));
        assert_eq!(stats.len(), 7);
        let row = |i: usize| (stats[i].new, stats[i].accepted, stats[i].closed, stats[i].reopened, stats[i].open, stats[i].accepted_total);
        assert_eq!(row(0), (2, 0, 0, 0, 2, 0)); // two detections
        assert_eq!(row(1), (0, 0, 0, 0, 2, 0)); // quiet day carries the stock
        assert_eq!(row(2), (0, 1, 1, 0, 0, 1)); // one accepted, one closed
        assert_eq!(row(5), (0, 0, 0, 1, 1, 1)); // reopened
        assert_eq!(row(6), (0, 0, 0, 0, 1, 1));

        // A window starting later starts from the carried stock
        let late = timeline(&events, d("2026-01-04"), d("2026-01-05"));
        assert_eq!((late[0].open, late[0].accepted_total, late[0].new), (0, 1, 0));
        // Before any event
        assert_eq!(timeline(&events, d("2025-12-30"), d("2025-12-31"))[1].open, 0);

        let statuses = |day: &str| -> Vec<String> { state_at(&events, d(day)).into_iter().map(|s| s.status).collect() };
        assert_eq!(statuses("2026-01-02"), ["untreated", "untreated"]);
        assert_eq!(statuses("2026-01-04"), ["accepted", "treated"]);
        assert_eq!(statuses("2026-01-07"), ["untreated", "accepted"]);
        assert!(statuses("2025-12-31").is_empty());
        let accepted = &state_at(&events, d("2026-01-04"))[0];
        assert_eq!((accepted.event.actor.as_str(), accepted.event.comment.as_deref()), ("alice", Some("ok")));
    }

    #[test]
    fn migration_backfills_history_of_existing_entries() {
        let (db, alice, project, app) = setup();
        // Back to a v7 shape: no events, one entry already handled
        db.conn()
            .execute_batch(
                "DROP TABLE watchlist_events;
                 UPDATE watchlist_entries SET status = 'treated', treated_at = '2026-02-02 10:00:00', notes = 'patched'
                 WHERE id = (SELECT MIN(id) FROM watchlist_entries);",
            )
            .unwrap();
        db.migrate_lifecycle().unwrap();
        db.migrate_history().unwrap();
        // The table was rebuilt in its v8 shape: the later migrations follow, as on a real upgrade
        db.migrate_version_unknown().unwrap();
        let events = db.lifecycle_events(alice, Some(project)).unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "detected").count(), 2);
        let decision = events.iter().find(|e| e.kind == "status").unwrap();
        assert_eq!(
            (decision.status.as_deref(), decision.actor.as_str(), decision.comment.as_deref(), decision.day()),
            (Some("treated"), "unknown", Some("patched"), "2026-02-02")
        );
        // The new status is accepted by the rebuilt table
        let entry = db.project_triage(project, false).unwrap()[0].entry_id;
        assert!(db.change_entry_status(entry, CveStatus::Accepted, &Actor::system("cli"), Some("x")).unwrap());
        let _ = app;
    }

    #[test]
    fn the_stock_by_severity_adds_up_to_the_stock_and_matches_the_state_of_each_day() {
        let event = |id: i64, entry_id: i64, day: u32, kind: &str, status: Option<&str>, cvss: Option<f64>| LifecycleEvent {
            id,
            entry_id,
            org: "acme".into(),
            project: "infra".into(),
            cve_id: format!("CVE-2026-{entry_id}"),
            app_name: "widget".into(),
            app_version: None,
            at: format!("2026-03-{day:02} 09:00:00"),
            kind: kind.into(),
            status: status.map(String::from),
            previous: None,
            actor: "t".into(),
            automatic: false,
            project_deleted: false,
            comment: None,
            cvss,
            kev: false,
        };
        // One entry per severity and one without a score, then decisions, a reopening and a removal
        let events = vec![
            event(1, 1, 2, "detected", Some("untreated"), Some(9.8)),
            event(2, 2, 2, "detected", Some("untreated"), Some(7.5)),
            event(3, 3, 3, "detected", Some("untreated"), Some(5.0)),
            event(4, 4, 3, "detected", Some("untreated"), Some(2.0)),
            event(5, 5, 4, "detected", Some("untreated"), None),
            event(6, 6, 4, "detected", Some("untreated"), Some(9.1)),
            event(7, 1, 5, "status", Some("accepted"), Some(9.8)),
            event(8, 2, 6, "status", Some("treated"), Some(7.5)),
            event(9, 3, 6, "status", Some("not_applicable"), Some(5.0)),
            event(10, 2, 8, "status", Some("untreated"), Some(7.5)),
            event(11, 6, 9, "removed", None, Some(9.1)),
            event(12, 1, 10, "status", Some("treated"), Some(9.8)),
            event(13, 4, 10, "status", Some("accepted"), Some(2.0)),
            // The same entry detected again by a later scan stays one entry
            event(14, 5, 11, "detected", Some("untreated"), None),
        ];
        let d = |day: u32| NaiveDate::from_ymd_opt(2026, 3, day).unwrap();
        let stats = timeline(&events, d(1), d(12));
        assert_eq!(stats.len(), 12);
        for (i, day) in stats.iter().enumerate() {
            let state = state_at(&events, d(i as u32 + 1));
            let open = |band: usize| state.iter().filter(|s| s.status == "untreated" && crate::deadlines::band(s.event.cvss) == band).count() as i64;
            assert_eq!(day.open_by_severity, [open(0), open(1), open(2), open(3), open(4)], "{}", day.day);
            assert_eq!(day.open_by_severity.iter().sum::<i64>(), day.open, "{}", day.day);
            assert_eq!(day.accepted_total, state.iter().filter(|s| s.status == "accepted").count() as i64, "{}", day.day);
        }
        let by_severity: Vec<[i64; 5]> = stats.iter().map(|s| s.open_by_severity).collect();
        assert_eq!(
            by_severity,
            [
                [0, 0, 0, 0, 0], // 1: nothing yet
                [1, 1, 0, 0, 0], // 2: a critical and a high one
                [1, 1, 1, 1, 0], // 3: a medium and a low one
                [2, 1, 1, 1, 1], // 4: one without a score, a second critical one
                [1, 1, 1, 1, 1], // 5: a critical risk accepted
                [1, 0, 0, 1, 1], // 6: the high one closed, the medium one not applicable
                [1, 0, 0, 1, 1], // 7: a quiet day carries the stock
                [1, 1, 0, 1, 1], // 8: the high one reopened
                [0, 1, 0, 1, 1], // 9: the second critical one left with its application
                [0, 1, 0, 0, 1], // 10: the low risk accepted
                [0, 1, 0, 0, 1], // 11
                [0, 1, 0, 0, 1], // 12
            ]
        );
        assert_eq!(stats.iter().map(|s| s.accepted_total).collect::<Vec<_>>(), [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]);
        // A window starting later starts from the stock carried so far, severity by severity
        let late = timeline(&events, d(7), d(8));
        assert_eq!((late[0].open_by_severity, late[0].open, late[0].accepted_total), ([1, 0, 0, 1, 1], 3, 1));
        assert_eq!(late[1].open_by_severity, [1, 1, 0, 1, 1]);
        assert_eq!(timeline(&events, d(20), d(20))[0].open_by_severity, [0, 1, 0, 0, 1]);
        // In the JSON of a day: five counts in the order critical, high, medium, low, no score
        assert_eq!(serde_json::to_value(&stats[3]).unwrap()["open_by_severity"], serde_json::json!([2, 1, 1, 1, 1]));
    }
}
