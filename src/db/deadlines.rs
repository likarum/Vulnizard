//! Storage of the remediation delays (schema v29): those of the instance
//! (metadata, as the other instance settings) and what each organization
//! replaces for its projects. The rule itself is in [`crate::deadlines`].

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::db::{Actor, Database, TriageItem};
use crate::deadlines::{DelayOverride, Delays, EntryTrack, Figures, Policies, FIELDS};

/// One row per organization replacing at least one delay; a NULL follows the instance
const DEADLINES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS organization_delays (
    organization_id INTEGER PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    critical INTEGER,
    high INTEGER,
    medium INTEGER,
    low INTEGER,
    kev INTEGER
);
INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '29');
"#;

/// Delays of the instance: "critical,high,medium,low,kev" in days
const KEY_DELAYS: &str = "setting.remediation_delays";

fn override_row(r: &rusqlite::Row, first: usize) -> rusqlite::Result<DelayOverride> {
    Ok(DelayOverride {
        critical: r.get(first)?,
        high: r.get(first + 1)?,
        medium: r.get(first + 2)?,
        low: r.get(first + 3)?,
        kev: r.get(first + 4)?,
    })
}

impl Database {
    pub(super) fn migrate_deadlines(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(DEADLINES_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// Delays of the instance: the defaults until an administrator sets them
    pub fn instance_delays(&self) -> Result<Delays> {
        let mut delays = DelayOverride::default();
        if let Some(stored) = self.get_metadata(KEY_DELAYS)? {
            for ((field, _), value) in FIELDS.iter().zip(stored.split(',')) {
                delays.set(field, value.parse().ok().filter(|days| *days > 0));
            }
        }
        Ok(Delays::default().with(&delays))
    }

    /// Sets the delays of the instance. A change is written to the security
    /// log with its author; returns false when nothing changed.
    pub fn set_instance_delays(&self, delays: &Delays, actor: &Actor) -> Result<bool> {
        let tx = self.write_tx()?;
        if self.instance_delays()? == *delays {
            return Ok(false);
        }
        let stored: Vec<String> = FIELDS.iter().map(|(field, _)| delays.get(field).to_string()).collect();
        self.set_metadata(KEY_DELAYS, &stored.join(","))?;
        let detail = format!("instance: {}", delays.as_override().describe());
        self.log_security_event(actor, None, "remediation_delays", Some(&detail))?;
        tx.commit()?;
        Ok(true)
    }

    /// What an organization replaces (nothing: it follows the instance)
    pub fn org_delay_override(&self, org_id: i64) -> Result<DelayOverride> {
        Ok(self
            .conn()
            .query_row(
                "SELECT critical, high, medium, low, kev FROM organization_delays WHERE organization_id = ?1",
                params![org_id],
                |r| override_row(r, 0),
            )
            .optional()?
            .unwrap_or_default())
    }

    /// Delays applying to the projects of an organization
    pub fn org_delays(&self, org_id: i64) -> Result<Delays> {
        Ok(self.instance_delays()?.with(&self.org_delay_override(org_id)?))
    }

    /// Sets what an organization replaces; an empty override puts it back on
    /// the delays of the instance. A change is written to the security log
    /// with its author; returns false when nothing changed.
    pub fn set_org_delay_override(&self, org_id: i64, replaced: &DelayOverride, actor: &Actor) -> Result<bool> {
        let tx = self.write_tx()?;
        if self.org_delay_override(org_id)? == *replaced {
            return Ok(false);
        }
        let name: String = tx.query_row("SELECT name FROM organizations WHERE id = ?1", params![org_id], |r| r.get(0))?;
        if replaced.is_empty() {
            tx.execute("DELETE FROM organization_delays WHERE organization_id = ?1", params![org_id])?;
        } else {
            tx.execute(
                "INSERT OR REPLACE INTO organization_delays (organization_id, critical, high, medium, low, kev)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![org_id, replaced.critical, replaced.high, replaced.medium, replaced.low, replaced.kev],
            )?;
        }
        let detail = format!("organization {name}: {}", replaced.describe());
        self.log_security_event(actor, None, "remediation_delays", Some(&detail))?;
        tx.commit()?;
        Ok(true)
    }

    /// Delays of the instance and of every organization, read at once: what
    /// a list or a count spanning several organizations resolves each entry
    /// with ([`Policies::deadline`], [`crate::deadlines::tracks`]).
    pub fn deadline_policies(&self) -> Result<Policies> {
        let mut policies = Policies::uniform(self.instance_delays()?);
        let mut stmt = self.conn().prepare(
            "SELECT o.name, d.critical, d.high, d.medium, d.low, d.kev
             FROM organization_delays d JOIN organizations o ON o.id = d.organization_id",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, override_row(r, 1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (org, replaced) in rows {
            policies.replace(&org, &replaced);
        }
        Ok(policies)
    }

    /// The history of every entry of a scope, each with the delays of its
    /// organization: the entries `reader` may read (`None`: the local
    /// operator, who reads everything), of one project when `project_id` is
    /// given, and of the organization named `org` when one is. The
    /// organization only narrows what the rights of the reader give.
    pub fn entry_tracks(&self, reader: Option<i64>, project_id: Option<i64>, org: Option<&str>) -> Result<Vec<EntryTrack>> {
        self.tracks_reaching(reader, project_id, org, super::Reach::View)
    }

    fn tracks_reaching(&self, reader: Option<i64>, project_id: Option<i64>, org: Option<&str>, reach: super::Reach) -> Result<Vec<EntryTrack>> {
        let mut events = self.lifecycle_events_reaching(reader, project_id, reach)?;
        if let Some(org) = org {
            events.retain(|e| e.org == org);
        }
        Ok(crate::deadlines::tracks(&events, &self.deadline_policies()?))
    }

    /// The executive figures of a scope (one project, every project the
    /// reader holds a role on, or those narrowed to an organization) as of
    /// today, the resolution averages being taken over the last `period_days`
    /// days. What the overview shows, and what the REST API and the MCP
    /// server answer: see [`crate::deadlines::figures`].
    ///
    /// The one reading that counts the projects the reader is only executive
    /// of (`Reach::Summary`): the entries counted never leave this function.
    pub fn figures(&self, reader: Option<i64>, project_id: Option<i64>, org: Option<&str>, period_days: i64) -> Result<Figures> {
        let tracks = self.tracks_reaching(reader, project_id, org, super::Reach::Summary)?;
        Ok(crate::deadlines::figures(&tracks, chrono::Utc::now().date_naive(), period_days))
    }

    /// Gives each entry its deadline as of today (`TriageItem::deadline`),
    /// with the delays of its organization
    pub(super) fn with_deadlines(&self, mut items: Vec<TriageItem>) -> Result<Vec<TriageItem>> {
        let policies = self.deadline_policies()?;
        let today = chrono::Utc::now().date_naive();
        for item in &mut items {
            item.deadline =
                policies.deadline(&item.org, &item.detected_at, item.decided_at.as_deref(), item.cvss, item.kev, today);
        }
        Ok(items)
    }

    /// The overdue entries among those to review that `scoped_triage` lists
    /// (same scope: the user's projects, one project, or those of one
    /// organization), most overdue first. Nothing is cut before the filter.
    pub fn scoped_overdue(&self, user_id: i64, project_id: Option<i64>, org: Option<&str>) -> Result<Vec<TriageItem>> {
        let mut items = self.scoped_triage(user_id, project_id, org, false, -1)?;
        items.retain(|item| item.deadline.is_some_and(|d| d.is_overdue()));
        items.sort_by_key(|item| std::cmp::Reverse(item.deadline.map(|d| d.overdue_days())));
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadlines::{tracks, BySeverity, DeadlineState, Lateness};
    use crate::models::{AffectedProduct, Application, Cve, CveStatus};
    use std::collections::BTreeMap;

    fn cve(db: &Database, id: &str, cvss: Option<f64>, kev: bool, fixed_in: &str) {
        let mut cve = Cve::new(id.into());
        cve.description = Some("Flaw".into());
        cve.cvss_v3_score = cvss;
        cve.kev_known_exploited = kev;
        cve.affected_products.push(AffectedProduct {
            vendor: Some("acme".into()),
            product: Some("widget".into()),
            version: Some("*".into()),
            version_start: None,
            version_end: Some(fixed_in.into()),
            cpe: Some("cpe".into()),
            ..Default::default()
        });
        db.upsert_cve(&cve).unwrap();
    }

    /// Makes everything recorded so far ten days old
    fn ten_days_ago(db: &Database) {
        db.conn().execute("UPDATE watchlist_entries SET created_at = datetime('now', '-10 days')", []).unwrap();
        db.conn().execute("UPDATE watchlist_events SET at = datetime('now', '-10 days')", []).unwrap();
    }

    /// CVE number -> (delay, days left) of the entries to review of a project
    fn open(db: &Database, project: i64) -> BTreeMap<String, (u32, i64)> {
        db.project_triage(project, false)
            .unwrap()
            .into_iter()
            .map(|i| {
                let d = i.deadline.expect("deadline");
                (i.cve_id[9..].to_string(), (d.delay_days, d.days_left().expect("to review")))
            })
            .collect()
    }

    #[test]
    fn the_deadline_of_an_entry_follows_its_detection_its_cve_and_its_organization() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let actor = Actor::user(alice, "alice");
        let acme = db.create_org("acme", alice).unwrap();
        let other = db.create_org("other", alice).unwrap();
        let infra = db.create_org_project(acme, alice, "infra", None).unwrap();
        let elsewhere = db.create_org_project(other, alice, "elsewhere", None).unwrap();
        // One CVE per case; 8002 is fixed in 2.0, the others in 5.0
        for (id, cvss, kev, fixed_in) in [
            ("CVE-2024-8001", Some(9.8), false, "5.0"),
            ("CVE-2024-8002", Some(8.0), false, "2.0"),
            ("CVE-2024-8003", Some(5.0), false, "5.0"),
            ("CVE-2024-8004", Some(2.0), false, "5.0"),
            ("CVE-2024-8005", None, false, "5.0"),
            ("CVE-2024-8006", Some(8.0), true, "5.0"),
            ("CVE-2024-8007", Some(9.8), true, "5.0"),
        ] {
            cve(&db, id, cvss, kev, fixed_in);
        }
        let mut app = Application::new(infra, "widget".into());
        app.version = Some("1.0".into());
        app.id = Some(db.create_application(&app).unwrap());
        db.scan_app_for_cves(&app).unwrap();
        let mut twin = Application::new(elsewhere, "widget".into());
        twin.version = Some("1.0".into());
        twin.id = Some(db.create_application(&twin).unwrap());
        db.scan_app_for_cves(&twin).unwrap();
        ten_days_ago(&db);

        // Each severity its delay, no score as medium, exploited: 14 days unless the severity asks for less
        let expected: BTreeMap<String, (u32, i64)> = [
            ("8001", (7, -3)), ("8002", (30, 20)), ("8003", (90, 80)), ("8004", (180, 170)), ("8005", (90, 80)), ("8006", (14, 4)), ("8007", (7, -3)),
        ]
        .into_iter()
        .map(|(id, v)| (id.to_string(), v))
        .collect();
        assert_eq!(open(&db, infra), expected);
        let overdue = |project: Option<i64>, org: Option<&str>| -> Vec<String> {
            db.scoped_overdue(alice, project, org).unwrap().into_iter().map(|i| format!("{}/{}", i.project, &i.cve_id[9..])).collect()
        };
        assert_eq!(overdue(Some(infra), None), ["infra/8007", "infra/8001"]);
        assert_eq!(overdue(None, None).len(), 4);
        assert_eq!(overdue(None, Some("other")), ["elsewhere/8007", "elsewhere/8001"]);

        // A decision stops the clock: never overdue, and how long it took is known
        let entry = |cve: &str| db.project_entries_for_cve(infra, cve).unwrap()[0].0;
        for (cve, status) in [("CVE-2024-8001", CveStatus::Accepted), ("CVE-2024-8007", CveStatus::NotApplicable)] {
            db.set_watchlist_status(infra, entry(cve), status, &actor, Some("because")).unwrap();
        }
        assert!(overdue(Some(infra), None).is_empty());
        let decided = db.project_triage(infra, true).unwrap();
        assert_eq!(decided.len(), 2);
        for item in &decided {
            let deadline = item.deadline.unwrap();
            assert_eq!(deadline.state, DeadlineState::Decided { took_days: 10, late_days: 3 }, "{}", item.cve_id);
            assert!(!deadline.is_overdue() && deadline.days_left().is_none());
        }
        // Reopened: due at its first deadline again, so overdue at once
        db.set_watchlist_status(infra, entry("CVE-2024-8001"), CveStatus::Untreated, &actor, None).unwrap();
        assert_eq!(open(&db, infra)["8001"], (7, -3));
        assert_eq!(overdue(Some(infra), None), ["infra/8001"]);

        // A version change closes what it fixes and moves no deadline
        db.change_application_version(app.id.unwrap(), "3.0", &actor).unwrap();
        let after = open(&db, infra);
        assert!(!after.contains_key("8002"));
        for id in ["8001", "8003", "8004", "8005", "8006"] {
            assert_eq!(after[id], expected[id], "{id}");
        }

        // The severity is the one of today: a score raised to critical shortens the deadline of the same entry
        cve(&db, "CVE-2024-8003", Some(9.5), false, "5.0");
        assert_eq!(open(&db, infra)["8003"], (7, -3));
        // Listed as exploited later on: 14 days where that is shorter
        cve(&db, "CVE-2024-8004", Some(2.0), true, "5.0");
        assert_eq!(open(&db, infra)["8004"], (14, 4));

        // The history tells the same as the entries
        let events = db.lifecycle_events_for(None, None).unwrap();
        let today = chrono::Utc::now().date_naive();
        let check = |project: i64, name: &str| {
            let tracked = tracks(&events, &db.deadline_policies().unwrap());
            for item in db.project_triage(project, false).unwrap().into_iter().chain(db.project_triage(project, true).unwrap()) {
                let track = tracked.iter().find(|t| t.entry_id == item.entry_id).unwrap();
                assert_eq!(track.project, name);
                assert_eq!(track.deadline(today), item.deadline, "{name} {}", item.cve_id);
                assert_eq!(track.overdue_on(today), item.deadline.unwrap().is_overdue(), "{name} {}", item.cve_id);
            }
        };
        check(infra, "infra");
        check(elsewhere, "elsewhere");

        // An organization replaces delays for its projects only; "all projects" gives each entry those of its own
        db.set_org_delay_override(acme, &DelayOverride { critical: Some(20), ..Default::default() }, &actor).unwrap();
        assert_eq!((open(&db, infra)["8001"], open(&db, infra)["8003"]), ((20, 10), (20, 10)));
        assert_eq!(open(&db, elsewhere)["8001"], (7, -3));
        assert!(overdue(Some(infra), None).is_empty());
        let mixed: BTreeMap<String, i64> = db
            .scoped_triage(alice, None, None, false, -1)
            .unwrap()
            .into_iter()
            .filter(|i| i.cve_id == "CVE-2024-8001")
            .map(|i| (i.org, i.deadline.unwrap().days_left().unwrap()))
            .collect();
        assert_eq!(mixed, BTreeMap::from([("acme".to_string(), 10), ("other".to_string(), -3)]));
        check(infra, "infra");
        check(elsewhere, "elsewhere");
    }

    #[test]
    fn delays_are_stored_for_the_instance_and_replaced_per_organization() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", true).unwrap();
        let acme = db.create_org("acme", alice).unwrap();
        let other = db.create_org("other", alice).unwrap();
        let actor = Actor::user(alice, "alice");

        // Defaults until set; nothing is logged for a save that changes nothing
        assert_eq!(db.instance_delays().unwrap(), Delays::default());
        assert!(!db.set_instance_delays(&Delays::default(), &actor).unwrap());
        let instance = Delays { critical: 3, high: 20, medium: 60, low: 120, kev: 10 };
        assert!(db.set_instance_delays(&instance, &actor).unwrap());
        assert_eq!(db.instance_delays().unwrap(), instance);
        assert_eq!(db.org_delays(acme).unwrap(), instance);

        // An organization replaces two values and follows the instance for the others
        let replaced = DelayOverride { critical: Some(1), kev: Some(40), ..Default::default() };
        assert!(db.set_org_delay_override(acme, &replaced, &actor).unwrap());
        assert!(!db.set_org_delay_override(acme, &replaced, &actor).unwrap());
        assert_eq!(db.org_delay_override(acme).unwrap(), replaced);
        assert_eq!(db.org_delays(acme).unwrap(), Delays { critical: 1, high: 20, medium: 60, low: 120, kev: 40 });
        assert_eq!(db.org_delays(other).unwrap(), instance);
        let policies = db.deadline_policies().unwrap();
        assert_eq!((policies.of_org("acme").critical, policies.of_org("other").critical), (1, 3));
        // The inherited values follow the instance when it changes
        db.set_instance_delays(&Delays { high: 25, ..instance }, &actor).unwrap();
        assert_eq!(db.org_delays(acme).unwrap().high, 25);

        // Back to the instance, as a whole
        assert!(db.set_org_delay_override(acme, &DelayOverride::default(), &actor).unwrap());
        assert_eq!(db.org_delays(acme).unwrap().critical, 3);

        // Every change is in the security log, with who made it (latest first)
        let logged: Vec<_> = db
            .list_security_events(None, 100)
            .unwrap()
            .into_iter()
            .filter(|e| e.event == "remediation_delays")
            .map(|e| (e.actor, e.detail.unwrap_or_default()))
            .collect();
        assert_eq!(
            logged,
            [
                ("alice".to_string(), "organization acme: inherited from the instance".to_string()),
                ("alice".to_string(), "instance: critical 3, high 25, medium 60, low 120, kev 10".to_string()),
                ("alice".to_string(), "organization acme: critical 1, kev 40".to_string()),
                ("alice".to_string(), "instance: critical 3, high 20, medium 60, low 120, kev 10".to_string()),
            ]
        );
        assert!(db.check_security_log().unwrap().intact());

        // What an organization replaced goes with it
        db.set_org_delay_override(other, &replaced, &actor).unwrap();
        db.delete_org(other).unwrap();
        let left: i64 = db.conn().query_row("SELECT COUNT(*) FROM organization_delays", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn the_figures_of_a_scope_follow_the_reader_the_organization_and_its_delays() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        let actor = Actor::user(alice, "alice");
        let acme = db.create_org("acme", alice).unwrap();
        let other = db.create_org("other", alice).unwrap();
        let infra = db.create_org_project(acme, alice, "infra", None).unwrap();
        let elsewhere = db.create_org_project(other, alice, "elsewhere", None).unwrap();
        // Each severity, one without a score, two known exploited
        for (id, cvss, kev) in [
            ("CVE-2024-8001", Some(9.8), false),
            ("CVE-2024-8002", Some(8.0), false),
            ("CVE-2024-8003", Some(5.0), false),
            ("CVE-2024-8004", Some(2.0), false),
            ("CVE-2024-8005", None, false),
            ("CVE-2024-8006", Some(8.0), true),
            ("CVE-2024-8007", Some(9.8), true),
        ] {
            cve(&db, id, cvss, kev, "5.0");
        }
        let mut apps = Vec::new();
        for project in [infra, elsewhere] {
            let mut app = Application::new(project, "widget".into());
            app.version = Some("1.0".into());
            app.id = Some(db.create_application(&app).unwrap());
            db.scan_app_for_cves(&app).unwrap();
            apps.push(app);
        }
        // Detected 20 days ago: the two critical ones are 13 days late, the exploited high one 6
        db.conn().execute("UPDATE watchlist_entries SET created_at = datetime('now', '-20 days')", []).unwrap();
        db.conn().execute("UPDATE watchlist_events SET at = datetime('now', '-20 days')", []).unwrap();

        let all = db.figures(Some(alice), None, None, 90).unwrap();
        assert_eq!(all.open, BySeverity { total: 14, critical: 4, high: 4, medium: 2, low: 2, none: 2 });
        assert_eq!(all.overdue, BySeverity { total: 6, critical: 4, high: 2, medium: 0, low: 0, none: 0 });
        assert_eq!(all.overdue_days, Lateness { avg: Some(10.7), max: Some(13) });
        assert_eq!((all.resolved.total, all.resolved_avg_days.total, all.period_days), (0, None, 90));
        assert_eq!(all.as_of, chrono::Utc::now().date_naive());
        // What is counted is what the lists show
        let listed = |project: Option<i64>, org: Option<&str>| {
            (db.scoped_triage(alice, project, org, false, -1).unwrap().len() as i64, db.scoped_overdue(alice, project, org).unwrap().len() as i64)
        };
        let counted = |project: Option<i64>, org: Option<&str>| {
            let f = db.figures(Some(alice), project, org, 90).unwrap();
            assert_eq!(f.open.bands().iter().map(|n| **n).sum::<i64>(), f.open.total);
            assert_eq!(f.overdue.bands().iter().map(|n| **n).sum::<i64>(), f.overdue.total);
            (f.open.total, f.overdue.total)
        };
        for (project, org) in [(None, None), (Some(infra), None), (Some(elsewhere), None), (None, Some("acme")), (None, Some("other")), (None, Some("nowhere"))] {
            assert_eq!(counted(project, org), listed(project, org), "{project:?} {org:?}");
        }
        assert_eq!((counted(Some(infra), None), counted(None, Some("other")), counted(None, Some("nowhere"))), ((7, 3), (7, 3), (0, 0)));
        // The local operator reads everything; who has no project reads nothing, whatever is asked
        assert_eq!(db.figures(None, None, None, 90).unwrap(), all);
        for (project, org) in [(None, None), (Some(infra), None), (None, Some("acme"))] {
            let nothing = db.figures(Some(bob), project, org, 90).unwrap();
            assert_eq!((nothing.open.total, nothing.overdue.total, nothing.overdue_days.max), (0, 0, None), "{project:?} {org:?}");
        }
        assert!(db.entry_tracks(Some(bob), None, None).unwrap().is_empty());
        assert_eq!(db.entry_tracks(Some(alice), None, Some("acme")).unwrap().len(), 7);

        // One organization gives itself 25 days for a critical CVE and 5 for a high one: each entry
        // follows the delays of its own organization, in "all projects" too
        db.set_org_delay_override(acme, &DelayOverride { critical: Some(25), high: Some(5), ..Default::default() }, &actor).unwrap();
        let (strict, plain) = (db.figures(Some(alice), None, Some("acme"), 90).unwrap(), db.figures(Some(alice), None, Some("other"), 90).unwrap());
        // acme: the two high ones are 15 days late, the critical ones are in time (the exploited one too: 14 days is shorter than 25 and 20 days have passed)
        assert_eq!(strict.overdue, BySeverity { total: 3, critical: 1, high: 2, medium: 0, low: 0, none: 0 });
        assert_eq!(strict.overdue_days, Lateness { avg: Some(12.0), max: Some(15) });
        assert_eq!(plain.overdue, BySeverity { total: 3, critical: 2, high: 1, medium: 0, low: 0, none: 0 });
        assert_eq!(plain.overdue_days, Lateness { avg: Some(10.7), max: Some(13) });
        let mixed = db.figures(Some(alice), None, None, 90).unwrap();
        assert_eq!(mixed.overdue, BySeverity { total: 6, critical: 3, high: 3, medium: 0, low: 0, none: 0 });
        assert_eq!(mixed.overdue_days, Lateness { avg: Some(11.3), max: Some(15) });
        assert_eq!(db.figures(Some(alice), Some(infra), None, 90).unwrap(), strict);
        assert_eq!(counted(None, None), listed(None, None));

        // Decisions: counted over the period, from the detection; a reopened one no longer counts
        let entry = |project: i64, cve: &str| db.project_entries_for_cve(project, cve).unwrap()[0].0;
        db.set_watchlist_status(elsewhere, entry(elsewhere, "CVE-2024-8001"), CveStatus::Accepted, &actor, Some("because")).unwrap();
        db.set_watchlist_status(elsewhere, entry(elsewhere, "CVE-2024-8005"), CveStatus::NotApplicable, &actor, None).unwrap();
        db.set_watchlist_status(elsewhere, entry(elsewhere, "CVE-2024-8004"), CveStatus::Treated, &actor, None).unwrap();
        db.set_watchlist_status(elsewhere, entry(elsewhere, "CVE-2024-8004"), CveStatus::Untreated, &actor, None).unwrap();
        let decided = db.figures(Some(alice), Some(elsewhere), None, 90).unwrap();
        assert_eq!((decided.open.total, decided.open.low, decided.overdue.total), (5, 1, 2));
        assert_eq!(decided.resolved, BySeverity { total: 2, critical: 1, high: 0, medium: 0, low: 0, none: 1 });
        assert_eq!(decided.resolved_avg_days, BySeverity { total: Some(20.0), critical: Some(20.0), high: None, medium: None, low: None, none: Some(20.0) });
        // The application is removed: nothing of it is open any more, and what was decided stays decided
        db.delete_application_by_id(elsewhere, apps[1].id.unwrap(), &actor).unwrap();
        let removed = db.figures(Some(alice), Some(elsewhere), None, 90).unwrap();
        assert_eq!((removed.open.total, removed.overdue.total, removed.overdue_days), (0, 0, Lateness::default()));
        assert_eq!((removed.resolved, removed.resolved_avg_days), (decided.resolved, decided.resolved_avg_days));
        // Out of the period, a decision is not counted: an average of nothing is not a zero
        db.conn().execute("UPDATE watchlist_events SET at = datetime(at, '-40 days')", []).unwrap();
        let month = db.figures(Some(alice), Some(elsewhere), None, 30).unwrap();
        assert_eq!((month.resolved.total, month.resolved_avg_days.total, month.resolved_avg_days.critical), (0, None, None));
        assert_eq!(db.figures(Some(alice), Some(elsewhere), None, 90).unwrap().resolved.total, 2);
    }
}
