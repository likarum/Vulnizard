//! Advisories of the package ecosystems (OSV), kept one by one.
//!
//! Several advisories may speak of the same CVE and the same package (a
//! GitHub advisory and the ecosystem's own, for instance): what a package of
//! a CVE is affected by is the sum of what they say. Keeping each advisory
//! lets a run read only those that changed and still work that sum out
//! again, and lets an advisory that is withdrawn stop counting.

use anyhow::Result;
use rusqlite::params;
use std::collections::BTreeSet;

use super::Database;

/// What one advisory says of one package for one CVE
#[derive(Debug, Clone, PartialEq)]
pub struct OsvStatement {
    pub cve_id: String,
    pub name: String,
    /// `None`: every version
    pub vulnerable_range: Option<String>,
    pub fixed_version: Option<String>,
}

/// Two statements about the same package add up: their ranges are put one
/// after the other. A statement without a range covers every version, and
/// the sum then does too.
pub fn add_ranges(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(a), Some(b)) => Some(format!("{a} {b}")),
        _ => None,
    }
}

impl Database {
    /// v25: the advisories of package ecosystems, one row per advisory. The
    /// next run of the source reads every ecosystem whole once to fill it.
    pub(super) fn migrate_osv_advisories(&self) -> Result<()> {
        self.conn().execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS osv_advisories (
                 ecosystem TEXT NOT NULL,
                 advisory_id TEXT NOT NULL,
                 cve_id TEXT NOT NULL,
                 name TEXT NOT NULL,
                 vulnerable_range TEXT,
                 fixed_version TEXT,
                 PRIMARY KEY (ecosystem, advisory_id, cve_id, name)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_osv_advisories_package ON osv_advisories(ecosystem, cve_id, name);
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '25');
             COMMIT;",
        )?;
        Ok(())
    }

    /// Runs `work` in a transaction of its own
    fn osv_transaction<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn().execute_batch("BEGIN")?;
        match work() {
            Ok(value) => {
                self.conn().execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(e) => {
                let _ = self.conn().execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn osv_insert(&self, ecosystem: &str, advisory: &str, statements: &[OsvStatement]) -> Result<()> {
        let mut insert = self.conn().prepare_cached(
            "INSERT OR REPLACE INTO osv_advisories (ecosystem, advisory_id, cve_id, name, vulnerable_range, fixed_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for s in statements {
            insert.execute(params![ecosystem, advisory, s.cve_id, s.name, s.vulnerable_range, s.fixed_version])?;
        }
        Ok(())
    }

    /// A whole export of an ecosystem was read: it replaces everything known
    /// of that ecosystem. Returns the number of CVEs it speaks of.
    pub fn osv_replace_ecosystem(&self, ecosystem: &str, advisories: &[(String, Vec<OsvStatement>)]) -> Result<i64> {
        self.osv_transaction(|| {
            self.conn().execute("DELETE FROM osv_advisories WHERE ecosystem = ?1", params![ecosystem])?;
            for (advisory, statements) in advisories {
                self.osv_insert(ecosystem, advisory, statements)?;
            }
            self.conn().execute("DELETE FROM affected_packages WHERE ecosystem = ?1", params![ecosystem])?;
            let packages: Vec<(String, String)> = {
                let mut stmt = self.conn().prepare(
                    "SELECT DISTINCT a.cve_id, a.name FROM osv_advisories a
                     WHERE a.ecosystem = ?1 AND EXISTS (SELECT 1 FROM cves c WHERE c.cve_id = a.cve_id)",
                )?;
                let rows = stmt.query_map(params![ecosystem], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
                rows
            };
            let mut cves = BTreeSet::new();
            for (cve, name) in &packages {
                self.osv_sum(ecosystem, cve, name)?;
                cves.insert(cve.as_str());
            }
            Ok(cves.len() as i64)
        })
    }

    /// Some advisories changed: each replaces what it said before. An
    /// advisory with nothing to say (withdrawn, removed, or no longer about a
    /// CVE) stops counting. Returns the number of CVEs whose packages were
    /// worked out again.
    pub fn osv_replace_advisories(&self, ecosystem: &str, advisories: &[(String, Vec<OsvStatement>)]) -> Result<i64> {
        self.osv_transaction(|| {
            let mut touched: BTreeSet<(String, String)> = BTreeSet::new();
            for (advisory, statements) in advisories {
                let before: Vec<(String, String)> = {
                    let mut stmt = self.conn().prepare_cached("SELECT cve_id, name FROM osv_advisories WHERE ecosystem = ?1 AND advisory_id = ?2")?;
                    let rows = stmt.query_map(params![ecosystem, advisory], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
                    rows
                };
                touched.extend(before);
                self.conn().execute("DELETE FROM osv_advisories WHERE ecosystem = ?1 AND advisory_id = ?2", params![ecosystem, advisory])?;
                self.osv_insert(ecosystem, advisory, statements)?;
                touched.extend(statements.iter().map(|s| (s.cve_id.clone(), s.name.clone())));
            }
            let mut cves = BTreeSet::new();
            for (cve, name) in &touched {
                self.osv_sum(ecosystem, cve, name)?;
                cves.insert(cve.as_str());
            }
            Ok(cves.len() as i64)
        })
    }

    /// A CVE may reach the database after the advisory that speaks of it:
    /// its packages are worked out then. Returns the number of CVEs caught up.
    pub fn osv_settle_late_cves(&self) -> Result<i64> {
        let late: Vec<(String, String, String)> = {
            let mut stmt = self.conn().prepare(
                "SELECT DISTINCT a.ecosystem, a.cve_id, a.name FROM osv_advisories a
                 JOIN cves c ON c.cve_id = a.cve_id
                 WHERE NOT EXISTS (SELECT 1 FROM affected_packages p
                                   WHERE p.cve_id = a.cve_id AND p.ecosystem = a.ecosystem AND p.name = a.name)",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
            rows
        };
        if late.is_empty() {
            return Ok(0);
        }
        self.osv_transaction(|| {
            let mut cves = BTreeSet::new();
            for (ecosystem, cve, name) in &late {
                self.osv_sum(ecosystem, cve, name)?;
                cves.insert(cve.as_str());
            }
            Ok(cves.len() as i64)
        })
    }

    /// Works out what a package of a CVE is affected by, from every advisory
    /// that speaks of it (in the order of their identifiers, so that the
    /// result does not depend on the order they were read in). Nothing is
    /// kept for a CVE the database does not hold: see `osv_settle_late_cves`.
    fn osv_sum(&self, ecosystem: &str, cve: &str, name: &str) -> Result<()> {
        let said: Vec<(Option<String>, Option<String>)> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT vulnerable_range, fixed_version FROM osv_advisories
                 WHERE ecosystem = ?1 AND cve_id = ?2 AND name = ?3 ORDER BY advisory_id",
            )?;
            let rows = stmt.query_map(params![ecosystem, cve, name], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            rows
        };
        let mut said = said.into_iter();
        let Some((mut range, mut fixed)) = said.next() else {
            self.conn().execute("DELETE FROM affected_packages WHERE cve_id = ?1 AND ecosystem = ?2 AND name = ?3", params![cve, ecosystem, name])?;
            return Ok(());
        };
        for (other_range, other_fixed) in said {
            range = add_ranges(range, other_range);
            fixed = fixed.or(other_fixed);
        }
        self.conn().execute(
            "INSERT INTO affected_packages (cve_id, ecosystem, name, vulnerable_range, fixed_version)
             SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM cves WHERE cve_id = ?1)
             ON CONFLICT(cve_id, ecosystem, name) DO UPDATE SET
                 vulnerable_range = excluded.vulnerable_range, fixed_version = excluded.fixed_version",
            params![cve, ecosystem, name, range, fixed],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Cve;

    fn says(cve: &str, name: &str, range: Option<&str>, fixed: Option<&str>) -> OsvStatement {
        OsvStatement { cve_id: cve.into(), name: name.into(), vulnerable_range: range.map(Into::into), fixed_version: fixed.map(Into::into) }
    }

    fn packages(db: &Database, cve: &str) -> Vec<(String, Option<String>, Option<String>)> {
        let mut stmt = db.conn().prepare("SELECT name, vulnerable_range, fixed_version FROM affected_packages WHERE cve_id = ?1 ORDER BY name").unwrap();
        let rows = stmt.query_map([cve], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        rows
    }

    fn database_with(cves: &[&str]) -> Database {
        let db = Database::open_in_memory().unwrap();
        for id in cves {
            db.upsert_cve(&Cve::new((*id).into())).unwrap();
        }
        db
    }

    #[test]
    fn advisories_about_the_same_package_add_up_and_one_changing_leaves_the_others() {
        let db = database_with(&["CVE-2024-1"]);
        let whole = vec![
            ("GHSA-b".to_string(), vec![says("CVE-2024-1", "tool", Some(">=2.0 <2.3"), None)]),
            ("GHSA-a".to_string(), vec![says("CVE-2024-1", "tool", Some(">=0 <1.4"), Some("1.4"))]),
        ];
        assert_eq!(db.osv_replace_ecosystem("Go", &whole).unwrap(), 1);
        // In the order of the identifiers, whatever the order they came in
        assert_eq!(packages(&db, "CVE-2024-1"), [("tool".to_string(), Some(">=0 <1.4 >=2.0 <2.3".to_string()), Some("1.4".to_string()))]);

        // One advisory is corrected: the other still counts
        let corrected = vec![("GHSA-b".to_string(), vec![says("CVE-2024-1", "tool", Some(">=2.0 <2.5"), Some("2.5"))])];
        assert_eq!(db.osv_replace_advisories("Go", &corrected).unwrap(), 1);
        assert_eq!(packages(&db, "CVE-2024-1")[0].1.as_deref(), Some(">=0 <1.4 >=2.0 <2.5"));

        // The same advisory again changes nothing
        db.osv_replace_advisories("Go", &corrected).unwrap();
        assert_eq!(packages(&db, "CVE-2024-1")[0].1.as_deref(), Some(">=0 <1.4 >=2.0 <2.5"));

        // An advisory without a range covers every version, and the sum too
        db.osv_replace_advisories("Go", &[("GHSA-c".to_string(), vec![says("CVE-2024-1", "tool", None, None)])]).unwrap();
        assert_eq!(packages(&db, "CVE-2024-1")[0].1, None);
    }

    #[test]
    fn a_withdrawn_advisory_stops_counting_and_the_last_one_removes_the_package() {
        let db = database_with(&["CVE-2024-1"]);
        let whole = vec![
            ("GHSA-a".to_string(), vec![says("CVE-2024-1", "tool", Some(">=0 <1.4"), Some("1.4")), says("CVE-2024-1", "other", Some(">=0 <3"), None)]),
            ("GHSA-b".to_string(), vec![says("CVE-2024-1", "tool", Some(">=2.0 <2.3"), None)]),
        ];
        db.osv_replace_ecosystem("npm", &whole).unwrap();
        assert_eq!(packages(&db, "CVE-2024-1").len(), 2);

        db.osv_replace_advisories("npm", &[("GHSA-a".to_string(), vec![])]).unwrap();
        assert_eq!(packages(&db, "CVE-2024-1"), [("tool".to_string(), Some(">=2.0 <2.3".to_string()), None)]);
        db.osv_replace_advisories("npm", &[("GHSA-b".to_string(), vec![])]).unwrap();
        assert!(packages(&db, "CVE-2024-1").is_empty());
        // An advisory never heard of, withdrawn: nothing to do, no error
        assert_eq!(db.osv_replace_advisories("npm", &[("GHSA-z".to_string(), vec![])]).unwrap(), 0);
    }

    #[test]
    fn a_whole_export_replaces_its_ecosystem_only() {
        let db = database_with(&["CVE-2024-1", "CVE-2024-2"]);
        db.osv_replace_ecosystem("npm", &[("GHSA-a".to_string(), vec![says("CVE-2024-1", "left-pad", Some(">=0 <2"), None)])]).unwrap();
        db.osv_replace_ecosystem("Go", &[("GO-1".to_string(), vec![says("CVE-2024-1", "tool", Some(">=0 <1"), None)])]).unwrap();
        // The next export of npm no longer holds the advisory: its package goes, Go keeps its own
        assert_eq!(db.osv_replace_ecosystem("npm", &[("GHSA-b".to_string(), vec![says("CVE-2024-2", "express", None, None)])]).unwrap(), 1);
        assert_eq!(packages(&db, "CVE-2024-1"), [("tool".to_string(), Some(">=0 <1".to_string()), None)]);
        assert_eq!(packages(&db, "CVE-2024-2"), [("express".to_string(), None, None)]);
    }

    #[test]
    fn an_advisory_read_before_its_cve_counts_once_the_cve_arrives() {
        let db = database_with(&[]);
        db.osv_replace_advisories("PyPI", &[("PYSEC-1".to_string(), vec![says("CVE-2025-9", "django", Some(">=0 <5.1"), Some("5.1"))])]).unwrap();
        assert!(packages(&db, "CVE-2025-9").is_empty());
        assert_eq!(db.osv_settle_late_cves().unwrap(), 0);

        db.upsert_cve(&Cve::new("CVE-2025-9".into())).unwrap();
        assert_eq!(db.osv_settle_late_cves().unwrap(), 1);
        assert_eq!(packages(&db, "CVE-2025-9"), [("django".to_string(), Some(">=0 <5.1".to_string()), Some("5.1".to_string()))]);
        // Nothing left to catch up
        assert_eq!(db.osv_settle_late_cves().unwrap(), 0);
    }
}
