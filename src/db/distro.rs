//! Linux distribution packages (schema v16).
//!
//! Distributions backport fixes: whether a package is vulnerable is decided
//! by the distribution's own advisories ("fixed in 1:9.2p1-2+deb12u3 on
//! Debian 12"), never by upstream version ranges. Advisories are stored per
//! ecosystem ("Debian:12") and source package, and versions are compared
//! with the distribution's own ordering.
//!
//! The same migration gives applications a **group**: the tag shared by the
//! inventory sources that are triaged together (ten identical web servers).
//! A package is tracked once per group; decisions on its CVEs hold for the
//! group. Applications added by hand have the empty group.

use anyhow::Result;
use rusqlite::params;
use std::cmp::Ordering;

use crate::db::Database;

const DISTRO_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS distro_advisories (
    ecosystem TEXT NOT NULL,      -- "Debian:12"
    package TEXT NOT NULL,        -- source package
    cve_id TEXT NOT NULL,
    introduced TEXT NOT NULL DEFAULT '0',
    fixed TEXT,                   -- NULL: no fixed version yet
    urgency TEXT,
    PRIMARY KEY (ecosystem, package, cve_id, introduced)
) WITHOUT ROWID;

ALTER TABLE inventory_sources ADD COLUMN grp TEXT NOT NULL DEFAULT '';
UPDATE inventory_sources SET grp = name;

-- applications: one per (project, group, name, version)
CREATE TABLE applications_v16 (
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
    grp TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, grp, name, version)
);
INSERT INTO applications_v16 (id, project_id, name, version, vendor, ecosystem, cpe_pattern, notes, created_at, updated_at, grp)
SELECT a.id, a.project_id, a.name, a.version, a.vendor, a.ecosystem, a.cpe_pattern, a.notes, a.created_at, a.updated_at,
       COALESCE((SELECT s.grp FROM inventory_components c JOIN inventory_sources s ON s.id = c.source_id
                 WHERE c.application_id = a.id LIMIT 1), '')
FROM applications a;
DROP TABLE applications;
ALTER TABLE applications_v16 RENAME TO applications;
CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '16');
"#;

/// An advisory of a distribution for one source package
#[derive(Debug, Clone, PartialEq)]
pub struct DistroAdvisory {
    pub ecosystem: String,
    pub package: String,
    pub cve_id: String,
    pub introduced: String,
    pub fixed: Option<String>,
    pub urgency: Option<String>,
    /// Text and date of the advisory, used when the CVE is not in the database yet
    pub details: Option<String>,
    pub published: Option<String>,
}

/// Ecosystems whose packages are matched with distribution advisories
pub fn is_distro_ecosystem(ecosystem: &str) -> bool {
    ecosystem.starts_with("Debian:")
}

/// Compares two package versions of a distribution ecosystem
pub fn distro_version_cmp(_ecosystem: &str, a: &str, b: &str) -> Ordering {
    // Debian today; rpm ordering will be chosen here by ecosystem
    dpkg_version_cmp(a, b)
}

/// dpkg ordering: `[epoch:]upstream[-revision]`, where `~` sorts before
/// everything (even the end), letters before other characters, and runs of
/// digits compare as numbers.
pub fn dpkg_version_cmp(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (u64, &str, &str) {
        let v = v.trim();
        let (epoch, rest) = match v.split_once(':') {
            Some((e, rest)) if !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()) => (e.parse().unwrap_or(0), rest),
            _ => (0, v),
        };
        match rest.rsplit_once('-') {
            Some((upstream, revision)) => (epoch, upstream, revision),
            None => (epoch, rest, ""),
        }
    }
    fn order(c: Option<u8>) -> i32 {
        match c {
            None => 0,
            Some(b'~') => -1,
            Some(c) if c.is_ascii_digit() => 0,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }
    fn part(a: &str, b: &str) -> Ordering {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let (mut i, mut j) = (0, 0);
        while i < a.len() || j < b.len() {
            // Non-digit prefixes, character by character
            while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
                let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
                if x != y {
                    return x.cmp(&y);
                }
                i += (i < a.len()) as usize;
                j += (j < b.len()) as usize;
            }
            // Digit runs, as numbers
            while i < a.len() && a[i] == b'0' {
                i += 1;
            }
            while j < b.len() && b[j] == b'0' {
                j += 1;
            }
            let mut first = Ordering::Equal;
            while i < a.len() && j < b.len() && a[i].is_ascii_digit() && b[j].is_ascii_digit() {
                if first == Ordering::Equal {
                    first = a[i].cmp(&b[j]);
                }
                i += 1;
                j += 1;
            }
            if i < a.len() && a[i].is_ascii_digit() {
                return Ordering::Greater;
            }
            if j < b.len() && b[j].is_ascii_digit() {
                return Ordering::Less;
            }
            if first != Ordering::Equal {
                return first;
            }
        }
        Ordering::Equal
    }
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb).then_with(|| part(ua, ub)).then_with(|| part(ra, rb))
}

impl Database {
    pub(super) fn migrate_distro(&self) -> Result<()> {
        // Rebuilding `applications` must not cascade to the entries that reference it
        self.conn().execute_batch("PRAGMA foreign_keys=OFF;")?;
        let result = (|| -> Result<()> {
            let tx = self.conn().unchecked_transaction()?;
            tx.execute_batch(DISTRO_SCHEMA)?;
            let broken: i64 = tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
            if broken > 0 {
                anyhow::bail!("schema v16: {broken} broken references after rebuilding applications");
            }
            tx.commit()?;
            Ok(())
        })();
        self.conn().execute_batch("PRAGMA foreign_keys=ON;")?;
        result
    }

    /// Whether an inventory source reported packages of a distribution
    pub fn has_distro_components(&self) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM inventory_components WHERE ecosystem LIKE 'Debian:%')",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn has_distro_advisories(&self) -> Result<bool> {
        Ok(self.conn().query_row("SELECT EXISTS(SELECT 1 FROM distro_advisories)", [], |r| r.get(0))?)
    }

    /// Replaces the advisories of a distribution family ("Debian") and makes
    /// sure their CVEs exist in the database. Returns the number of advisories.
    pub fn replace_distro_advisories(&self, family: &str, advisories: &[DistroAdvisory]) -> Result<usize> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute("DELETE FROM distro_advisories WHERE ecosystem LIKE ?1", params![format!("{family}:%")])?;
        {
            let mut insert = tx.prepare(
                "INSERT OR REPLACE INTO distro_advisories (ecosystem, package, cve_id, introduced, fixed, urgency)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            // A CVE older than the synchronized history still needs a description
            let mut stub = tx.prepare("INSERT OR IGNORE INTO cves (cve_id, description, published_at) VALUES (?1, ?2, ?3)")?;
            for a in advisories {
                insert.execute(params![a.ecosystem, a.package, a.cve_id, a.introduced, a.fixed, a.urgency])?;
                stub.execute(params![a.cve_id, a.details, a.published])?;
            }
        }
        tx.commit()?;
        Ok(advisories.len())
    }

    /// CVEs affecting this version of a source package on this distribution
    /// release. Issues the distribution rates "unimportant" (no security
    /// impact as packaged) are left out.
    pub fn distro_cves(&self, ecosystem: &str, package: &str, version: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT cve_id, introduced, fixed FROM distro_advisories
             WHERE ecosystem = ?1 AND package = ?2 AND COALESCE(urgency, '') != 'unimportant'",
        )?;
        let rows = stmt
            .query_map(params![ecosystem, package], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut ids: Vec<String> = Vec::new();
        for (cve_id, introduced, fixed) in rows {
            let after_start = introduced == "0" || distro_version_cmp(ecosystem, version, &introduced) != Ordering::Less;
            let before_fix = fixed.as_deref().is_none_or(|f| distro_version_cmp(ecosystem, version, f) == Ordering::Less);
            if after_start && before_fix && !ids.contains(&cve_id) {
                ids.push(cve_id);
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_versions_are_ordered_like_dpkg() {
        let lt = |a: &str, b: &str| {
            assert_eq!(dpkg_version_cmp(a, b), Ordering::Less, "{a} < {b}");
            assert_eq!(dpkg_version_cmp(b, a), Ordering::Greater, "{b} > {a}");
        };
        lt("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3");
        lt("1:9.2p1-2+deb12u9", "1:9.2p1-2+deb12u10");
        lt("9.9", "1:1.0"); // epoch wins
        lt("1.0~rc1", "1.0"); // ~ sorts before the end
        lt("1.0~rc1", "1.0~rc2");
        lt("1.0", "1.0+b1");
        lt("1.0-1", "1.0-1+deb12u1");
        lt("1.0-1~bpo12+1", "1.0-1");
        lt("2.36-9", "2.36-9+deb12u4");
        lt("1.2.9", "1.2.10");
        lt("1.0a", "1.0+"); // letters sort before other characters
        lt("3.0.11-1~deb12u2", "3.0.15-1~deb12u1");
        lt("1.0-1", "1.0.1-1"); // the revision is after the last hyphen
        for same in [("1.0", "1.0"), ("0:1.0", "1.0"), ("1.00", "1.0"), ("1.0-0", "1.0-00")] {
            assert_eq!(dpkg_version_cmp(same.0, same.1), Ordering::Equal, "{same:?}");
        }
    }

    #[test]
    fn a_package_is_vulnerable_until_the_release_fixes_it() {
        let db = Database::open_in_memory().unwrap();
        let advisory = |ecosystem: &str, cve: &str, fixed: Option<&str>, urgency: Option<&str>| DistroAdvisory {
            ecosystem: ecosystem.into(),
            package: "openssh".into(),
            cve_id: cve.into(),
            introduced: "0".into(),
            fixed: fixed.map(String::from),
            urgency: urgency.map(String::from),
            details: Some("A flaw in sshd".into()),
            published: Some("2024-07-01T13:15:06Z".into()),
        };
        let stored = db
            .replace_distro_advisories(
                "Debian",
                &[
                    advisory("Debian:12", "CVE-2024-6387", Some("1:9.2p1-2+deb12u3"), None),
                    advisory("Debian:13", "CVE-2024-6387", Some("1:9.7p1-7"), None),
                    advisory("Debian:12", "CVE-2023-0001", None, None),
                    advisory("Debian:12", "CVE-2023-0002", None, Some("unimportant")),
                ],
            )
            .unwrap();
        assert_eq!(stored, 4);
        // Before the fix of the release: affected; the unfixed issue too, the unimportant one never
        assert_eq!(db.distro_cves("Debian:12", "openssh", "1:9.2p1-2+deb12u2").unwrap(), ["CVE-2023-0001", "CVE-2024-6387"]);
        // The backported fix closes it although upstream 9.2 is "vulnerable"
        assert_eq!(db.distro_cves("Debian:12", "openssh", "1:9.2p1-2+deb12u3").unwrap(), ["CVE-2023-0001"]);
        // Each release has its own fixed version; other packages are untouched
        assert_eq!(db.distro_cves("Debian:13", "openssh", "1:9.2p1-2+deb12u3").unwrap(), ["CVE-2024-6387"]);
        assert!(db.distro_cves("Debian:12", "openssl", "1.0").unwrap().is_empty());
        // The CVE exists with its description even outside the synchronized history
        let description: Option<String> =
            db.conn().query_row("SELECT description FROM cves WHERE cve_id = 'CVE-2024-6387'", [], |r| r.get(0)).unwrap();
        assert_eq!(description.as_deref(), Some("A flaw in sshd"));
        // A new delivery replaces the family
        db.replace_distro_advisories("Debian", &[]).unwrap();
        assert!(db.distro_cves("Debian:12", "openssh", "1:9.2p1-2+deb12u2").unwrap().is_empty());
        assert!(is_distro_ecosystem("Debian:12") && !is_distro_ecosystem("npm"));
    }
}
