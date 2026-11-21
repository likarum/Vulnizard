//! Chained logs in the database (schema v22): each security event and each
//! audit event carries the hash that links it to the previous one (see
//! `crate::trail`). The security log is one chain; the audit of decisions is
//! one chain per organization, which is what an organization can export.

use anyhow::{anyhow, Result};
use p256::ecdsa::SigningKey;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use crate::db::Database;
use crate::trail::{self, Export};

const TRAIL_SCHEMA: &str = r#"
ALTER TABLE security_events ADD COLUMN chain TEXT;
ALTER TABLE watchlist_events ADD COLUMN chain TEXT;
CREATE INDEX IF NOT EXISTS idx_security_events_unchained ON security_events(id) WHERE chain IS NULL;
CREATE INDEX IF NOT EXISTS idx_wevents_unchained ON watchlist_events(id) WHERE chain IS NULL;

-- An entry is written, then linked to the previous one; after that it cannot change
DROP TRIGGER IF EXISTS security_events_no_update;
CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events
WHEN OLD.chain IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'security events cannot be changed'); END;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '22');
"#;

const KEY_SIGNING: &str = "log.signing_key";

/// State of a chain as stored
#[derive(Debug, Clone, PartialEq)]
pub struct ChainCheck {
    pub entries: usize,
    /// Position (from 1) and id of the first entry that does not chain, if any
    pub broken_at: Option<(usize, i64)>,
}

impl ChainCheck {
    pub fn intact(&self) -> bool {
        self.broken_at.is_none()
    }
}

fn security_entry(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?,
        "at": r.get::<_, String>(1)?,
        "actor_id": r.get::<_, Option<i64>>(2)?,
        "actor": r.get::<_, String>(3)?,
        "user_id": r.get::<_, Option<i64>>(4)?,
        "username": r.get::<_, String>(5)?,
        "event": r.get::<_, String>(6)?,
        "detail": r.get::<_, Option<String>>(7)?,
        "chain": r.get::<_, Option<String>>(8)?,
    }))
}

const SECURITY_COLUMNS: &str = "id, at, actor_id, actor, user_id, username, event, detail, chain";

fn audit_entry(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?,
        "organization_id": r.get::<_, i64>(1)?,
        "project": r.get::<_, String>(2)?,
        "entry_id": r.get::<_, i64>(3)?,
        "cve_id": r.get::<_, String>(4)?,
        "app_name": r.get::<_, String>(5)?,
        "app_version": r.get::<_, Option<String>>(6)?,
        "at": r.get::<_, String>(7)?,
        "kind": r.get::<_, String>(8)?,
        "status": r.get::<_, Option<String>>(9)?,
        "previous": r.get::<_, Option<String>>(10)?,
        "actor": r.get::<_, String>(11)?,
        "comment": r.get::<_, Option<String>>(12)?,
        "chain": r.get::<_, Option<String>>(13)?,
    }))
}

const AUDIT_COLUMNS: &str =
    "id, organization_id, project_name, entry_id, cve_id, app_name, app_version, at, kind, status, previous, actor, comment, chain";

fn check(log: &str, entries: &[Value]) -> ChainCheck {
    let mut previous = String::new();
    for (position, entry) in entries.iter().enumerate() {
        let stored = entry.get("chain").and_then(Value::as_str).unwrap_or("");
        if trail::link(log, &previous, entry) != stored {
            return ChainCheck { entries: entries.len(), broken_at: Some((position + 1, entry["id"].as_i64().unwrap_or(0))) };
        }
        previous = stored.to_string();
    }
    ChainCheck { entries: entries.len(), broken_at: None }
}

impl Database {
    pub(super) fn migrate_trail(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(TRAIL_SCHEMA)?;
        tx.commit()?;
        // Entries written before chaining existed are linked in the order they were written
        self.seal_security_events()?;
        self.seal_audit_events()?;
        Ok(())
    }

    /// True once the tables carry their chain column (false while an older
    /// database is being brought up to date: events written then are linked
    /// when the migration that adds the column runs)
    fn chained(&self, table: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = 'chain'"), [], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Links the security events not linked yet, in order
    pub(crate) fn seal_security_events(&self) -> Result<()> {
        if !self.chained("security_events")? {
            return Ok(());
        }
        let pending: Vec<Value> = {
            let mut stmt = self
                .conn()
                .prepare(&format!("SELECT {SECURITY_COLUMNS} FROM security_events WHERE chain IS NULL ORDER BY id"))?;
            let rows = stmt.query_map([], security_entry)?.collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for entry in pending {
            let id = entry["id"].as_i64().unwrap_or(0);
            let previous: String = self
                .conn()
                .query_row(
                    "SELECT chain FROM security_events WHERE id < ?1 AND chain IS NOT NULL ORDER BY id DESC LIMIT 1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_default();
            let chain = trail::link(trail::SECURITY, &previous, &entry);
            self.conn().execute("UPDATE security_events SET chain = ?1 WHERE id = ?2 AND chain IS NULL", params![chain, id])?;
        }
        Ok(())
    }

    /// Links the audit events not linked yet, each to the previous one of its organization
    pub(crate) fn seal_audit_events(&self) -> Result<()> {
        if !self.chained("watchlist_events")? {
            return Ok(());
        }
        let pending: Vec<Value> = {
            let mut stmt = self
                .conn()
                .prepare(&format!("SELECT {AUDIT_COLUMNS} FROM watchlist_events WHERE chain IS NULL ORDER BY id"))?;
            let rows = stmt.query_map([], audit_entry)?.collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        // Head of each organization touched, read once then carried along
        let mut heads: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
        for entry in pending {
            let (id, org) = (entry["id"].as_i64().unwrap_or(0), entry["organization_id"].as_i64().unwrap_or(0));
            let previous = match heads.get(&org) {
                Some(head) => head.clone(),
                None => self
                    .conn()
                    .query_row(
                        "SELECT chain FROM watchlist_events
                         WHERE organization_id = ?1 AND id < ?2 AND chain IS NOT NULL ORDER BY id DESC LIMIT 1",
                        params![org, id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or_default(),
            };
            let chain = trail::link(trail::AUDIT, &previous, &entry);
            self.conn().execute("UPDATE watchlist_events SET chain = ?1 WHERE id = ?2 AND chain IS NULL", params![chain, id])?;
            heads.insert(org, chain);
        }
        Ok(())
    }

    fn security_entries(&self) -> Result<Vec<Value>> {
        self.seal_security_events()?;
        let mut stmt = self.conn().prepare(&format!("SELECT {SECURITY_COLUMNS} FROM security_events ORDER BY id"))?;
        let rows = stmt.query_map([], security_entry)?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn audit_entries(&self, org_id: i64) -> Result<Vec<Value>> {
        self.seal_audit_events()?;
        let mut stmt = self
            .conn()
            .prepare(&format!("SELECT {AUDIT_COLUMNS} FROM watchlist_events WHERE organization_id = ?1 ORDER BY id"))?;
        let rows = stmt.query_map(params![org_id], audit_entry)?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Whether the stored security log still chains from its first entry
    pub fn check_security_log(&self) -> Result<ChainCheck> {
        Ok(check(trail::SECURITY, &self.security_entries()?))
    }

    /// Whether the stored audit of an organization still chains from its first entry
    pub fn check_audit_log(&self, org_id: i64) -> Result<ChainCheck> {
        Ok(check(trail::AUDIT, &self.audit_entries(org_id)?))
    }

    /// Key that signs the exports of this instance, created on first use
    fn log_signing_key(&self) -> Result<SigningKey> {
        if let Some(stored) = self.get_secret(KEY_SIGNING)? {
            let bytes = hex::decode(stored).map_err(|_| anyhow!("invalid log signing key"))?;
            return SigningKey::from_slice(&bytes).map_err(|_| anyhow!("invalid log signing key"));
        }
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        self.set_secret(KEY_SIGNING, &hex::encode(key.to_bytes()))?;
        Ok(key)
    }

    /// Fingerprint of the key that signs the exports (what a verifier compares with)
    pub fn log_key_fingerprint(&self) -> Result<String> {
        Ok(trail::fingerprint(&trail::public_key_of(&self.log_signing_key()?)))
    }

    /// Signed export of the whole security log
    pub fn export_security_log(&self) -> Result<Export> {
        Ok(trail::sign_export(&self.log_signing_key()?, trail::SECURITY, "instance", self.security_entries()?))
    }

    /// Signed export of the whole audit of an organization
    pub fn export_audit_log(&self, org_id: i64, org_name: &str) -> Result<Export> {
        let scope = format!("organization:{org_name}");
        Ok(trail::sign_export(&self.log_signing_key()?, trail::AUDIT, &scope, self.audit_entries(org_id)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Actor;

    #[test]
    fn security_events_are_chained_as_they_are_written() {
        let db = Database::open_in_memory().unwrap();
        let root = db.create_account("root", None, "h", true).unwrap();
        let actor = Actor::user(root, "root");
        for event in ["totp_enabled", "recovery_codes_generated", "totp_removed"] {
            db.log_security_event(&actor, Some(root), event, None).unwrap();
        }
        let unchained: i64 = db.conn().query_row("SELECT COUNT(*) FROM security_events WHERE chain IS NULL", [], |r| r.get(0)).unwrap();
        assert_eq!(unchained, 0);
        assert_eq!(db.check_security_log().unwrap(), ChainCheck { entries: 3, broken_at: None });

        // The export verifies offline, signed by the key of the instance
        let export = db.export_security_log().unwrap();
        let verified = trail::verify(&export, Some(&db.log_key_fingerprint().unwrap())).unwrap();
        assert_eq!((verified.count, verified.scope.as_str()), (3, "instance"));
        // The key is created once
        assert_eq!(db.log_key_fingerprint().unwrap(), verified.key_fingerprint);

        // Someone with direct access to the database who changes or removes an entry is found out
        db.conn().execute_batch("DROP TRIGGER security_events_no_update; DROP TRIGGER security_events_no_delete;").unwrap();
        db.conn().execute("UPDATE security_events SET actor = 'nobody' WHERE id = 2", []).unwrap();
        assert_eq!(db.check_security_log().unwrap().broken_at, Some((2, 2)));
        db.conn().execute("UPDATE security_events SET actor = 'root' WHERE id = 2", []).unwrap();
        assert!(db.check_security_log().unwrap().intact());
        db.conn().execute("DELETE FROM security_events WHERE id = 2", []).unwrap();
        assert_eq!(db.check_security_log().unwrap().broken_at, Some((2, 3)));
    }

    #[test]
    fn the_audit_is_one_chain_per_organization() {
        use crate::models::{AffectedProduct, Application, Cve, CveStatus};
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let acme = db.create_org("acme", alice).unwrap();
        let other = db.create_org("other", alice).unwrap();
        let mut tracked = Vec::new();
        for (i, org) in [acme, other].into_iter().enumerate() {
            let project = db.create_org_project(org, alice, &format!("p{i}"), None).unwrap();
            let mut cve = Cve::new(format!("CVE-2024-000{i}"));
            cve.description = Some("Flaw".into());
            cve.affected_products.push(AffectedProduct {
                vendor: Some("acme".into()),
                product: Some(format!("widget{i}")),
                version: Some("*".into()),
                version_start: None,
                version_end: None,
                cpe: Some("cpe".into()),
            });
            db.upsert_cve(&cve).unwrap();
            let mut app = Application::new(project, format!("widget{i}"));
            assert_eq!(db.add_application_scanned(&mut app).unwrap(), 1);
            tracked.push(project);
        }
        // A decision in one organization
        let entry: i64 = db.conn().query_row("SELECT MIN(id) FROM watchlist_entries", [], |r| r.get(0)).unwrap();
        db.change_entry_status(entry, CveStatus::Accepted, &Actor::user(alice, "alice"), Some("mitigated")).unwrap();

        let unchained: i64 = db.conn().query_row("SELECT COUNT(*) FROM watchlist_events WHERE chain IS NULL", [], |r| r.get(0)).unwrap();
        assert_eq!(unchained, 0);
        assert_eq!(db.check_audit_log(acme).unwrap(), ChainCheck { entries: 2, broken_at: None });
        assert_eq!(db.check_audit_log(other).unwrap(), ChainCheck { entries: 1, broken_at: None });

        let export = db.export_audit_log(acme, "acme").unwrap();
        let verified = trail::verify(&export, None).unwrap();
        assert_eq!((verified.count, verified.scope.as_str()), (2, "organization:acme"));
        assert_eq!(export.entries[1]["comment"], "mitigated");
        // The other organization's events are not in it
        assert!(export.entries.iter().all(|e| e["organization_id"] == acme));

        // Rewriting who decided is detected, in that organization only
        db.conn().execute("UPDATE watchlist_events SET actor = 'someone-else' WHERE kind = 'status'", []).unwrap();
        assert_eq!(db.check_audit_log(acme).unwrap().broken_at.map(|(position, _)| position), Some(2));
        assert!(db.check_audit_log(other).unwrap().intact());
    }
}
