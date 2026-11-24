//! Second factors of local accounts (schema v17): authenticator app (TOTP),
//! passkeys, recovery codes, pending second-factor checks, and the
//! requirement set on the instance or on an organization.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use crate::db::Database;

const MFA_SCHEMA: &str = r#"
-- The secret must be readable to compute the codes: it is stored as is
CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS mfa_passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id TEXT UNIQUE NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mfa_passkeys_user ON mfa_passkeys(user_id);

-- Stable random identifier given to authenticators instead of the account id
CREATE TABLE IF NOT EXISTS mfa_handles (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    handle TEXT UNIQUE NOT NULL
);

-- A password was accepted and the second factor is awaited ('login'), or a
-- passkey is being registered ('register')
CREATE TABLE IF NOT EXISTS mfa_pending (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose IN ('login', 'register')),
    state TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
);

ALTER TABLE organizations ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '17');
"#;

/// Schema v18: trail of account security events. Rows are never changed or
/// removed, and outlive the accounts they mention (names are copied).
const SECURITY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL DEFAULT (datetime('now')),
    actor_id INTEGER,
    actor TEXT NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL DEFAULT '',
    event TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);

CREATE TRIGGER IF NOT EXISTS security_events_no_update BEFORE UPDATE ON security_events
BEGIN SELECT RAISE(ABORT, 'security events cannot be changed'); END;
CREATE TRIGGER IF NOT EXISTS security_events_no_delete BEFORE DELETE ON security_events
BEGIN SELECT RAISE(ABORT, 'security events cannot be removed'); END;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '18');
"#;

/// Kinds of security events and what they are shown as
pub const SECURITY_EVENTS: &[(&str, &str)] = &[
    ("instance_set_up", "Instance set up: first administrator created"),
    ("totp_enabled", "Authenticator app set up"),
    ("totp_removed", "Authenticator app removed"),
    ("passkey_added", "Passkey added"),
    ("passkey_removed", "Passkey removed"),
    ("recovery_codes_generated", "Recovery codes generated"),
    ("recovery_code_used", "Signed in with a recovery code"),
    ("second_step_locked", "Second step locked after too many wrong answers"),
    ("mfa_reset", "Two-step sign-in reset"),
    ("mfa_requirement", "Two-step sign-in requirement changed"),
];

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub at: String,
    /// Who did it (an account, or "cli")
    pub actor: String,
    /// Account concerned; empty for an instance or organization setting
    pub username: String,
    pub event: String,
    pub detail: Option<String>,
}

impl SecurityEvent {
    pub fn label(&self) -> &str {
        SECURITY_EVENTS.iter().find(|(k, _)| *k == self.event).map(|(_, l)| *l).unwrap_or(&self.event)
    }
}

/// Schema v19: sign-in with a passkey alone. The challenge is issued before
/// the account is known, so it cannot live in `mfa_pending`.
const PASSKEY_LOGIN_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS passkey_logins (
    token_hash TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '19');
"#;

/// Schema v20.
///
/// The access views leave out an organization that requires a second factor
/// for the accounts that sign in with a password and have none: the
/// requirement of an organization closes that organization, nothing else.
/// (Before, it confined the whole account, so the owner of any organization
/// could add someone and lock them out of everything.)
///
/// `disabled_by_admin` remembers that an administrator disabled an account,
/// so that provisioning cannot enable it again.
const ACCESS_V20_SCHEMA: &str = r#"
DROP VIEW project_access;
DROP VIEW org_access;
CREATE VIEW org_access AS
SELECT a.user_id, a.organization_id, a.rank FROM (
    SELECT user_id, organization_id, MAX(rank) AS rank FROM (
        SELECT user_id, organization_id,
               CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END AS rank
        FROM memberships
        UNION ALL
        SELECT u.id, o.id, CASE u.instance_role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM users u JOIN organizations o WHERE u.instance_role IS NOT NULL
        UNION ALL
        SELECT gm.user_id, o.id, CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM scim_group_members gm
        JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        JOIN organizations o ON gr.level = 'instance' OR (gr.level = 'organization' AND gr.target_id = o.id)
        WHERE gr.level IN ('instance', 'organization')
    ) GROUP BY user_id, organization_id
) a
WHERE NOT EXISTS (
    SELECT 1 FROM organizations o JOIN users u ON u.id = a.user_id
    WHERE o.id = a.organization_id AND o.require_mfa = 1 AND u.password_hash IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.confirmed = 1)
      AND NOT EXISTS (SELECT 1 FROM mfa_passkeys k WHERE k.user_id = u.id)
);
CREATE VIEW project_access AS
SELECT a.user_id, a.project_id, a.rank FROM (
    SELECT user_id, project_id, MAX(rank) AS rank FROM (
        SELECT a.user_id, p.id AS project_id, a.rank
        FROM org_access a JOIN projects p ON p.organization_id = a.organization_id
        UNION ALL
        SELECT user_id, project_id, CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM project_memberships
        UNION ALL
        SELECT gm.user_id, gr.target_id, CASE gr.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END
        FROM scim_group_members gm JOIN scim_group_roles gr ON gr.group_id = gm.group_id
        WHERE gr.level = 'project'
    ) GROUP BY user_id, project_id
) a
WHERE NOT EXISTS (
    SELECT 1 FROM projects p
    JOIN organizations o ON o.id = p.organization_id
    JOIN users u ON u.id = a.user_id
    WHERE p.id = a.project_id AND o.require_mfa = 1 AND u.password_hash IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.confirmed = 1)
      AND NOT EXISTS (SELECT 1 FROM mfa_passkeys k WHERE k.user_id = u.id)
);

ALTER TABLE users ADD COLUMN disabled_by_admin INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_passkey_logins_expiry ON passkey_logins(expires_at);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '20');
"#;

/// Passkey sign-ins started and not finished, kept at once
const MAX_PENDING_PASSKEY_LOGINS: i64 = 10_000;

const KEY_REQUIRE_MFA: &str = "setting.require_mfa";
/// Wrong codes accepted before the pending check is dropped
pub const MAX_MFA_ATTEMPTS: i64 = 5;

#[derive(Debug, Clone)]
pub struct PasskeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Second factors of an account
#[derive(Debug, Clone, Default)]
pub struct MfaStatus {
    pub totp: bool,
    pub passkeys: Vec<PasskeyInfo>,
    /// Unused recovery codes
    pub recovery_left: usize,
}

impl MfaStatus {
    pub fn enrolled(&self) -> bool {
        self.totp || !self.passkeys.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct MfaPending {
    pub user_id: i64,
    pub state: Option<String>,
}

impl Database {
    pub(super) fn migrate_mfa(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(MFA_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn migrate_security(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(SECURITY_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn migrate_access_v20(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(ACCESS_V20_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// Schema v21: the secrets stored in clear so far are encrypted in place
    /// (see `crate::secrets`). Safe to run again: sealed values are left alone.
    pub(super) fn migrate_seal_secrets(&self) -> Result<usize> {
        let mut sealed = 0;
        let tx = self.conn().unchecked_transaction()?;
        for (table, id, column) in [
            ("destinations", "id", "config"),
            ("inventory_sources", "id", "config"),
            ("oidc_providers", "id", "client_secret"),
            ("mfa_totp", "user_id", "secret"),
        ] {
            let rows: Vec<(i64, String)> = {
                let mut stmt = tx.prepare(&format!("SELECT {id}, {column} FROM {table}"))?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            for (row, value) in rows {
                if !value.is_empty() && !crate::secrets::is_sealed(&value) {
                    tx.execute(&format!("UPDATE {table} SET {column} = ?1 WHERE {id} = ?2"), params![self.seal(&value), row])?;
                    sealed += 1;
                }
            }
        }
        let key = "setting.nvd_api_key";
        let value: Option<String> = tx.query_row("SELECT value FROM metadata WHERE key = ?1", params![key], |r| r.get(0)).optional()?;
        if let Some(value) = value.filter(|v| !v.is_empty() && !crate::secrets::is_sealed(v)) {
            tx.execute("UPDATE metadata SET value = ?1 WHERE key = ?2", params![self.seal(&value), key])?;
            sealed += 1;
        }
        tx.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '21')", [])?;
        tx.commit()?;
        Ok(sealed)
    }

    pub(super) fn migrate_passkey_login(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(PASSKEY_LOGIN_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    // ---------- sign-in with a passkey alone ----------

    pub fn create_passkey_login(&self, token_hash: &str, state: &str, ttl_secs: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM passkey_logins WHERE expires_at < CAST(strftime('%s','now') AS INTEGER)", [])?;
        // Anonymous endpoint: the table stays bounded, the oldest challenges make room
        let pending: i64 = conn.query_row("SELECT COUNT(*) FROM passkey_logins", [], |r| r.get(0))?;
        if pending >= MAX_PENDING_PASSKEY_LOGINS {
            conn.execute(
                "DELETE FROM passkey_logins WHERE token_hash IN (
                     SELECT token_hash FROM passkey_logins ORDER BY expires_at LIMIT ?1)",
                params![pending - MAX_PENDING_PASSKEY_LOGINS + 1],
            )?;
        }
        conn.execute(
            "INSERT INTO passkey_logins (token_hash, state, expires_at)
             VALUES (?1, ?2, CAST(strftime('%s','now') AS INTEGER) + ?3)",
            params![token_hash, state, ttl_secs],
        )?;
        Ok(())
    }

    /// Takes a pending challenge: it is returned once, if not expired
    pub fn take_passkey_login(&self, token_hash: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "DELETE FROM passkey_logins WHERE token_hash = ?1 RETURNING state,
                     expires_at > CAST(strftime('%s','now') AS INTEGER)",
                params![token_hash],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?
            .and_then(|(state, valid)| valid.then_some(state)))
    }

    /// Enabled account an authenticator knows under this identifier
    pub fn user_by_mfa_handle(&self, handle: &str) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT u.id FROM mfa_handles h JOIN users u ON u.id = h.user_id WHERE h.handle = ?1 AND u.disabled = 0",
                params![handle],
                |r| r.get(0),
            )
            .optional()?)
    }

    // ---------- security trail ----------

    /// Records a security event about an account (`user_id`), or about a
    /// setting of the instance or of an organization (`None`).
    pub fn log_security_event(&self, actor: &super::Actor, user_id: Option<i64>, event: &str, detail: Option<&str>) -> Result<()> {
        let username: String = match user_id {
            Some(id) => self
                .conn()
                .query_row("SELECT username FROM users WHERE id = ?1", params![id], |r| r.get(0))
                .optional()?
                .unwrap_or_default(),
            None => String::new(),
        };
        self.conn().execute(
            "INSERT INTO security_events (actor_id, actor, user_id, username, event, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![actor.user_id, actor.name, user_id, username, event, detail],
        )?;
        // Linked to the previous entry at once: from then on it cannot be changed unnoticed
        self.seal_security_events()
    }

    /// Most recent events first; of one account, or all of them
    pub fn list_security_events(&self, user_id: Option<i64>, limit: i64) -> Result<Vec<SecurityEvent>> {
        let mut stmt = self.conn().prepare(
            "SELECT at, actor, username, event, detail FROM security_events
             WHERE ?1 IS NULL OR user_id = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![user_id, limit], |r| {
                Ok(SecurityEvent { at: r.get(0)?, actor: r.get(1)?, username: r.get(2)?, event: r.get(3)?, detail: r.get(4)? })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---------- status and requirement ----------

    pub fn mfa_status(&self, user_id: i64) -> Result<MfaStatus> {
        let conn = self.conn();
        let totp = conn
            .query_row("SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed = 1", params![user_id], |_| Ok(()))
            .optional()?
            .is_some();
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used_at FROM mfa_passkeys WHERE user_id = ?1 ORDER BY id",
        )?;
        let passkeys = stmt
            .query_map(params![user_id], |r| {
                Ok(PasskeyInfo { id: r.get(0)?, name: r.get(1)?, created_at: r.get(2)?, last_used_at: r.get(3)? })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let recovery_left: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
            params![user_id],
            |r| r.get(0),
        )?;
        Ok(MfaStatus { totp, passkeys, recovery_left: recovery_left as usize })
    }

    pub fn has_second_factor(&self, user_id: i64) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed = 1)
                 OR EXISTS(SELECT 1 FROM mfa_passkeys WHERE user_id = ?1)",
            params![user_id],
            |r| r.get::<_, i64>(0),
        )? != 0)
    }

    /// True if the account signs in with a password. Accounts that only come
    /// through single sign-on have their second factor at the identity provider.
    pub fn has_password(&self, user_id: i64) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT password_hash IS NOT NULL FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get::<_, i64>(0),
        ).optional()?.unwrap_or(0) != 0)
    }

    pub fn instance_requires_mfa(&self) -> Result<bool> {
        Ok(self.get_metadata(KEY_REQUIRE_MFA)?.as_deref() == Some("1"))
    }

    pub fn set_instance_requires_mfa(&self, required: bool) -> Result<()> {
        self.set_metadata(KEY_REQUIRE_MFA, if required { "1" } else { "0" })
    }

    pub fn org_requires_mfa(&self, org_id: i64) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT require_mfa FROM organizations WHERE id = ?1",
            params![org_id],
            |r| r.get::<_, i64>(0),
        ).optional()?.unwrap_or(0) != 0)
    }

    pub fn set_org_requires_mfa(&self, org_id: i64, required: bool) -> Result<()> {
        self.conn().execute(
            "UPDATE organizations SET require_mfa = ?2 WHERE id = ?1",
            params![org_id, required as i64],
        )?;
        Ok(())
    }

    /// True if the instance requires a second factor of this account (it signs
    /// in with a password). The requirement of an organization is not counted
    /// here: it only closes that organization (see the access views).
    pub fn mfa_required(&self, user_id: i64) -> Result<bool> {
        Ok(self.has_password(user_id)? && self.instance_requires_mfa()?)
    }

    /// Organizations this account has a role in but cannot open until it sets
    /// up a second factor
    pub fn orgs_awaiting_mfa(&self, user_id: i64) -> Result<Vec<String>> {
        if !self.has_password(user_id)? || self.has_second_factor(user_id)? {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn().prepare(
            "SELECT DISTINCT o.name FROM organizations o
             WHERE o.require_mfa = 1 AND (
                 EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = o.id AND m.user_id = ?1)
                 OR EXISTS (SELECT 1 FROM project_memberships pm JOIN projects p ON p.id = pm.project_id
                            WHERE p.organization_id = o.id AND pm.user_id = ?1))
             ORDER BY o.name COLLATE NOCASE",
        )?;
        let names = stmt
            .query_map(params![user_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(names)
    }

    /// Leaves an organization: the account gives up its own memberships in it
    /// (the organization and its projects). The last owner stays.
    pub fn leave_org(&self, org_name: &str, user_id: i64) -> Result<bool> {
        let tx = self.conn().unchecked_transaction()?;
        let Some(org_id) = tx
            .query_row("SELECT id FROM organizations WHERE name = ?1 COLLATE NOCASE", params![org_name], |r| r.get::<_, i64>(0))
            .optional()?
        else {
            return Ok(false);
        };
        let left = tx.execute("DELETE FROM memberships WHERE organization_id = ?1 AND user_id = ?2", params![org_id, user_id])?
            + tx.execute(
                "DELETE FROM project_memberships WHERE user_id = ?2
                 AND project_id IN (SELECT id FROM projects WHERE organization_id = ?1)",
                params![org_id, user_id],
            )?;
        if left == 0 {
            // Nothing of their own to give up (no role, or one that comes from the instance or a group)
            return Ok(false);
        }
        let owners: i64 = tx.query_row(
            "SELECT COUNT(*) FROM memberships WHERE organization_id = ?1 AND role = 'owner'",
            params![org_id],
            |r| r.get(0),
        )?;
        if owners == 0 {
            return Err(super::watchlist::UserFacing("An organization must keep at least one owner: name another owner first.".into()).into());
        }
        tx.commit()?;
        Ok(true)
    }

    /// Organizations this account was itself made a member of (as opposed to
    /// a role coming from the instance or a provisioned group): those it can leave
    pub fn own_org_memberships(&self, user_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn().prepare(
            "SELECT DISTINCT o.name FROM organizations o
             WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = o.id AND m.user_id = ?1)
                OR EXISTS (SELECT 1 FROM project_memberships pm JOIN projects p ON p.id = pm.project_id
                           WHERE p.organization_id = o.id AND pm.user_id = ?1)",
        )?;
        let names = stmt
            .query_map(params![user_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(names)
    }

    /// Required and missing: the account can do nothing but enrol
    pub fn must_enrol_mfa(&self, user_id: i64) -> Result<bool> {
        Ok(self.mfa_required(user_id)? && !self.has_second_factor(user_id)?)
    }

    // ---------- authenticator app ----------

    /// Stores a new, unconfirmed secret (replacing a previous unconfirmed one).
    /// Refused while a confirmed one exists.
    pub fn begin_totp(&self, user_id: i64, secret: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "INSERT INTO mfa_totp (user_id, secret) VALUES (?1, ?2)
             ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, last_step = 0, created_at = datetime('now')
             WHERE mfa_totp.confirmed = 0",
            params![user_id, self.seal(secret)],
        )?;
        Ok(changed > 0)
    }

    /// (secret, confirmed, last accepted step)
    pub fn totp(&self, user_id: i64) -> Result<Option<(String, bool, u64)>> {
        let stored: Option<(String, bool, u64)> = self
            .conn()
            .query_row(
                "SELECT secret, confirmed, last_step FROM mfa_totp WHERE user_id = ?1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, i64>(2)? as u64)),
            )
            .optional()?;
        stored
            .map(|(secret, confirmed, last_step)| Ok((self.unseal(&secret)?, confirmed, last_step)))
            .transpose()
    }

    /// Records an accepted code. The step only moves forward, so two requests
    /// with the same code cannot both succeed.
    pub fn accept_totp_step(&self, user_id: i64, step: u64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE mfa_totp SET confirmed = 1, last_step = ?2 WHERE user_id = ?1 AND last_step < ?2",
            params![user_id, step as i64],
        )?;
        Ok(changed > 0)
    }

    pub fn delete_totp(&self, user_id: i64) -> Result<()> {
        self.conn().execute("DELETE FROM mfa_totp WHERE user_id = ?1", params![user_id])?;
        self.drop_recovery_codes_without_factor(user_id)
    }

    // ---------- recovery codes ----------

    pub fn replace_recovery_codes(&self, user_id: i64, hashes: &[String]) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?1", params![user_id])?;
        for hash in hashes {
            tx.execute(
                "INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                params![user_id, hash],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Consumes a recovery code; false if unknown or already used
    pub fn use_recovery_code(&self, user_id: i64, hash: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE mfa_recovery_codes SET used_at = datetime('now')
             WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
            params![user_id, hash],
        )?;
        Ok(changed > 0)
    }

    /// Recovery codes make no sense without a factor to recover from
    fn drop_recovery_codes_without_factor(&self, user_id: i64) -> Result<()> {
        if !self.has_second_factor(user_id)? {
            self.conn().execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?1", params![user_id])?;
        }
        Ok(())
    }

    // ---------- passkeys ----------

    /// Random identifier of the account for authenticators, created on first use
    pub fn mfa_handle(&self, user_id: i64) -> Result<String> {
        self.conn().execute(
            "INSERT OR IGNORE INTO mfa_handles (user_id, handle) VALUES (?1, ?2)",
            params![user_id, uuid::Uuid::new_v4().to_string()],
        )?;
        Ok(self.conn().query_row("SELECT handle FROM mfa_handles WHERE user_id = ?1", params![user_id], |r| r.get(0))?)
    }

    /// False if this credential is already registered (to any account)
    pub fn add_passkey(&self, user_id: i64, name: &str, credential_id: &str, data: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "INSERT OR IGNORE INTO mfa_passkeys (user_id, name, credential_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, name, credential_id, data],
        )?;
        Ok(changed > 0)
    }

    /// (credential id, serialized credential) of every passkey of the account
    pub fn passkeys(&self, user_id: i64) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn().prepare("SELECT credential_id, data FROM mfa_passkeys WHERE user_id = ?1 ORDER BY id")?;
        let rows = stmt
            .query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn touch_passkey(&self, user_id: i64, credential_id: &str, data: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE mfa_passkeys SET data = ?3, last_used_at = datetime('now') WHERE user_id = ?1 AND credential_id = ?2",
            params![user_id, credential_id, data],
        )?;
        Ok(())
    }

    pub fn delete_passkey(&self, user_id: i64, id: i64) -> Result<bool> {
        let changed = self.conn().execute("DELETE FROM mfa_passkeys WHERE user_id = ?1 AND id = ?2", params![user_id, id])?;
        self.drop_recovery_codes_without_factor(user_id)?;
        Ok(changed > 0)
    }

    // ---------- pending checks ----------

    /// Opens a pending check, replacing the previous ones of the same kind for this account
    pub fn create_mfa_pending(&self, token_hash: &str, user_id: i64, purpose: &str, state: Option<&str>, ttl_secs: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM mfa_pending WHERE expires_at < CAST(strftime('%s','now') AS INTEGER) OR (user_id = ?1 AND purpose = ?2)",
            params![user_id, purpose],
        )?;
        conn.execute(
            "INSERT INTO mfa_pending (token_hash, user_id, purpose, state, expires_at)
             VALUES (?1, ?2, ?3, ?4, CAST(strftime('%s','now') AS INTEGER) + ?5)",
            params![token_hash, user_id, purpose, state, ttl_secs],
        )?;
        Ok(())
    }

    /// Pending check of an enabled account, if not expired
    pub fn mfa_pending(&self, token_hash: &str, purpose: &str) -> Result<Option<MfaPending>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT p.user_id, p.state FROM mfa_pending p JOIN users u ON u.id = p.user_id
                 WHERE p.token_hash = ?1 AND p.purpose = ?2 AND u.disabled = 0
                   AND p.expires_at > CAST(strftime('%s','now') AS INTEGER)",
                params![token_hash, purpose],
                |r| Ok(MfaPending { user_id: r.get(0)?, state: r.get(1)? }),
            )
            .optional()?)
    }

    pub fn set_mfa_pending_state(&self, token_hash: &str, state: Option<&str>) -> Result<()> {
        self.conn().execute("UPDATE mfa_pending SET state = ?2 WHERE token_hash = ?1", params![token_hash, state])?;
        Ok(())
    }

    /// Counts a wrong answer; the check is dropped after too many. Returns
    /// true while another attempt is allowed.
    pub fn fail_mfa_pending(&self, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        conn.execute("UPDATE mfa_pending SET attempts = attempts + 1 WHERE token_hash = ?1", params![token_hash])?;
        let dropped = conn.execute(
            "DELETE FROM mfa_pending WHERE token_hash = ?1 AND attempts >= ?2",
            params![token_hash, MAX_MFA_ATTEMPTS],
        )?;
        Ok(dropped == 0)
    }

    pub fn delete_mfa_pending(&self, token_hash: &str) -> Result<()> {
        self.conn().execute("DELETE FROM mfa_pending WHERE token_hash = ?1", params![token_hash])?;
        Ok(())
    }

    // ---------- reset ----------

    /// Removes every second factor of an account and closes its sessions
    /// (lost device). The account signs in with its password alone, and
    /// enrols again if a second factor is required.
    pub fn reset_mfa(&self, user_id: i64) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        for table in ["mfa_totp", "mfa_passkeys", "mfa_recovery_codes", "mfa_pending", "sessions"] {
            tx.execute(&format!("DELETE FROM {table} WHERE user_id = ?1"), params![user_id])?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(db: &Database, name: &str) -> i64 {
        db.create_account(name, None, "hash", false).unwrap()
    }

    #[test]
    fn the_instance_requirement_confines_and_an_organization_requirement_closes_it() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        let bob = account(&db, "bob");
        assert!(!db.mfa_required(alice).unwrap());

        // An organization requiring it is closed to its members without a factor, and only that
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        let other = db.create_org("other", alice).unwrap();
        db.add_member(org, "bob", "viewer").unwrap();
        db.add_member(other, "bob", "viewer").unwrap();
        let orgs = |user: i64| -> Vec<String> { db.list_orgs(user).unwrap().into_iter().map(|o| o.name).collect() };
        assert_eq!(orgs(bob), ["acme", "other"]);
        db.set_org_requires_mfa(org, true).unwrap();
        assert!(db.org_requires_mfa(org).unwrap());
        assert!(!db.must_enrol_mfa(bob).unwrap() && !db.mfa_required(bob).unwrap());
        assert_eq!(orgs(bob), ["other"]);
        assert!(db.get_org("acme", bob).unwrap().is_none());
        assert!(db.project_role(bob, project).unwrap().is_none());
        assert!(db.list_user_projects(bob).unwrap().is_empty());
        assert_eq!(db.orgs_awaiting_mfa(bob).unwrap(), ["acme"]);

        // With a factor it opens again
        db.begin_totp(bob, "SECRET").unwrap();
        assert_eq!(orgs(bob), ["other"]); // not confirmed yet
        assert!(db.accept_totp_step(bob, 10).unwrap());
        assert_eq!(orgs(bob), ["acme", "other"]);
        assert!(db.project_role(bob, project).unwrap().is_some());
        assert!(db.orgs_awaiting_mfa(bob).unwrap().is_empty());
        db.delete_totp(bob).unwrap();

        // An account without password signs in elsewhere: its provider handles the second step
        db.conn().execute("UPDATE users SET password_hash = NULL WHERE id = ?1", params![bob]).unwrap();
        assert_eq!(orgs(bob), ["acme", "other"]);
        db.conn().execute("UPDATE users SET password_hash = 'hash' WHERE id = ?1", params![bob]).unwrap();

        // Nobody has to stay where they were added; the last owner does
        assert!(db.leave_org("acme", bob).unwrap());
        assert!(!db.leave_org("acme", bob).unwrap());
        assert!(db.orgs_awaiting_mfa(bob).unwrap().is_empty());
        assert!(db.leave_org("other", alice).is_err());
        assert!(!db.leave_org("nope", alice).unwrap());

        // The requirement of the instance confines the whole account until it enrols
        db.set_instance_requires_mfa(true).unwrap();
        assert!(db.must_enrol_mfa(bob).unwrap());
        db.conn().execute("UPDATE users SET password_hash = NULL WHERE id = ?1", params![bob]).unwrap();
        assert!(!db.mfa_required(bob).unwrap());
        db.begin_totp(alice, "SECRET").unwrap();
        assert!(db.must_enrol_mfa(alice).unwrap());
        assert!(db.accept_totp_step(alice, 10).unwrap());
        assert!(db.mfa_required(alice).unwrap() && !db.must_enrol_mfa(alice).unwrap());
    }

    #[test]
    fn codes_and_recovery_codes_are_single_use() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        assert!(db.begin_totp(alice, "ONE").unwrap());
        assert!(db.begin_totp(alice, "TWO").unwrap());
        assert_eq!(db.totp(alice).unwrap(), Some(("TWO".into(), false, 0)));
        assert!(!db.mfa_status(alice).unwrap().enrolled());

        assert!(db.accept_totp_step(alice, 5).unwrap());
        assert!(!db.accept_totp_step(alice, 5).unwrap());
        assert!(!db.accept_totp_step(alice, 4).unwrap());
        // A confirmed secret is not replaced silently
        assert!(!db.begin_totp(alice, "THREE").unwrap());

        db.replace_recovery_codes(alice, &["a".into(), "b".into()]).unwrap();
        assert!(db.use_recovery_code(alice, "a").unwrap());
        assert!(!db.use_recovery_code(alice, "a").unwrap());
        assert!(!db.use_recovery_code(alice, "zzz").unwrap());
        assert_eq!(db.mfa_status(alice).unwrap().recovery_left, 1);

        // Removing the last factor drops the recovery codes
        db.delete_totp(alice).unwrap();
        let status = db.mfa_status(alice).unwrap();
        assert!(!status.enrolled() && status.recovery_left == 0);
    }

    #[test]
    fn pending_checks_expire_after_too_many_attempts() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        db.create_mfa_pending("t1", alice, "login", None, 300).unwrap();
        assert!(db.mfa_pending("t1", "register").unwrap().is_none());
        for _ in 1..MAX_MFA_ATTEMPTS {
            assert!(db.fail_mfa_pending("t1").unwrap());
        }
        assert!(!db.fail_mfa_pending("t1").unwrap());
        assert!(db.mfa_pending("t1", "login").unwrap().is_none());

        // A new login replaces the previous pending one; an expired one is ignored
        db.create_mfa_pending("t2", alice, "login", None, 300).unwrap();
        db.create_mfa_pending("t3", alice, "login", None, -1).unwrap();
        assert!(db.mfa_pending("t2", "login").unwrap().is_none());
        assert!(db.mfa_pending("t3", "login").unwrap().is_none());
    }

    #[test]
    fn the_security_trail_is_append_only_and_outlives_accounts() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        let root = account(&db, "root");
        db.log_security_event(&crate::db::Actor::user(alice, "alice"), Some(alice), "totp_enabled", None).unwrap();
        db.log_security_event(&crate::db::Actor::user(root, "root"), Some(alice), "mfa_reset", None).unwrap();
        db.log_security_event(&crate::db::Actor::system("cli"), None, "mfa_requirement", Some("instance: required")).unwrap();

        let of_alice = db.list_security_events(Some(alice), 10).unwrap();
        assert_eq!(of_alice.iter().map(|e| e.event.as_str()).collect::<Vec<_>>(), ["mfa_reset", "totp_enabled"]);
        assert_eq!((of_alice[0].actor.as_str(), of_alice[0].label()), ("root", "Two-step sign-in reset"));
        assert_eq!(db.list_security_events(None, 10).unwrap().len(), 3);
        assert_eq!(db.list_security_events(None, 1).unwrap()[0].detail.as_deref(), Some("instance: required"));

        assert!(db.conn().execute("UPDATE security_events SET actor = 'nobody'", []).is_err());
        assert!(db.conn().execute("DELETE FROM security_events", []).is_err());
        // The account goes, its trail stays under its name
        db.conn().execute("DELETE FROM users WHERE id = ?1", params![alice]).unwrap();
        assert_eq!(db.list_security_events(None, 10).unwrap().iter().filter(|e| e.username == "alice").count(), 2);
    }

    #[test]
    fn a_passkey_login_challenge_serves_once() {
        let db = Database::open_in_memory().unwrap();
        db.create_passkey_login("a", "state", 300).unwrap();
        db.create_passkey_login("old", "state", -1).unwrap();
        assert_eq!(db.take_passkey_login("a").unwrap().as_deref(), Some("state"));
        assert!(db.take_passkey_login("a").unwrap().is_none());
        assert!(db.take_passkey_login("old").unwrap().is_none());

        db.create_account("root", None, "hash", true).unwrap();
        let alice = account(&db, "alice");
        let handle = db.mfa_handle(alice).unwrap();
        assert_eq!(db.mfa_handle(alice).unwrap(), handle);
        assert_eq!(db.user_by_mfa_handle(&handle).unwrap(), Some(alice));
        db.set_disabled(alice, true).unwrap();
        assert_eq!(db.user_by_mfa_handle(&handle).unwrap(), None);
    }

    #[test]
    fn secrets_are_stored_encrypted_and_old_ones_are_sealed_by_the_migration() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();

        // Written through the application: nothing readable in the tables
        db.begin_totp(alice, "TOTPSEED").unwrap();
        let hook = serde_json::json!({ "url": "https://hooks.example.org/T0KEN" });
        let destination = db.create_destination("project", Some(project), "hook", "webhook", &hook, false).unwrap();
        let source = db
            .create_inventory_source(project, "repo", "", "git", &serde_json::json!({ "token": "GITTOKEN" }), None)
            .unwrap();
        db.set_secret("setting.nvd_api_key", "NVDKEY").unwrap();
        let raw = |sql: &str| -> String { db.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
        for (sql, clear) in [
            ("SELECT secret FROM mfa_totp", "TOTPSEED"),
            ("SELECT config FROM destinations", "T0KEN"),
            ("SELECT config FROM inventory_sources", "GITTOKEN"),
            ("SELECT value FROM metadata WHERE key = 'setting.nvd_api_key'", "NVDKEY"),
        ] {
            let stored = raw(sql);
            assert!(crate::secrets::is_sealed(&stored) && !stored.contains(clear), "{sql}");
        }
        // ... and read back in clear by the application
        assert_eq!(db.totp(alice).unwrap().unwrap().0, "TOTPSEED");
        assert_eq!(db.get_destination(destination).unwrap().unwrap().config, hook);
        assert_eq!(db.get_inventory_source(project, source).unwrap().unwrap().config["token"], "GITTOKEN");
        assert_eq!(db.get_secret("setting.nvd_api_key").unwrap().as_deref(), Some("NVDKEY"));

        // Values written in clear by an earlier version are read, then sealed by the migration
        db.conn().execute("UPDATE mfa_totp SET secret = 'OLDSEED'", []).unwrap();
        db.conn().execute("UPDATE destinations SET config = '{\"url\":\"https://old.example.org/x\"}'", []).unwrap();
        db.conn().execute("UPDATE metadata SET value = 'OLDKEY' WHERE key = 'setting.nvd_api_key'", []).unwrap();
        assert_eq!(db.totp(alice).unwrap().unwrap().0, "OLDSEED");
        db.migrate_seal_secrets().unwrap();
        assert!(crate::secrets::is_sealed(&raw("SELECT secret FROM mfa_totp")));
        assert!(crate::secrets::is_sealed(&raw("SELECT config FROM destinations")));
        assert!(crate::secrets::is_sealed(&raw("SELECT value FROM metadata WHERE key = 'setting.nvd_api_key'")));
        assert_eq!(db.totp(alice).unwrap().unwrap().0, "OLDSEED");
        assert_eq!(db.get_destination(destination).unwrap().unwrap().config["url"], "https://old.example.org/x");
        assert_eq!(db.get_secret("setting.nvd_api_key").unwrap().as_deref(), Some("OLDKEY"));
        // Running it again changes nothing
        let before = raw("SELECT secret FROM mfa_totp");
        db.migrate_seal_secrets().unwrap();
        assert_eq!(raw("SELECT secret FROM mfa_totp"), before);
    }

    #[test]
    fn reset_removes_factors_and_sessions() {
        let db = Database::open_in_memory().unwrap();
        let alice = account(&db, "alice");
        db.begin_totp(alice, "S").unwrap();
        db.accept_totp_step(alice, 1).unwrap();
        assert!(db.add_passkey(alice, "key", "cred", "{}").unwrap());
        assert!(!db.add_passkey(alice, "again", "cred", "{}").unwrap());
        db.create_session(alice, "session", 3600).unwrap();
        db.reset_mfa(alice).unwrap();
        assert!(!db.has_second_factor(alice).unwrap());
        assert!(db.get_session_account("session").unwrap().is_none());
    }
}
