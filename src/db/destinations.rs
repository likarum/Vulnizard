//! Notification destinations and rules (schema v13).
//!
//! A **destination** is where messages go (an email address with its SMTP
//! server, a webhook, a Slack or ntfy URL, the browsers of the members). It
//! belongs to the instance, an organization or a single project, so each
//! project can have its own. A **rule** (`notifications` table) connects a
//! project to a destination, with the events and the minimum CVSS it wants.
//!
//! Browser notifications use Web Push: subscriptions and the per-user inbox
//! the service worker reads are stored here.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

use crate::db::{Database, Notification};

const DESTINATIONS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS destinations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL CHECK(scope IN ('instance', 'organization', 'project')),
    -- organization or project id (NULL for the instance)
    scope_id INTEGER,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('webhook', 'slack', 'email', 'ntfy', 'browser')),
    config TEXT NOT NULL DEFAULT '{}',
    -- instance destinations may also receive instance events (sync finished)
    system_events INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_destinations_scope ON destinations(scope, scope_id);

-- Each existing notification becomes a destination of its project (same id) and a rule
INSERT INTO destinations (id, scope, scope_id, name, kind, config)
SELECT id, 'project', project_id, name, kind,
       json_object(CASE kind WHEN 'email' THEN 'to' ELSE 'url' END, target)
FROM notifications;

CREATE TABLE notifications_v13 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    destination_id INTEGER NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
    events TEXT NOT NULL DEFAULT '[]',
    min_cvss REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, destination_id)
);
INSERT INTO notifications_v13 (id, project_id, destination_id, events, min_cvss, enabled, created_at)
SELECT id, project_id, id, events, min_cvss, enabled, created_at FROM notifications;
DROP TABLE notifications;
ALTER TABLE notifications_v13 RENAME TO notifications;

-- A destination disappears with the project or organization it belongs to
CREATE TRIGGER IF NOT EXISTS destinations_project_deleted AFTER DELETE ON projects BEGIN
    DELETE FROM destinations WHERE scope = 'project' AND scope_id = OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS destinations_organization_deleted AFTER DELETE ON organizations BEGIN
    DELETE FROM destinations WHERE scope = 'organization' AND scope_id = OLD.id;
END;

-- Web Push: browsers that asked for notifications, and what each user has to read
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS push_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_push_inbox_user ON push_inbox(user_id, id);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '13');
"#;

pub const DESTINATION_KINDS: [(&str, &str); 5] = [
    ("email", "Email"),
    ("ntfy", "ntfy topic"),
    ("slack", "Slack incoming webhook"),
    ("webhook", "Webhook (JSON POST)"),
    ("browser", "Browser notifications of the members"),
];

#[derive(Debug, Clone)]
pub struct Destination {
    pub id: i64,
    /// instance | organization | project
    pub scope: String,
    pub scope_id: Option<i64>,
    /// "acme" or "acme / infra" (empty for the instance)
    pub scope_label: String,
    pub name: String,
    pub kind: String,
    /// Kind-specific settings; may hold an SMTP password: never rendered
    pub config: Value,
    pub system_events: bool,
    /// Number of project rules using it
    pub rules: i64,
}

impl Destination {
    /// What is shown for the destination (never a secret)
    pub fn target(&self) -> String {
        target_of(&self.kind, &self.config)
    }
}

pub fn target_of(kind: &str, config: &Value) -> String {
    match kind {
        "email" => {
            let to = config.get("to").and_then(Value::as_str).unwrap_or("");
            match config.get("smtp").and_then(|s| s.get("host")).and_then(Value::as_str) {
                Some(host) => format!("{to} (via {host})"),
                None => to.to_string(),
            }
        }
        "browser" => "browsers of the members".to_string(),
        _ => config.get("url").and_then(Value::as_str).unwrap_or("").to_string(),
    }
}

/// A message waiting in a user's browser inbox
#[derive(Debug, Clone, serde::Serialize)]
pub struct PushItem {
    pub title: String,
    pub body: String,
    pub url: String,
}

const DESTINATION_SELECT: &str = "
    SELECT d.id, d.scope, d.scope_id,
           CASE d.scope
             WHEN 'organization' THEN COALESCE((SELECT name FROM organizations WHERE id = d.scope_id), '?')
             WHEN 'project' THEN COALESCE((SELECT o.name || ' / ' || p.name FROM projects p
                                           LEFT JOIN organizations o ON o.id = p.organization_id
                                           WHERE p.id = d.scope_id), '?')
             ELSE '' END,
           d.name, d.kind, d.config, d.system_events,
           (SELECT COUNT(*) FROM notifications n WHERE n.destination_id = d.id)
    FROM destinations d";

/// Settings of a destination as stored (encrypted: they hold URLs that are
/// secrets, and SMTP passwords). Unreadable settings leave the destination
/// unusable rather than failing the whole listing.
fn stored_config(db: &Database, stored: &str) -> Value {
    match db.unseal(stored) {
        Ok(json) => serde_json::from_str(&json).unwrap_or(Value::Null),
        Err(e) => {
            tracing::error!("a notification destination cannot be read: {e}");
            Value::Null
        }
    }
}

fn destination_row(db: &Database, r: &rusqlite::Row) -> rusqlite::Result<Destination> {
    Ok(Destination {
        id: r.get(0)?,
        scope: r.get(1)?,
        scope_id: r.get(2)?,
        scope_label: r.get(3)?,
        name: r.get(4)?,
        kind: r.get(5)?,
        config: stored_config(db, &r.get::<_, String>(6)?),
        system_events: r.get::<_, i64>(7)? != 0,
        rules: r.get(8)?,
    })
}

fn notification_row(db: &Database, r: &rusqlite::Row) -> rusqlite::Result<Notification> {
    let kind: String = r.get(2)?;
    let config: Value = stored_config(db, &r.get::<_, String>(3)?);
    Ok(Notification {
        id: r.get(0)?,
        name: r.get(1)?,
        target: target_of(&kind, &config),
        kind,
        events: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        min_cvss: r.get(5)?,
        enabled: r.get::<_, i64>(6)? != 0,
        destination_id: r.get(7)?,
        config,
    })
}

const NOTIFICATION_SELECT: &str = "
    SELECT n.id, d.name, d.kind, d.config, n.events, n.min_cvss, n.enabled, d.id
    FROM notifications n JOIN destinations d ON d.id = n.destination_id";

impl Database {
    pub(super) fn migrate_destinations(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(DESTINATIONS_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    // ---------- destinations ----------

    pub fn create_destination(
        &self,
        scope: &str,
        scope_id: Option<i64>,
        name: &str,
        kind: &str,
        config: &Value,
        system_events: bool,
    ) -> Result<i64> {
        let taken: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM destinations WHERE scope = ?1 AND scope_id IS ?2 AND name = ?3)",
            params![scope, scope_id, name],
            |r| r.get(0),
        )?;
        if taken {
            return Err(anyhow!("A destination with this name already exists here"));
        }
        self.conn()
            .execute(
                "INSERT INTO destinations (scope, scope_id, name, kind, config, system_events)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![scope, scope_id, name, kind, self.seal(&config.to_string()), (system_events && scope == "instance") as i32],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    anyhow!("Invalid destination type")
                }
                e => e.into(),
            })?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn get_destination(&self, id: i64) -> Result<Option<Destination>> {
        Ok(self
            .conn()
            .query_row(&format!("{DESTINATION_SELECT} WHERE d.id = ?1"), params![id], |r| destination_row(self, r))
            .optional()?)
    }

    /// Every destination of the instance (administrators)
    pub fn list_all_destinations(&self) -> Result<Vec<Destination>> {
        let mut stmt = self
            .conn()
            .prepare(&format!("{DESTINATION_SELECT} ORDER BY d.scope, 4, d.name"))?;
        let rows = stmt
            .query_map([], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Destinations a project may use: its own, those of its organization
    /// and those of the instance.
    pub fn list_project_destinations(&self, project_id: i64) -> Result<Vec<Destination>> {
        let mut stmt = self.conn().prepare(&format!(
            "{DESTINATION_SELECT}
             WHERE d.scope = 'instance'
                OR (d.scope = 'project' AND d.scope_id = ?1)
                OR (d.scope = 'organization'
                    AND d.scope_id = (SELECT organization_id FROM projects WHERE id = ?1))
             ORDER BY CASE d.scope WHEN 'project' THEN 0 WHEN 'organization' THEN 1 ELSE 2 END, d.name"
        ))?;
        let rows = stmt
            .query_map(params![project_id], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Deletes a destination and the rules using it
    pub fn delete_destination(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM destinations WHERE id = ?1", params![id])? > 0)
    }

    /// Instance destinations that receive instance events (sync finished…)
    pub fn list_system_destinations(&self) -> Result<Vec<Destination>> {
        let mut stmt = self.conn().prepare(&format!(
            "{DESTINATION_SELECT} WHERE d.scope = 'instance' AND d.system_events = 1 ORDER BY d.name"
        ))?;
        let rows = stmt
            .query_map([], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---------- rules ----------

    /// Connects a project to a destination it may use
    pub fn create_rule(&self, project_id: i64, destination_id: i64, events: &[String], min_cvss: Option<f64>) -> Result<i64> {
        let usable = self
            .list_project_destinations(project_id)?
            .iter()
            .any(|d| d.id == destination_id);
        if !usable {
            return Err(anyhow!("This destination is not available to the project"));
        }
        self.conn()
            .execute(
                "INSERT INTO notifications (project_id, destination_id, events, min_cvss) VALUES (?1, ?2, ?3, ?4)",
                params![project_id, destination_id, serde_json::to_string(events)?, min_cvss],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    anyhow!("The project already notifies this destination")
                }
                e => e.into(),
            })?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Creates a destination of the project and its rule in one step
    #[cfg(test)]
    pub fn create_notification(
        &self,
        project_id: i64,
        name: &str,
        kind: &str,
        target: &str,
        events: &[String],
        min_cvss: Option<f64>,
    ) -> Result<()> {
        let config = match kind {
            "email" => serde_json::json!({ "to": target }),
            "browser" => serde_json::json!({}),
            _ => serde_json::json!({ "url": target }),
        };
        let tx = self.conn().unchecked_transaction()?;
        let destination = self.create_destination("project", Some(project_id), name, kind, &config, false)?;
        self.create_rule(project_id, destination, events, min_cvss)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_notifications(&self, project_id: i64) -> Result<Vec<Notification>> {
        let mut stmt = self
            .conn()
            .prepare(&format!("{NOTIFICATION_SELECT} WHERE n.project_id = ?1 ORDER BY d.name"))?;
        let rows = stmt
            .query_map(params![project_id], |r| notification_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every rule of the instance: (organization, project, rule)
    pub fn list_all_rules(&self) -> Result<Vec<(String, String, Notification)>> {
        let mut stmt = self.conn().prepare(
            "SELECT n.id, d.name, d.kind, d.config, n.events, n.min_cvss, n.enabled, d.id,
                    COALESCE(o.name, ''), p.name
             FROM notifications n
             JOIN destinations d ON d.id = n.destination_id
             JOIN projects p ON p.id = n.project_id
             LEFT JOIN organizations o ON o.id = p.organization_id
             ORDER BY o.name, p.name, d.name",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(8)?, r.get(9)?, notification_row(self, r)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---------- Web Push ----------

    pub fn add_push_subscription(&self, user_id: i64, endpoint: &str, label: Option<&str>) -> Result<()> {
        // A browser belongs to the last user who subscribed with it
        self.conn().execute(
            "INSERT INTO push_subscriptions (user_id, endpoint, label) VALUES (?1, ?2, ?3)
             ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, label = excluded.label",
            params![user_id, endpoint, label],
        )?;
        Ok(())
    }

    pub fn remove_push_subscription(&self, user_id: i64, endpoint: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM push_subscriptions WHERE user_id = ?1 AND endpoint = ?2",
            params![user_id, endpoint],
        )?;
        Ok(())
    }

    /// Removes a subscription the push service reported as gone
    pub fn forget_push_endpoint(&self, endpoint: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM push_subscriptions WHERE endpoint = ?1", params![endpoint])?;
        Ok(())
    }

    /// (endpoint, label) of the browsers of a user
    pub fn list_push_subscriptions(&self, user_id: i64) -> Result<Vec<(String, Option<String>)>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT endpoint, label FROM push_subscriptions WHERE user_id = ?1 ORDER BY id")?;
        let rows = stmt
            .query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Enabled users who can read the project
    pub fn users_with_project_access(&self, project_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn().prepare(
            "SELECT pa.user_id FROM project_access pa JOIN users u ON u.id = pa.user_id
             WHERE pa.project_id = ?1 AND u.disabled = 0",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<i64>, _>>()?;
        Ok(rows)
    }

    /// Queues a message for the browsers of a user (at most 50 kept)
    pub fn push_enqueue(&self, user_id: i64, title: &str, body: &str, url: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO push_inbox (user_id, title, body, url) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, title, body, url],
        )?;
        self.conn().execute(
            "DELETE FROM push_inbox WHERE user_id = ?1 AND id NOT IN
                (SELECT id FROM push_inbox WHERE user_id = ?1 ORDER BY id DESC LIMIT 50)",
            params![user_id],
        )?;
        Ok(())
    }

    /// Returns the messages waiting for the user and removes them
    pub fn push_take(&self, user_id: i64) -> Result<Vec<PushItem>> {
        let tx = self.conn().unchecked_transaction()?;
        let items = {
            let mut stmt =
                tx.prepare("SELECT title, body, url FROM push_inbox WHERE user_id = ?1 ORDER BY id LIMIT 20")?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    Ok(PushItem {
                        title: r.get(0)?,
                        body: r.get(1)?,
                        url: r.get(2)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        tx.execute("DELETE FROM push_inbox WHERE user_id = ?1", params![user_id])?;
        tx.commit()?;
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn destinations_are_scoped_and_rules_connect_projects_to_them() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let infra = db.create_org_project(org, alice, "infra", None).unwrap();
        let web = db.create_org_project(org, alice, "web", None).unwrap();
        let other = db.create_org("other", alice).unwrap();
        let misc = db.create_org_project(other, alice, "misc", None).unwrap();

        let ntfy = db
            .create_destination("project", Some(infra), "phone", "ntfy", &json!({ "url": "https://ntfy.example.org/infra" }), false)
            .unwrap();
        let team = db
            .create_destination("organization", Some(org), "team", "slack", &json!({ "url": "https://hooks.example.org/x" }), false)
            .unwrap();
        let ops = db
            .create_destination("instance", None, "ops", "email", &json!({ "to": "ops@example.org", "smtp": { "host": "smtp.example.org", "password": "secret" } }), true)
            .unwrap();
        assert!(db.create_destination("project", Some(infra), "phone", "ntfy", &json!({}), false).is_err());
        assert!(db.create_destination("project", Some(infra), "x", "pager", &json!({}), false).is_err());

        // What each project may use
        let ids = |project| -> Vec<i64> { db.list_project_destinations(project).unwrap().into_iter().map(|d| d.id).collect() };
        assert_eq!(ids(infra), [ntfy, team, ops]);
        assert_eq!(ids(web), [team, ops]);
        assert_eq!(ids(misc), [ops]);

        // A rule only on a usable destination, once
        db.create_rule(infra, ntfy, &["kev".into()], Some(7.0)).unwrap();
        assert!(db.create_rule(infra, ntfy, &[], None).is_err());
        assert!(db.create_rule(web, ntfy, &[], None).is_err());
        assert!(db.create_rule(misc, team, &[], None).is_err());
        db.create_rule(misc, ops, &[], None).unwrap();

        let rules = db.list_notifications(infra).unwrap();
        assert_eq!((rules[0].name.as_str(), rules[0].kind.as_str(), rules[0].target.as_str()), ("phone", "ntfy", "https://ntfy.example.org/infra"));
        // The displayed target never contains the SMTP secret
        let ops_rule = &db.list_notifications(misc).unwrap()[0];
        assert_eq!(ops_rule.target, "ops@example.org (via smtp.example.org)");
        assert_eq!(db.list_all_rules().unwrap().len(), 2);
        assert_eq!(db.list_system_destinations().unwrap().len(), 1);
        assert_eq!(db.get_destination(ntfy).unwrap().unwrap().rules, 1);

        // Deleting a destination removes its rules; deleting a project removes its destinations
        assert!(db.delete_destination(ops).unwrap());
        assert!(db.list_notifications(misc).unwrap().is_empty());
        db.delete_project_by_id(infra, &crate::db::Actor::system("test")).unwrap();
        assert!(db.get_destination(ntfy).unwrap().is_none());
        db.delete_org(org).unwrap();
        assert!(db.get_destination(team).unwrap().is_none());
    }

    #[test]
    fn push_inbox_is_per_user_and_read_once() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let bob = db.create_account("bob", None, "h", false).unwrap();
        db.add_push_subscription(alice, "https://push.example.org/a", Some("laptop")).unwrap();
        db.add_push_subscription(bob, "https://push.example.org/a", None).unwrap(); // same browser, new user
        assert!(db.list_push_subscriptions(alice).unwrap().is_empty());
        assert_eq!(db.list_push_subscriptions(bob).unwrap().len(), 1);

        db.push_enqueue(bob, "Sync finished", "nvd: 3 added", "/admin/sources").unwrap();
        assert!(db.push_take(alice).unwrap().is_empty());
        assert_eq!(db.push_take(bob).unwrap()[0].title, "Sync finished");
        assert!(db.push_take(bob).unwrap().is_empty());
        for i in 0..60 {
            db.push_enqueue(bob, &format!("m{i}"), "", "/").unwrap();
        }
        let kept: i64 = db.conn().query_row("SELECT COUNT(*) FROM push_inbox", [], |r| r.get(0)).unwrap();
        assert_eq!(kept, 50);
        db.forget_push_endpoint("https://push.example.org/a").unwrap();
        assert!(db.list_push_subscriptions(bob).unwrap().is_empty());
    }
}
