//! Notification destinations (schema v13, settings on the destination since v27).
//!
//! A **destination** is where messages go (an email address with its SMTP
//! server, a webhook, a Slack or ntfy URL, the browsers of the members). It
//! belongs to the instance, an organization or a single project, and that
//! alone decides what it receives: a destination of the instance gets the
//! notifications of every project, one of an organization those of its
//! projects, one of a project those of that project. No project picks it.
//! What it sends is set on the destination itself: the event types, a
//! minimum CVSS, and whether it is enabled.
//!
//! Browser notifications use Web Push: subscriptions and the per-user inbox
//! the service worker reads are stored here.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

use crate::changes::EVENT_TYPES;
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
    /// Event types it sends; none = it sends nothing about CVEs and projects
    pub events: Vec<String>,
    pub min_cvss: Option<f64>,
    pub enabled: bool,
}

impl Destination {
    /// What is shown for the destination (never a secret)
    pub fn target(&self) -> String {
        target_of(&self.kind, &self.config)
    }

    /// The destination as the delivery pipeline takes it
    pub fn notification(&self) -> Notification {
        Notification {
            id: self.id,
            name: self.name.clone(),
            kind: self.kind.clone(),
            target: self.target(),
            events: self.events.clone(),
            min_cvss: self.min_cvss,
            enabled: self.enabled,
            scope: self.scope.clone(),
            config: self.config.clone(),
        }
    }
}

/// Every event type: what a new destination sends
pub fn all_events() -> Vec<String> {
    EVENT_TYPES.iter().map(|(kind, _)| kind.to_string()).collect()
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
           d.name, d.kind, d.config, d.system_events, d.events, d.min_cvss, d.enabled
    FROM destinations d";

/// The destinations whose scope holds the project `?1`: its own, those of its
/// organization, those of the instance. The only place deciding what a
/// destination receives.
const COVERS_PROJECT: &str = "(d.scope = 'instance'
    OR (d.scope = 'project' AND d.scope_id = ?1)
    OR (d.scope = 'organization'
        AND d.scope_id = (SELECT organization_id FROM projects WHERE id = ?1)))";

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
        events: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
        min_cvss: r.get(9)?,
        enabled: r.get::<_, i64>(10)? != 0,
    })
}

impl Database {
    pub(super) fn migrate_destinations(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(DESTINATIONS_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// v27: what a destination sends is set on the destination, and its
    /// scope alone decides which projects it receives. Destinations of the
    /// instance and of an organization start sending everything for every
    /// project they cover; a destination of a project keeps what the rule of
    /// its project said ("no event" meant all of them then), and one that no
    /// rule used sends nothing. The rules are gone.
    pub(super) fn migrate_destination_settings(&self) -> Result<()> {
        let all = serde_json::to_string(&all_events())?;
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(
            "ALTER TABLE destinations ADD COLUMN events TEXT NOT NULL DEFAULT '[]';
             ALTER TABLE destinations ADD COLUMN min_cvss REAL;
             ALTER TABLE destinations ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;",
        )?;
        tx.execute("UPDATE destinations SET events = ?1 WHERE scope IN ('instance', 'organization')", params![all])?;
        tx.execute(
            "UPDATE destinations SET
                events = (SELECT CASE WHEN json_valid(n.events) AND json_array_length(n.events) > 0 THEN n.events ELSE ?1 END
                          FROM notifications n WHERE n.destination_id = destinations.id AND n.project_id = destinations.scope_id),
                min_cvss = (SELECT n.min_cvss FROM notifications n
                            WHERE n.destination_id = destinations.id AND n.project_id = destinations.scope_id),
                enabled = (SELECT n.enabled FROM notifications n
                           WHERE n.destination_id = destinations.id AND n.project_id = destinations.scope_id)
             WHERE scope = 'project'
               AND EXISTS (SELECT 1 FROM notifications n
                           WHERE n.destination_id = destinations.id AND n.project_id = destinations.scope_id)",
            params![all],
        )?;
        tx.execute_batch(
            "DROP TABLE notifications;
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '27');",
        )?;
        tx.commit()?;
        Ok(())
    }

    // ---------- destinations ----------

    /// A new destination sends every event type, without a minimum CVSS, and is enabled
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
                "INSERT INTO destinations (scope, scope_id, name, kind, config, system_events, events)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    scope,
                    scope_id,
                    name,
                    kind,
                    self.seal(&config.to_string()),
                    (system_events && scope == "instance") as i32,
                    serde_json::to_string(&all_events())?
                ],
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

    /// What a destination sends: event types (none = nothing), minimum CVSS,
    /// enabled or not, and for a destination of the instance the instance events
    pub fn update_destination_settings(
        &self,
        id: i64,
        events: &[String],
        min_cvss: Option<f64>,
        enabled: bool,
        system_events: Option<bool>,
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE destinations SET events = ?2, min_cvss = ?3, enabled = ?4,
                    system_events = CASE WHEN scope = 'instance' THEN COALESCE(?5, system_events) ELSE 0 END
             WHERE id = ?1",
            params![id, serde_json::to_string(events)?, min_cvss, enabled as i32, system_events.map(|s| s as i32)],
        )?;
        Ok(changed > 0)
    }

    /// The destinations belonging to a project, the only ones it manages
    pub fn list_project_destinations(&self, project_id: i64) -> Result<Vec<Destination>> {
        let mut stmt = self.conn().prepare(&format!(
            "{DESTINATION_SELECT} WHERE d.scope = 'project' AND d.scope_id = ?1 ORDER BY d.name"
        ))?;
        let rows = stmt
            .query_map(params![project_id], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every destination that receives the notifications of a project: its
    /// own, then those of its organization, then those of the instance. Each
    /// destination is there once.
    pub fn destinations_covering(&self, project_id: i64) -> Result<Vec<Destination>> {
        let mut stmt = self.conn().prepare(&format!(
            "{DESTINATION_SELECT} WHERE {COVERS_PROJECT}
             ORDER BY CASE d.scope WHEN 'project' THEN 0 WHEN 'organization' THEN 1 ELSE 2 END, d.name"
        ))?;
        let rows = stmt
            .query_map(params![project_id], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Deletes a destination
    pub fn delete_destination(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM destinations WHERE id = ?1", params![id])? > 0)
    }

    /// Enabled instance destinations that receive instance events (sync finished…)
    pub fn list_system_destinations(&self) -> Result<Vec<Destination>> {
        let mut stmt = self.conn().prepare(&format!(
            "{DESTINATION_SELECT} WHERE d.scope = 'instance' AND d.system_events = 1 AND d.enabled = 1 ORDER BY d.name"
        ))?;
        let rows = stmt
            .query_map([], |r| destination_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---------- what notifies a project ----------

    /// Creates a destination of the project sending the given events
    /// (none = every event, as a new destination does)
    #[cfg(test)]
    pub fn create_notification(
        &self,
        project_id: i64,
        name: &str,
        kind: &str,
        target: &str,
        events: &[String],
        min_cvss: Option<f64>,
    ) -> Result<i64> {
        let config = match kind {
            "email" => serde_json::json!({ "to": target }),
            "browser" => serde_json::json!({}),
            _ => serde_json::json!({ "url": target }),
        };
        let tx = self.conn().unchecked_transaction()?;
        let destination = self.create_destination("project", Some(project_id), name, kind, &config, false)?;
        let events = if events.is_empty() { all_events() } else { events.to_vec() };
        self.update_destination_settings(destination, &events, min_cvss, true, None)?;
        tx.commit()?;
        Ok(destination)
    }

    /// What notifies a project, as the delivery pipeline takes it: one entry
    /// per destination covering it (see `destinations_covering`)
    pub fn list_notifications(&self, project_id: i64) -> Result<Vec<Notification>> {
        Ok(self.destinations_covering(project_id)?.iter().map(Destination::notification).collect())
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
    fn a_destination_receives_by_its_scope_and_holds_what_it_sends() {
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

        // A new destination sends everything: every event, no minimum CVSS, enabled
        for id in [ntfy, team, ops] {
            let d = db.get_destination(id).unwrap().unwrap();
            assert_eq!((d.events, d.min_cvss, d.enabled), (all_events(), None, true));
        }

        // What notifies each project, without anyone picking anything; each destination once
        let ids = |project| -> Vec<i64> { db.list_notifications(project).unwrap().into_iter().map(|n| n.id).collect() };
        assert_eq!(ids(infra), [ntfy, team, ops]);
        assert_eq!(ids(web), [team, ops]);
        assert_eq!(ids(misc), [ops]);
        // What a project manages: its own only
        let own = |project| -> Vec<i64> { db.list_project_destinations(project).unwrap().into_iter().map(|d| d.id).collect() };
        assert_eq!((own(infra), own(web), own(misc)), (vec![ntfy], vec![], vec![]));

        let rules = db.list_notifications(infra).unwrap();
        assert_eq!((rules[0].name.as_str(), rules[0].kind.as_str(), rules[0].target.as_str()), ("phone", "ntfy", "https://ntfy.example.org/infra"));
        assert_eq!((rules[0].scope.as_str(), rules[1].scope.as_str(), rules[2].scope.as_str()), ("project", "organization", "instance"));
        // The displayed target never contains the SMTP secret
        assert_eq!(rules[2].target, "ops@example.org (via smtp.example.org)");

        // Its settings are its own; instance events only for a destination of the instance
        assert!(db.update_destination_settings(ntfy, &["kev".into()], Some(7.0), false, Some(true)).unwrap());
        let d = db.get_destination(ntfy).unwrap().unwrap();
        assert_eq!((d.events, d.min_cvss, d.enabled, d.system_events), (vec!["kev".to_string()], Some(7.0), false, false));
        assert_eq!(db.list_system_destinations().unwrap().len(), 1);
        // Left alone when the form does not hold them, and a disabled destination gets no instance event either
        db.update_destination_settings(ops, &[], None, true, None).unwrap();
        assert_eq!(db.list_system_destinations().unwrap().len(), 1);
        db.update_destination_settings(ops, &[], None, false, None).unwrap();
        assert!(db.list_system_destinations().unwrap().is_empty());
        assert!(!db.update_destination_settings(9999, &[], None, true, None).unwrap());

        // Deleting a destination stops it; deleting a project or an organization removes its destinations
        assert!(db.delete_destination(ops).unwrap());
        assert!(db.list_notifications(misc).unwrap().is_empty());
        db.delete_project_by_id(infra, &crate::db::Actor::system("test")).unwrap();
        assert!(db.get_destination(ntfy).unwrap().is_none());
        db.delete_org(org).unwrap();
        assert!(db.get_destination(team).unwrap().is_none());
    }

    /// A database as version 26 left it: the settings on the rules, in `notifications`
    fn back_to_v26(db: &Database) {
        db.conn()
            .execute_batch(
                "ALTER TABLE destinations DROP COLUMN events;
                 ALTER TABLE destinations DROP COLUMN min_cvss;
                 ALTER TABLE destinations DROP COLUMN enabled;
                 CREATE TABLE notifications (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                     destination_id INTEGER NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
                     events TEXT NOT NULL DEFAULT '[]',
                     min_cvss REAL,
                     enabled INTEGER NOT NULL DEFAULT 1,
                     created_at TEXT NOT NULL DEFAULT (datetime('now')),
                     UNIQUE (project_id, destination_id)
                 );
                 INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '26');",
            )
            .unwrap();
    }

    #[test]
    fn version_26_rules_become_the_settings_of_the_destinations() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v26.db");
        let (ops, team, phone, everything, unused);
        {
            let db = Database::open(&path).unwrap();
            let alice = db.create_account("alice", None, "h", false).unwrap();
            let org = db.create_org("acme", alice).unwrap();
            let infra = db.create_org_project(org, alice, "infra", None).unwrap();
            let web = db.create_org_project(org, alice, "web", None).unwrap();
            let hook = json!({ "url": "https://example.org/h" });
            ops = db.create_destination("instance", None, "ops", "webhook", &hook, true).unwrap();
            team = db.create_destination("organization", Some(org), "team", "webhook", &hook, false).unwrap();
            phone = db.create_destination("project", Some(infra), "phone", "webhook", &hook, false).unwrap();
            everything = db.create_destination("project", Some(infra), "everything", "webhook", &hook, false).unwrap();
            unused = db.create_destination("project", Some(web), "unused", "webhook", &hook, false).unwrap();
            back_to_v26(&db);
            let rule = |project: i64, destination: i64, events: &str, min_cvss: Option<f64>, enabled: bool| {
                db.conn()
                    .execute(
                        "INSERT INTO notifications (project_id, destination_id, events, min_cvss, enabled) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![project, destination, events, min_cvss, enabled],
                    )
                    .unwrap();
            };
            // One project had picked the instance destination, narrowly and disabled; nobody the organization one
            rule(web, ops, r#"["kev"]"#, Some(9.0), false);
            rule(infra, phone, r#"["created","kev"]"#, Some(7.0), false);
            // No event meant every event
            rule(infra, everything, "[]", None, true);
        }

        // Opening it upgrades it
        let db = Database::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 27);
        let settings = |id: i64| {
            let d = db.get_destination(id).unwrap().unwrap();
            (d.events, d.min_cvss, d.enabled)
        };
        // Instance and organization: everything, for every project they cover, whatever a rule said
        assert_eq!(settings(ops), (all_events(), None, true));
        assert_eq!(settings(team), (all_events(), None, true));
        assert!(db.get_destination(ops).unwrap().unwrap().system_events);
        // A destination of a project keeps exactly what its rule said
        assert_eq!(settings(phone), (vec!["created".to_string(), "kev".to_string()], Some(7.0), false));
        assert_eq!(settings(everything), (all_events(), None, true));
        // One that no rule used sent nothing, and still sends nothing
        assert_eq!(settings(unused), (vec![], None, true));
        // The rules are gone
        let rules: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'notifications'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rules, 0);
        // And opening it again changes nothing
        drop(db);
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get_destination(phone).unwrap().unwrap().events, ["created", "kev"]);
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
