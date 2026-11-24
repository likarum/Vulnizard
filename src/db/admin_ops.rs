//! Instance-wide operations of the administration UI on notifications
//! (schema v11 adds the `ntfy` notification type).

use anyhow::Result;
use crate::db::{Database, Notification};

const NOTIFICATION_SCHEMA: &str = r#"
-- New notification type 'ntfy': the CHECK constraint must be rebuilt
CREATE TABLE notifications_v11 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('webhook', 'slack', 'email', 'ntfy')),
    target TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    min_cvss REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, name)
);
INSERT INTO notifications_v11 (id, project_id, name, kind, target, events, min_cvss, enabled, created_at)
SELECT id, project_id, name, kind, target, events, min_cvss, enabled, created_at FROM notifications;
DROP TABLE notifications;
ALTER TABLE notifications_v11 RENAME TO notifications;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '11');
"#;

/// What notifies a project: one destination covering it
#[derive(Debug, Clone)]
pub struct AdminNotification {
    pub project_id: i64,
    pub org: String,
    pub project: String,
    pub notification: Notification,
}

impl Database {
    pub(super) fn migrate_notifications(&self) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        tx.execute_batch(NOTIFICATION_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// For every project of the instance, each destination that receives its
    /// notifications, its own or not (administrators only)
    pub fn list_all_notifications(&self) -> Result<Vec<AdminNotification>> {
        let mut all = Vec::new();
        for p in self.list_all_projects()? {
            for notification in self.list_notifications(p.id)? {
                all.push(AdminNotification { project_id: p.id, org: p.org.clone(), project: p.name.clone(), notification });
            }
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntfy_notifications_are_accepted_and_listed_for_admins() {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        db.create_notification(project, "phone", "ntfy", "https://ntfy.example.org/vulns", &[], None)
            .unwrap();
        assert!(db.create_notification(project, "bad", "pager", "x", &[], None).is_err());
        // A destination of the instance is listed with every project, one of a project with its own
        db.create_destination("instance", None, "ops", "ntfy", &serde_json::json!({ "url": "https://ntfy.example.org/ops" }), false)
            .unwrap();
        let web = db.create_org_project(org, alice, "web", None).unwrap();

        let all: Vec<(i64, String, String)> = db
            .list_all_notifications()
            .unwrap()
            .into_iter()
            .filter(|n| n.org == "acme")
            .map(|n| (n.project_id, n.notification.name, n.notification.scope))
            .collect();
        assert_eq!(
            all,
            [
                (project, "phone".to_string(), "project".to_string()),
                (project, "ops".to_string(), "instance".to_string()),
                (web, "ops".to_string(), "instance".to_string()),
            ]
        );
    }
}
