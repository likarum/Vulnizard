//! Instance-wide operations of the administration UI on notifications
//! (schema v11 adds the `ntfy` notification type).

use anyhow::Result;
use rusqlite::params;

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

/// A rule with the project it belongs to
#[derive(Debug, Clone)]
pub struct AdminNotification {
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

    /// Every rule of the instance (administrators only)
    pub fn list_all_notifications(&self) -> Result<Vec<AdminNotification>> {
        Ok(self
            .list_all_rules()?
            .into_iter()
            .map(|(org, project, notification)| AdminNotification { org, project, notification })
            .collect())
    }

    pub fn get_notification(&self, id: i64) -> Result<Option<AdminNotification>> {
        Ok(self.list_all_notifications()?.into_iter().find(|n| n.notification.id == id))
    }

    pub fn admin_toggle_notification(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn()
            .execute("UPDATE notifications SET enabled = 1 - enabled WHERE id = ?1", params![id])?
            > 0)
    }

    pub fn admin_delete_notification(&self, id: i64) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM notifications WHERE id = ?1", params![id])? > 0)
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

        let all = db.list_all_notifications().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].org.as_str(), all[0].project.as_str(), all[0].notification.kind.as_str()), ("acme", "infra", "ntfy"));
        let id = all[0].notification.id;
        assert!(db.admin_toggle_notification(id).unwrap());
        assert!(!db.get_notification(id).unwrap().unwrap().notification.enabled);
        assert!(db.admin_delete_notification(id).unwrap());
        assert!(!db.admin_delete_notification(id).unwrap());
        assert!(db.get_notification(id).unwrap().is_none());
    }
}
