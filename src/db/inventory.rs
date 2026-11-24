//! Inventory of what is deployed (schema v15).
//!
//! An **inventory source** of a project receives the list of components
//! found on an infrastructure, pushed with a token or read from a file in a
//! Git repository. Each delivery replaces the previous list of that source.
//! Components are *candidates*: the user ticks those to monitor (or the
//! source monitors everything), which become tracked applications kept in
//! step with the source (version changes, removals).
//!
//! A source belongs to a **group** — a tag shared by the sources that are
//! triaged together, such as ten identical web servers. A component in a
//! given version is one application per group, whatever the number of
//! sources reporting it: its CVEs are decided once for the group, and it
//! stops being tracked when the last source stops reporting it.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::{Actor, Database};
use crate::models::Application;

const INVENTORY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS inventory_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('push', 'git')),
    -- git: {provider, repository, branch, path, token}
    config TEXT NOT NULL DEFAULT '{}',
    -- push: hash of the token the collector sends
    token_hash TEXT UNIQUE,
    last_run_at TEXT,
    last_status TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS inventory_components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES inventory_sources(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    vendor TEXT,
    ecosystem TEXT,
    -- listens on the network, as reported by the collector
    exposed INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'new' CHECK(state IN ('new', 'monitored', 'ignored')),
    application_id INTEGER,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (source_id, name)
);
CREATE INDEX IF NOT EXISTS idx_components_state ON inventory_components(state);

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '15');
"#;

/// A component reported by a collector: only what is needed to match CVEs
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// Listens on the network
    #[serde(default)]
    pub exposed: bool,
}

#[derive(Debug, Clone)]
pub struct InventorySource {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub kind: String,
    /// Tag shared by the sources triaged together (its own name by default)
    pub group: String,
    /// Every reported component is monitored without being ticked
    pub auto_monitor: bool,
    /// Settings of a Git source; holds its access token: never rendered
    pub config: serde_json::Value,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub components: i64,
}

/// A discovered component with what makes it worth monitoring
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub id: i64,
    pub source: String,
    pub group: String,
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub exposed: bool,
    /// new | monitored | ignored
    pub state: String,
    /// Known CVEs for a product of this name in the database
    pub known_cves: i64,
    /// Name of a well-known network service (ssh, nginx…)
    pub known_service: bool,
    pub first_seen: String,
}

impl Candidate {
    /// Likely to matter: it listens on the network or is a well-known service
    pub fn probable_service(&self) -> bool {
        self.exposed || self.known_service
    }

    /// Sort key: exposed first, then well-known services, then by CVE history
    pub fn likelihood(&self) -> i64 {
        (self.exposed as i64) * 1_000_000 + (self.known_service as i64) * 100_000 + self.known_cves.min(99_999)
    }
}

/// Software that usually listens on the network. Matched on the component
/// name; used to rank candidates and to announce a new probable service.
const KNOWN_SERVICES: &[&str] = &[
    "openssh", "sshd", "ssh", "nginx", "apache", "httpd", "http_server", "traefik", "haproxy", "caddy", "envoy",
    "postgresql", "postgres", "mysql", "mariadb", "mongodb", "redis", "valkey", "memcached", "elasticsearch",
    "opensearch", "rabbitmq", "mosquitto", "kafka", "nats", "etcd", "consul", "vault", "bind", "unbound", "dnsmasq",
    "dnsserver", "adguardhome", "pihole", "postfix", "exim", "dovecot", "samba", "vsftpd", "proftpd", "openvpn",
    "wireguard", "strongswan", "squid", "jenkins", "gitlab", "gitea", "forgejo", "grafana", "prometheus", "kibana",
    "keycloak", "vaultwarden", "nextcloud", "home_assistant", "home-assistant", "jellyfin", "plex", "docker", "moby",
    "podman", "kubernetes", "k3s", "minio", "cloudflared", "tomcat", "jetty", "wildfly", "iis", "exchange",
];

pub fn is_known_service(name: &str) -> bool {
    let name = name.to_lowercase();
    KNOWN_SERVICES.iter().any(|service| name == *service || name.replace('-', "_") == service.replace('-', "_"))
}

/// What an ingestion changed
#[derive(Debug, Default, Serialize)]
pub struct IngestOutcome {
    pub received: usize,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    /// Newly seen components that look like network services
    pub new_probable_services: Vec<String>,
}

const MAX_COMPONENTS: usize = 5000;

fn clean(value: &Option<String>, max: usize) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.chars().count() <= max && !v.chars().any(char::is_control))
        .map(String::from)
}

impl Database {
    pub(super) fn migrate_inventory(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(INVENTORY_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    // ---------- sources ----------

    /// Creates a source. `group` is the tag it shares with the sources triaged
    /// with it; empty means the source is its own group.
    pub fn create_inventory_source(
        &self,
        project_id: i64,
        name: &str,
        group: &str,
        kind: &str,
        config: &serde_json::Value,
        token_hash: Option<&str>,
    ) -> Result<i64> {
        let group = if group.is_empty() { name } else { group };
        self.conn()
            .execute(
                "INSERT INTO inventory_sources (project_id, name, grp, kind, config, token_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![project_id, name, group, kind, self.seal(&config.to_string()), token_hash],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    anyhow!("A source with this name already exists in the project")
                }
                e => e.into(),
            })?;
        Ok(self.conn().last_insert_rowid())
    }

    fn sources_where(&self, filter: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<InventorySource>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT s.id, s.project_id, s.name, s.kind, s.config, s.last_run_at, s.last_status, s.last_error,
                    (SELECT COUNT(*) FROM inventory_components c WHERE c.source_id = s.id), s.grp
             FROM inventory_sources s WHERE {filter} ORDER BY s.grp, s.name"
        ))?;
        let rows = stmt
            .query_map(args, |r| {
                // Stored encrypted: a Git source keeps its token there
                let config: serde_json::Value = self
                    .unseal(&r.get::<_, String>(4)?)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                    .unwrap_or(serde_json::Value::Null);
                Ok(InventorySource {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    name: r.get(2)?,
                    kind: r.get(3)?,
                    group: r.get(9)?,
                    auto_monitor: config.get("auto_monitor").and_then(serde_json::Value::as_bool).unwrap_or(false),
                    config,
                    last_run_at: r.get(5)?,
                    last_status: r.get(6)?,
                    last_error: r.get(7)?,
                    components: r.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_inventory_sources(&self, project_id: i64) -> Result<Vec<InventorySource>> {
        self.sources_where("s.project_id = ?1", &[&project_id])
    }

    /// Git sources of every project (pulled by the scheduler)
    pub fn list_git_sources(&self) -> Result<Vec<InventorySource>> {
        self.sources_where("s.kind = 'git'", &[])
    }

    pub fn get_inventory_source(&self, project_id: i64, id: i64) -> Result<Option<InventorySource>> {
        Ok(self.sources_where("s.project_id = ?1 AND s.id = ?2", &[&project_id, &id])?.pop())
    }

    /// Source a push token belongs to
    pub fn inventory_source_by_token(&self, token_hash: &str) -> Result<Option<InventorySource>> {
        Ok(self.sources_where("s.token_hash = ?1 AND s.kind = 'push'", &[&token_hash])?.pop())
    }

    /// Deletes a source. What only this source reported stops being tracked
    /// (the history of its CVEs is kept); what other sources of the group
    /// still report stays.
    pub fn delete_inventory_source(&self, project_id: i64, id: i64, actor: &Actor) -> Result<bool> {
        let apps: Vec<i64> = {
            let mut stmt = self.conn().prepare(
                "SELECT DISTINCT c.application_id FROM inventory_components c
                 JOIN inventory_sources s ON s.id = c.source_id
                 WHERE s.id = ?1 AND s.project_id = ?2 AND c.application_id IS NOT NULL",
            )?;
            let rows = stmt.query_map(params![id, project_id], |r| r.get(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let deleted = self.conn().execute(
            "DELETE FROM inventory_sources WHERE id = ?1 AND project_id = ?2",
            params![id, project_id],
        )? > 0;
        if deleted {
            for app_id in apps {
                self.release_application(project_id, app_id, actor)?;
            }
        }
        Ok(deleted)
    }

    pub fn record_inventory_run(&self, source_id: i64, error: Option<&str>) -> Result<()> {
        self.conn().execute(
            "UPDATE inventory_sources SET last_run_at = datetime('now'), last_status = ?1, last_error = ?2 WHERE id = ?3",
            params![if error.is_some() { "failed" } else { "ok" }, error, source_id],
        )?;
        Ok(())
    }

    // ---------- components and the applications of their group ----------

    /// Stops tracking an application no source reports any more
    fn release_application(&self, project_id: i64, app_id: i64, actor: &Actor) -> Result<()> {
        let still_reported: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM inventory_components WHERE application_id = ?1)",
            params![app_id],
            |r| r.get(0),
        )?;
        if !still_reported {
            self.delete_application_by_id(project_id, app_id, actor)?;
        }
        Ok(())
    }

    /// Application of the source's group for this component and version,
    /// created and scanned if the group does not track it yet
    fn group_application(
        &self,
        source: &InventorySource,
        name: &str,
        version: Option<&str>,
        vendor: Option<&str>,
        ecosystem: Option<&str>,
    ) -> Result<(i64, bool)> {
        if let Some(app) = self.get_group_application(source.project_id, &source.group, name, version)? {
            return Ok((app.id.unwrap_or_default(), false));
        }
        let mut app = Application::new(source.project_id, name.to_string());
        app.version = version.map(String::from);
        app.vendor = vendor.map(String::from);
        app.ecosystem = ecosystem.map(String::from);
        app.group = source.group.clone();
        let id = self.create_application(&app)?;
        app.id = Some(id);
        match self.scan_app_for_cves(&app) {
            // Monitored, but nothing is listed until the name is made precise
            Err(e) if crate::db::watchlist::is_refusal(&e) => tracing::warn!("component '{name}' of '{}': {e}", source.name),
            other => {
                other?;
            }
        }
        Ok((id, true))
    }

    /// Starts monitoring a component
    fn attach_component(
        &self,
        source: &InventorySource,
        component_id: i64,
        name: &str,
        version: Option<&str>,
        vendor: Option<&str>,
        ecosystem: Option<&str>,
    ) -> Result<()> {
        let (app_id, _) = self.group_application(source, name, version, vendor, ecosystem)?;
        self.conn().execute(
            "UPDATE inventory_components SET state = 'monitored', application_id = ?1 WHERE id = ?2",
            params![app_id, component_id],
        )?;
        Ok(())
    }

    /// A monitored component changed version on this source. If the source
    /// was the only one with the old version, the application follows (which
    /// closes the CVEs the new version fixes). Otherwise the group now runs
    /// two versions: the source joins the application of the new one, and
    /// the decisions taken on CVEs that still apply are carried over.
    #[allow(clippy::too_many_arguments)]
    fn move_component(
        &self,
        source: &InventorySource,
        component_id: i64,
        old_app_id: i64,
        name: &str,
        version: Option<&str>,
        vendor: Option<&str>,
        ecosystem: Option<&str>,
        actor: &Actor,
    ) -> Result<()> {
        let alone: bool = self.conn().query_row(
            "SELECT COUNT(*) = 1 FROM inventory_components WHERE application_id = ?1",
            params![old_app_id],
            |r| r.get(0),
        )?;
        let target = self.get_group_application(source.project_id, &source.group, name, version)?;
        if let (true, None, Some(new_version)) = (alone, &target, version) {
            self.update_application_version(old_app_id, new_version)?;
            self.conn().execute(
                "UPDATE applications SET ecosystem = COALESCE(?1, ecosystem) WHERE id = ?2",
                params![ecosystem, old_app_id],
            )?;
            if let Some(app) = self.get_application(old_app_id)? {
                match self.rescan_after_upgrade(&app, actor) {
                    // Followed at its new version, with nothing listed until the name is made precise
                    Err(e) if crate::db::watchlist::is_refusal(&e) => tracing::warn!("component '{name}' of '{}': {e}", source.name),
                    other => {
                        other?;
                    }
                }
            }
            return Ok(());
        }
        let (new_app_id, created) = self.group_application(source, name, version, vendor, ecosystem)?;
        if created {
            self.carry_decisions(old_app_id, new_app_id, actor)?;
        }
        self.conn().execute(
            "UPDATE inventory_components SET application_id = ?1 WHERE id = ?2",
            params![new_app_id, component_id],
        )?;
        self.release_application(source.project_id, old_app_id, actor)
    }

    /// Accepted risks and "not applicable" decisions of an application, for
    /// the CVEs another version of it still has
    fn carry_decisions(&self, from_app: i64, to_app: i64, actor: &Actor) -> Result<()> {
        let decisions: Vec<(i64, String, Option<String>, Option<String>)> = {
            let mut stmt = self.conn().prepare(
                "SELECT new.id, old.status, old.notes, a.version
                 FROM watchlist_entries old
                 JOIN watchlist_entries new ON new.cve_id = old.cve_id AND new.app_id = ?2
                 JOIN applications a ON a.id = old.app_id
                 WHERE old.app_id = ?1 AND old.status IN ('accepted', 'not_applicable') AND new.status = 'untreated'",
            )?;
            let rows = stmt
                .query_map(params![from_app, to_app], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for (entry_id, status, notes, version) in decisions {
            let Some(status) = crate::models::CveStatus::from_str(&status) else {
                continue;
            };
            let comment = format!(
                "decision carried over from version {}: {}",
                version.as_deref().unwrap_or("?"),
                notes.as_deref().unwrap_or("no justification")
            );
            self.change_entry_status(entry_id, status, actor, Some(&comment))?;
        }
        Ok(())
    }

    // ---------- ingestion ----------

    /// Replaces the components of a source with the delivered list. Monitored
    /// components follow: a new version moves the source to the application
    /// of that version (closing the CVEs it fixes), a disappearance stops
    /// tracking what no other source of the group reports (history kept).
    pub fn ingest_inventory(&self, source: &InventorySource, components: &[Component]) -> Result<IngestOutcome> {
        if components.len() > MAX_COMPONENTS {
            return Err(anyhow!("too many components (at most {MAX_COMPONENTS})"));
        }
        // ':' cannot appear in a username: this author cannot be impersonated
        let actor = Actor::system(&format!("inventory:{}", source.name));
        // An empty list is far more often a broken collector than an emptied
        // infrastructure: it would stop tracking everything monitored here
        if components.is_empty() && source.components > 0 {
            return Err(anyhow!(
                "empty inventory refused: it would remove the {} components of this source (delete the source instead)",
                source.components
            ));
        }
        let mut outcome = IngestOutcome {
            received: components.len(),
            ..Default::default()
        };
        // No enclosing transaction: version changes and removals run their own
        // (decision history). A delivery cut short is completed by the next one.
        let conn = self.conn();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for component in components {
            let Some(name) = clean(&Some(component.name.to_lowercase()), 100) else {
                continue;
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            let version = clean(&component.version, 64);
            let vendor = clean(&component.vendor, 100).map(|v| v.to_lowercase());
            let ecosystem = clean(&component.ecosystem, 50);
            let existing: Option<(i64, Option<String>, String, Option<i64>)> = conn
                .query_row(
                    "SELECT id, version, state, application_id FROM inventory_components WHERE source_id = ?1 AND name = ?2",
                    params![source.id, name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            match existing {
                Some((id, old_version, state, application_id)) => {
                    conn.execute(
                        "UPDATE inventory_components SET version = ?1, vendor = ?2, ecosystem = ?3, exposed = ?4,
                                last_seen = datetime('now') WHERE id = ?5",
                        params![version, vendor, ecosystem, component.exposed as i32, id],
                    )?;
                    if old_version != version {
                        outcome.updated += 1;
                    }
                    match (state.as_str(), application_id) {
                        ("monitored", Some(app_id)) if old_version != version => self.move_component(
                            source,
                            id,
                            app_id,
                            &name,
                            version.as_deref(),
                            vendor.as_deref(),
                            ecosystem.as_deref(),
                            &actor,
                        )?,
                        ("new", _) if source.auto_monitor => {
                            self.attach_component(source, id, &name, version.as_deref(), vendor.as_deref(), ecosystem.as_deref())?
                        }
                        _ => {}
                    }
                }
                None => {
                    conn.execute(
                        "INSERT INTO inventory_components (source_id, name, version, vendor, ecosystem, exposed)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![source.id, name, version, vendor, ecosystem, component.exposed as i32],
                    )?;
                    let id = conn.last_insert_rowid();
                    outcome.added += 1;
                    if component.exposed || is_known_service(&name) {
                        outcome.new_probable_services.push(match &version {
                            Some(v) => format!("{name} {v}"),
                            None => name.clone(),
                        });
                    }
                    if source.auto_monitor {
                        self.attach_component(source, id, &name, version.as_deref(), vendor.as_deref(), ecosystem.as_deref())?;
                    }
                }
            }
        }
        // What the source no longer reports
        let gone: Vec<(i64, String, Option<i64>)> = {
            let mut stmt = conn.prepare("SELECT id, name, application_id FROM inventory_components WHERE source_id = ?1")?;
            let rows = stmt
                .query_map(params![source.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.into_iter().filter(|(_, name, _)| !seen.contains(name)).collect()
        };
        for (id, _, application_id) in gone {
            conn.execute("DELETE FROM inventory_components WHERE id = ?1", params![id])?;
            if let Some(app_id) = application_id {
                self.release_application(source.project_id, app_id, &actor)?;
            }
            outcome.removed += 1;
        }
        conn.execute(
            "UPDATE inventory_sources SET last_run_at = datetime('now'), last_status = 'ok', last_error = NULL WHERE id = ?1",
            params![source.id],
        )?;
        Ok(outcome)
    }

    // ---------- candidates ----------

    /// Components discovered for a project, most likely to matter first
    pub fn list_candidates(&self, project_id: i64) -> Result<Vec<Candidate>> {
        let mut stmt = self.conn().prepare(
            "SELECT c.id, s.name, c.name, c.version, c.vendor, c.exposed, c.state, c.first_seen,
                    COALESCE((SELECT SUM(p.cve_count) FROM products p
                              WHERE p.product = c.name AND (c.vendor IS NULL OR p.vendor = c.vendor)), 0),
                    s.grp, c.ecosystem
             FROM inventory_components c JOIN inventory_sources s ON s.id = c.source_id
             WHERE s.project_id = ?1",
        )?;
        let rows = stmt
            .query_map(params![project_id], |r| {
                let name: String = r.get(2)?;
                Ok((
                    Candidate {
                        id: r.get(0)?,
                        source: r.get(1)?,
                        group: r.get(9)?,
                        known_service: is_known_service(&name),
                        name,
                        version: r.get(3)?,
                        vendor: r.get(4)?,
                        exposed: r.get::<_, i64>(5)? != 0,
                        state: r.get(6)?,
                        first_seen: r.get(7)?,
                        known_cves: r.get(8)?,
                    },
                    r.get::<_, Option<String>>(10)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut candidates = Vec::with_capacity(rows.len());
        for (mut candidate, ecosystem) in rows {
            // A distribution package counts the CVEs its release has not fixed in this version
            if let Some(ecosystem) = ecosystem.filter(|e| crate::db::is_distro_ecosystem(e)) {
                candidate.known_cves = match candidate.version.as_deref() {
                    Some(version) => self.distro_cves(&ecosystem, &candidate.name, version)?.len() as i64,
                    None => 0,
                };
            }
            candidates.push(candidate);
        }
        candidates.sort_by(|a, b| b.likelihood().cmp(&a.likelihood()).then(a.name.cmp(&b.name)));
        Ok(candidates)
    }

    /// Component of the project with what is needed to monitor it
    #[allow(clippy::type_complexity)]
    fn component_of(
        &self,
        project_id: i64,
        component_id: i64,
    ) -> Result<Option<(InventorySource, String, Option<String>, Option<String>, Option<String>, String, Option<i64>)>> {
        let row: Option<(i64, String, Option<String>, Option<String>, Option<String>, String, Option<i64>)> = self
            .conn()
            .query_row(
                "SELECT c.source_id, c.name, c.version, c.vendor, c.ecosystem, c.state, c.application_id
                 FROM inventory_components c JOIN inventory_sources s ON s.id = c.source_id
                 WHERE c.id = ?1 AND s.project_id = ?2",
                params![component_id, project_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .optional()?;
        let Some((source_id, name, version, vendor, ecosystem, state, application_id)) = row else {
            return Ok(None);
        };
        Ok(self
            .get_inventory_source(project_id, source_id)?
            .map(|source| (source, name, version, vendor, ecosystem, state, application_id)))
    }

    /// Starts monitoring the chosen components: each becomes a tracked
    /// application of its source's group, scanned at once. Returns how many
    /// were added.
    pub fn monitor_components(&self, project_id: i64, component_ids: &[i64]) -> Result<usize> {
        let mut done = 0;
        for id in component_ids {
            let Some((source, name, version, vendor, ecosystem, state, _)) = self.component_of(project_id, *id)? else {
                continue;
            };
            if state == "monitored" {
                continue;
            }
            self.attach_component(&source, *id, &name, version.as_deref(), vendor.as_deref(), ecosystem.as_deref())?;
            done += 1;
        }
        Ok(done)
    }

    /// Ignores the chosen components; what no other source of the group
    /// reports stops being tracked (the history of its CVEs is kept).
    pub fn ignore_components(&self, project_id: i64, component_ids: &[i64], actor: &Actor) -> Result<usize> {
        let mut done = 0;
        for id in component_ids {
            let Some((_, _, _, _, _, _, application_id)) = self.component_of(project_id, *id)? else {
                continue;
            };
            self.conn().execute(
                "UPDATE inventory_components SET state = 'ignored', application_id = NULL WHERE id = ?1",
                params![id],
            )?;
            if let Some(app_id) = application_id {
                self.release_application(project_id, app_id, actor)?;
            }
            done += 1;
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DistroAdvisory;
    use crate::models::{AffectedProduct, Cve};

    fn component(name: &str, version: &str, exposed: bool) -> Component {
        Component {
            name: name.into(),
            version: Some(version.into()),
            exposed,
            ..Default::default()
        }
    }

    fn setup() -> (Database, i64, i64, InventorySource) {
        let db = Database::open_in_memory().unwrap();
        let alice = db.create_account("alice", None, "h", false).unwrap();
        let org = db.create_org("acme", alice).unwrap();
        let project = db.create_org_project(org, alice, "infra", None).unwrap();
        // A CVE affecting widget before 2.0, and a product with a CVE history
        let mut cve = Cve::new("CVE-2024-9001".into());
        cve.description = Some("Flaw".into());
        cve.affected_products.push(AffectedProduct {
            vendor: Some("acme".into()),
            product: Some("widget".into()),
            version: Some("*".into()),
            version_start: None,
            version_end: Some("2.0".into()),
            cpe: Some("cpe".into()),
            ..Default::default()
        });
        db.upsert_cve(&cve).unwrap();
        db.rebuild_catalog().unwrap();
        let id = db
            .create_inventory_source(project, "ci", "", "push", &serde_json::json!({}), Some("hash"))
            .unwrap();
        let source = db.get_inventory_source(project, id).unwrap().unwrap();
        (db, alice, project, source)
    }

    #[test]
    fn candidates_are_ranked_by_likelihood() {
        let (db, _, project, source) = setup();
        let outcome = db
            .ingest_inventory(
                &source,
                &[
                    component("libfoo", "1.0", false),
                    component("widget", "1.0", false),
                    component("nginx", "1.30", false),
                    component("custom-daemon", "0.1", true),
                    component("NGINX", "9.9", false), // duplicate name: first one wins
                ],
            )
            .unwrap();
        assert_eq!((outcome.received, outcome.added), (5, 4));
        // Exposed and well-known services are announced
        assert_eq!(outcome.new_probable_services, ["nginx 1.30", "custom-daemon 0.1"]);

        let names: Vec<String> = db.list_candidates(project).unwrap().into_iter().map(|c| c.name).collect();
        // exposed, then well-known service, then CVE history, then the rest
        assert_eq!(names, ["custom-daemon", "nginx", "widget", "libfoo"]);
        let widget = db.list_candidates(project).unwrap().into_iter().find(|c| c.name == "widget").unwrap();
        assert_eq!((widget.known_cves, widget.probable_service(), widget.state.as_str()), (1, false, "new"));
        assert!(is_known_service("OpenSSH") && is_known_service("home-assistant") && !is_known_service("libfoo"));
    }

    #[test]
    fn monitored_components_follow_the_source() {
        let (db, alice, project, source) = setup();
        db.ingest_inventory(&source, &[component("widget", "1.0", false), component("libfoo", "1.0", false)])
            .unwrap();
        let ids: Vec<i64> = db.list_candidates(project).unwrap().iter().map(|c| c.id).collect();
        assert_eq!(db.monitor_components(project, &ids[..1]).unwrap(), 1);
        assert_eq!(db.monitor_components(project, &ids[..1]).unwrap(), 0);
        assert_eq!(db.monitor_components(project + 1, &ids).unwrap(), 0);
        let apps = db.list_applications(project).unwrap();
        assert_eq!((apps.len(), apps[0].name.as_str(), apps[0].version.as_deref()), (1, "widget", Some("1.0")));
        assert_eq!(db.project_triage(project, false).unwrap().len(), 1);

        // Nothing new in the same delivery
        let again = db
            .ingest_inventory(&source, &[component("widget", "1.0", false), component("libfoo", "1.0", false)])
            .unwrap();
        assert_eq!((again.added, again.updated, again.removed), (0, 0, 0));

        // The upgrade is followed and closes the CVE it fixes
        let upgraded = db.ingest_inventory(&source, &[component("widget", "2.5", false)]).unwrap();
        assert_eq!((upgraded.updated, upgraded.removed), (1, 1));
        assert_eq!(db.list_applications(project).unwrap()[0].version.as_deref(), Some("2.5"));
        assert!(db.project_triage(project, false).unwrap().is_empty());
        let events = db.lifecycle_events(alice, Some(project)).unwrap();
        assert!(events.iter().any(|e| e.actor == "inventory:ci" && e.status.as_deref() == Some("treated")));

        // Gone from the source: no longer tracked, history kept
        // An empty delivery is refused; a component that disappears is removed
        let source = db.get_inventory_source(project, source.id).unwrap().unwrap();
        assert!(db.ingest_inventory(&source, &[]).is_err());
        assert_eq!(db.list_applications(project).unwrap().len(), 1);
        let emptied = db.ingest_inventory(&source, &[component("libbar", "1", false)]).unwrap();
        assert_eq!(emptied.removed, 1);
        assert!(db.list_applications(project).unwrap().is_empty());
        assert!(db.lifecycle_events(alice, Some(project)).unwrap().iter().any(|e| e.kind == "removed"));
    }

    #[test]
    fn ignoring_stops_monitoring_and_sources_are_scoped() {
        let (db, alice, project, source) = setup();
        db.ingest_inventory(&source, &[component("widget", "1.0", false)]).unwrap();
        let id = db.list_candidates(project).unwrap()[0].id;
        db.monitor_components(project, &[id]).unwrap();
        let actor = Actor::user(alice, "alice");
        assert_eq!(db.ignore_components(project + 1, &[id], &actor).unwrap(), 0);
        assert_eq!(db.ignore_components(project, &[id], &actor).unwrap(), 1);
        assert!(db.list_applications(project).unwrap().is_empty());
        assert_eq!(db.list_candidates(project).unwrap()[0].state, "ignored");
        // An ignored component stays ignored at the next delivery and is not announced again
        let outcome = db.ingest_inventory(&source, &[component("widget", "1.0", true)]).unwrap();
        assert!(outcome.new_probable_services.is_empty());
        assert_eq!(db.list_candidates(project).unwrap()[0].state, "ignored");

        assert!(db.inventory_source_by_token("hash").unwrap().is_some());
        assert!(db.inventory_source_by_token("other").unwrap().is_none());
        assert!(db.create_inventory_source(project, "ci", "", "push", &serde_json::json!({}), Some("h2")).is_err());
        assert!(db.get_inventory_source(project + 1, source.id).unwrap().is_none());
        assert!(!db.delete_inventory_source(project + 1, source.id, &actor).unwrap());
        assert!(db.delete_inventory_source(project, source.id, &actor).unwrap());
        assert!(db.list_candidates(project).unwrap().is_empty());

        let too_many: Vec<Component> = (0..MAX_COMPONENTS + 1).map(|i| component(&format!("c{i}"), "1", false)).collect();
        let id = db.create_inventory_source(project, "big", "", "push", &serde_json::json!({}), Some("h3")).unwrap();
        let big = db.get_inventory_source(project, id).unwrap().unwrap();
        assert!(db.ingest_inventory(&big, &too_many).is_err());
    }

    /// Ten identical web servers: one line per package, decided once for the group
    #[test]
    fn sources_of_a_group_share_applications_and_decisions() {
        let (db, alice, project, _) = setup();
        db.replace_distro_advisories(
            "Debian",
            &[
                DistroAdvisory {
                    ecosystem: "Debian:12".into(),
                    package: "openssh".into(),
                    cve_id: "CVE-2024-6387".into(),
                    introduced: "0".into(),
                    fixed: Some("1:9.2p1-2+deb12u3".into()),
                    urgency: None,
                    details: Some("sshd race".into()),
                    published: None,
                },
                DistroAdvisory {
                    ecosystem: "Debian:12".into(),
                    package: "openssh".into(),
                    cve_id: "CVE-2023-9999".into(),
                    introduced: "0".into(),
                    fixed: None,
                    urgency: None,
                    details: Some("unfixed".into()),
                    published: None,
                },
            ],
        )
        .unwrap();
        let everything = serde_json::json!({ "auto_monitor": true });
        let source = |name: &str, group: &str| {
            let id = db.create_inventory_source(project, name, group, "push", &everything, Some(name)).unwrap();
            db.get_inventory_source(project, id).unwrap().unwrap()
        };
        let reload = |s: &InventorySource| db.get_inventory_source(project, s.id).unwrap().unwrap();
        let deb = |version: &str| Component {
            name: "openssh".into(),
            version: Some(version.into()),
            ecosystem: Some("Debian:12".into()),
            ..Default::default()
        };
        let (web1, web2, db1) = (source("web-01", "web"), source("web-02", "web"), source("db-01", "db"));
        assert!(web1.auto_monitor && web1.group == "web");
        let old = "1:9.2p1-2+deb12u2";
        let fixed = "1:9.2p1-2+deb12u3";
        for s in [&web1, &web2, &db1] {
            db.ingest_inventory(s, &[deb(old), Component { name: "bash".into(), version: Some("5.2.15-2".into()), ecosystem: Some("Debian:12".into()), ..Default::default() }])
                .unwrap();
        }
        // Monitored without ticking; one application per group, not per machine
        let apps = db.list_applications(project).unwrap();
        let of = |apps: &[Application], group: &str, name: &str| -> Vec<Option<String>> {
            apps.iter().filter(|a| a.group == group && a.name == name).map(|a| a.version.clone()).collect()
        };
        assert_eq!(apps.len(), 4);
        assert_eq!((of(&apps, "web", "openssh").len(), of(&apps, "db", "openssh").len()), (1, 1));
        // Two CVEs per group, from the distribution's advisories (bash has none)
        let triage = db.project_triage(project, false).unwrap();
        assert_eq!(triage.len(), 4);
        // The checklist ranks by what the release has not fixed in that version
        let candidate = db.list_candidates(project).unwrap().into_iter().find(|c| c.name == "openssh" && c.source == "web-01").unwrap();
        assert_eq!((candidate.known_cves, candidate.group.as_str(), candidate.state.as_str()), (2, "web", "monitored"));

        // The unfixed CVE is accepted for the web group only
        let web_app = apps.iter().find(|a| a.group == "web" && a.name == "openssh").unwrap().id.unwrap();
        let entry: i64 = db
            .conn()
            .query_row("SELECT id FROM watchlist_entries WHERE app_id = ?1 AND cve_id = 'CVE-2023-9999'", [web_app], |r| r.get(0))
            .unwrap();
        db.set_watchlist_status(project, entry, crate::models::CveStatus::Accepted, &Actor::user(alice, "alice"), Some("no fix upstream")).unwrap();
        assert_eq!(db.project_triage(project, false).unwrap().len(), 3);

        // One web server is upgraded: the group now runs two versions
        db.ingest_inventory(&reload(&web1), &[deb(fixed)]).unwrap();
        let apps = db.list_applications(project).unwrap();
        let mut versions = of(&apps, "web", "openssh");
        versions.sort();
        assert_eq!(versions, [Some(old.to_string()), Some(fixed.to_string())]);
        // The new version no longer has the fixed CVE, and inherits the accepted risk
        let new_app = apps.iter().find(|a| a.group == "web" && a.version.as_deref() == Some(fixed)).unwrap().id.unwrap();
        let statuses: Vec<(String, String)> = {
            let mut stmt = db.conn().prepare("SELECT cve_id, status FROM watchlist_entries WHERE app_id = ?1").unwrap();
            let rows = stmt.query_map([new_app], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap();
            rows
        };
        assert_eq!(statuses, [("CVE-2023-9999".to_string(), "accepted".to_string())]);
        // web-02 still runs the old one, with its CVE open; the db group is untouched
        assert_eq!(db.project_triage(project, false).unwrap().len(), 3);

        // The last web server follows: the old version leaves the group, its history is kept
        db.ingest_inventory(&reload(&web2), &[deb(fixed)]).unwrap();
        let apps = db.list_applications(project).unwrap();
        assert_eq!(of(&apps, "web", "openssh"), [Some(fixed.to_string())]);
        assert_eq!(of(&apps, "db", "openssh"), [Some(old.to_string())]);
        assert_eq!(db.project_triage(project, false).unwrap().len(), 2);
        let events = db.lifecycle_events(alice, Some(project)).unwrap();
        assert!(events.iter().any(|e| e.actor == "inventory:web-01" && e.status.as_deref() == Some("accepted")));

        // Deleting a source only stops tracking what it alone reported
        assert!(db.delete_inventory_source(project, web1.id, &Actor::user(alice, "alice")).unwrap());
        assert_eq!(of(&db.list_applications(project).unwrap(), "web", "openssh").len(), 1);
        assert!(db.delete_inventory_source(project, web2.id, &Actor::user(alice, "alice")).unwrap());
        assert!(of(&db.list_applications(project).unwrap(), "web", "openssh").is_empty());

        // Applications added by hand are never taken over by a source
        let mut manual = Application::new(project, "openssh".into());
        manual.version = Some(old.into());
        let manual_id = db.create_application(&manual).unwrap();
        db.ingest_inventory(&reload(&db1), &[deb(fixed)]).unwrap();
        let kept = db.get_application(manual_id).unwrap().unwrap();
        assert_eq!((kept.version.as_deref(), kept.group.as_str()), (Some(old), ""));
    }
}
