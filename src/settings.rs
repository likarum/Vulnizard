//! Instance settings managed from the administration UI. They are stored in
//! the database and override the configuration file, so the scheduler and
//! the web handlers always work on the *effective* configuration.

use anyhow::Result;

use crate::config::Config;
use crate::db::Database;

/// Vulnerability sources: (key, label, what it provides)
pub const SOURCES: [(&str, &str, &str); 8] = [
    ("nvd", "NVD", "CVE records: description, CVSS, weaknesses, affected products (CPE), references"),
    ("cisa_kev", "CISA KEV", "Known Exploited Vulnerabilities catalog"),
    ("epss", "EPSS", "Exploit Prediction Scoring System: probability of exploitation"),
    ("vulnrichment", "CISA Vulnrichment", "SSVC decision points (exploitation, automatable, technical impact)"),
    ("osv", "OSV", "Advisories per package ecosystem (npm, PyPI, Go, crates.io…), including GitHub advisories"),
    (
        "distros",
        "Distribution advisories",
        "Fixed versions per Linux distribution release (Debian), for system packages reported by inventory sources; skipped while no inventory reports any",
    ),
    ("exploitdb", "Exploit-DB", "Public exploits referencing a CVE"),
    ("metasploit", "Metasploit", "Metasploit modules referencing a CVE"),
];

const KEY_SOURCES: &str = "setting.sources";
/// Source that only makes sense with the inventory feature
pub const INVENTORY_SOURCE: &str = "distros";
const KEY_INTERVAL: &str = "setting.sync_interval_minutes";
const KEY_NVD_API_KEY: &str = "setting.nvd_api_key";
const KEY_PRIVATE_WEBHOOKS: &str = "setting.allow_private_webhooks";
const KEY_MCP_HTTP: &str = "setting.mcp_http_enabled";
const KEY_MCP_WRITE: &str = "setting.mcp_http_allow_write";

pub fn is_source(key: &str) -> bool {
    SOURCES.iter().any(|(k, _, _)| *k == key)
}

fn flag(db: &Database, key: &str) -> Result<Option<bool>> {
    Ok(db.get_metadata(key)?.map(|v| v == "1"))
}

fn set_flag(db: &Database, key: &str, value: bool) -> Result<()> {
    db.set_metadata(key, if value { "1" } else { "0" })
}

fn overlaid(base: &Config, db: &Database) -> Result<Config> {
    let mut config = base.clone();
    if let Some(sources) = db.get_metadata(KEY_SOURCES)? {
        config.sync.sources = sources.split(',').filter(|s| is_source(s)).map(String::from).collect();
    }
    if let Some(interval) = db.get_metadata(KEY_INTERVAL)?.and_then(|v| v.parse().ok()) {
        config.web.sync_interval_minutes = interval;
    }
    if let Some(key) = db.get_secret(KEY_NVD_API_KEY)?.filter(|k| !k.is_empty()) {
        config.nvd.api_key = Some(key);
    }
    if let Some(allowed) = flag(db, KEY_PRIVATE_WEBHOOKS)? {
        config.web.allow_private_webhooks = allowed;
    }
    Ok(config)
}

/// Configuration file overlaid with the settings saved from the UI
pub fn effective(base: &Config, db: &Database) -> Result<Config> {
    let mut config = overlaid(base, db)?;
    if !config.inventory.enabled {
        // Distribution advisories only serve the inventory; the saved choice is kept
        config.sync.sources.retain(|s| s != INVENTORY_SOURCE);
    }
    Ok(config)
}

/// Enables or disables a source, keeping the canonical order
pub fn set_source_enabled(base: &Config, db: &Database, source: &str, enabled: bool) -> Result<()> {
    let current = overlaid(base, db)?.sync.sources;
    let sources: Vec<&str> = SOURCES
        .iter()
        .map(|(key, _, _)| *key)
        .filter(|key| if *key == source { enabled } else { current.iter().any(|s| s == key) })
        .collect();
    db.set_metadata(KEY_SOURCES, &sources.join(","))
}

pub fn set_sync_interval(db: &Database, minutes: u64) -> Result<()> {
    db.set_metadata(KEY_INTERVAL, &minutes.to_string())
}

/// Stores the NVD API key; an empty value removes the one saved from the UI
pub fn set_nvd_api_key(db: &Database, key: &str) -> Result<()> {
    db.set_secret(KEY_NVD_API_KEY, key)
}

pub fn set_private_webhooks(db: &Database, allowed: bool) -> Result<()> {
    set_flag(db, KEY_PRIVATE_WEBHOOKS, allowed)
}

/// MCP over HTTP: off by default, read-only by default
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct McpSettings {
    pub http_enabled: bool,
    pub allow_write: bool,
}

pub fn mcp(db: &Database) -> Result<McpSettings> {
    Ok(McpSettings {
        http_enabled: flag(db, KEY_MCP_HTTP)?.unwrap_or(false),
        allow_write: flag(db, KEY_MCP_WRITE)?.unwrap_or(false),
    })
}

pub fn set_mcp(db: &Database, settings: McpSettings) -> Result<()> {
    set_flag(db, KEY_MCP_HTTP, settings.http_enabled)?;
    set_flag(db, KEY_MCP_WRITE, settings.allow_write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_override_the_configuration_file() {
        let db = Database::open_in_memory().unwrap();
        let base = Config::default();
        let before = effective(&base, &db).unwrap();
        assert_eq!(before.sync.sources, ["nvd", "cisa_kev", "epss", "vulnrichment"]);
        assert_eq!(before.web.sync_interval_minutes, 60);

        set_source_enabled(&base, &db, "osv", true).unwrap();
        set_source_enabled(&base, &db, "epss", false).unwrap();
        set_source_enabled(&base, &db, "bogus", true).unwrap();
        set_sync_interval(&db, 15).unwrap();
        set_nvd_api_key(&db, "key-123").unwrap();
        set_private_webhooks(&db, true).unwrap();
        let after = effective(&base, &db).unwrap();
        // Canonical order, unknown names ignored; distribution advisories only with the inventory
        assert_eq!(after.sync.sources, ["nvd", "cisa_kev", "vulnrichment", "osv"]);
        let mut preview = base.clone();
        preview.inventory.enabled = true;
        assert_eq!(effective(&preview, &db).unwrap().sync.sources, ["nvd", "cisa_kev", "vulnrichment", "osv", "distros"]);
        assert_eq!(after.web.sync_interval_minutes, 15);
        assert_eq!(after.nvd.api_key.as_deref(), Some("key-123"));
        assert!(after.web.allow_private_webhooks);

        // Removing the key falls back to the file
        set_nvd_api_key(&db, "").unwrap();
        assert_eq!(effective(&base, &db).unwrap().nvd.api_key, None);
    }

    #[test]
    fn mcp_settings() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(mcp(&db).unwrap(), McpSettings::default());
        set_mcp(&db, McpSettings { http_enabled: true, allow_write: false }).unwrap();
        assert_eq!(mcp(&db).unwrap(), McpSettings { http_enabled: true, allow_write: false });
    }
}
