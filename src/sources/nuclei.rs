//! Nuclei templates: tells which CVEs have a ready-made detection template
//! in the ProjectDiscovery repository. One small index file is downloaded
//! (`cves.json`, one JSON object per line); nothing is cloned.
//!
//! A template is a way to **check** for a vulnerability, not an exploit: it
//! does not make the CVE "publicly exploited".

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

use crate::db::Database;
use crate::models::Cve;
use crate::sources::{CveSource, SyncOptions, SyncResult};

const INDEX_URL: &str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json";
/// The index is a few megabytes; anything much larger is not it
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

pub struct NucleiSource {
    client: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct IndexLine {
    #[serde(rename = "ID")]
    id: String,
    file_path: String,
}

/// CVE id → path of its template, from the index. Lines that are not a CVE
/// template, or whose path is not a plain relative `.yaml` path, are left out.
pub fn parse_index(text: &str) -> BTreeMap<String, String> {
    let mut templates = BTreeMap::new();
    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<IndexLine>(line) else {
            continue;
        };
        let id = entry.id.trim().to_uppercase();
        let path = entry.file_path.trim();
        let plain_id = id.starts_with("CVE-") && id.len() <= 24 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        let plain_path = path.ends_with(".yaml")
            && path.len() <= 200
            && !path.starts_with('/')
            && !path.contains("..")
            && path.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'));
        if plain_id && plain_path {
            templates.insert(id, path.to_string());
        }
    }
    templates
}

impl NucleiSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("vulnizard/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Failed to create HTTP client");
        Self { client }
    }

    fn fetch_index(&self) -> Result<String> {
        use std::io::Read;
        let response = self.client.get(INDEX_URL).send().context("Failed to fetch the Nuclei templates index")?;
        if !response.status().is_success() {
            anyhow::bail!("the Nuclei templates index returned status {}", response.status());
        }
        let mut text = String::new();
        response.take(MAX_INDEX_BYTES).read_to_string(&mut text).context("Failed to read the Nuclei templates index")?;
        Ok(text)
    }
}

impl CveSource for NucleiSource {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        // Templates are added a few times a week
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (chrono::Utc::now() - last).num_hours();
                if hours_since < 24 {
                    println!("━━━ Nuclei: Skipped (last sync {hours_since}h ago) ━━━");
                    return Ok(SyncResult::skipped());
                }
            }
        }
        println!("━━━ Nuclei: Fetching the templates index... ━━━");
        let templates = parse_index(&self.fetch_index()?);
        if templates.is_empty() {
            anyhow::bail!("the Nuclei templates index holds no CVE template: its format may have changed");
        }
        let mut result = SyncResult::default();
        for (cve_id, path) in templates {
            let mut cve = Cve::new(cve_id);
            cve.nuclei_template = Some(path);
            match db.upsert_cve(&cve) {
                Ok(true) => result.added += 1,
                Ok(false) => result.updated += 1,
                Err(_) => result.errors += 1,
            }
        }
        println!("  {} CVEs with a Nuclei template ✓", result.added + result.updated);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_gives_cve_templates_and_nothing_else() {
        let index = r#"{"ID":"CVE-2000-0114","Info":{"Name":"FrontPage","Severity":"medium"},"file_path":"http/cves/2000/CVE-2000-0114.yaml"}
{"ID":"cve-2021-44228","Info":{},"file_path":"http/cves/2021/CVE-2021-44228.yaml"}
{"ID":"apache-detect","Info":{},"file_path":"http/technologies/apache-detect.yaml"}
{"ID":"CVE-2022-0001","Info":{},"file_path":"../../etc/passwd.yaml"}
{"ID":"CVE-2022-0002","Info":{},"file_path":"/abs/CVE-2022-0002.yaml"}
{"ID":"CVE-2022-0003","Info":{},"file_path":"http/cves/2022/<script>.yaml"}
{"ID":"CVE-2022-0004","Info":{},"file_path":"http/cves/2022/CVE-2022-0004.txt"}
not json at all
{"ID":"CVE-2023-9999"}
"#;
        let templates = parse_index(index);
        assert_eq!(
            templates.into_iter().collect::<Vec<_>>(),
            [
                ("CVE-2000-0114".to_string(), "http/cves/2000/CVE-2000-0114.yaml".to_string()),
                ("CVE-2021-44228".to_string(), "http/cves/2021/CVE-2021-44228.yaml".to_string()),
            ]
        );
        assert!(parse_index("").is_empty());
    }

    #[test]
    fn a_template_enriches_a_cve_without_marking_it_exploited() {
        let db = Database::open_in_memory().unwrap();
        let mut known = Cve::new("CVE-2021-44228".into());
        known.description = Some("Log4Shell".into());
        db.upsert_cve(&known).unwrap();
        let mut enriched = Cve::new("CVE-2021-44228".into());
        enriched.nuclei_template = Some("http/cves/2021/CVE-2021-44228.yaml".into());
        db.upsert_cve(&enriched).unwrap();
        let stored = db.get_cve("CVE-2021-44228").unwrap().unwrap();
        assert_eq!(stored.nuclei_template.as_deref(), Some("http/cves/2021/CVE-2021-44228.yaml"));
        assert_eq!(stored.description.as_deref(), Some("Log4Shell"));
        assert!(!stored.exploit_public);
    }

    /// Reads the real index. Run with `cargo test -- --ignored real_nuclei`.
    #[test]
    #[ignore]
    fn real_nuclei_index_is_read() {
        let templates = parse_index(&NucleiSource::new().fetch_index().unwrap());
        assert!(templates.len() > 3000, "{}", templates.len());
        assert!(templates.contains_key("CVE-2021-44228"));
    }
}
