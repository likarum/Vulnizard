//! Source Metasploit - enrichit les CVE avec les modules Metasploit disponibles

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use crate::db::Database;
use crate::models::Cve;
use crate::sources::{CveSource, SyncOptions, SyncResult};

const METASPLOIT_JSON_URL: &str = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json";

pub struct MetasploitSource {
    client: reqwest::blocking::Client,
}

impl MetasploitSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    fn fetch_modules(&self) -> Result<HashMap<String, String>> {
        tracing::info!("Fetching Metasploit modules metadata...");

        let response = self
            .client
            .get(METASPLOIT_JSON_URL)
            .send()
            .with_context(|| "Failed to fetch Metasploit modules")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Metasploit returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            );
        }

        let modules: HashMap<String, ModuleMetadata> = response
            .json()
            .with_context(|| "Failed to parse Metasploit JSON")?;

        // Build CVE -> module path mapping
        let mut cve_to_module: HashMap<String, String> = HashMap::new();

        for (path, metadata) in modules {
            for reference in &metadata.references {
                if reference.starts_with("CVE-") {
                    // Keep only exploit modules, prioritize over auxiliary
                    let should_update = if let Some(existing) = cve_to_module.get(reference) {
                        // Prefer exploit/ over auxiliary/
                        path.starts_with("exploit/") && !existing.starts_with("exploit/")
                    } else {
                        true
                    };

                    if should_update {
                        cve_to_module.insert(reference.clone(), path.clone());
                    }
                }
            }
        }

        tracing::info!("Found {} CVEs with Metasploit modules", cve_to_module.len());
        Ok(cve_to_module)
    }
}

impl CveSource for MetasploitSource {
    fn name(&self) -> &'static str {
        "metasploit"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        use chrono::Utc;
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();

        // Metasploit est mis à jour quelques fois par semaine - skip si sync < 24h
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < super::min_hours("metasploit") {
                    println!("━━━ Metasploit: Skipped (last sync {}h ago) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ Metasploit: Fetching modules... ━━━");

        let modules = self.fetch_modules()?;
        let total = modules.len();

        let pb = ProgressBar::new(total as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.blue/black}] {pos}/{len} modules ({percent}%)")
            .unwrap()
            .progress_chars("█▓░"));

        for (cve_id, module_path) in modules.into_iter() {
            let mut cve = Cve::new(cve_id);
            cve.exploit_public = true;
            cve.metasploit_module = Some(module_path);

            match db.upsert_cve(&cve) {
                Ok(true) => result.added += 1,
                Ok(false) => result.updated += 1,
                Err(_) => result.errors += 1,
            }
            pb.inc(1);
        }

        pb.finish_with_message(format!("{} Metasploit modules processed ✓", total));

        Ok(result)
    }
}

#[derive(Debug, Deserialize)]
struct ModuleMetadata {
    #[serde(default)]
    references: Vec<String>,
}
