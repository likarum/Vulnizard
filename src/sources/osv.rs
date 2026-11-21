//! Source OSV (Open Source Vulnerabilities) - enrichit les CVE avec les packages affectés

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use crate::db::Database;
use crate::models::AffectedPackage;
use crate::sources::{CveSource, SyncOptions, SyncResult};

// OSV data is stored per ecosystem
const OSV_ECOSYSTEMS: &[(&str, &str)] = &[
    ("npm", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"),
    ("PyPI", "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"),
    ("Go", "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip"),
    ("crates.io", "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"),
    ("Maven", "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"),
];

pub struct OsvSource {
    client: reqwest::blocking::Client,
}

impl OsvSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    fn fetch_ecosystem(&self, ecosystem: &str, url: &str) -> Result<HashMap<String, Vec<AffectedPackage>>> {
        tracing::info!("Fetching OSV data for ecosystem: {}", ecosystem);

        let response = self
            .client
            .get(url)
            .send()
            .with_context(|| format!("Failed to fetch OSV data for {}", ecosystem))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV returned status {} for {}: {}",
                response.status(),
                ecosystem,
                response.text().unwrap_or_default()
            );
        }

        let bytes = response.bytes()?;
        self.parse_zip(&bytes, ecosystem)
    }

    fn parse_zip(&self, data: &[u8], ecosystem: &str) -> Result<HashMap<String, Vec<AffectedPackage>>> {
        let mut cve_to_packages: HashMap<String, Vec<AffectedPackage>> = HashMap::new();

        let reader = std::io::Cursor::new(data);
        let mut archive = zip::ZipArchive::new(reader)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if !file.name().ends_with(".json") {
                continue;
            }

            let mut content = String::new();
            file.read_to_string(&mut content)?;

            let vuln: OsvVulnerability = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Find CVE aliases
            let cve_ids: Vec<String> = vuln
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .cloned()
                .collect();

            if cve_ids.is_empty() {
                continue;
            }

            // Extract affected packages
            for affected in &vuln.affected {
                let pkg = &affected.package;

                // Build version range string
                let range_str = affected
                    .ranges
                    .iter()
                    .flat_map(|r| &r.events)
                    .map(|e| {
                        if let Some(ref introduced) = e.introduced {
                            format!(">={}", introduced)
                        } else if let Some(ref fixed) = e.fixed {
                            format!("<{}", fixed)
                        } else {
                            String::new()
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");

                // Find fixed version
                let fixed_version = affected
                    .ranges
                    .iter()
                    .flat_map(|r| &r.events)
                    .find_map(|e| e.fixed.clone());

                let package = AffectedPackage {
                    ecosystem: ecosystem.to_string(),
                    name: pkg.name.clone(),
                    vulnerable_range: if range_str.is_empty() { None } else { Some(range_str) },
                    fixed_version,
                };

                for cve_id in &cve_ids {
                    cve_to_packages
                        .entry(cve_id.clone())
                        .or_default()
                        .push(package.clone());
                }
            }
        }

        tracing::info!(
            "Parsed {} CVEs with packages for ecosystem {}",
            cve_to_packages.len(),
            ecosystem
        );

        Ok(cve_to_packages)
    }
}

impl CveSource for OsvSource {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        let mut result = SyncResult::default();

        use chrono::Utc;
        use indicatif::{ProgressBar, ProgressStyle};

        // OSV est mis à jour quotidiennement - skip si sync < 12h
        if !opts.force_full {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < 12 {
                    println!("━━━ OSV: Skipped (last sync {}h ago) ━━━", hours_since);
                    return Ok(result);
                }
            }
        }

        println!("━━━ OSV: Fetching package vulnerabilities ━━━");

        let total_ecosystems = OSV_ECOSYSTEMS.len();
        for (idx, (ecosystem, url)) in OSV_ECOSYSTEMS.iter().enumerate() {
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(ProgressStyle::default_spinner()
                .template("  {spinner:.green} [{pos}/{len}] {msg}")
                .unwrap());
            spinner.set_length(total_ecosystems as u64);
            spinner.set_position((idx + 1) as u64);
            spinner.set_message(format!("Downloading {}...", ecosystem));
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));

            match self.fetch_ecosystem(ecosystem, url) {
                Ok(packages) => {
                    let batch: Vec<(String, Vec<AffectedPackage>)> = packages.into_iter().collect();
                    let batch_size = batch.len();

                    spinner.set_message(format!("Inserting {} packages for {}...", batch_size, ecosystem));

                    match db.batch_add_packages(&batch) {
                        Ok((added, skipped)) => {
                            result.updated += added;
                            spinner.finish_with_message(format!(
                                "{}: {} CVEs enriched, {} skipped ✓",
                                ecosystem, added, skipped
                            ));
                        }
                        Err(e) => {
                            spinner.finish_with_message(format!("{}: Error - {}", ecosystem, e));
                            result.errors += 1;
                        }
                    }
                }
                Err(e) => {
                    spinner.finish_with_message(format!("{}: Failed - {}", ecosystem, e));
                    result.errors += 1;
                }
            }
        }

        tracing::info!(
            "OSV sync complete: {} CVEs enriched with package info",
            result.updated
        );

        Ok(result)
    }
}

// OSV JSON structures
#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvPackage {
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}
