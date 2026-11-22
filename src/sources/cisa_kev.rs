use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

use crate::db::Database;
use crate::models::{AffectedProduct, Cve};
use crate::sources::{CveSource, SyncOptions, SyncResult};

const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub struct CisaKevSource {
    client: reqwest::blocking::Client,
}

impl CisaKevSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    fn fetch_catalog(&self) -> Result<KevCatalog> {
        tracing::debug!("Fetching CISA KEV catalog");

        let response = self
            .client
            .get(KEV_URL)
            .send()
            .with_context(|| "Failed to fetch CISA KEV catalog")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "CISA KEV API returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            );
        }

        let catalog: KevCatalog = response
            .json()
            .with_context(|| "Failed to parse CISA KEV response")?;

        Ok(catalog)
    }
}

impl CveSource for CisaKevSource {
    fn name(&self) -> &'static str {
        "cisa_kev"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        use chrono::Utc;
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();

        // KEV est mis à jour quelques fois par semaine - skip si sync < 6h
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < 6 {
                    println!("━━━ CISA KEV: Skipped (last sync {}h ago) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ CISA KEV: Fetching catalog... ━━━");

        let catalog = self.fetch_catalog()?;
        let total = catalog.vulnerabilities.len();

        let pb = ProgressBar::new(total as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.yellow/red}] {pos}/{len} KEV entries ({percent}%)")
            .unwrap()
            .progress_chars("█▓░"));

        for vuln in &catalog.vulnerabilities {
            let mut cve = Cve::new(vuln.cve_id.clone());
            cve.kev_known_exploited = true;
            cve.kev_date_added = Some(vuln.date_added.clone());

            if cve.description.is_none() {
                cve.description = Some(format!(
                    "{} - {}",
                    vuln.vulnerability_name, vuln.short_description
                ));
            }

            cve.affected_products.push(AffectedProduct {
                vendor: Some(vuln.vendor_project.to_lowercase().replace(' ', "_")),
                product: Some(vuln.product.to_lowercase().replace(' ', "_")),
                version: Some("*".to_string()),
                version_start: None,
                version_end: None,
                cpe: None,
                ..Default::default()
            });

            match db.upsert_cve(&cve) {
                Ok(true) => result.added += 1,
                Ok(false) => result.updated += 1,
                Err(_) => result.errors += 1,
            }
            pb.inc(1);
        }

        pb.finish_with_message(format!("{} KEV entries processed ✓", total));

        Ok(result)
    }
}

// ============ CISA KEV Response Structures ============

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct KevCatalog {
    title: String,
    catalog_version: String,
    date_released: String,
    count: u32,
    vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct KevVulnerability {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    required_action: String,
    due_date: String,
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    cwes: Option<Vec<String>>,
}
