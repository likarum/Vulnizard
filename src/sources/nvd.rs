use anyhow::{Context, Result};
use chrono::Utc;
use serde::Deserialize;
use std::time::Duration;

use crate::db::Database;
use crate::extraction;
use crate::models::{AffectedProduct, Cve, Reference};
use crate::sources::{CveSource, SyncOptions, SyncResult};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RESULTS_PER_PAGE: u32 = 2000;

pub struct NvdSource {
    client: reqwest::blocking::Client,
    api_key: Option<String>,
}

impl NvdSource {
    pub fn new(api_key: Option<String>) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, api_key }
    }

    /// Fetch a page of CVEs. If `use_last_mod` is true, uses lastModStartDate/lastModEndDate
    /// instead of pubStartDate/pubEndDate (for incremental sync).
    fn fetch_page(&self, start_index: u32, date_start: &str, date_end: &str, use_last_mod: bool) -> Result<NvdResponse> {
        let url = if use_last_mod {
            format!(
                "{}?resultsPerPage={}&startIndex={}&lastModStartDate={}&lastModEndDate={}",
                NVD_API_BASE, RESULTS_PER_PAGE, start_index, date_start, date_end
            )
        } else {
            format!(
                "{}?resultsPerPage={}&startIndex={}&pubStartDate={}&pubEndDate={}",
                NVD_API_BASE, RESULTS_PER_PAGE, start_index, date_start, date_end
            )
        };

        let mut request = self.client.get(&url);

        if let Some(ref key) = self.api_key {
            request = request.header("apiKey", key);
        }

        // Rate limiting: sans API key, NVD limite à ~5 req/30sec
        // Avec API key: ~50 req/30sec
        let delay = if self.api_key.is_some() {
            Duration::from_millis(600)
        } else {
            Duration::from_secs(6)
        };

        if start_index > 0 {
            std::thread::sleep(delay);
        }

        let response = request
            .send()
            .with_context(|| format!("Failed to fetch NVD data from {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "NVD API returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            );
        }

        let data: NvdResponse = response.json().with_context(|| "Failed to parse NVD response")?;

        Ok(data)
    }

    fn convert_to_cve(&self, vuln: &NvdVulnerability) -> Cve {
        let cve_item = &vuln.cve;
        let mut cve = Cve::new(cve_item.id.clone());

        // Description (préférence pour l'anglais)
        if let Some(desc) = cve_item
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .or_else(|| cve_item.descriptions.first())
        {
            cve.description = Some(desc.value.clone());
        }

        // CVSS v3.1 ou v3.0
        if let Some(ref metrics) = cve_item.metrics {
            // Essayer cvssMetricV31 d'abord
            if let Some(ref cvss_v31) = metrics.cvss_metric_v31 {
                if let Some(metric) = cvss_v31.first() {
                    cve.cvss_v3_score = Some(metric.cvss_data.base_score);
                    cve.cvss_v3_vector = Some(metric.cvss_data.vector_string.clone());
                }
            }
            // Sinon cvssMetricV30
            else if let Some(ref cvss_v30) = metrics.cvss_metric_v30 {
                if let Some(metric) = cvss_v30.first() {
                    cve.cvss_v3_score = Some(metric.cvss_data.base_score);
                    cve.cvss_v3_vector = Some(metric.cvss_data.vector_string.clone());
                }
            }
        }

        // CWE
        if let Some(ref weaknesses) = cve_item.weaknesses {
            for weakness in weaknesses {
                for desc in &weakness.description {
                    if desc.value.starts_with("CWE-") {
                        cve.cwe_ids.push(desc.value.clone());
                    }
                }
            }
        }

        // Affected products (depuis configurations)
        if let Some(ref configs) = cve_item.configurations {
            for config in configs {
                for node in &config.nodes {
                    Self::extract_cpe_matches(&mut cve.affected_products, node);
                }
            }
        }

        // References
        if let Some(ref refs) = cve_item.references {
            for r in refs {
                cve.references.push(Reference {
                    url: r.url.clone(),
                    source: r.source.clone(),
                    tags: r.tags.clone().unwrap_or_default(),
                });
            }
        }

        // Dates - NVD format is "2026-01-30T23:16:12.333" (no timezone, assume UTC)
        if let Some(ref published) = cve_item.published {
            cve.published_at = chrono::NaiveDateTime::parse_from_str(published, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|d| d.and_utc());
        }

        if let Some(ref modified) = cve_item.last_modified {
            cve.modified_at = chrono::NaiveDateTime::parse_from_str(modified, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|d| d.and_utc());
        }

        cve
    }

    fn extract_cpe_matches(products: &mut Vec<AffectedProduct>, node: &NvdNode) {
        if let Some(ref matches) = node.cpe_match {
            for m in matches {
                if m.vulnerable {
                    // Parse CPE 2.3: cpe:2.3:a:vendor:product:version:...
                    let parts: Vec<&str> = m.criteria.split(':').collect();
                    if parts.len() >= 5 {
                        // Determine version info from range fields or CPE
                        let version = parts.get(5).map(|s| s.to_string());
                        let version_start = m.version_start_including.clone()
                            .or_else(|| m.version_start_excluding.clone());
                        let version_end = m.version_end_excluding.clone()
                            .or_else(|| m.version_end_including.clone());

                        products.push(AffectedProduct {
                            vendor: Some(parts[3].to_string()),
                            product: Some(parts[4].to_string()),
                            version,
                            version_start,
                            version_end,
                            cpe: Some(m.criteria.clone()),
                        });
                    }
                }
            }
        }

        // Récursion sur les enfants
        if let Some(ref children) = node.children {
            for child in children {
                Self::extract_cpe_matches(products, child);
            }
        }
    }
}

impl CveSource for NvdSource {
    fn name(&self) -> &'static str {
        "nvd"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        use chrono::Duration;
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();
        let now = Utc::now();

        // Déterminer le mode de sync
        let (start_date, use_last_mod, mode_label) = if opts.is_incremental() {
            let last = opts.last_sync.unwrap();
            // Ajouter une marge de sécurité de 1 heure pour éviter de rater des mises à jour
            let safe_start = last - Duration::hours(1);
            (safe_start, true, "incremental")
        } else {
            let start = now - Duration::days(opts.months as i64 * 30);
            (start, false, "full")
        };

        println!(
            "━━━ NVD: {} sync {} → {} ━━━",
            mode_label.to_uppercase(),
            start_date.format("%Y-%m-%d %H:%M"),
            now.format("%Y-%m-%d %H:%M")
        );

        // NVD API limite à 120 jours par requête - on utilise des chunks de 100 jours
        const CHUNK_DAYS: i64 = 100;
        let total_days = (now - start_date).num_days().max(1);
        let total_chunks = (total_days / CHUNK_DAYS) + 1;
        let mut chunk_start = start_date;
        let mut chunk_num = 0;
        // Windows that could not be read entirely. What was read is kept, but the
        // run must not count as done: the next one starts again from the same date.
        let mut fetch_failures: Vec<String> = Vec::new();

        while chunk_start < now {
            chunk_num += 1;
            let chunk_end = std::cmp::min(chunk_start + Duration::days(CHUNK_DAYS), now);

            let date_start = chunk_start.format("%Y-%m-%dT%H:%M:%S.000").to_string();
            let date_end = chunk_end.format("%Y-%m-%dT%H:%M:%S.999").to_string();

            // Première requête pour obtenir le total
            let first_response = match self.fetch_page(0, &date_start, &date_end, use_last_mod) {
                Ok(r) => r,
                Err(e) => {
                    println!("  ✗ Chunk {}/{}: Error - {}", chunk_num, total_chunks, e);
                    fetch_failures.push(format!("{} → {}: {e}", chunk_start.format("%Y-%m-%d"), chunk_end.format("%Y-%m-%d")));
                    result.errors += 1;
                    chunk_start = chunk_end;
                    continue;
                }
            };

            let chunk_total = first_response.total_results;

            if chunk_total == 0 {
                println!("  ○ Chunk {}/{}: No updates", chunk_num, total_chunks);
                chunk_start = chunk_end;
                continue;
            }

            // Créer la barre de progression
            let pb = ProgressBar::new(chunk_total as u64);
            pb.set_style(ProgressStyle::default_bar()
                .template("  [{bar:40.cyan/blue}] {pos}/{len} CVEs ({percent}%) - {msg}")
                .unwrap()
                .progress_chars("█▓░"));
            pb.set_message(format!(
                "Chunk {}/{}: {} → {}",
                chunk_num,
                total_chunks,
                chunk_start.format("%Y-%m-%d"),
                chunk_end.format("%Y-%m-%d")
            ));

            // Traiter la première page
            for vuln in &first_response.vulnerabilities {
                let mut cve = self.convert_to_cve(vuln);
                if cve.affected_products.is_empty() {
                    if let Some(ref desc) = cve.description {
                        cve.affected_products = extraction::extract_from_description(desc);
                    }
                }
                match db.upsert_cve(&cve) {
                    Ok(true) => result.added += 1,
                    Ok(false) => result.updated += 1,
                    Err(_) => result.errors += 1,
                }
            }
            pb.set_position(first_response.vulnerabilities.len() as u64);

            // Continuer avec les pages suivantes
            let mut start_index = RESULTS_PER_PAGE;
            while start_index < chunk_total {
                match self.fetch_page(start_index, &date_start, &date_end, use_last_mod) {
                    Ok(response) => {
                        for vuln in &response.vulnerabilities {
                            let mut cve = self.convert_to_cve(vuln);
                            if cve.affected_products.is_empty() {
                                if let Some(ref desc) = cve.description {
                                    cve.affected_products = extraction::extract_from_description(desc);
                                }
                            }
                            match db.upsert_cve(&cve) {
                                Ok(true) => result.added += 1,
                                Ok(false) => result.updated += 1,
                                Err(_) => result.errors += 1,
                            }
                        }
                        pb.set_position((start_index + response.vulnerabilities.len() as u32) as u64);
                        start_index += RESULTS_PER_PAGE;
                    }
                    Err(e) => {
                        pb.abandon_with_message(format!("Error: {}", e));
                        fetch_failures.push(format!("{} → {} (from result {start_index}): {e}", chunk_start.format("%Y-%m-%d"), chunk_end.format("%Y-%m-%d")));
                        result.errors += 1;
                        break;
                    }
                }
            }

            pb.finish_with_message(format!(
                "Chunk {}/{}: {} CVEs ✓",
                chunk_num,
                total_chunks,
                chunk_total
            ));

            chunk_start = chunk_end;
        }

        if !fetch_failures.is_empty() {
            anyhow::bail!(
                "{} period(s) could not be read from the NVD ({} added, {} updated before that): {}",
                fetch_failures.len(),
                result.added,
                result.updated,
                fetch_failures.join("; ")
            );
        }
        Ok(result)
    }
}

// ============ NVD API Response Structures ============

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct NvdResponse {
    results_per_page: u32,
    start_index: u32,
    total_results: u32,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    weaknesses: Option<Vec<NvdWeakness>>,
    configurations: Option<Vec<NvdConfiguration>>,
    references: Option<Vec<NvdReference>>,
    published: Option<String>,
    last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssMetric {
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssData {
    base_score: f64,
    vector_string: String,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    cpe_match: Option<Vec<NvdCpeMatch>>,
    children: Option<Vec<NvdNode>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
    source: Option<String>,
    tags: Option<Vec<String>>,
}
