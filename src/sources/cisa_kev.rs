use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

use crate::db::Database;
use crate::models::{AffectedProduct, Cve};
use crate::sources::{CveSource, SyncOptions, SyncResult};

const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub struct CisaKevSource {
    client: reqwest::blocking::Client,
    url: String,
}

impl CisaKevSource {
    pub fn new() -> Self {
        Self::at(KEV_URL)
    }

    /// Reads from another address (the tests)
    pub(super) fn at(url: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(super::USER_AGENT)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, url: url.to_string() }
    }

    /// The catalog, unless it is the one already read
    fn fetch_catalog(&self, db: &Database, opts: &SyncOptions) -> Result<Option<(KevCatalog, super::Mark)>> {
        tracing::debug!("Fetching CISA KEV catalog");
        let Some(download) = super::download_if_changed(&self.client, db, "cisa_kev", &self.url, opts)? else {
            return Ok(None);
        };
        let catalog: KevCatalog = download.response.json().with_context(|| "Failed to parse CISA KEV response")?;
        Ok(Some((catalog, download.mark)))
    }
}

impl CveSource for CisaKevSource {
    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        use chrono::Utc;
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();

        // KEV est mis à jour quelques fois par semaine - skip si sync < 6h
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < super::min_hours("cisa_kev") {
                    println!("━━━ CISA KEV: Skipped (last sync {}h ago) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ CISA KEV: Fetching catalog... ━━━");

        let Some((catalog, mark)) = self.fetch_catalog(db, opts)? else {
            println!("━━━ CISA KEV: unchanged since the last run ━━━");
            return Ok(SyncResult::unchanged());
        };
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

            // The catalog's own wording is only for a CVE nobody described yet:
            // it must not replace the description the NVD gave
            if !db.has_description(&vuln.cve_id)? {
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

            result.count(db.upsert_cve(&cve));
            pb.inc(1);
        }

        pb.finish_with_message(format!("{} KEV entries processed ✓", total));

        mark.remember(db)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Stored;
    use crate::sources::testserver::{Answer, Server};

    #[test]
    fn the_catalog_describes_only_what_nobody_described() {
        let catalog = br#"{"title": "t", "catalogVersion": "1", "dateReleased": "d", "count": 2, "vulnerabilities": [
            {"cveID": "CVE-2024-1", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme Widget Flaw", "dateAdded": "2024-01-01",
             "shortDescription": "The catalog's wording.", "requiredAction": "a", "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-2024-2", "vendorProject": "Acme", "product": "Gadget", "vulnerabilityName": "Acme Gadget Flaw", "dateAdded": "2024-01-02",
             "shortDescription": "Only the catalog knows it.", "requiredAction": "a", "dueDate": "2024-02-02", "knownRansomwareCampaignUse": "Unknown"}]}"#
            .to_vec();
        let server = Server::start(move |_| Answer::ok(catalog.clone()));
        let db = Database::open_in_memory().unwrap();
        let mut known = Cve::new("CVE-2024-1".into());
        known.description = Some("What the NVD says.".into());
        assert_eq!(db.upsert_cve(&known).unwrap(), Stored::Created);

        let source = CisaKevSource::at(&server.url);
        let opts = SyncOptions::new(0).ignore_freshness(true).force_full();
        let first = source.sync(&db, &opts).unwrap();
        assert_eq!((first.added, first.updated, first.same), (1, 1, 0));
        let stored = db.get_cve("CVE-2024-1").unwrap().unwrap();
        assert!(stored.kev_known_exploited);
        assert_eq!(stored.description.as_deref(), Some("What the NVD says."));
        // Being exploited is news; the description did not move
        let news: Vec<String> =
            db.list_cve_changes("CVE-2024-1").unwrap().iter().flat_map(|c| c.events.iter().map(|e| e.kind().to_string())).collect();
        assert!(news.iter().any(|kind| kind == "kev") && !news.iter().any(|kind| kind == "description"), "{news:?}");
        assert_eq!(
            db.get_cve("CVE-2024-2").unwrap().unwrap().description.as_deref(),
            Some("Acme Gadget Flaw - Only the catalog knows it.")
        );

        // The same catalog read again changes nothing, and the NVD rewriting its CVE is not undone
        let again = source.sync(&db, &opts).unwrap();
        assert_eq!((again.added, again.updated, again.same), (0, 0, 2));
    }
}

// ============ CISA KEV Response Structures ============

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevCatalog {
    vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevVulnerability {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
}
