use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use std::time::Duration;

use crate::db::Database;
use crate::models::Cve;
use crate::sources::{CveSource, SyncOptions, SyncResult};

const EPSS_URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

pub struct EpssSource {
    client: reqwest::blocking::Client,
}

impl EpssSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    fn fetch_scores(&self) -> Result<Vec<EpssScore>> {
        tracing::debug!("Fetching EPSS scores");

        let response = self
            .client
            .get(EPSS_URL)
            .send()
            .with_context(|| "Failed to fetch EPSS scores")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "EPSS API returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            );
        }

        let bytes = response
            .bytes()
            .with_context(|| "Failed to read EPSS response")?;

        // Décompression gzip
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut csv_data = String::new();
        decoder
            .read_to_string(&mut csv_data)
            .with_context(|| "Failed to decompress EPSS data")?;

        // Parse CSV
        let mut scores = Vec::new();
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .comment(Some(b'#'))
            .from_reader(csv_data.as_bytes());

        for result in reader.records() {
            let record = result.with_context(|| "Failed to parse EPSS CSV record")?;
            if record.len() >= 3 {
                let cve_id = record.get(0).unwrap_or("").to_string();
                let epss: f64 = record.get(1).unwrap_or("0").parse().unwrap_or(0.0);
                let percentile: f64 = record.get(2).unwrap_or("0").parse().unwrap_or(0.0);

                if cve_id.starts_with("CVE-") {
                    scores.push(EpssScore {
                        cve_id,
                        epss,
                        percentile,
                    });
                }
            }
        }

        Ok(scores)
    }
}

impl CveSource for EpssSource {
    fn name(&self) -> &'static str {
        "epss"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        use chrono::Utc;
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();

        // EPSS est mis à jour quotidiennement - skip si sync < 12h
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < 12 {
                    println!("━━━ EPSS: Skipped (last sync {}h ago, updates daily) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ EPSS: Fetching exploit prediction scores... ━━━");

        let scores = self.fetch_scores()?;
        let total = scores.len();

        let pb = ProgressBar::new(total as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.green/black}] {pos}/{len} scores ({percent}%)")
            .unwrap()
            .progress_chars("█▓░"));

        for score in &scores {
            let mut cve = Cve::new(score.cve_id.clone());
            cve.epss_score = Some(score.epss);
            cve.epss_percentile = Some(score.percentile);

            match db.upsert_cve(&cve) {
                Ok(true) => result.added += 1,
                Ok(false) => result.updated += 1,
                Err(_) => result.errors += 1,
            }
            pb.inc(1);
        }

        pb.finish_with_message(format!("{} EPSS scores processed ✓", total));

        Ok(result)
    }
}

struct EpssScore {
    cve_id: String,
    epss: f64,
    percentile: f64,
}
