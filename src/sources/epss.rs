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
    url: String,
}

impl EpssSource {
    pub fn new() -> Self {
        Self::at(EPSS_URL)
    }

    /// Reads from another address (the tests)
    pub(super) fn at(url: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(super::USER_AGENT)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, url: url.to_string() }
    }

    /// The scores, unless the file is the one already read
    fn fetch_scores(&self, db: &Database, opts: &SyncOptions) -> Result<Option<(Vec<EpssScore>, super::Mark)>> {
        tracing::debug!("Fetching EPSS scores");
        let Some(download) = super::download_if_changed(&self.client, db, "epss", &self.url, opts)? else {
            return Ok(None);
        };
        let mark = download.mark;

        let bytes = download
            .response
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

        Ok(Some((scores, mark)))
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
                if hours_since < super::min_hours("epss") {
                    println!("━━━ EPSS: Skipped (last sync {}h ago, updates daily) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ EPSS: Fetching exploit prediction scores... ━━━");

        let Some((scores, mark)) = self.fetch_scores(db, opts)? else {
            println!("  unchanged since the last run");
            return Ok(SyncResult::unchanged());
        };
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

        mark.remember(db)?;
        Ok(result)
    }
}

struct EpssScore {
    cve_id: String,
    epss: f64,
    percentile: f64,
}
