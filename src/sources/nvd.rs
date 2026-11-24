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
    /// When the last request was sent: the NVD counts them
    last_request: std::sync::Mutex<Option<std::time::Instant>>,
}

impl NvdSource {
    pub fn new(api_key: Option<String>) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(super::USER_AGENT)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, api_key, last_request: std::sync::Mutex::new(None) }
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

        // The NVD allows about 5 requests per 30 seconds without a key and 50
        // with one, whatever they return: every request waits its turn, and
        // a refusal for going too fast is tried again after a pause
        let spacing = if self.api_key.is_some() { Duration::from_millis(700) } else { Duration::from_millis(6500) };
        const ATTEMPTS: u32 = 5;
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            {
                let mut last = self.last_request.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(wait) = last.and_then(|at| spacing.checked_sub(at.elapsed())) {
                    std::thread::sleep(wait);
                }
                *last = Some(std::time::Instant::now());
            }
            let mut request = self.client.get(&url);
            if let Some(ref key) = self.api_key {
                request = request.header("apiKey", key);
            }
            let outcome = request.send();
            let retry = match &outcome {
                Ok(response) => matches!(response.status().as_u16(), 403 | 429 | 500..=599),
                Err(e) => e.is_timeout() || e.is_connect(),
            };
            if retry && attempt < ATTEMPTS {
                let pause = Duration::from_secs(30 * attempt as u64);
                tracing::warn!("NVD: request refused or failed (attempt {attempt}/{ATTEMPTS}), trying again in {}s", pause.as_secs());
                std::thread::sleep(pause);
                continue;
            }
            break outcome.with_context(|| "Failed to fetch NVD data")?;
        };

        if !response.status().is_success() {
            let status = response.status();
            // The body of a refusal is a whole web page: its first words are enough
            let body: String = response.text().unwrap_or_default().chars().filter(|c| !c.is_control()).take(120).collect();
            anyhow::bail!("NVD API returned status {status}: {body}");
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
                        // Each bound is included or not: "up to 1.4 included" also
                        // affects 1.4, "before 1.4" does not
                        let version_start_excluded = m.version_start_including.is_none() && m.version_start_excluding.is_some();
                        let version_start = m.version_start_including.clone()
                            .or_else(|| m.version_start_excluding.clone());
                        let version_end_included = m.version_end_excluding.is_none() && m.version_end_including.is_some();
                        let version_end = m.version_end_excluding.clone()
                            .or_else(|| m.version_end_including.clone());

                        products.push(AffectedProduct {
                            vendor: Some(parts[3].to_string()),
                            product: Some(parts[4].to_string()),
                            version,
                            version_start,
                            version_end,
                            version_start_excluded,
                            version_end_included,
                            cpe: Some(m.criteria.clone()),
                            ..Default::default()
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

        let mut result = SyncResult::default();
        let now = Utc::now();

        // 1. What changed since the last run
        if opts.is_incremental() {
            // One hour of margin, not to miss an update
            let since = opts.last_sync.unwrap() - Duration::hours(1);
            println!("━━━ NVD: changes {} → {} ━━━", since.format("%Y-%m-%d %H:%M"), now.format("%Y-%m-%d %H:%M"));
            self.import(db, since, now, Window::Modified, &mut result, &mut |_| Ok(()))?;
        }

        // 2. The history, when it was never read, not read far enough back,
        // or not read to its end
        let wanted = history_start(opts.months, now);
        let covered = if opts.force_full { None } else { stored_date(db, KEY_HISTORY_FROM)? };
        if covered.is_some_and(|from| from <= wanted + Duration::days(1)) {
            return Ok(result);
        }
        // A read interrupted earlier goes on from where it stopped, if it
        // started as far back as what is wanted now
        let progress = if opts.force_full { None } else { Backfill::load(db)? }.filter(|p| p.from <= wanted + Duration::days(1));
        let until = covered.unwrap_or(now);
        let (from, first_started) = match &progress {
            Some(p) => (p.done_until.max(wanted), p.started),
            None => (wanted, now),
        };
        println!("━━━ NVD: history {} → {} ━━━", from.format("%Y-%m-%d"), until.format("%Y-%m-%d"));
        tracing::info!("NVD: reading the history from {} to {}", from.format("%Y-%m-%d"), until.format("%Y-%m-%d"));
        let start_of_history = progress.as_ref().map_or(wanted, |p| p.from);
        self.import(db, from, until, Window::Published, &mut result, &mut |done_until| {
            Backfill { from: start_of_history, done_until, started: first_started }.save(db)
        })?;
        // What changed while the history was read over several runs
        if first_started < now {
            self.import(db, first_started - Duration::hours(1), now, Window::Modified, &mut result, &mut |_| Ok(()))?;
        }
        db.set_metadata(KEY_HISTORY_FROM, &start_of_history.to_rfc3339())?;
        db.delete_metadata(KEY_BACKFILL)?;
        tracing::info!("NVD: history read from {}", start_of_history.format("%Y-%m-%d"));
        Ok(result)
    }
}

/// The history is known from this date on
const KEY_HISTORY_FROM: &str = "nvd.history_from";
/// Reading of the history in progress: "from done_until started"
const KEY_BACKFILL: &str = "nvd.backfill";
/// The oldest CVEs were published in October 1988
const FIRST_PUBLICATION: &str = "1988-01-01T00:00:00Z";

/// Where the history starts: `months` back, or the first publication for 0
fn history_start(months: u32, now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    let first = chrono::DateTime::parse_from_rfc3339(FIRST_PUBLICATION).expect("constant date").with_timezone(&Utc);
    match months {
        0 => first,
        months => (now - chrono::Duration::days(months as i64 * 30)).max(first),
    }
}

fn parse_date(text: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(text).ok().map(|d| d.with_timezone(&Utc))
}

fn stored_date(db: &Database, key: &str) -> Result<Option<chrono::DateTime<Utc>>> {
    Ok(db.get_metadata(key)?.as_deref().and_then(parse_date))
}

/// A reading of the history that did not reach its end yet
#[derive(Debug, PartialEq)]
struct Backfill {
    /// Where the history being read starts
    from: chrono::DateTime<Utc>,
    /// Everything published before this date is read
    done_until: chrono::DateTime<Utc>,
    /// When the reading began: what changed since is read at the end
    started: chrono::DateTime<Utc>,
}

impl Backfill {
    fn load(db: &Database) -> Result<Option<Self>> {
        let Some(text) = db.get_metadata(KEY_BACKFILL)? else {
            return Ok(None);
        };
        let mut dates = text.split(' ').map(parse_date);
        Ok(match (dates.next().flatten(), dates.next().flatten(), dates.next().flatten()) {
            (Some(from), Some(done_until), Some(started)) => Some(Self { from, done_until, started }),
            _ => None,
        })
    }

    fn save(&self, db: &Database) -> Result<()> {
        db.set_metadata(KEY_BACKFILL, &format!("{} {} {}", self.from.to_rfc3339(), self.done_until.to_rfc3339(), self.started.to_rfc3339()))
    }
}

/// Which date of a CVE a period is about
#[derive(Clone, Copy, PartialEq)]
enum Window {
    /// Published in the period: the history. Nothing is recorded as a change.
    Published,
    /// Modified in the period: what happened since the last run
    Modified,
}

impl NvdSource {
    /// Reads every CVE published (or modified) between two dates, by periods
    /// of 100 days (the NVD refuses more than 120). Stops at the first period
    /// that cannot be read entirely: what was read is kept, `period_done` was
    /// called for every period before it, and the run fails.
    fn import(
        &self,
        db: &Database,
        from: chrono::DateTime<Utc>,
        until: chrono::DateTime<Utc>,
        window: Window,
        result: &mut SyncResult,
        period_done: &mut dyn FnMut(chrono::DateTime<Utc>) -> Result<()>,
    ) -> Result<()> {
        use chrono::Duration;
        use indicatif::{ProgressBar, ProgressStyle};
        const CHUNK_DAYS: i64 = 100;
        let total_chunks = ((until - from).num_days().max(1) / CHUNK_DAYS) + 1;
        let by_modification = window == Window::Modified;
        let mut chunk_start = from;
        let mut chunk_num = 0;

        while chunk_start < until {
            chunk_num += 1;
            let chunk_end = std::cmp::min(chunk_start + Duration::days(CHUNK_DAYS), until);
            let date_start = chunk_start.format("%Y-%m-%dT%H:%M:%S.000").to_string();
            let date_end = chunk_end.format("%Y-%m-%dT%H:%M:%S.999").to_string();
            let period = format!("{} → {}", chunk_start.format("%Y-%m-%d"), chunk_end.format("%Y-%m-%d"));
            let failed = |e: anyhow::Error, result: &SyncResult| {
                anyhow::anyhow!(
                    "the period {period} could not be read from the NVD ({} added, {} updated before that; the next run goes on from there): {e}",
                    result.added,
                    result.updated
                )
            };

            let mut start_index = 0;
            let mut progress: Option<ProgressBar> = None;
            loop {
                let response = match self.fetch_page(start_index, &date_start, &date_end, by_modification) {
                    Ok(r) => r,
                    Err(e) => {
                        if let Some(pb) = &progress {
                            pb.abandon_with_message(format!("Error: {e}"));
                        }
                        result.errors += 1;
                        return Err(failed(e, result));
                    }
                };
                let total = response.total_results;
                if total == 0 {
                    println!("  ○ Period {chunk_num}/{total_chunks}: nothing");
                    break;
                }
                let pb = progress.get_or_insert_with(|| {
                    let pb = ProgressBar::new(total as u64);
                    pb.set_style(
                        ProgressStyle::default_bar()
                            .template("  [{bar:40.cyan/blue}] {pos}/{len} CVEs ({percent}%) - {msg}")
                            .unwrap()
                            .progress_chars("█▓░"),
                    );
                    pb.set_message(format!("Period {chunk_num}/{total_chunks}: {period}"));
                    pb
                });
                for vuln in &response.vulnerabilities {
                    let mut cve = self.convert_to_cve(vuln);
                    if cve.affected_products.is_empty() {
                        if let Some(ref desc) = cve.description {
                            cve.affected_products = extraction::extract_from_description(desc);
                        }
                    }
                    let stored = match window {
                        Window::Modified => db.upsert_cve(&cve),
                        Window::Published => db.upsert_cve_untracked(&cve),
                    };
                    result.count(stored);
                }
                start_index += RESULTS_PER_PAGE;
                pb.set_position(start_index.min(total) as u64);
                if start_index >= total || response.vulnerabilities.is_empty() {
                    pb.finish_with_message(format!("Period {chunk_num}/{total_chunks}: {total} CVEs ✓"));
                    break;
                }
            }

            period_done(chunk_end)?;
            chunk_start = chunk_end;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_bound_of_a_range_is_included_or_not() {
        let node: NvdNode = serde_json::from_str(
            r#"{"cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "1.4"},
                {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionStartExcluding": "2.0", "versionEndIncluding": "2.3"},
                {"vulnerable": false, "criteria": "cpe:2.3:o:acme:os:*:*:*:*:*:*:*:*"}
            ]}"#,
        )
        .unwrap();
        let mut products = Vec::new();
        NvdSource::extract_cpe_matches(&mut products, &node);
        let bounds: Vec<_> = products
            .iter()
            .map(|p| (p.version_start.as_deref(), p.version_start_excluded, p.version_end.as_deref(), p.version_end_included))
            .collect();
        assert_eq!(bounds, [(Some("1.0"), false, Some("1.4"), false), (Some("2.0"), true, Some("2.3"), true)]);
    }

    #[test]
    fn the_history_starts_at_the_first_publication_unless_limited() {
        let now = parse_date("2026-11-22T00:00:00Z").unwrap();
        assert_eq!(history_start(0, now), parse_date(FIRST_PUBLICATION).unwrap());
        assert_eq!(history_start(6, now), parse_date("2026-05-26T00:00:00Z").unwrap());
        assert_eq!(history_start(100_000, now), parse_date(FIRST_PUBLICATION).unwrap());
    }

    #[test]
    fn an_interrupted_reading_of_the_history_is_remembered() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(Backfill::load(&db).unwrap(), None);
        let reading = Backfill {
            from: parse_date(FIRST_PUBLICATION).unwrap(),
            done_until: parse_date("2014-03-01T00:00:00Z").unwrap(),
            started: parse_date("2026-11-22T08:00:00Z").unwrap(),
        };
        reading.save(&db).unwrap();
        assert_eq!(Backfill::load(&db).unwrap(), Some(reading));
        db.set_metadata(KEY_BACKFILL, "garbage").unwrap();
        assert_eq!(Backfill::load(&db).unwrap(), None);
    }
}
