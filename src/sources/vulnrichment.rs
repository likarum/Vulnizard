use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

use crate::db::Database;
use crate::sources::{CveSource, SyncOptions, SyncResult};

const VULNRICHMENT_ARCHIVE_URL: &str =
    "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.tar.gz";
const GITHUB_API_COMMITS: &str =
    "https://api.github.com/repos/cisagov/vulnrichment/commits";
const RAW_CONTENT_BASE: &str =
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop";

const METADATA_KEY_LAST_COMMIT: &str = "vulnrichment_last_commit";
const METADATA_KEY_LAST_SYNC: &str = "vulnrichment_last_sync";

pub struct VulnrichmentSource {
    client: reqwest::blocking::Client,
}

impl VulnrichmentSource {
    pub fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();

        // Add GitHub token if available
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if let Ok(auth_value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)) {
                headers.insert(reqwest::header::AUTHORIZATION, auth_value);
            }
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent("vulnizard/0.1")
            .default_headers(headers)
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Full sync: streams the repository tarball and reads the CVE files as
    /// they arrive. Nothing is buffered beyond one file, and the archive is
    /// never held in memory (it weighs several hundred megabytes).
    fn full_sync(&self, db: &Database) -> Result<SyncResult> {
        println!("  Downloading and reading the repository archive...");

        let response = self
            .client
            .get(VULNRICHMENT_ARCHIVE_URL)
            .send()
            .with_context(|| "Failed to download the Vulnrichment archive")?;

        if !response.status().is_success() {
            anyhow::bail!("GitHub returned status {}", response.status());
        }

        let ssvc_updates = read_ssvc_archive(response, |json| self.parse_ssvc(json))
            .with_context(|| "Failed to read the Vulnrichment archive")?;

        let mut result = SyncResult::default();
        if !ssvc_updates.is_empty() {
            println!("  Updating {} CVEs with SSVC data...", ssvc_updates.len());
            let updated = db.batch_update_ssvc(&ssvc_updates)?;
            result.updated = updated;
            result.added = ssvc_updates.len() as i64 - updated;
        }

        // Get and store latest commit SHA
        if let Ok(Some(sha)) = self.get_latest_commit_sha() {
            db.set_metadata(METADATA_KEY_LAST_COMMIT, &sha)?;
        }

        // Store sync timestamp
        db.set_metadata(METADATA_KEY_LAST_SYNC, &Utc::now().to_rfc3339())?;

        Ok(result)
    }

    /// Incremental sync via GitHub API
    fn incremental_sync(&self, db: &Database, since: DateTime<Utc>) -> Result<SyncResult> {
        use indicatif::{ProgressBar, ProgressStyle};

        let mut result = SyncResult::default();

        // Get last known commit SHA
        let last_commit = db.get_metadata(METADATA_KEY_LAST_COMMIT)?;

        // Fetch commits since last sync
        let commits_url = format!(
            "{}?since={}&per_page=100",
            GITHUB_API_COMMITS,
            since.to_rfc3339()
        );

        tracing::debug!("Fetching commits since {}", since);

        let response = self
            .client
            .get(&commits_url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .with_context(|| "Failed to fetch commits")?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::FORBIDDEN {
                println!("  GitHub rate limit reached. Set GITHUB_TOKEN env var for higher limits.");
                println!("  Falling back to full sync...");
                return self.full_sync(db);
            }
            anyhow::bail!(
                "GitHub API returned status {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            );
        }

        let commits: Vec<GitHubCommit> = response.json()
            .with_context(|| "Failed to parse commits response")?;

        // One page of commits is read. A full page means there are more (a long
        // interruption): rather than miss files, everything is read again.
        if commits.len() >= 100 {
            println!("  Too many commits since the last sync: full sync");
            return self.full_sync(db);
        }

        if commits.is_empty() {
            println!("  No new commits since last sync");
            return Ok(result);
        }

        // Get modified CVE files from each commit
        let mut modified_cve_files: std::collections::HashSet<String> = std::collections::HashSet::new();

        for commit in &commits {
            // Skip if we've already processed this commit
            if let Some(ref last) = last_commit {
                if &commit.sha == last {
                    continue;
                }
            }

            // Get commit details to see modified files
            let commit_url = format!("{}/{}", GITHUB_API_COMMITS, commit.sha);

            let commit_response = self
                .client
                .get(&commit_url)
                .header("Accept", "application/vnd.github.v3+json")
                .send();

            // A commit that cannot be read (rate limit, network) would leave its files
            // unknown while the sync is recorded as done: read everything instead
            let details = match commit_response {
                Ok(resp) if resp.status().is_success() => resp.json::<GitHubCommitDetails>().ok(),
                _ => None,
            };
            let Some(details) = details else {
                println!("  A commit could not be read: full sync");
                return self.full_sync(db);
            };
            for file in details.files {
                if file.filename.ends_with(".json") && file.filename.contains("/CVE-") {
                    modified_cve_files.insert(file.filename);
                }
            }
        }

        if modified_cve_files.is_empty() {
            println!("  No CVE files modified");
            db.set_metadata(METADATA_KEY_LAST_SYNC, &Utc::now().to_rfc3339())?;
            if let Some(sha) = commits.first().map(|c| &c.sha) {
                db.set_metadata(METADATA_KEY_LAST_COMMIT, sha)?;
            }
            return Ok(result);
        }

        println!("  Found {} modified CVE files", modified_cve_files.len());

        let pb = ProgressBar::new(modified_cve_files.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.green/black}] {pos}/{len} files ({percent}%)")
            .unwrap()
            .progress_chars("█▓░"));

        let mut ssvc_updates: Vec<(String, Option<String>, Option<String>, Option<String>)> = Vec::new();

        for file_path in &modified_cve_files {
            // Fetch raw file content
            let raw_url = format!("{}/{}", RAW_CONTENT_BASE, file_path);

            if let Ok(response) = self.client.get(&raw_url).send() {
                if response.status().is_success() {
                    if let Ok(content) = response.text() {
                        if let Some(cve_id) = extract_cve_id_from_path(file_path) {
                            if let Some(ssvc) = self.parse_ssvc(&content) {
                                ssvc_updates.push((
                                    cve_id,
                                    Some(ssvc.exploitation),
                                    Some(ssvc.automatable),
                                    Some(ssvc.technical_impact),
                                ));
                            }
                        }
                    }
                }
            }

            pb.inc(1);
        }

        pb.finish_and_clear();

        // Batch update SSVC fields
        if !ssvc_updates.is_empty() {
            println!("  Updating {} CVEs with SSVC data...", ssvc_updates.len());
            let updated = db.batch_update_ssvc(&ssvc_updates)?;
            result.updated = updated;
        }

        // Update metadata
        db.set_metadata(METADATA_KEY_LAST_SYNC, &Utc::now().to_rfc3339())?;
        if let Some(sha) = commits.first().map(|c| &c.sha) {
            db.set_metadata(METADATA_KEY_LAST_COMMIT, sha)?;
        }

        Ok(result)
    }

    /// Parse SSVC data from Vulnrichment JSON
    fn parse_ssvc(&self, json: &str) -> Option<SsvcData> {
        let doc: VulnrichmentDoc = serde_json::from_str(json).ok()?;

        // Look in containers.adp array
        for adp in doc.containers.adp.unwrap_or_default() {
            // Look in metrics array for SSVC
            for metric in adp.metrics.unwrap_or_default() {
                if let Some(other) = metric.other {
                    if other.metric_type == "ssvc" {
                        // Options are published as a list of single-key
                        // objects: [{"Exploitation": "none"}, {"Automatable": "yes"}, …]
                        // (a plain object is accepted too)
                        let options = other.content.as_ref().and_then(|c| c.get("options"));
                        let mut values = std::collections::HashMap::new();
                        match options {
                            Some(serde_json::Value::Array(list)) => {
                                for object in list.iter().filter_map(|o| o.as_object()) {
                                    for (key, value) in object {
                                        if let Some(text) = value.as_str() {
                                            values.insert(key.to_lowercase(), text.to_lowercase());
                                        }
                                    }
                                }
                            }
                            Some(serde_json::Value::Object(object)) => {
                                for (key, value) in object {
                                    if let Some(text) = value.as_str() {
                                        values.insert(key.to_lowercase(), text.to_lowercase());
                                    }
                                }
                            }
                            _ => {}
                        }
                        if !values.is_empty() {
                            let pick = |key: &str, default: &str| {
                                values.get(key).cloned().unwrap_or_else(|| default.to_string())
                            };
                            return Some(SsvcData {
                                exploitation: pick("exploitation", "none"),
                                automatable: pick("automatable", "no"),
                                technical_impact: pick("technical impact", "partial"),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Get latest commit SHA from GitHub
    fn get_latest_commit_sha(&self) -> Result<Option<String>> {
        let response = self
            .client
            .get(format!("{}?per_page=1", GITHUB_API_COMMITS))
            .header("Accept", "application/vnd.github.v3+json")
            .send()?;

        if response.status().is_success() {
            let commits: Vec<GitHubCommit> = response.json()?;
            Ok(commits.first().map(|c| c.sha.clone()))
        } else {
            Ok(None)
        }
    }
}

impl CveSource for VulnrichmentSource {
    fn name(&self) -> &'static str {
        "vulnrichment"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        // Check if sync should be skipped (< 24h since last sync)
        if opts.may_skip_if_fresh() {
            if let Ok(Some(last_sync_str)) = db.get_metadata(METADATA_KEY_LAST_SYNC) {
                if let Ok(last_sync) = DateTime::parse_from_rfc3339(&last_sync_str) {
                    let hours_since = (Utc::now() - last_sync.with_timezone(&Utc)).num_hours();
                    if hours_since < super::min_hours("vulnrichment") {
                        println!("━━━ Vulnrichment: Skipped (last sync {}h ago, updates daily) ━━━", hours_since);
                        return Ok(SyncResult::skipped());
                    }
                }
            }
        }

        println!("━━━ Vulnrichment: Fetching SSVC enrichment data... ━━━");

        // Determine sync mode
        let has_previous_sync = db.get_metadata(METADATA_KEY_LAST_COMMIT)?.is_some();

        if opts.force_full || !has_previous_sync {
            println!("  Mode: Full sync (downloading ZIP)");
            self.full_sync(db)
        } else if let Some(last) = opts.last_sync {
            println!("  Mode: Incremental sync (via GitHub API)");
            self.incremental_sync(db, last)
        } else {
            println!("  Mode: Full sync (no previous sync date)");
            self.full_sync(db)
        }
    }
}

/// A CVE record larger than this is skipped rather than read into memory
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

type SsvcUpdate = (String, Option<String>, Option<String>, Option<String>);

/// Reads a gzipped tar archive of the repository and returns the SSVC data of
/// every CVE file found in it.
fn read_ssvc_archive(
    archive: impl Read,
    parse: impl Fn(&str) -> Option<SsvcData>,
) -> Result<Vec<SsvcUpdate>> {
    let mut updates = Vec::new();
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_RECORD_BYTES {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if !(path.ends_with(".json") && path.contains("/CVE-")) {
            continue;
        }
        let Some(cve_id) = extract_cve_id_from_path(&path) else {
            continue;
        };
        let mut content = String::new();
        if entry.read_to_string(&mut content).is_err() {
            continue; // not UTF-8: not a CVE record
        }
        if let Some(ssvc) = parse(&content) {
            updates.push((
                cve_id,
                Some(ssvc.exploitation),
                Some(ssvc.automatable),
                Some(ssvc.technical_impact),
            ));
        }
    }
    Ok(updates)
}

/// Extract CVE ID from file path
fn extract_cve_id_from_path(path: &str) -> Option<String> {
    // Path format: vulnrichment-develop/2024/25xxx/CVE-2024-25522.json
    // or: 2024/25xxx/CVE-2024-25522.json
    let filename = path.rsplit('/').next()?;
    if filename.starts_with("CVE-") && filename.ends_with(".json") {
        Some(filename.trim_end_matches(".json").to_string())
    } else {
        None
    }
}

// ==========================================
// JSON Structures for Vulnrichment
// ==========================================

#[derive(Debug, Deserialize)]
struct VulnrichmentDoc {
    containers: Containers,
}

#[derive(Debug, Deserialize)]
struct Containers {
    adp: Option<Vec<AdpContainer>>,
}

#[derive(Debug, Deserialize)]
struct AdpContainer {
    metrics: Option<Vec<Metric>>,
}

#[derive(Debug, Deserialize)]
struct Metric {
    other: Option<OtherMetric>,
}

#[derive(Debug, Deserialize)]
struct OtherMetric {
    #[serde(rename = "type")]
    metric_type: String,
    /// Free-form: only the SSVC entries have the shape we read
    content: Option<serde_json::Value>,
}

// ==========================================
// GitHub API Structures
// ==========================================

#[derive(Debug, Deserialize)]
struct GitHubCommit {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitDetails {
    files: Vec<GitHubFile>,
}

#[derive(Debug, Deserialize)]
struct GitHubFile {
    filename: String,
}

// ==========================================
// Internal Structures
// ==========================================

#[derive(Debug)]
struct SsvcData {
    exploitation: String,      // none | poc | active
    automatable: String,       // yes | no
    technical_impact: String,  // partial | total
}

// ==========================================
// Tests
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cve_id_from_path() {
        // Standard path from ZIP
        assert_eq!(
            extract_cve_id_from_path("vulnrichment-develop/2024/25xxx/CVE-2024-25522.json"),
            Some("CVE-2024-25522".to_string())
        );

        // Raw GitHub path
        assert_eq!(
            extract_cve_id_from_path("2024/25xxx/CVE-2024-25522.json"),
            Some("CVE-2024-25522".to_string())
        );

        // Different year
        assert_eq!(
            extract_cve_id_from_path("2023/12xxx/CVE-2023-12345.json"),
            Some("CVE-2023-12345".to_string())
        );

        // Invalid paths
        assert_eq!(extract_cve_id_from_path("README.md"), None);
        assert_eq!(extract_cve_id_from_path("2024/25xxx/config.json"), None);
        assert_eq!(extract_cve_id_from_path(""), None);
    }

    #[test]
    fn test_parse_ssvc_complete() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "active",
                                            "Automatable": "yes",
                                            "Technical Impact": "total"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "active");
        assert_eq!(ssvc.automatable, "yes");
        assert_eq!(ssvc.technical_impact, "total");
    }

    #[test]
    fn test_parse_ssvc_poc_exploitation() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "poc",
                                            "Automatable": "no",
                                            "Technical Impact": "partial"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "poc");
        assert_eq!(ssvc.automatable, "no");
        assert_eq!(ssvc.technical_impact, "partial");
    }

    #[test]
    fn test_parse_ssvc_none_exploitation() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "none",
                                            "Automatable": "no",
                                            "Technical Impact": "partial"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "none");
        assert_eq!(ssvc.automatable, "no");
        assert_eq!(ssvc.technical_impact, "partial");
    }

    #[test]
    fn test_parse_ssvc_missing_fields_uses_defaults() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "active"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "active");
        assert_eq!(ssvc.automatable, "no"); // default
        assert_eq!(ssvc.technical_impact, "partial"); // default
    }

    #[test]
    fn test_parse_ssvc_no_ssvc_metrics() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "baseScore": 9.8
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ssvc_empty_adp() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": []
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ssvc_no_containers() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "cveMetadata": {
                "cveId": "CVE-2024-12345"
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ssvc_invalid_json() {
        let source = VulnrichmentSource::new();
        let json = "not valid json{";

        let result = source.parse_ssvc(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ssvc_multiple_adp_containers() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "baseScore": 7.5
                                }
                            }
                        ]
                    },
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "poc",
                                            "Automatable": "yes",
                                            "Technical Impact": "total"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "poc");
        assert_eq!(ssvc.automatable, "yes");
        assert_eq!(ssvc.technical_impact, "total");
    }

    #[test]
    fn test_parse_ssvc_with_other_metric_types() {
        let source = VulnrichmentSource::new();
        let json = r#"{
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "kev",
                                    "content": {
                                        "dateAdded": "2024-01-01"
                                    }
                                }
                            },
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": {
                                            "Exploitation": "active",
                                            "Automatable": "yes",
                                            "Technical Impact": "total"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let result = source.parse_ssvc(json);
        assert!(result.is_some());

        let ssvc = result.unwrap();
        assert_eq!(ssvc.exploitation, "active");
        assert_eq!(ssvc.automatable, "yes");
        assert_eq!(ssvc.technical_impact, "total");
    }

    #[test]
    fn ssvc_options_are_read_in_the_published_format() {
        // Shape of the real records: a list of single-key objects
        let record = r#"{"containers":{"adp":[{"metrics":[
            {"cvssV3_1":{"baseScore":9.8}},
            {"other":{"type":"ssvc","content":{"id":"CVE-1999-0006","options":[
                {"Exploitation":"Active"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}
        ]}]}}"#;
        let ssvc = VulnrichmentSource::new().parse_ssvc(record).expect("ssvc");
        assert_eq!(
            (ssvc.exploitation.as_str(), ssvc.automatable.as_str(), ssvc.technical_impact.as_str()),
            ("active", "yes", "total")
        );
        // Other "other" metrics, with another content shape, do not break the record
        let mixed = r#"{"containers":{"adp":[{"metrics":[
            {"other":{"type":"kev","content":{"dateAdded":"2024-01-01"}}},
            {"other":{"type":"ssvc","content":{"options":{"Exploitation":"poc"}}}}
        ]}]}}"#;
        let ssvc = VulnrichmentSource::new().parse_ssvc(mixed).expect("ssvc");
        assert_eq!((ssvc.exploitation.as_str(), ssvc.automatable.as_str()), ("poc", "no"));
        assert!(VulnrichmentSource::new().parse_ssvc(r#"{"containers":{}}"#).is_none());
    }

    #[test]
    fn archive_is_read_as_a_stream_of_cve_files() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        // A small repository tarball: two CVE records, one unrelated file
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, body) in [
            ("vulnrichment-develop/README.md", "# readme"),
            ("vulnrichment-develop/2024/25xxx/CVE-2024-25522.json", "{\"with\":\"ssvc\"}"),
            ("vulnrichment-develop/2024/25xxx/CVE-2024-25523.json", "{\"without\":true}"),
            ("vulnrichment-develop/2024/notes/other.json", "{}"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, body.as_bytes()).unwrap();
        }
        let archive = builder.into_inner().unwrap().finish().unwrap();

        let updates = read_ssvc_archive(&archive[..], |json| {
            json.contains("ssvc").then(|| SsvcData {
                exploitation: "active".into(),
                automatable: "yes".into(),
                technical_impact: "total".into(),
            })
        })
        .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, "CVE-2024-25522");
        assert_eq!(updates[0].1.as_deref(), Some("active"));

        // A truncated download is an error, not a silent partial result
        assert!(read_ssvc_archive(&archive[..archive.len() / 2], |_| None).is_err());
    }
}
