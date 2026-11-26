//! OSV (Open Source Vulnerabilities): which packages of an ecosystem a CVE
//! affects, and in which versions.
//!
//! Each ecosystem is published as one archive of every advisory (hundreds
//! of megabytes for npm) and as a list of the advisories with the date each
//! last changed, newest first. The archive is read once; after that a run
//! reads the top of the list and fetches only the advisories that changed.
//! The archive is read again once a month, to catch what the list cannot
//! tell (an advisory deleted upstream), and when too much changed at once.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};

use crate::db::{add_ranges, Database, OsvStatement};
use crate::sources::{CveSource, SyncOptions, SyncResult};

const BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const ECOSYSTEMS: &[&str] = &["npm", "PyPI", "Go", "crates.io", "Maven"];

/// The whole archive is read again after this long
const WHOLE_EVERY_DAYS: i64 = 30;
/// More advisories changed than this: the archive is read instead of
/// fetching them one by one
const MAX_CHANGED: usize = 2000;
/// The list is read a little further back than the last advisory seen: an
/// advisory may be listed slightly after a more recent one
const MARGIN_MINUTES: i64 = 60;
/// An archive, or an advisory, larger than this is refused
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ADVISORY_BYTES: u64 = 8 * 1024 * 1024;

pub struct OsvSource {
    client: reqwest::blocking::Client,
    base: String,
}

/// What an archive, or a set of advisories, says: per advisory
type Advisories = Vec<(String, Vec<OsvStatement>)>;

impl OsvSource {
    pub fn new() -> Self {
        Self::at(BUCKET)
    }

    /// Reads from another address (the tests)
    fn at(base: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .user_agent(super::USER_AGENT)
            .build()
            .expect("Failed to create HTTP client");
        Self { client, base: base.trim_end_matches('/').to_string() }
    }

    /// Brings one ecosystem up to date. Returns the number of CVEs whose
    /// packages were worked out again.
    fn sync_ecosystem(&self, db: &Database, ecosystem: &str, opts: &SyncOptions) -> Result<i64> {
        let now = Utc::now();
        let seen = stored_time(db, &key_seen(ecosystem))?;
        let whole_at = stored_time(db, &key_whole(ecosystem))?;
        let whole_is_due = whole_at.is_none_or(|at| now - at > Duration::days(WHOLE_EVERY_DAYS));
        if let (Some(seen), false) = (seen, opts.force_full || whole_is_due) {
            let changed = self.changed_since(ecosystem, seen - Duration::minutes(MARGIN_MINUTES))?;
            if changed.len() <= MAX_CHANGED {
                return self.read_changed(db, ecosystem, seen, &changed);
            }
            tracing::info!("OSV {ecosystem}: {} advisories changed, the whole archive is read instead", changed.len());
        }
        self.read_whole(db, ecosystem, now)
    }

    /// The advisories that changed since a date, newest first: the top of
    /// the list of the ecosystem, read only as far as that date
    fn changed_since(&self, ecosystem: &str, since: DateTime<Utc>) -> Result<Vec<(DateTime<Utc>, String)>> {
        let url = format!("{}/{ecosystem}/modified_id.csv", self.base);
        let response = self.client.get(&url).send().with_context(|| format!("cannot fetch the list of changed {ecosystem} advisories"))?;
        if !response.status().is_success() {
            bail!("the list of changed {ecosystem} advisories answered HTTP {}", response.status());
        }
        let mut changed = Vec::new();
        let mut known = HashSet::new();
        for line in BufReader::new(response).lines() {
            let line = line.with_context(|| format!("the list of changed {ecosystem} advisories was cut"))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // A line that cannot be read stops the run rather than being skipped:
            // what it names would never be fetched
            let (at, id) = line.split_once(',').with_context(|| format!("unexpected line in the list of changed {ecosystem} advisories"))?;
            let at = DateTime::parse_from_rfc3339(at.trim())
                .with_context(|| format!("unexpected date in the list of changed {ecosystem} advisories"))?
                .with_timezone(&Utc);
            if at < since {
                // Newest first: everything below is older. The rest is not downloaded.
                break;
            }
            let id = id.trim();
            if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')) || id.starts_with('.') {
                bail!("unexpected advisory name in the list of changed {ecosystem} advisories");
            }
            if known.insert(id.to_string()) {
                changed.push((at, id.to_string()));
            }
        }
        Ok(changed)
    }

    /// Fetches the advisories that changed, one by one, and stores them. The
    /// date of the last advisory seen moves only if every one was read: a run
    /// that fails is made again from the same point.
    fn read_changed(&self, db: &Database, ecosystem: &str, seen: DateTime<Utc>, changed: &[(DateTime<Utc>, String)]) -> Result<i64> {
        let mut advisories: Advisories = Vec::new();
        for (_, id) in changed {
            let url = format!("{}/{ecosystem}/{id}.json", self.base);
            let response = self.client.get(&url).send().with_context(|| format!("cannot fetch the advisory {id}"))?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                // Listed, then removed: it stops counting
                advisories.push((id.clone(), Vec::new()));
                continue;
            }
            if !response.status().is_success() {
                bail!("the advisory {id} answered HTTP {}", response.status());
            }
            let mut content = String::new();
            response.take(MAX_ADVISORY_BYTES + 1).read_to_string(&mut content).with_context(|| format!("the advisory {id} was cut"))?;
            if content.len() as u64 > MAX_ADVISORY_BYTES {
                bail!("the advisory {id} is larger than expected");
            }
            match serde_json::from_str::<OsvVulnerability>(&content) {
                Ok(advisory) => advisories.push((id.clone(), statements_of(&advisory, ecosystem))),
                // As in an archive, an advisory that cannot be read is left as it was known
                Err(e) => tracing::warn!("OSV {ecosystem}: the advisory {id} could not be read ({e})"),
            }
        }
        let cves = db.osv_replace_advisories(ecosystem, &advisories)?;
        if let Some(newest) = changed.iter().map(|(at, _)| *at).max() {
            if newest > seen {
                db.set_metadata(&key_seen(ecosystem), &newest.to_rfc3339())?;
            }
        }
        tracing::info!("OSV {ecosystem}: {} advisories changed, {cves} CVEs worked out again", changed.len());
        Ok(cves)
    }

    /// Reads the whole archive of an ecosystem: it replaces everything known of it
    fn read_whole(&self, db: &Database, ecosystem: &str, now: DateTime<Utc>) -> Result<i64> {
        tracing::info!("OSV {ecosystem}: reading the whole archive");
        let url = format!("{}/{ecosystem}/all.zip", self.base);
        let response = self.client.get(&url).send().with_context(|| format!("cannot fetch the {ecosystem} archive"))?;
        if !response.status().is_success() {
            bail!("the {ecosystem} archive answered HTTP {}", response.status());
        }
        let mut data = Vec::new();
        response.take(MAX_ARCHIVE_BYTES + 1).read_to_end(&mut data).with_context(|| format!("the {ecosystem} archive was cut"))?;
        if data.len() as u64 > MAX_ARCHIVE_BYTES {
            bail!("the {ecosystem} archive is larger than expected");
        }
        let (advisories, newest) = parse_archive(&data, ecosystem)?;
        let cves = db.osv_replace_ecosystem(ecosystem, &advisories)?;
        // What changed after the archive was made is listed after its newest advisory.
        // An archive without a date: the list is read a day back, to be safe.
        db.set_metadata(&key_seen(ecosystem), &newest.unwrap_or(now - Duration::days(1)).to_rfc3339())?;
        db.set_metadata(&key_whole(ecosystem), &now.to_rfc3339())?;
        tracing::info!("OSV {ecosystem}: {} advisories about a CVE, {cves} CVEs", advisories.len());
        Ok(cves)
    }
}

fn key_seen(ecosystem: &str) -> String {
    format!("osv.{ecosystem}.seen")
}

fn key_whole(ecosystem: &str) -> String {
    format!("osv.{ecosystem}.whole_at")
}

fn stored_time(db: &Database, key: &str) -> Result<Option<DateTime<Utc>>> {
    Ok(db.get_metadata(key)?.and_then(|text| DateTime::parse_from_rfc3339(&text).ok()).map(|d| d.with_timezone(&Utc)))
}

/// Reads an archive: what each advisory says, and the date of the most
/// recently changed one
fn parse_archive(data: &[u8], ecosystem: &str) -> Result<(Advisories, Option<DateTime<Utc>>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))?;
    let mut advisories: Advisories = Vec::new();
    let mut newest: Option<DateTime<Utc>> = None;
    let mut content = String::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if !file.name().ends_with(".json") {
            continue;
        }
        content.clear();
        if file.read_to_string(&mut content).is_err() {
            continue;
        }
        let Ok(advisory) = serde_json::from_str::<OsvVulnerability>(&content) else {
            continue;
        };
        if let Some(at) = advisory.modified.as_deref().and_then(|m| DateTime::parse_from_rfc3339(m).ok()) {
            let at = at.with_timezone(&Utc);
            newest = Some(newest.map_or(at, |n| n.max(at)));
        }
        let statements = statements_of(&advisory, ecosystem);
        if !statements.is_empty() {
            let id = if advisory.id.is_empty() { file.name().trim_end_matches(".json").to_string() } else { advisory.id.clone() };
            advisories.push((id, statements));
        }
    }
    Ok((advisories, newest))
}

/// What an advisory says: for each CVE it is another name of, each package
/// of the ecosystem and the versions affected. Nothing for an advisory that
/// was withdrawn, or that is not about a CVE.
fn statements_of(advisory: &OsvVulnerability, ecosystem: &str) -> Vec<OsvStatement> {
    if advisory.withdrawn.is_some() {
        return Vec::new();
    }
    let cves: Vec<&String> = advisory.aliases.iter().filter(|a| a.starts_with("CVE-")).collect();
    let mut statements: Vec<OsvStatement> = Vec::new();
    for affected in &advisory.affected {
        let Some(package) = &affected.package else { continue };
        // An advisory may also name packages of other ecosystems: they are
        // read with their own ecosystem, where the advisory is listed too
        let other = &package.ecosystem;
        if !(other.is_empty() || other == ecosystem || other.strip_prefix(ecosystem).is_some_and(|rest| rest.starts_with(':'))) {
            continue;
        }
        let range = range_of(affected);
        let fixed = affected.ranges.iter().filter(|r| !r.kind.eq_ignore_ascii_case("GIT")).flat_map(|r| &r.events).find_map(|e| e.fixed.clone());
        for cve in &cves {
            // Several entries of one advisory may name the same package: their ranges add up
            match statements.iter_mut().find(|s| &s.cve_id == *cve && s.name == package.name) {
                Some(known) => {
                    known.vulnerable_range = add_ranges(known.vulnerable_range.take(), range.clone());
                    if known.fixed_version.is_none() {
                        known.fixed_version = fixed.clone();
                    }
                }
                None => statements.push(OsvStatement {
                    cve_id: (*cve).clone(),
                    name: package.name.clone(),
                    vulnerable_range: range.clone(),
                    fixed_version: fixed.clone(),
                }),
            }
        }
    }
    statements
}

impl CveSource for OsvSource {
    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        let mut result = SyncResult::default();
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours_since = (Utc::now() - last).num_hours();
                if hours_since < super::min_hours("osv") {
                    println!("━━━ OSV: Skipped (last sync {}h ago) ━━━", hours_since);
                    return Ok(SyncResult::skipped());
                }
            }
        }

        println!("━━━ OSV: package advisories ━━━");
        let mut failed = Vec::new();
        for ecosystem in ECOSYSTEMS {
            match self.sync_ecosystem(db, ecosystem, opts) {
                Ok(cves) => {
                    println!("  ✓ {ecosystem}: {cves} CVEs brought up to date");
                    result.updated += cves;
                }
                Err(e) => {
                    println!("  ✗ {ecosystem}: {e:#}");
                    tracing::warn!("OSV {ecosystem} failed: {e:#}");
                    result.errors += 1;
                    failed.push(format!("{ecosystem}: {e:#}"));
                }
            }
        }
        result.updated += db.osv_settle_late_cves()?;
        // What was read is kept; the run is recorded as failed so that the
        // ecosystems that could not be read are read again at the next cycle
        if !failed.is_empty() {
            bail!("{} of {} ecosystems could not be read; the next run reads them again ({})", failed.len(), ECOSYSTEMS.len(), failed.join("; "));
        }
        Ok(result)
    }
}

// OSV JSON structures
#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    #[serde(default)]
    id: String,
    /// When the advisory last changed
    #[serde(default)]
    modified: Option<String>,
    /// Set once the advisory is withdrawn: it no longer stands
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    /// Absent from an entry that only gives commit ranges of a repository
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

/// The version ranges of an affected package, as `>=1.0 <1.4 >=2.0 <=2.3`:
/// each `>=` opens a range that the next `<` or `<=` closes (a range left
/// open has no fix). Ranges given as Git commits are left out: they are not
/// versions. `None` when no version range is known.
fn range_of(affected: &OsvAffected) -> Option<String> {
    let events: Vec<String> = affected
        .ranges
        .iter()
        .filter(|r| !r.kind.eq_ignore_ascii_case("GIT"))
        .flat_map(|r| &r.events)
        .filter_map(|e| {
            if let Some(v) = &e.introduced {
                Some(format!(">={v}"))
            } else if let Some(v) = &e.fixed {
                Some(format!("<{v}"))
            } else {
                e.last_affected.as_ref().map(|v| format!("<={v}"))
            }
        })
        .collect();
    (!events.is_empty()).then(|| events.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Cve;
    use crate::sources::testserver::{Answer, Server};
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// A stand-in for the upstream: files that the test changes between runs
    struct Upstream {
        files: Arc<Mutex<HashMap<String, (u16, Vec<u8>)>>>,
        server: Server,
    }

    impl Upstream {
        fn start() -> Self {
            let files: Arc<Mutex<HashMap<String, (u16, Vec<u8>)>>> = Arc::default();
            let served = files.clone();
            let server = Server::start(move |asked| match served.lock().unwrap().get(&asked.path) {
                Some((200, body)) => Answer::ok(body.clone()),
                Some((status, _)) => Answer::status(*status),
                None => Answer::status(404),
            });
            Self { files, server }
        }

        fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
            self.files.lock().unwrap().insert(path.to_string(), (200, body.into()));
        }

        fn fail(&self, path: &str, status: u16) {
            self.files.lock().unwrap().insert(path.to_string(), (status, Vec::new()));
        }

        fn remove(&self, path: &str) {
            self.files.lock().unwrap().remove(path);
        }

        /// The archive of an ecosystem holding these advisories; the others are empty
        fn archive(&self, ecosystem: &str, advisories: &[String]) {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for (i, advisory) in advisories.iter().enumerate() {
                zip.start_file(format!("{i}.json"), zip::write::SimpleFileOptions::default()).unwrap();
                zip.write_all(advisory.as_bytes()).unwrap();
            }
            self.put(&format!("/{ecosystem}/all.zip"), zip.finish().unwrap().into_inner());
        }

        /// Every ecosystem published, empty, except what the test fills in
        fn publish_empty(&self) {
            for ecosystem in ECOSYSTEMS {
                self.archive(ecosystem, &[]);
                self.put(&format!("/{ecosystem}/modified_id.csv"), "");
            }
        }

        /// What was asked since the last call
        fn asked(&self, seen: &mut usize) -> Vec<String> {
            let all = self.server.paths();
            let new = all[*seen..].to_vec();
            *seen = all.len();
            new
        }
    }

    fn advisory(id: &str, modified: &str, cve: &str, package: &str, ecosystem: &str, fixed: &str) -> String {
        format!(
            r#"{{"id": "{id}", "modified": "{modified}", "aliases": ["{cve}"],
                "affected": [{{"package": {{"name": "{package}", "ecosystem": "{ecosystem}"}},
                               "ranges": [{{"type": "SEMVER", "events": [{{"introduced": "0"}}, {{"fixed": "{fixed}"}}]}}]}}]}}"#
        )
    }

    fn range(db: &Database, cve: &str, package: &str) -> Option<String> {
        db.conn()
            .query_row("SELECT vulnerable_range FROM affected_packages WHERE cve_id = ?1 AND name = ?2", [cve, package], |r| r.get::<_, Option<String>>(0))
            .ok()
            .flatten()
    }

    fn database() -> Database {
        let db = Database::open_in_memory().unwrap();
        for id in ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"] {
            db.upsert_cve(&Cve::new(id.into())).unwrap();
        }
        db
    }

    /// A run that does not wait for the delay between two runs
    fn run(source: &OsvSource, db: &Database) -> Result<SyncResult> {
        source.sync(db, &SyncOptions::new(0))
    }

    #[test]
    fn the_archive_is_read_once_then_only_what_changed() {
        let upstream = Upstream::start();
        upstream.publish_empty();
        upstream.archive(
            "Go",
            &[
                advisory("GO-1", "2026-03-01T10:00:00Z", "CVE-2024-1", "tool", "Go", "1.4"),
                advisory("GHSA-a", "2026-03-02T10:00:00Z", "CVE-2024-2", "lib", "Go", "2.0"),
            ],
        );
        let db = database();
        let source = OsvSource::at(&upstream.server.url);
        let mut seen = 0;

        // First run: nothing is known, every archive is read
        run(&source, &db).unwrap();
        assert_eq!(upstream.asked(&mut seen), ["/npm/all.zip", "/PyPI/all.zip", "/Go/all.zip", "/crates.io/all.zip", "/Maven/all.zip"]);
        assert_eq!(range(&db, "CVE-2024-1", "tool").as_deref(), Some(">=0 <1.4"));
        assert_eq!(range(&db, "CVE-2024-2", "lib").as_deref(), Some(">=0 <2.0"));

        // Upstream corrects one advisory and publishes a new one. The list names them, newest first,
        // above everything the archive already held.
        upstream.put("/Go/GO-1.json", advisory("GO-1", "2026-03-05T08:00:00Z", "CVE-2024-1", "tool", "Go", "1.5"));
        upstream.put("/Go/GO-2.json", advisory("GO-2", "2026-03-05T09:00:00Z", "CVE-2024-3", "newcomer", "Go", "0.9"));
        upstream.put("/Go/modified_id.csv", "2026-03-05T09:00:00Z,GO-2\n2026-03-05T08:00:00.123456789Z,GO-1\n2026-03-02T10:00:00Z,GHSA-a\n2026-03-01T10:00:00Z,GO-1-old\n");

        // Second run: no archive, the lists, and only the two advisories that changed.
        // GHSA-a is within the hour before the last one seen: it is not asked again beyond that margin,
        // and what is older than the margin is not asked at all.
        run(&source, &db).unwrap();
        let asked = upstream.asked(&mut seen);
        assert!(!asked.iter().any(|p| p.ends_with("all.zip")), "{asked:?}");
        assert_eq!(asked.iter().filter(|p| p.ends_with(".json")).collect::<Vec<_>>(), ["/Go/GO-2.json", "/Go/GO-1.json", "/Go/GHSA-a.json"]);
        assert_eq!(range(&db, "CVE-2024-1", "tool").as_deref(), Some(">=0 <1.5"));
        assert_eq!(range(&db, "CVE-2024-3", "newcomer").as_deref(), Some(">=0 <0.9"));
        // GHSA-a is listed but its file is not published here (404): the advisory was removed, it stops counting
        assert_eq!(range(&db, "CVE-2024-2", "lib"), None);

        // Third run, nothing new upstream: the lists only, and at most what the margin covers again
        run(&source, &db).unwrap();
        let asked = upstream.asked(&mut seen);
        assert!(!asked.iter().any(|p| p.ends_with("all.zip")), "{asked:?}");
        assert_eq!(asked.iter().filter(|p| p.ends_with(".json")).collect::<Vec<_>>(), ["/Go/GO-2.json", "/Go/GO-1.json"]);
        assert_eq!(range(&db, "CVE-2024-1", "tool").as_deref(), Some(">=0 <1.5"));
    }

    #[test]
    fn a_withdrawn_advisory_stops_counting() {
        let upstream = Upstream::start();
        upstream.publish_empty();
        upstream.archive("npm", &[advisory("GHSA-w", "2026-03-01T10:00:00Z", "CVE-2024-1", "left-pad", "npm", "2.0")]);
        let db = database();
        let source = OsvSource::at(&upstream.server.url);
        run(&source, &db).unwrap();
        assert_eq!(range(&db, "CVE-2024-1", "left-pad").as_deref(), Some(">=0 <2.0"));

        let withdrawn = advisory("GHSA-w", "2026-03-04T10:00:00Z", "CVE-2024-1", "left-pad", "npm", "2.0").replacen('{', r#"{"withdrawn": "2026-03-04T10:00:00Z", "#, 1);
        upstream.put("/npm/GHSA-w.json", withdrawn.clone());
        upstream.put("/npm/modified_id.csv", "2026-03-04T10:00:00Z,GHSA-w\n");
        run(&source, &db).unwrap();
        assert_eq!(range(&db, "CVE-2024-1", "left-pad"), None);

        // Withdrawn advisories of an archive do not count either
        let db = database();
        upstream.archive("npm", &[withdrawn]);
        run(&source, &db).unwrap();
        assert_eq!(range(&db, "CVE-2024-1", "left-pad"), None);
    }

    #[test]
    fn a_run_that_fails_is_made_again_from_the_same_point() {
        let upstream = Upstream::start();
        upstream.publish_empty();
        upstream.archive("PyPI", &[advisory("PYSEC-1", "2026-03-01T10:00:00Z", "CVE-2024-1", "django", "PyPI", "5.0")]);
        let db = database();
        let source = OsvSource::at(&upstream.server.url);
        run(&source, &db).unwrap();

        upstream.put("/PyPI/modified_id.csv", "2026-03-06T10:00:00Z,PYSEC-2\n2026-03-05T10:00:00Z,PYSEC-1\n");
        upstream.put("/PyPI/PYSEC-1.json", advisory("PYSEC-1", "2026-03-05T10:00:00Z", "CVE-2024-1", "django", "PyPI", "5.1"));
        upstream.fail("/PyPI/PYSEC-2.json", 503);
        // One advisory cannot be read: the run fails, says which ecosystem, and nothing of that ecosystem moves
        let failed = run(&source, &db).unwrap_err().to_string();
        assert!(failed.contains("1 of 5 ecosystems") && failed.contains("PyPI") && failed.contains("503"), "{failed}");
        assert_eq!(range(&db, "CVE-2024-1", "django").as_deref(), Some(">=0 <5.0"));

        // The server answers again: the same two advisories are read, none was lost
        upstream.put("/PyPI/PYSEC-2.json", advisory("PYSEC-2", "2026-03-06T10:00:00Z", "CVE-2024-2", "flask", "PyPI", "3.0"));
        run(&source, &db).unwrap();
        assert_eq!(range(&db, "CVE-2024-1", "django").as_deref(), Some(">=0 <5.1"));
        assert_eq!(range(&db, "CVE-2024-2", "flask").as_deref(), Some(">=0 <3.0"));

        // A list that cannot be read is an error too, not "nothing changed"
        upstream.put("/PyPI/modified_id.csv", "not a date,PYSEC-3\n");
        assert!(run(&source, &db).is_err());
        upstream.remove("/PyPI/modified_id.csv");
        assert!(run(&source, &db).is_err());
    }

    #[test]
    fn the_archive_is_read_again_after_a_month_when_too_much_changed_or_when_forced() {
        let upstream = Upstream::start();
        upstream.publish_empty();
        upstream.archive("Maven", &[advisory("GHSA-m", "2026-03-01T10:00:00Z", "CVE-2024-1", "org.acme:core", "Maven", "1.1")]);
        let db = database();
        let source = OsvSource::at(&upstream.server.url);
        let mut seen = 0;
        run(&source, &db).unwrap();
        upstream.asked(&mut seen);

        let archives = |asked: &[String]| asked.iter().filter(|p| p.ends_with("all.zip")).cloned().collect::<Vec<_>>();
        // Nothing special: no archive
        run(&source, &db).unwrap();
        assert!(archives(&upstream.asked(&mut seen)).is_empty());

        // The archive of one ecosystem was read more than a month ago: that one is read again, and it
        // drops what it no longer holds
        upstream.archive("Maven", &[]);
        db.set_metadata(&key_whole("Maven"), &(Utc::now() - Duration::days(WHOLE_EVERY_DAYS + 1)).to_rfc3339()).unwrap();
        run(&source, &db).unwrap();
        assert_eq!(archives(&upstream.asked(&mut seen)), ["/Maven/all.zip"]);
        assert_eq!(range(&db, "CVE-2024-1", "org.acme:core"), None);

        // More advisories changed than are fetched one by one: the archive instead, and none of them is asked
        let today = Utc::now().to_rfc3339();
        let many: String = (0..=MAX_CHANGED).map(|i| format!("{today},GHSA-{i}\n")).collect();
        upstream.put("/npm/modified_id.csv", many);
        run(&source, &db).unwrap();
        let asked = upstream.asked(&mut seen);
        assert_eq!(archives(&asked), ["/npm/all.zip"]);
        assert!(!asked.iter().any(|p| p.ends_with(".json")), "{asked:?}");

        // A forced full synchronization reads every archive
        source.sync(&db, &SyncOptions::new(0).force_full()).unwrap();
        assert_eq!(archives(&upstream.asked(&mut seen)).len(), ECOSYSTEMS.len());
    }

    #[test]
    fn packages_of_another_ecosystem_are_left_to_that_ecosystem() {
        let both: OsvVulnerability = serde_json::from_str(
            r#"{"id": "GHSA-x", "aliases": ["CVE-2024-1", "GHSA-other"],
                "affected": [
                  {"package": {"name": "protobuf", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}]},
                  {"package": {"name": "protobuf", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.2"}]}]},
                  {"package": {"name": "protobuf", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.1"}, {"fixed": "3.5"}]}]}
                ]}"#,
        )
        .unwrap();
        let npm = statements_of(&both, "npm");
        assert_eq!(npm.len(), 1);
        assert_eq!((npm[0].vulnerable_range.as_deref(), npm[0].fixed_version.as_deref()), (Some(">=0 <3.0 >=3.1 <3.5"), Some("3.0")));
        let pypi = statements_of(&both, "PyPI");
        assert_eq!(pypi[0].vulnerable_range.as_deref(), Some(">=0 <4.2"));
        assert!(statements_of(&both, "Go").is_empty());

        // An advisory that is not about a CVE says nothing
        let malware: OsvVulnerability = serde_json::from_str(r#"{"id": "MAL-1", "affected": [{"package": {"name": "evil", "ecosystem": "npm"}}]}"#).unwrap();
        assert!(statements_of(&malware, "npm").is_empty());

        // An entry without a package (commit ranges only) does not sink the others
        let mixed: OsvVulnerability = serde_json::from_str(
            r#"{"id": "EEF-x", "aliases": ["CVE-2024-2"],
                "affected": [
                  {"package": {"name": "phoenix", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.7"}]}]},
                  {"package": null, "ranges": [{"type": "GIT", "repo": "https://example.org/phoenix", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]},
                  {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
                ]}"#,
        )
        .unwrap();
        let npm = statements_of(&mixed, "npm");
        assert_eq!((npm.len(), npm[0].fixed_version.as_deref()), (1, Some("1.7")));
    }

    #[test]
    fn a_run_waits_its_delay_unless_asked_by_name() {
        let upstream = Upstream::start();
        upstream.publish_empty();
        let db = database();
        let source = OsvSource::at(&upstream.server.url);
        let recent = SyncOptions::new(0).with_last_sync(Some(Utc::now() - Duration::hours(1)));
        assert!(source.sync(&db, &recent).unwrap().skipped);
        assert!(upstream.server.paths().is_empty());
        assert!(!source.sync(&db, &recent.clone().ignore_freshness(true)).unwrap().skipped);
        assert!(!upstream.server.paths().is_empty());
    }

    #[test]
    fn version_ranges_are_kept_and_commit_ranges_left_out() {
        let affected: OsvAffected = serde_json::from_str(
            r#"{"package": {"name": "github.com/acme/tool/v3", "ecosystem": "Go"},
                "ranges": [
                  {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "0123456789abcdef0123456789abcdef01234567"}]},
                  {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.6.7"}, {"introduced": "3.7.0"}, {"last_affected": "3.7.2"}]}
                ]}"#,
        )
        .unwrap();
        assert_eq!(range_of(&affected).as_deref(), Some(">=0 <3.6.7 >=3.7.0 <=3.7.2"));

        let commits_only: OsvAffected = serde_json::from_str(
            r#"{"package": {"name": "tool"}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}"#,
        )
        .unwrap();
        assert_eq!(range_of(&commits_only), None);
    }
}
