//! Advisories of Linux distributions, from OSV's per-distribution exports.
//!
//! They say, for each release ("Debian:12") and source package, which
//! version fixes a CVE. They are what decides whether a system package
//! reported by an inventory source is vulnerable (see `db::distro`).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

use crate::db::{Database, DistroAdvisory};
use crate::sources::{CveSource, SyncOptions, SyncResult};

/// (family, export, oldest release kept)
const DISTROS: &[(&str, &str, u32)] = &[("Debian", "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip", 11)];

/// An export larger than this is refused
const MAX_EXPORT_BYTES: u64 = 1024 * 1024 * 1024;

pub struct DistrosSource {
    client: reqwest::blocking::Client,
}

impl DistrosSource {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(900))
            .user_agent("vulnizard/0.1")
            .build()
            .expect("Failed to create HTTP client");
        Self { client }
    }

    fn fetch(&self, family: &str, url: &str, oldest: u32) -> Result<Vec<DistroAdvisory>> {
        let response = self.client.get(url).send().with_context(|| format!("cannot fetch the {family} advisories"))?;
        if !response.status().is_success() {
            bail!("the {family} advisories answered HTTP {}", response.status());
        }
        let mut data = Vec::new();
        response.take(MAX_EXPORT_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_EXPORT_BYTES {
            bail!("the {family} advisories are larger than expected");
        }
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))?;
        let mut advisories = Vec::new();
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
            advisories.extend(parse_record(&content, family, oldest));
        }
        Ok(advisories)
    }
}

/// Reads one OSV record. Only the per-CVE records of the distribution's
/// security tracker are used (`DEBIAN-CVE-2024-6387`): they are the
/// authority on which version of which release fixes the CVE.
pub fn parse_record(json: &str, family: &str, oldest: u32) -> Vec<DistroAdvisory> {
    let Ok(record) = serde_json::from_str::<Record>(json) else {
        return Vec::new();
    };
    let prefix = format!("{}-", family.to_uppercase());
    let Some(cve_id) = record.id.strip_prefix(&prefix).filter(|id| id.starts_with("CVE-")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for affected in record.affected {
        // "Debian:12": keep supported releases only
        let release = affected.package.ecosystem.strip_prefix(family).and_then(|r| r.strip_prefix(':'));
        if !release.and_then(|r| r.parse::<u32>().ok()).is_some_and(|r| r >= oldest) {
            continue;
        }
        let urgency = affected.ecosystem_specific.and_then(|s| s.urgency);
        for range in affected.ranges.iter().filter(|r| r.kind == "ECOSYSTEM") {
            // Events come as introduced [fixed] introduced [fixed]…
            let mut introduced: Option<String> = None;
            let mut push = |introduced: String, fixed: Option<String>| {
                out.push(DistroAdvisory {
                    ecosystem: affected.package.ecosystem.clone(),
                    package: affected.package.name.clone(),
                    cve_id: cve_id.to_string(),
                    introduced,
                    fixed,
                    urgency: urgency.clone(),
                    details: record.details.clone(),
                    published: record.published.clone(),
                });
            };
            for event in &range.events {
                if let Some(start) = &event.introduced {
                    if let Some(open) = introduced.replace(start.clone()) {
                        push(open, None);
                    }
                } else if let Some(fixed) = &event.fixed {
                    push(introduced.take().unwrap_or_else(|| "0".into()), Some(fixed.clone()));
                }
            }
            if let Some(open) = introduced {
                push(open, None);
            }
        }
    }
    out
}

impl CveSource for DistrosSource {
    fn name(&self) -> &'static str {
        "distros"
    }

    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult> {
        let mut result = SyncResult::default();
        // Only useful once an inventory reports system packages
        if !db.has_distro_components()? {
            println!("━━━ Distributions: Skipped (no inventory reports system packages) ━━━");
            return Ok(SyncResult::skipped());
        }
        if opts.may_skip_if_fresh() {
            if let Some(last) = opts.last_sync {
                let hours = (chrono::Utc::now() - last).num_hours();
                if hours < super::min_hours("distros") && db.has_distro_advisories()? {
                    println!("━━━ Distributions: Skipped (last sync {hours}h ago) ━━━");
                    return Ok(SyncResult::skipped());
                }
            }
        }
        for (family, url, oldest) in DISTROS {
            println!("━━━ Distributions: fetching {family} advisories ━━━");
            match self.fetch(family, url, *oldest).and_then(|advisories| db.replace_distro_advisories(family, &advisories)) {
                Ok(count) => {
                    tracing::info!("{family}: {count} advisories");
                    result.updated += count as i64;
                }
                Err(e) => {
                    tracing::warn!("{family} advisories failed: {e:#}");
                    result.errors += 1;
                }
            }
        }
        if result.errors > 0 && result.updated == 0 {
            bail!("no distribution advisories could be fetched");
        }
        Ok(result)
    }
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: Package,
    #[serde(default)]
    ranges: Vec<Range>,
    #[serde(default)]
    ecosystem_specific: Option<Specific>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Specific {
    #[serde(default)]
    urgency: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_tracker_records_give_the_fixed_version_per_release() {
        // Shape of https://api.osv.dev/v1/vulns/DEBIAN-CVE-2024-6387
        let record = r#"{
          "id": "DEBIAN-CVE-2024-6387", "details": "A security regression was discovered in sshd.",
          "published": "2024-07-01T13:15:06.467Z", "upstream": ["CVE-2024-6387"],
          "affected": [
            {"package": {"name": "openssh", "ecosystem": "Debian:10"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
            {"package": {"name": "openssh", "ecosystem": "Debian:12", "purl": "pkg:deb/debian/openssh?arch=source&distro=bookworm"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}],
             "versions": ["1:9.2p1-2"], "ecosystem_specific": {"urgency": "not yet assigned"}},
            {"package": {"name": "openssh", "ecosystem": "Debian:13"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]},
                        {"type": "GIT", "events": [{"introduced": "abc"}]}],
             "ecosystem_specific": {"urgency": "unimportant"}}
          ]}"#;
        let advisories = parse_record(record, "Debian", 11);
        let summary: Vec<(&str, &str, Option<&str>, Option<&str>)> = advisories
            .iter()
            .map(|a| (a.ecosystem.as_str(), a.introduced.as_str(), a.fixed.as_deref(), a.urgency.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                ("Debian:12", "0", Some("1:9.2p1-2+deb12u3"), Some("not yet assigned")),
                // No fixed version yet on this release
                ("Debian:13", "0", None, Some("unimportant")),
            ]
        );
        assert!(advisories.iter().all(|a| a.cve_id == "CVE-2024-6387" && a.package == "openssh"));
        assert_eq!(advisories[0].details.as_deref(), Some("A security regression was discovered in sshd."));
        // Announcements (DSA, DLA) repeat the tracker and are not used; garbage is ignored
        assert!(parse_record(&record.replace("DEBIAN-CVE-2024-6387", "DSA-5724-1"), "Debian", 11).is_empty());
        assert!(parse_record("not json", "Debian", 11).is_empty());
    }

    /// Network test against the real export: `cargo test -- --ignored real_debian`
    #[test]
    #[ignore]
    fn real_debian_export_is_ingested() {
        let db = Database::open_in_memory().unwrap();
        let started = std::time::Instant::now();
        let advisories = DistrosSource::new().fetch("Debian", DISTROS[0].1, DISTROS[0].2).unwrap();
        println!("parsed {} advisories in {:?}", advisories.len(), started.elapsed());
        let started = std::time::Instant::now();
        db.replace_distro_advisories("Debian", &advisories).unwrap();
        println!("stored in {:?}", started.elapsed());
        for (release, version) in [("Debian:12", "1:9.2p1-2+deb12u2"), ("Debian:12", "1:9.2p1-2+deb12u3"), ("Debian:12", "1:9.2p1-2+deb12u99")] {
            let cves = db.distro_cves(release, "openssh", version).unwrap();
            println!("openssh {version} on {release}: {} CVEs, regreSSHion: {}", cves.len(), cves.contains(&"CVE-2024-6387".to_string()));
        }
        let releases: Vec<(String, i64)> = {
            let mut stmt = db.conn().prepare("SELECT ecosystem, COUNT(*) FROM distro_advisories GROUP BY 1 ORDER BY 1").unwrap();
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap();
            rows
        };
        println!("{releases:?}");
        assert!(db.distro_cves("Debian:12", "openssh", "1:9.2p1-2+deb12u2").unwrap().contains(&"CVE-2024-6387".to_string()));
        assert!(!db.distro_cves("Debian:12", "openssh", "1:9.2p1-2+deb12u3").unwrap().contains(&"CVE-2024-6387".to_string()));
    }
}
