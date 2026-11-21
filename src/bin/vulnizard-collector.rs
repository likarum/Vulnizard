//! vulnizard-collector — a small, explicit inventory collector.
//!
//! It gathers the name and version of what is deployed and delivers the list
//! to a Vulnizard inventory source. It collects **only what its configuration
//! lists** and sends nothing else: no file content, no hostname, no
//! environment. `--dry-run` prints exactly what would leave the machine.
//!
//! ```text
//! vulnizard-collector --config collector.toml --dry-run          # show
//! vulnizard-collector --config collector.toml --output inv.json  # write a file (Git source)
//! VULNIZARD_TOKEN=… vulnizard-collector --config collector.toml --server https://vulnizard.example.org
//! ```

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "vulnizard-collector", version, about = "Collects the names and versions of what is deployed, for Vulnizard")]
struct Cli {
    /// Configuration listing what to collect
    #[arg(short, long)]
    config: PathBuf,

    /// Vulnizard URL (the inventory is pushed to <server>/api/inventory)
    #[arg(long)]
    server: Option<String>,

    /// Environment variable holding the token of the inventory source
    #[arg(long, default_value = "VULNIZARD_TOKEN")]
    token_env: String,

    /// Print what would be sent, and send nothing
    #[arg(long)]
    dry_run: bool,

    /// Write the inventory to a file instead of sending it
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Component {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    exposed: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    collect: Vec<Collector>,
    #[serde(default)]
    filter: Filter,
    /// Collected name -> name known by the CVE database
    #[serde(default)]
    rename: BTreeMap<String, String>,
    /// Component name -> vendor known by the CVE database
    #[serde(default)]
    vendor: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum Collector {
    /// Container image references found in the given files (`image = "…"` / `image: …`)
    Images { files: Vec<String> },
    /// Output of a command you choose: a JSON object `{"name": "version"}` or a list of components
    Command { run: Vec<String> },
    /// Installed Debian packages: source package and version, nothing else.
    /// `release` overrides the detected one (e.g. "Debian:12").
    Dpkg {
        #[serde(default)]
        release: Option<String>,
    },
    /// Programs listening on a non-loopback address are marked as exposed
    Listening,
    /// Components written by hand
    Static { components: Vec<Component> },
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    /// When set, only the names matching one of these patterns are sent
    #[serde(default)]
    include: Vec<String>,
    /// Names matching one of these patterns are never sent
    #[serde(default)]
    exclude: Vec<String>,
}

/// `registry/owner/name:tag@sha256:…` -> (name, owner, version)
fn parse_image(reference: &str) -> Option<Component> {
    let without_digest = reference.split('@').next()?;
    let (path, tag) = match without_digest.rsplit_once(':') {
        // A colon before the last slash is a registry port, not a tag
        Some((path, tag)) if !tag.contains('/') => (path, Some(tag)),
        _ => (without_digest, None),
    };
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let name = segments.pop()?.to_lowercase();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return None;
    }
    // The owner, unless it is the registry host
    let vendor = segments
        .pop()
        .filter(|s| !s.contains('.') && !s.contains(':') && *s != "library")
        .map(str::to_lowercase);
    let version = tag
        .filter(|t| !matches!(*t, "latest" | "stable" | "main" | "master"))
        .map(|t| t.trim_start_matches('v').to_string());
    Some(Component {
        name,
        version,
        vendor,
        ..Default::default()
    })
}

fn collect_images(patterns: &[String]) -> Result<Vec<Component>> {
    let image = regex::Regex::new(r#"(?m)^\s*image\s*[=:]\s*["']?([A-Za-z0-9][A-Za-z0-9._/:@-]+)"#)?;
    let mut out = Vec::new();
    for pattern in patterns {
        for path in glob::glob(pattern).with_context(|| format!("invalid file pattern: {pattern}"))?.flatten() {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for capture in image.captures_iter(&text) {
                if let Some(component) = parse_image(&capture[1]) {
                    out.push(component);
                }
            }
        }
    }
    Ok(out)
}

fn collect_command(argv: &[String]) -> Result<Vec<Component>> {
    let (program, args) = argv.split_first().ok_or_else(|| anyhow!("a command collector needs a program"))?;
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !output.status.success() {
        bail!("{program} failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    parse_command_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_command_output(stdout: &str) -> Result<Vec<Component>> {
    let value: serde_json::Value = serde_json::from_str(stdout).context("the command did not print JSON")?;
    match value {
        serde_json::Value::Object(map) => Ok(map
            .into_iter()
            .map(|(name, version)| Component {
                name,
                version: version.as_str().map(String::from),
                ..Default::default()
            })
            .collect()),
        list @ serde_json::Value::Array(_) => Ok(serde_json::from_value(list).context("invalid component in the command output")?),
        _ => bail!("the command must print a JSON object or list"),
    }
}

/// "Debian:12" from the content of /etc/os-release
fn debian_release(os_release: &str) -> Result<String> {
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
            .map(|value| value.trim().trim_matches('"').to_string())
    };
    match (field("ID").as_deref(), field("VERSION_ID")) {
        (Some("debian"), Some(version)) if version.chars().all(|c| c.is_ascii_digit()) && !version.is_empty() => {
            Ok(format!("Debian:{version}"))
        }
        (Some("debian"), _) => bail!("this Debian has no release number (testing/unstable): set `release = \"Debian:14\"` in the dpkg collector"),
        (other, _) => bail!(
            "the dpkg collector supports Debian only for now (found: {}); set `release` to force one",
            other.unwrap_or("unknown")
        ),
    }
}

/// Installed packages from `dpkg-query -W -f '${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n'`.
/// Advisories are published per **source** package: binary packages built
/// from the same source collapse into one component.
fn parse_dpkg(output: &str, release: &str) -> Vec<Component> {
    let mut out: Vec<Component> = Vec::new();
    for line in output.lines() {
        let mut fields = line.split('\t');
        let (Some(name), Some(version), Some(status)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        // "ii ": installed; removed-but-configured packages are not running code
        if !status.starts_with("ii") || name.is_empty() || version.is_empty() {
            continue;
        }
        if out.iter().any(|c| c.name == name) {
            continue;
        }
        out.push(Component {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Some(release.to_string()),
            ..Default::default()
        });
    }
    out
}

fn collect_dpkg(release: Option<&str>) -> Result<Vec<Component>> {
    let release = match release {
        Some(release) => release.to_string(),
        None => debian_release(&std::fs::read_to_string("/etc/os-release").context("cannot read /etc/os-release")?)?,
    };
    let output = Command::new("dpkg-query")
        .args(["-W", "-f", "${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"])
        .output()
        .context("cannot run dpkg-query")?;
    if !output.status.success() {
        bail!("dpkg-query failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(parse_dpkg(&String::from_utf8_lossy(&output.stdout), &release))
}

/// Names of the programs listening on a non-loopback address (`ss -H -ltnp`)
fn parse_listening(ss_output: &str) -> Vec<String> {
    let process = regex::Regex::new(r#"users:\(\("([^"]+)""#).expect("valid regex");
    let mut names = Vec::new();
    for line in ss_output.lines() {
        let Some(local) = line.split_whitespace().nth(3) else {
            continue;
        };
        let address = local.rsplit_once(':').map(|(a, _)| a).unwrap_or(local);
        let loopback = address.starts_with("127.") || address == "[::1]" || address == "localhost";
        if loopback {
            continue;
        }
        if let Some(capture) = process.captures(line) {
            let name = capture[1].to_lowercase();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

fn collect_listening() -> Result<Vec<String>> {
    let output = Command::new("ss").args(["-H", "-ltnp"]).output().context("cannot run ss")?;
    Ok(parse_listening(&String::from_utf8_lossy(&output.stdout)))
}

fn matches_any(patterns: &[String], name: &str) -> bool {
    patterns
        .iter()
        .any(|p| glob::Pattern::new(p).map(|pattern| pattern.matches(name)).unwrap_or(false))
}

/// Applies renames, vendors and filters, and merges duplicates
fn finalize(config: &Config, collected: Vec<Component>, listening: &[String]) -> Vec<Component> {
    let mut merged: BTreeMap<String, Component> = BTreeMap::new();
    for mut component in collected {
        let original = component.name.to_lowercase();
        component.name = config.rename.get(&original).cloned().unwrap_or(original.clone());
        if listening.contains(&original) || listening.contains(&component.name) {
            component.exposed = true;
        }
        if component.vendor.is_none() {
            component.vendor = config.vendor.get(&component.name).cloned();
        }
        if let Some(vendor) = config.vendor.get(&component.name) {
            component.vendor = Some(vendor.clone());
        }
        match merged.get_mut(&component.name) {
            Some(existing) => {
                // Same component seen twice: keep what each occurrence knows
                existing.exposed |= component.exposed;
                existing.version = existing.version.take().or(component.version);
                existing.vendor = existing.vendor.take().or(component.vendor);
            }
            None => {
                merged.insert(component.name.clone(), component);
            }
        }
    }
    // A listening program not otherwise collected is still worth reporting
    for name in listening {
        let name = config.rename.get(name).cloned().unwrap_or_else(|| name.clone());
        merged.entry(name.clone()).or_insert_with(|| Component {
            vendor: config.vendor.get(&name).cloned(),
            name,
            exposed: true,
            ..Default::default()
        });
    }
    merged
        .into_values()
        .filter(|c| config.filter.include.is_empty() || matches_any(&config.filter.include, &c.name))
        .filter(|c| !matches_any(&config.filter.exclude, &c.name))
        .collect()
}

fn run(cli: &Cli) -> Result<()> {
    let text = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("cannot read {}", cli.config.display()))?;
    let config: Config = toml::from_str(&text).context("invalid configuration")?;
    if config.collect.is_empty() {
        bail!("the configuration lists nothing to collect");
    }

    let mut collected = Vec::new();
    let mut listening = Vec::new();
    for collector in &config.collect {
        match collector {
            Collector::Images { files } => collected.extend(collect_images(files)?),
            Collector::Command { run } => collected.extend(collect_command(run)?),
            Collector::Dpkg { release } => collected.extend(collect_dpkg(release.as_deref())?),
            Collector::Listening => listening = collect_listening()?,
            Collector::Static { components } => collected.extend(components.iter().cloned()),
        }
    }
    let components = finalize(&config, collected, &listening);
    let body = serde_json::to_string_pretty(&serde_json::json!({ "components": components }))?;

    if cli.dry_run {
        println!("{body}");
        eprintln!("{} component(s) would be sent; nothing was sent.", components.len());
        return Ok(());
    }
    if let Some(path) = &cli.output {
        std::fs::write(path, format!("{body}\n")).with_context(|| format!("cannot write {}", path.display()))?;
        eprintln!("{} component(s) written to {}", components.len(), path.display());
        return Ok(());
    }
    let server = cli
        .server
        .as_deref()
        .ok_or_else(|| anyhow!("--server is required (or use --dry-run / --output)"))?;
    check_server_url(server)?;
    let token = std::env::var(&cli.token_env)
        .map_err(|_| anyhow!("the token of the inventory source is expected in ${}", cli.token_env))?;
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?
        .post(format!("{}/api/inventory", server.trim_end_matches('/')))
        .bearer_auth(token.trim())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|e| anyhow!("cannot reach the server: {}", e.without_url()))?;
    let status = response.status();
    let answer = response.text().unwrap_or_default();
    if !status.is_success() {
        bail!("the server refused the inventory (HTTP {status}): {answer}");
    }
    eprintln!("{} component(s) sent: {answer}", components.len());
    Ok(())
}

fn main() {
    if let Err(e) = run(&Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

/// The token of the source travels with the inventory: https only, except to
/// this very machine (a local reverse proxy or a test instance).
fn check_server_url(server: &str) -> Result<()> {
    let url = reqwest::Url::parse(server).map_err(|_| anyhow!("--server is not a valid URL"))?;
    let local = match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost" || name.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if local => Ok(()),
        "http" => bail!("--server must be https: the token of the source would travel in clear"),
        _ => bail!("--server must be an https URL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(reference: &str) -> (String, Option<String>, Option<String>) {
        let c = parse_image(reference).unwrap();
        (c.name, c.vendor, c.version)
    }

    #[test]
    fn image_references_give_name_owner_and_version() {
        assert_eq!(image("vaultwarden/server:1.37.4"), ("server".into(), Some("vaultwarden".into()), Some("1.37.4".into())));
        assert_eq!(
            image("ghcr.io/pocket-id/pocket-id:v2.19.0@sha256:f7299b41ed76"),
            ("pocket-id".into(), Some("pocket-id".into()), Some("2.19.0".into()))
        );
        assert_eq!(image("eclipse-mosquitto:2.0.22"), ("eclipse-mosquitto".into(), None, Some("2.0.22".into())));
        assert_eq!(image("codeberg.org/forgejo/forgejo:17"), ("forgejo".into(), Some("forgejo".into()), Some("17".into())));
        // No usable version in a rolling tag; a registry port is not a tag
        assert_eq!(image("nousresearch/hermes-agent:latest").2, None);
        assert_eq!(image("registry.example.org:5000/team/app"), ("app".into(), Some("team".into()), None));
        assert_eq!(image("docker.io/library/nginx:1.30").1, None);
    }

    #[test]
    fn only_non_loopback_listeners_are_exposed() {
        let ss = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))\n\
                  LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=900,fd=6),(\"nginx\",pid=901,fd=6))\n\
                  LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=77,fd=7))\n\
                  LISTEN 0 128 [::1]:5432 [::]:* users:((\"postgres\",pid=5,fd=5))\n\
                  LISTEN 0 128 10.0.0.5:8080 0.0.0.0:*\n";
        assert_eq!(parse_listening(ss), ["sshd", "nginx"]);
    }

    #[test]
    fn nothing_but_the_listed_names_leaves_the_machine() {
        let config: Config = toml::from_str(
            r#"
            [[collect]]
            type = "static"
            components = [{ name = "placeholder" }]
            [filter]
            include = ["open*", "nginx", "dnsserver"]
            exclude = ["openssl"]
            [rename]
            sshd = "openssh"
            dns-server = "dnsserver"
            [vendor]
            openssh = "openbsd"
            "#,
        )
        .unwrap();
        let collected = vec![
            Component { name: "dns-server".into(), version: Some("15.6.2".into()), vendor: Some("technitium".into()), ..Default::default() },
            Component { name: "openssl".into(), version: Some("3.4".into()), ..Default::default() },
            Component { name: "secret-internal-tool".into(), version: Some("1".into()), ..Default::default() },
            Component { name: "nginx".into(), ..Default::default() },
            Component { name: "nginx".into(), version: Some("1.30.6".into()), ..Default::default() },
        ];
        let sent = finalize(&config, collected, &["sshd".to_string(), "nginx".to_string()]);
        let summary: Vec<(String, Option<String>, Option<String>, bool)> =
            sent.iter().map(|c| (c.name.clone(), c.version.clone(), c.vendor.clone(), c.exposed)).collect();
        assert_eq!(
            summary,
            vec![
                ("dnsserver".into(), Some("15.6.2".into()), Some("technitium".into()), false),
                ("nginx".into(), Some("1.30.6".into()), None, true),
                // A listening program with no known version is still reported, renamed
                ("openssh".into(), None, Some("openbsd".into()), true),
            ]
        );
        // Unknown keys are refused rather than silently ignored
        assert!(toml::from_str::<Config>("[[collect]]\ntype = \"everything\"").is_err());
        assert!(toml::from_str::<Config>("upload_files = true").is_err());
    }

    #[test]
    fn command_output_is_a_map_or_a_list() {
        let map = parse_command_output(r#"{"nginx":"1.30.6","openssh":"10.6p2"}"#).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.iter().any(|c| c.name == "nginx" && c.version.as_deref() == Some("1.30.6")));
        let list = parse_command_output(r#"[{"name":"mongodb","version":"8.0.34","exposed":true}]"#).unwrap();
        assert!(list[0].exposed);
        assert!(parse_command_output("plain text").is_err());
        assert!(parse_command_output("42").is_err());
    }

    #[test]
    fn dpkg_gives_source_packages_of_what_is_installed() {
        let output = "openssh\t1:9.2p1-2+deb12u3\tii \n\
                      openssh\t1:9.2p1-2+deb12u3\tii \n\
                      glibc\t2.36-9+deb12u9\tii \n\
                      nginx\t1.22.1-9\trc \n\
                      broken line\n";
        let components = parse_dpkg(output, "Debian:12");
        let summary: Vec<(&str, Option<&str>, Option<&str>)> =
            components.iter().map(|c| (c.name.as_str(), c.version.as_deref(), c.ecosystem.as_deref())).collect();
        assert_eq!(
            summary,
            [
                // openssh-client and openssh-server are one source package
                ("openssh", Some("1:9.2p1-2+deb12u3"), Some("Debian:12")),
                ("glibc", Some("2.36-9+deb12u9"), Some("Debian:12")),
            ]
        );
        assert_eq!(debian_release("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n").unwrap(), "Debian:12");
        assert!(debian_release("ID=debian\nVERSION_CODENAME=forky\n").is_err());
        assert!(debian_release("ID=ubuntu\nVERSION_ID=\"24.04\"\n").is_err());
        // The epoch and the Debian revision survive the final filtering
        let config: Config = toml::from_str("[[collect]]\ntype = \"dpkg\"\n[filter]\nexclude = [\"glibc\"]").unwrap();
        let sent = finalize(&config, components, &[]);
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0].version.as_deref(), sent[0].ecosystem.as_deref()), (Some("1:9.2p1-2+deb12u3"), Some("Debian:12")));
    }

    #[test]
    fn the_token_only_leaves_over_https_or_to_this_machine() {
        for ok in ["https://vulnizard.example.org", "https://10.0.0.5:8443/", "http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"] {
            assert!(check_server_url(ok).is_ok(), "{ok}");
        }
        for refused in ["http://vulnizard.example.org", "http://10.0.0.5:8000", "ftp://example.org", "vulnizard.example.org", ""] {
            assert!(check_server_url(refused).is_err(), "{refused}");
        }
    }
}
