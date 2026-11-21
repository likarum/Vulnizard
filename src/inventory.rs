//! Collecting what is deployed: reading an inventory (pushed by a collector
//! or fetched from a file in a Git repository) and announcing new probable
//! services.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

use crate::config::Config;
use crate::db::{Component, Database, IngestOutcome, InventorySource};

/// An inventory file larger than this is refused
const MAX_INVENTORY_BYTES: u64 = 5 * 1024 * 1024;

/// Reads an inventory: the simple format (`{"components": [...]}` or a bare
/// list) or a CycloneDX JSON SBOM.
pub fn parse_inventory(text: &str) -> Result<Vec<Component>> {
    let value: Value = serde_json::from_str(text).context("the inventory is not valid JSON")?;
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        return Ok(parse_cyclonedx(&value));
    }
    let list = match &value {
        Value::Array(_) => value.clone(),
        Value::Object(o) => o
            .get("components")
            .cloned()
            .ok_or_else(|| anyhow!("the inventory has no \"components\" list"))?,
        _ => bail!("the inventory must be a list of components"),
    };
    serde_json::from_value(list).context("a component of the inventory is invalid (name is required)")
}

fn parse_cyclonedx(bom: &Value) -> Vec<Component> {
    let mut out = Vec::new();
    for c in bom.get("components").and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = c.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut component = Component {
            name: name.to_string(),
            version: c.get("version").and_then(Value::as_str).map(String::from),
            ..Default::default()
        };
        // cpe:2.3:a:vendor:product:version:… gives the names used by the CVE database
        if let Some(cpe) = c.get("cpe").and_then(Value::as_str) {
            let parts: Vec<&str> = cpe.split(':').collect();
            if parts.len() > 4 && parts[0] == "cpe" {
                component.vendor = Some(parts[3].to_string()).filter(|v| v != "*" && !v.is_empty());
                if !parts[4].is_empty() && parts[4] != "*" {
                    component.name = parts[4].to_string();
                }
            }
        }
        // pkg:npm/name@1.0 gives the package ecosystem
        if let Some(purl) = c.get("purl").and_then(Value::as_str) {
            component.ecosystem = purl
                .strip_prefix("pkg:")
                .and_then(|p| p.split('/').next())
                .map(String::from)
                .filter(|e| !e.is_empty());
        }
        component.exposed = c
            .get("properties")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|p| {
                p.get("name").and_then(Value::as_str) == Some("vulnizard:exposed")
                    && p.get("value").and_then(Value::as_str) == Some("true")
            });
        out.push(component);
    }
    out
}

/// Settings of a Git source
#[derive(Debug, Clone, PartialEq)]
pub struct GitSource {
    /// forgejo | gitea | github | gitlab | raw
    pub provider: String,
    /// Repository URL, e.g. https://git.example.org/owner/repo (or the file URL for `raw`)
    pub repository: String,
    pub branch: String,
    /// Path of the inventory file in the repository
    pub path: String,
    pub token: Option<String>,
}

pub const GIT_PROVIDERS: [(&str, &str); 5] = [
    ("forgejo", "Forgejo"),
    ("gitea", "Gitea"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("raw", "Other (direct file URL)"),
];

impl GitSource {
    pub fn from_config(config: &Value) -> Option<GitSource> {
        let text = |key: &str| config.get(key).and_then(Value::as_str).map(String::from);
        Some(GitSource {
            provider: text("provider")?,
            repository: text("repository")?,
            branch: text("branch").unwrap_or_default(),
            path: text("path").unwrap_or_default(),
            token: text("token").filter(|t| !t.is_empty()),
        })
    }

    pub fn to_config(&self) -> Value {
        serde_json::json!({
            "provider": self.provider,
            "repository": self.repository,
            "branch": self.branch,
            "path": self.path,
            "token": self.token,
        })
    }

    /// Checks the settings (the URL itself is validated when it is fetched)
    pub fn validate(&self) -> Result<()> {
        if !GIT_PROVIDERS.iter().any(|(key, _)| *key == self.provider) {
            bail!("unknown Git provider");
        }
        let repository = self.repository.trim_end_matches('/');
        if !(repository.starts_with("https://") || repository.starts_with("http://")) || repository.len() > 500 {
            bail!("the repository must be an http(s) URL");
        }
        if self.provider != "raw" {
            let clean = |s: &str, max: usize| {
                !s.is_empty()
                    && s.len() <= max
                    && !s.contains("..")
                    && !s.starts_with('/')
                    && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
            };
            if !clean(&self.branch, 100) {
                bail!("invalid branch name");
            }
            if !clean(&self.path, 300) {
                bail!("invalid file path (relative path of the inventory file in the repository)");
            }
        }
        if self.token.is_some() && !repository.starts_with("https://") {
            bail!("an access token is only sent over https");
        }
        if self.token.as_deref().is_some_and(|t| t.len() > 500 || t.chars().any(|c| c.is_control() || c.is_whitespace())) {
            bail!("invalid access token");
        }
        Ok(())
    }

    /// The one URL Vulnizard reads: the inventory file, nothing else
    pub fn file_url(&self) -> String {
        let repository = self.repository.trim_end_matches('/');
        match self.provider.as_str() {
            "forgejo" | "gitea" => format!("{repository}/raw/branch/{}/{}", self.branch, self.path),
            "gitlab" => format!("{repository}/-/raw/{}/{}", self.branch, self.path),
            "github" => {
                let owner_repo = repository.trim_start_matches("https://github.com/").trim_end_matches(".git");
                format!("https://raw.githubusercontent.com/{owner_repo}/{}/{}", self.branch, self.path)
            }
            _ => repository.to_string(),
        }
    }

    /// Header carrying the read-only access token, per provider
    fn auth_header(&self) -> Option<(&'static str, String)> {
        let token = self.token.as_deref()?;
        Some(match self.provider.as_str() {
            "forgejo" | "gitea" => ("Authorization", format!("token {token}")),
            "gitlab" => ("PRIVATE-TOKEN", token.to_string()),
            _ => ("Authorization", format!("Bearer {token}")),
        })
    }
}

/// Fetches the inventory file of a Git source (read-only, one file)
fn fetch(config: &Config, git: &GitSource) -> Result<String> {
    git.validate()?;
    // Same rule as notification targets: private addresses only if the instance allows them
    let target = crate::notify::check_webhook_url(config, &git.file_url())
        .map_err(|_| anyhow!("the file URL is not allowed (private addresses must be allowed in Admin > Notifications > Delivery)"))?;
    let mut request = crate::notify::client_for(&target)?
        .get(target.url.clone())
        .timeout(Duration::from_secs(20));
    if let Some((name, value)) = git.auth_header() {
        request = request.header(name, value);
    }
    let response = request.send().map_err(|e| anyhow!("{}", e.without_url()))?;
    if !response.status().is_success() {
        bail!("the Git server answered HTTP {}", response.status());
    }
    let mut text = String::new();
    response
        .take(MAX_INVENTORY_BYTES + 1)
        .read_to_string(&mut text)
        .context("the inventory file is not text")?;
    if text.len() as u64 > MAX_INVENTORY_BYTES {
        bail!("the inventory file is too large");
    }
    Ok(text)
}

/// Reads a Git source and ingests its inventory. The outcome (or the error)
/// is recorded on the source.
pub fn pull(db: &Database, config: &Config, source: &InventorySource) -> Result<IngestOutcome> {
    let result = (|| {
        let git = GitSource::from_config(&source.config).ok_or_else(|| anyhow!("incomplete Git settings"))?;
        let components = parse_inventory(&fetch(config, &git)?)?;
        db.ingest_inventory(source, &components)
    })();
    match &result {
        Ok(outcome) => announce(db, config, source, outcome),
        Err(e) => db.record_inventory_run(source.id, Some(&format!("{e:#}")))?,
    }
    result
}

/// Tells the project when new probable services appeared
pub fn announce(db: &Database, config: &Config, source: &InventorySource, outcome: &IngestOutcome) {
    if outcome.new_probable_services.is_empty() {
        return;
    }
    let listed: Vec<&str> = outcome.new_probable_services.iter().take(10).map(String::as_str).collect();
    let more = outcome.new_probable_services.len() - listed.len();
    let mut body = format!("Discovered by “{}”: {}", source.name, listed.join(", "));
    if more > 0 {
        body.push_str(&format!(" and {more} more"));
    }
    body.push_str(". Choose whether to monitor them.");
    let title = format!("{} new probable service(s)", outcome.new_probable_services.len());
    if let Err(e) = crate::notify::project_event(config, db, source.project_id, "service", &title, &body, "applications") {
        tracing::warn!("inventory: notification failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_inventories_are_read() {
        let list = parse_inventory(r#"[{"name":"nginx","version":"1.30.6","exposed":true},{"name":"libfoo"}]"#).unwrap();
        assert_eq!((list.len(), list[0].exposed, list[1].version.as_deref()), (2, true, None));
        let object = parse_inventory(r#"{"components":[{"name":"openssh","version":"10.6","vendor":"openbsd"}]}"#).unwrap();
        assert_eq!(object[0].vendor.as_deref(), Some("openbsd"));
        assert!(parse_inventory("not json").is_err());
        assert!(parse_inventory(r#"{"nothing":1}"#).is_err());
        assert!(parse_inventory(r#"[{"version":"1"}]"#).is_err());
    }

    #[test]
    fn cyclonedx_gives_exact_names_and_ecosystems() {
        let bom = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"type":"application","name":"OpenSSH Server","version":"10.6","cpe":"cpe:2.3:a:openbsd:openssh:10.6:*:*:*:*:*:*:*"},
            {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
            {"type":"application","name":"nginx","version":"1.30","properties":[{"name":"vulnizard:exposed","value":"true"}]},
            {"type":"file"}
        ]}"#;
        let components = parse_inventory(bom).unwrap();
        assert_eq!(components.len(), 3);
        assert_eq!((components[0].name.as_str(), components[0].vendor.as_deref()), ("openssh", Some("openbsd")));
        assert_eq!(components[1].ecosystem.as_deref(), Some("npm"));
        assert!(components[2].exposed && !components[0].exposed);
    }

    #[test]
    fn git_sources_read_exactly_one_file() {
        let git = |provider: &str, repository: &str| GitSource {
            provider: provider.into(),
            repository: repository.into(),
            branch: "main".into(),
            path: "inventory/io.json".into(),
            token: Some("t0ken".into()),
        };
        let forgejo = git("forgejo", "https://git.example.org/me/nixos/");
        assert_eq!(forgejo.file_url(), "https://git.example.org/me/nixos/raw/branch/main/inventory/io.json");
        assert_eq!(forgejo.auth_header(), Some(("Authorization", "token t0ken".to_string())));
        assert_eq!(
            git("github", "https://github.com/me/infra.git").file_url(),
            "https://raw.githubusercontent.com/me/infra/main/inventory/io.json"
        );
        let gitlab = git("gitlab", "https://gitlab.com/me/infra");
        assert_eq!(gitlab.file_url(), "https://gitlab.com/me/infra/-/raw/main/inventory/io.json");
        assert_eq!(gitlab.auth_header().unwrap().0, "PRIVATE-TOKEN");
        assert_eq!(git("raw", "https://example.org/inv.json").file_url(), "https://example.org/inv.json");
        // Settings survive storage
        assert_eq!(GitSource::from_config(&forgejo.to_config()), Some(forgejo.clone()));

        assert!(forgejo.validate().is_ok());
        for (field, value) in [("path", "../secrets.json"), ("path", "/etc/passwd"), ("branch", "main branch"), ("path", "")] {
            let mut bad = forgejo.clone();
            match field {
                "path" => bad.path = value.into(),
                _ => bad.branch = value.into(),
            }
            assert!(bad.validate().is_err(), "{field}={value}");
        }
        assert!(git("svn", "https://example.org/x").validate().is_err());
        assert!(git("forgejo", "ssh://git@example.org/x").validate().is_err());
    }
}
