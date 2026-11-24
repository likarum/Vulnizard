use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    #[serde(default)]
    pub sync: SyncConfig,

    #[serde(default)]
    pub nvd: NvdConfig,

    #[serde(default)]
    pub web: WebConfig,

    /// SMTP settings for email notifications (optional)
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,

    /// Single sign-on through an OpenID Connect provider (optional)
    #[serde(default)]
    pub oidc: Option<OidcConfig>,

    /// Collecting what is deployed (inventory sources, collectors)
    #[serde(default)]
    pub inventory: InventoryConfig,
}

/// Inventory sources are not part of the first release: the feature is shown
/// greyed out and its endpoints are closed unless explicitly enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryConfig {
    /// Preview: sources pushed by a collector or read from Git, groups,
    /// distribution advisories
    pub enabled: bool,
}

/// OpenID Connect provider (authorization code flow with PKCE).
/// The redirect URI to register at the provider is `<web.base_url>/auth/oidc/callback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL, e.g. "https://id.example.org" (discovery document is fetched from it)
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Label of the login button
    #[serde(default = "default_oidc_name")]
    pub name: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: String,
    /// Create an account at the first login of an unknown user
    #[serde(default = "default_true")]
    pub auto_create: bool,
    /// Link a first SSO login to the existing local account whose username is
    /// exactly the provider's `preferred_username`. Administrator and disabled
    /// accounts are never linked. Only enable if the provider's usernames are
    /// trusted (users cannot choose them freely).
    #[serde(default)]
    pub link_existing_accounts: bool,
    /// Members of this group (from the `groups` claim) are administrators;
    /// when set, the flag is synchronized at every login.
    #[serde(default)]
    pub admin_group: Option<String>,
    /// When not empty, only verified emails of these domains may sign in
    /// (required for public providers such as Google).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

fn default_oidc_name() -> String {
    "SSO".to_string()
}

fn default_oidc_scopes() -> String {
    "openid profile email groups".to_string()
}

fn default_true() -> bool {
    true
}

/// Web server settings (`vulnizard serve`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Listen address
    pub bind: String,
    /// Public URL, used in notification links
    pub base_url: String,
    /// Allow self-registration from the UI (the first registered account is admin).
    /// Off by default: create accounts with `vulnizard user create`.
    pub allow_registration: bool,
    /// Minutes between two background syncs (0 disables the scheduler)
    pub sync_interval_minutes: u64,
    /// Set the Secure flag on the session cookie (enable behind HTTPS)
    pub secure_cookies: bool,
    /// Allow webhook/Slack notifications to target loopback or private addresses
    pub allow_private_webhooks: bool,
    /// Addresses of reverse proxies whose `X-Forwarded-For` is trusted to tell
    /// the client address (used to throttle sign-in attempts). A proxy on
    /// this machine (loopback) is always trusted.
    pub trusted_proxies: Vec<String>,
    /// Minutes before a source that just ran can be synchronized again on
    /// request (web, MCP). 0 = no limit. The periodic cycle is not concerned.
    pub min_manual_sync_minutes: u64,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8000".to_string(),
            base_url: "http://127.0.0.1:8000".to_string(),
            allow_registration: false,
            sync_interval_minutes: 60,
            secure_cookies: false,
            allow_private_webhooks: false,
            trusted_proxies: Vec::new(),
            min_manual_sync_minutes: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Sender address, e.g. "Vulnizard <vulnizard@example.org>"
    pub from: String,
}

fn default_smtp_port() -> u16 {
    587
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// How far back the NVD is read, in months; 0 (the default) reads the
    /// whole history. A tracked application is only matched against the CVEs
    /// the NVD was read for: a short history misses the older ones.
    #[serde(default = "default_history_months")]
    pub history_months: u32,

    /// Sources à synchroniser
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdConfig {
    /// API key NVD (optionnel, mais recommandé pour éviter le rate limiting)
    pub api_key: Option<String>,
}

fn default_db_path() -> PathBuf {
    PathBuf::from("vulnizard.db")
}

fn default_history_months() -> u32 {
    0
}

fn default_sources() -> Vec<String> {
    vec![
        "nvd".to_string(),
        "cisa_kev".to_string(),
        "epss".to_string(),
        "vulnrichment".to_string(),
        // Skips itself while no inventory reports system packages
        "distros".to_string(),
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            sync: SyncConfig::default(),
            nvd: NvdConfig::default(),
            web: WebConfig::default(),
            smtp: None,
            oidc: None,
            inventory: InventoryConfig::default(),
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            history_months: default_history_months(),
            sources: default_sources(),
        }
    }
}

impl Config {
    /// Charge la config depuis un fichier TOML
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse config file")?;
        Ok(config)
    }

    /// Charge la config depuis un fichier s'il existe, sinon utilise les valeurs par défaut
    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => Self::load(p),
            _ => Ok(Self::default()),
        }
    }

    /// Sauvegarde la config dans un fichier TOML
    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).with_context(|| "Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}
