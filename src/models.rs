use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Représentation unifiée d'une CVE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub cve_id: String,
    pub description: Option<String>,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v3_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub cwe_ids: Vec<String>,
    pub affected_products: Vec<AffectedProduct>,
    pub references: Vec<Reference>,
    pub kev_known_exploited: bool,
    pub kev_date_added: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,

    // Enrichissement: Exploitabilité
    #[serde(default)]
    pub exploit_public: bool,
    #[serde(default)]
    pub exploit_urls: Vec<String>,
    pub metasploit_module: Option<String>,
    pub nuclei_template: Option<String>,

    // Enrichissement: Packages écosystème
    #[serde(default)]
    pub affected_packages: Vec<AffectedPackage>,

    // Enrichissement: SSVC (Vulnrichment)
    pub ssvc_exploitation: Option<String>,      // "none" | "poc" | "active"
    pub ssvc_automatable: Option<String>,       // "yes" | "no"
    pub ssvc_technical_impact: Option<String>,  // "partial" | "total"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub version_start: Option<String>,
    #[serde(default)]
    pub version_end: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub ecosystem: String,           // npm, pip, go, maven, cargo, etc.
    pub name: String,                // Nom du package
    pub vulnerable_range: Option<String>, // >=1.0.0 <2.0.0
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
    pub source: Option<String>,
    pub tags: Vec<String>,
}

impl Cve {
    /// Sources that have data on this CVE, told from the fields each one fills
    /// (same rules as the `source` filter of the lists)
    pub fn sources(&self) -> Vec<&'static str> {
        let mut sources = Vec::new();
        let mut add = |present: bool, key: &'static str| {
            if present {
                sources.push(key);
            }
        };
        add(self.published_at.is_some(), "nvd");
        add(self.kev_known_exploited, "cisa_kev");
        add(self.epss_score.is_some(), "epss");
        add(
            self.ssvc_exploitation.is_some() || self.ssvc_automatable.is_some() || self.ssvc_technical_impact.is_some(),
            "vulnrichment",
        );
        add(!self.affected_packages.is_empty(), "osv");
        add(!self.exploit_urls.is_empty(), "exploitdb");
        add(self.metasploit_module.is_some(), "metasploit");
        add(self.nuclei_template.is_some(), "nuclei");
        sources
    }

    pub fn new(cve_id: String) -> Self {
        Self {
            cve_id,
            description: None,
            cvss_v3_score: None,
            cvss_v3_vector: None,
            epss_score: None,
            epss_percentile: None,
            cwe_ids: Vec::new(),
            affected_products: Vec::new(),
            references: Vec::new(),
            kev_known_exploited: false,
            kev_date_added: None,
            published_at: None,
            modified_at: None,
            // Enrichissement
            exploit_public: false,
            exploit_urls: Vec::new(),
            metasploit_module: None,
            nuclei_template: None,
            affected_packages: Vec::new(),
            // SSVC
            ssvc_exploitation: None,
            ssvc_automatable: None,
            ssvc_technical_impact: None,
        }
    }
}

/// Résultat de recherche pour affichage
#[derive(Debug)]
#[allow(dead_code)]
pub struct SearchResult {
    pub cve: Cve,
    pub relevance: f64,
}

// ==========================================
// Watchlist Models
// ==========================================

/// User in the watchlist system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub username: String,
    pub email: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl User {
    #[allow(dead_code)]
    pub fn new(username: String) -> Self {
        Self {
            id: None,
            username,
            email: None,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Project belonging to a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Option<i64>,
    pub user_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl Project {
    pub fn new(user_id: i64, name: String) -> Self {
        Self {
            id: None,
            user_id,
            name,
            description: None,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Application being monitored within a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Option<i64>,
    pub project_id: i64,
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub ecosystem: Option<String>,
    pub cpe_pattern: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// Group of inventory sources it is tracked for; empty when added by hand
    #[serde(default)]
    pub group: String,
}

impl Application {
    pub fn new(project_id: i64, name: String) -> Self {
        Self {
            id: None,
            project_id,
            name,
            version: None,
            vendor: None,
            ecosystem: None,
            cpe_pattern: None,
            notes: None,
            created_at: None,
            updated_at: None,
            group: String::new(),
        }
    }
}

/// CVE tracking status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CveStatus {
    Untreated,
    Treated,
    NotApplicable,
    /// Risk accepted (kept open on purpose, with a justification)
    Accepted,
}

impl CveStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CveStatus::Untreated => "untreated",
            CveStatus::Treated => "treated",
            CveStatus::NotApplicable => "not_applicable",
            CveStatus::Accepted => "accepted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "untreated" => Some(CveStatus::Untreated),
            "treated" => Some(CveStatus::Treated),
            "not_applicable" | "notapplicable" => Some(CveStatus::NotApplicable),
            "accepted" => Some(CveStatus::Accepted),
            _ => None,
        }
    }
}

impl std::fmt::Display for CveStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveStatus::Untreated => write!(f, "Untreated"),
            CveStatus::Treated => write!(f, "Treated"),
            CveStatus::NotApplicable => write!(f, "Not Applicable"),
            CveStatus::Accepted => write!(f, "Risk Accepted"),
        }
    }
}

/// Priority level for watchlist entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::Critical => "critical",
            Priority::High => "high",
            Priority::Medium => "medium",
            Priority::Low => "low",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Priority::Critical),
            "high" => Some(Priority::High),
            "medium" => Some(Priority::Medium),
            "low" => Some(Priority::Low),
            _ => None,
        }
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Critical => write!(f, "Critical"),
            Priority::High => write!(f, "High"),
            Priority::Medium => write!(f, "Medium"),
            Priority::Low => write!(f, "Low"),
        }
    }
}

/// Watchlist entry linking an application to a CVE with tracking info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistEntry {
    pub id: Option<i64>,
    pub app_id: i64,
    pub cve_id: String,
    pub status: CveStatus,
    pub priority: Priority,
    pub assigned_to: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub treated_at: Option<String>,
}

impl WatchlistEntry {
    #[allow(dead_code)]
    pub fn new(app_id: i64, cve_id: String) -> Self {
        Self {
            id: None,
            app_id,
            cve_id,
            status: CveStatus::Untreated,
            priority: Priority::Medium,
            assigned_to: None,
            notes: None,
            created_at: None,
            updated_at: None,
            treated_at: None,
        }
    }
}

/// Extended watchlist entry with context (for display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistEntryWithContext {
    pub entry: WatchlistEntry,
    pub app_name: String,
    pub app_version: Option<String>,
    pub project_name: String,
    pub username: String,
    // CVE details (optional, may not exist if CVE not in DB)
    pub cve_cvss: Option<f64>,
    pub cve_description: Option<String>,
    pub cve_kev: bool,
}

/// Summary statistics for watchlist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistSummary {
    pub total_entries: i64,
    pub untreated: i64,
    pub treated: i64,
    pub not_applicable: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_new_has_none_ssvc_fields() {
        let cve = Cve::new("CVE-2024-12345".to_string());

        assert_eq!(cve.cve_id, "CVE-2024-12345");
        assert_eq!(cve.ssvc_exploitation, None);
        assert_eq!(cve.ssvc_automatable, None);
        assert_eq!(cve.ssvc_technical_impact, None);
    }

    #[test]
    fn test_cve_with_ssvc_serialization() {
        let mut cve = Cve::new("CVE-2024-99999".to_string());
        cve.description = Some("Test CVE".to_string());
        cve.cvss_v3_score = Some(9.8);
        cve.ssvc_exploitation = Some("active".to_string());
        cve.ssvc_automatable = Some("yes".to_string());
        cve.ssvc_technical_impact = Some("total".to_string());

        // Serialize to JSON
        let json = serde_json::to_string(&cve).unwrap();
        assert!(json.contains("active"));
        assert!(json.contains("\"ssvc_exploitation\""));
        assert!(json.contains("\"ssvc_automatable\""));
        assert!(json.contains("\"ssvc_technical_impact\""));

        // Deserialize back
        let deserialized: Cve = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cve_id, "CVE-2024-99999");
        assert_eq!(deserialized.ssvc_exploitation, Some("active".to_string()));
        assert_eq!(deserialized.ssvc_automatable, Some("yes".to_string()));
        assert_eq!(deserialized.ssvc_technical_impact, Some("total".to_string()));
    }

    #[test]
    fn test_cve_without_ssvc_serialization() {
        let mut cve = Cve::new("CVE-2024-00001".to_string());
        cve.description = Some("Test CVE without SSVC".to_string());
        cve.cvss_v3_score = Some(7.5);

        // Serialize to JSON
        let json = serde_json::to_string(&cve).unwrap();

        // Deserialize back
        let deserialized: Cve = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.cve_id, "CVE-2024-00001");
        assert_eq!(deserialized.ssvc_exploitation, None);
        assert_eq!(deserialized.ssvc_automatable, None);
        assert_eq!(deserialized.ssvc_technical_impact, None);
    }

    #[test]
    fn test_cve_partial_ssvc() {
        let mut cve = Cve::new("CVE-2024-11111".to_string());
        cve.ssvc_exploitation = Some("poc".to_string());
        // automatable and technical_impact are None

        let json = serde_json::to_string(&cve).unwrap();
        let deserialized: Cve = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ssvc_exploitation, Some("poc".to_string()));
        assert_eq!(deserialized.ssvc_automatable, None);
        assert_eq!(deserialized.ssvc_technical_impact, None);
    }

    #[test]
    fn test_ssvc_values() {
        let mut cve = Cve::new("CVE-2024-TEST".to_string());

        // Test all valid exploitation values
        cve.ssvc_exploitation = Some("none".to_string());
        assert_eq!(cve.ssvc_exploitation.as_deref(), Some("none"));

        cve.ssvc_exploitation = Some("poc".to_string());
        assert_eq!(cve.ssvc_exploitation.as_deref(), Some("poc"));

        cve.ssvc_exploitation = Some("active".to_string());
        assert_eq!(cve.ssvc_exploitation.as_deref(), Some("active"));

        // Test all valid automatable values
        cve.ssvc_automatable = Some("yes".to_string());
        assert_eq!(cve.ssvc_automatable.as_deref(), Some("yes"));

        cve.ssvc_automatable = Some("no".to_string());
        assert_eq!(cve.ssvc_automatable.as_deref(), Some("no"));

        // Test all valid technical impact values
        cve.ssvc_technical_impact = Some("partial".to_string());
        assert_eq!(cve.ssvc_technical_impact.as_deref(), Some("partial"));

        cve.ssvc_technical_impact = Some("total".to_string());
        assert_eq!(cve.ssvc_technical_impact.as_deref(), Some("total"));
    }

    #[test]
    fn test_cve_json_compatibility() {
        // Test that old JSON (without SSVC fields) can still be deserialized
        let old_json = r#"{
            "cve_id": "CVE-2023-12345",
            "description": "Old CVE",
            "cvss_v3_score": 8.5,
            "cvss_v3_vector": null,
            "epss_score": null,
            "epss_percentile": null,
            "cwe_ids": [],
            "affected_products": [],
            "references": [],
            "kev_known_exploited": false,
            "kev_date_added": null,
            "published_at": null,
            "modified_at": null,
            "exploit_public": false,
            "exploit_urls": [],
            "metasploit_module": null,
            "nuclei_template": null,
            "affected_packages": []
        }"#;

        let cve: Cve = serde_json::from_str(old_json).unwrap();
        assert_eq!(cve.cve_id, "CVE-2023-12345");
        assert_eq!(cve.ssvc_exploitation, None);
        assert_eq!(cve.ssvc_automatable, None);
        assert_eq!(cve.ssvc_technical_impact, None);
    }
}
