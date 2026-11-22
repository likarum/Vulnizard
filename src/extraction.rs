//! Extraction de produits affectés depuis les descriptions CVE
//!
//! Ce module utilise des patterns regex pour extraire les noms de produits
//! et versions depuis les descriptions textuelles des CVE, utile quand
//! les données CPE ne sont pas disponibles dans NVD.

use regex::Regex;

use crate::models::AffectedProduct;

/// Extrait les produits et versions depuis une description CVE
pub fn extract_from_description(description: &str) -> Vec<AffectedProduct> {
    let mut products = Vec::new();
    let desc_lower = description.to_lowercase();

    // Pattern 1: "A flaw was found in {Product}" or "A vulnerability was found in {Product}"
    if let Some(product) = extract_pattern_flaw_found(&desc_lower) {
        products.push(product);
    }

    // Pattern 2: "{Product} before/prior to {version}"
    if let Some(product) = extract_pattern_product_before(&desc_lower) {
        products.push(product);
    }

    // Pattern 3: "{Product} {version} and earlier"
    if let Some(product) = extract_pattern_version_earlier(&desc_lower) {
        products.push(product);
    }

    // Pattern 4: "vulnerability in {Product}"
    if let Some(product) = extract_pattern_vulnerability_in(&desc_lower) {
        products.push(product);
    }

    // Pattern 5: "affects {Product}"
    if let Some(product) = extract_pattern_affects(&desc_lower) {
        products.push(product);
    }

    // Dédupliquer par nom de produit
    products.dedup_by(|a, b| a.product == b.product);
    products
}

/// Pattern: "A flaw was found in {Product}" or "A vulnerability was found in {Product}"
fn extract_pattern_flaw_found(description: &str) -> Option<AffectedProduct> {
    let re = Regex::new(
        r"(?:flaw|vulnerability|issue)\s+(?:was\s+)?found\s+in\s+(?:the\s+)?([a-z][a-z0-9_.-]+)(?:\s+(?:before|prior to|through|up to)\s+([0-9][0-9.]+))?"
    ).ok()?;

    let caps = re.captures(description)?;
    let product_name = clean_product_name(caps.get(1)?.as_str());
    let version_end = caps.get(2).map(|m| m.as_str().to_string());

    if is_common_word(&product_name) {
        return None;
    }

    Some(AffectedProduct {
        vendor: None,
        product: Some(product_name),
        version: Some("*".to_string()),
        version_start: None,
        version_end,
        cpe: None,
        ..Default::default()
    })
}

/// Pattern: "{Product} before/prior to {version}"
fn extract_pattern_product_before(description: &str) -> Option<AffectedProduct> {
    let re = Regex::new(
        r"([a-z][a-z0-9_.-]+)\s+(?:versions?\s+)?(?:before|prior to|<)\s+([0-9][0-9.]+)"
    ).ok()?;

    let caps = re.captures(description)?;
    let product_name = clean_product_name(caps.get(1)?.as_str());
    let version_end = caps.get(2).map(|m| m.as_str().to_string());

    if is_common_word(&product_name) {
        return None;
    }

    Some(AffectedProduct {
        vendor: None,
        product: Some(product_name),
        version: Some("*".to_string()),
        version_start: None,
        version_end,
        cpe: None,
        ..Default::default()
    })
}

/// Pattern: "{Product} {version} and earlier"
fn extract_pattern_version_earlier(description: &str) -> Option<AffectedProduct> {
    let re = Regex::new(
        r"([a-z][a-z0-9_.-]+)\s+([0-9][0-9.]+)\s+and\s+(?:earlier|before)"
    ).ok()?;

    let caps = re.captures(description)?;
    let product_name = clean_product_name(caps.get(1)?.as_str());
    let version_end = caps.get(2).map(|m| m.as_str().to_string());

    if is_common_word(&product_name) {
        return None;
    }

    Some(AffectedProduct {
        vendor: None,
        product: Some(product_name),
        version: Some("*".to_string()),
        version_start: None,
        version_end,
        cpe: None,
        ..Default::default()
    })
}

/// Pattern: "vulnerability in {Product}"
fn extract_pattern_vulnerability_in(description: &str) -> Option<AffectedProduct> {
    let re = Regex::new(
        r"vulnerability\s+in\s+(?:the\s+)?([a-z][a-z0-9_.-]+)"
    ).ok()?;

    let caps = re.captures(description)?;
    let product_name = clean_product_name(caps.get(1)?.as_str());

    if is_common_word(&product_name) {
        return None;
    }

    Some(AffectedProduct {
        vendor: None,
        product: Some(product_name),
        version: Some("*".to_string()),
        version_start: None,
        version_end: None,
        cpe: None,
        ..Default::default()
    })
}

/// Pattern: "affects {Product}"
fn extract_pattern_affects(description: &str) -> Option<AffectedProduct> {
    let re = Regex::new(
        r"affects?\s+(?:the\s+)?([a-z][a-z0-9_.-]+)"
    ).ok()?;

    let caps = re.captures(description)?;
    let product_name = clean_product_name(caps.get(1)?.as_str());

    if is_common_word(&product_name) {
        return None;
    }

    Some(AffectedProduct {
        vendor: None,
        product: Some(product_name),
        version: Some("*".to_string()),
        version_start: None,
        version_end: None,
        cpe: None,
        ..Default::default()
    })
}

/// Nettoie le nom de produit extrait (retire ponctuation finale, etc.)
fn clean_product_name(name: &str) -> String {
    name.trim_end_matches(|c: char| c == '.' || c == ',' || c == ':' || c == ';' || c == '\'')
        .to_string()
}

/// Filtre les mots communs qui ne sont pas des noms de produits
fn is_common_word(word: &str) -> bool {
    const COMMON: &[&str] = &[
        // Articles et pronoms
        "the", "a", "an", "this", "that", "which", "where", "when", "what",
        // Termes de vulnérabilité
        "vulnerability", "flaw", "issue", "bug", "error", "problem", "defect",
        "weakness", "security", "attack", "exploit", "injection", "overflow",
        // Termes techniques génériques
        "version", "versions", "release", "component", "module", "package",
        "library", "framework", "application", "software", "system", "service",
        "function", "method", "class", "interface", "api", "endpoint",
        // Acteurs
        "attacker", "user", "admin", "administrator", "root", "guest",
        // Environnement
        "server", "client", "remote", "local", "network", "web", "http", "https",
        // Mots de liaison
        "allows", "could", "may", "might", "can", "via", "through", "using",
        "leading", "resulting", "causing", "enabling", "allowing",
        // Mots trop courts ou génériques
        "code", "data", "file", "files", "path", "input", "output", "memory",
        "buffer", "stack", "heap", "request", "response", "header", "cookie",
        "session", "token", "key", "value", "string", "integer", "object",
    ];
    COMMON.contains(&word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_flaw_found() {
        let desc = "A flaw was found in Keycloak before 24.0.3";
        let products = extract_from_description(desc);
        assert!(!products.is_empty());
        assert_eq!(products[0].product, Some("keycloak".to_string()));
        assert_eq!(products[0].version_end, Some("24.0.3".to_string()));
    }

    #[test]
    fn test_extract_flaw_found_with_apostrophe() {
        let desc = "A flaw was found in Keycloak's SAML brokering functionality.";
        let products = extract_from_description(desc);
        assert!(!products.is_empty(), "Should extract keycloak from description with apostrophe");
        assert_eq!(products[0].product, Some("keycloak".to_string()));
    }

    #[test]
    fn test_extract_product_before() {
        let desc = "traefik versions before 2.11.0 are affected";
        let products = extract_from_description(desc);
        assert!(!products.is_empty());
        assert_eq!(products[0].product, Some("traefik".to_string()));
    }

    #[test]
    fn test_extract_version_earlier() {
        let desc = "nginx 1.25.3 and earlier has a vulnerability";
        let products = extract_from_description(desc);
        assert!(!products.is_empty());
        assert_eq!(products[0].product, Some("nginx".to_string()));
    }

    #[test]
    fn test_filter_common_words() {
        let desc = "A vulnerability in the code allows remote attackers";
        let products = extract_from_description(desc);
        // Should not extract "code" as a product
        assert!(products.iter().all(|p| p.product != Some("code".to_string())));
    }
}
