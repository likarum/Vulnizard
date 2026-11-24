//! Single sign-on providers managed from the administration UI (schema v9).
//! Any number of OpenID Connect providers can be declared; the optional
//! `[oidc]` section of the configuration file is one more, read-only.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use crate::config::OidcConfig;
use crate::db::{Database, Scope};

const SSO_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS oidc_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    scopes TEXT NOT NULL,
    auto_create INTEGER NOT NULL DEFAULT 1,
    link_existing INTEGER NOT NULL DEFAULT 0,
    admin_group TEXT,
    allowed_domains TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- A pending login belongs to the provider it was started with
ALTER TABLE oidc_states ADD COLUMN provider TEXT NOT NULL DEFAULT '';

INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '9');
"#;

/// Slug of the provider declared in the configuration file
pub const CONFIG_PROVIDER: &str = "config";

#[derive(Debug, Clone)]
pub struct Provider {
    /// Identifier used in the login and callback URLs
    pub slug: String,
    /// Label of the login button
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    /// Create an account at the first login of an unknown user
    pub auto_create: bool,
    pub link_existing_accounts: bool,
    pub admin_group: Option<String>,
    /// When not empty, only verified emails of these domains may sign in
    pub allowed_domains: Vec<String>,
    pub enabled: bool,
    /// Declared in the configuration file: not editable from the UI
    pub from_config: bool,
    /// What the provider belongs to: accounts it creates only exist there
    pub scope: Scope,
    /// "acme" or "acme / infra" (empty for the instance)
    pub scope_label: String,
    /// Role given in that scope at the first sign-in (none = no right yet)
    pub default_role: Option<String>,
}

impl Provider {
    pub fn from_config(config: &OidcConfig) -> Self {
        Self {
            slug: CONFIG_PROVIDER.to_string(),
            name: config.name.clone(),
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            scopes: config.scopes.clone(),
            auto_create: config.auto_create,
            link_existing_accounts: config.link_existing_accounts,
            admin_group: config.admin_group.clone(),
            allowed_domains: normalize_domains(&config.allowed_domains.join(",")),
            enabled: true,
            from_config: true,
            scope: Scope::Instance,
            scope_label: String::new(),
            default_role: None,
        }
    }
}

/// "Example.org, @corp.example" -> ["example.org", "corp.example"]
pub fn normalize_domains(raw: &str) -> Vec<String> {
    let mut domains: Vec<String> = raw
        .split([',', ' ', '\n', ';'])
        .map(|d| d.trim().trim_start_matches('@').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    domains.sort();
    domains.dedup();
    domains
}

fn provider_row(db: &Database, r: &rusqlite::Row) -> rusqlite::Result<Provider> {
    Ok(Provider {
        slug: r.get(0)?,
        name: r.get(1)?,
        issuer: r.get(2)?,
        client_id: r.get(3)?,
        // Stored encrypted; unreadable, the provider has no secret and sign-in through it fails
        client_secret: db.unseal(&r.get::<_, String>(4)?).unwrap_or_default(),
        scopes: r.get(5)?,
        auto_create: r.get::<_, i64>(6)? != 0,
        link_existing_accounts: r.get::<_, i64>(7)? != 0,
        admin_group: r.get(8)?,
        allowed_domains: normalize_domains(&r.get::<_, String>(9)?),
        enabled: r.get::<_, i64>(10)? != 0,
        from_config: false,
        scope: Scope::from_parts(&r.get::<_, String>(11)?, r.get(12)?).unwrap_or(Scope::Instance),
        default_role: r.get(13)?,
        scope_label: r.get(14)?,
    })
}

const PROVIDER_COLUMNS: &str =
    "slug, name, issuer, client_id, client_secret, scopes, auto_create, link_existing, admin_group, allowed_domains, enabled,
     scope, scope_id, default_role,
     CASE scope
       WHEN 'organization' THEN COALESCE((SELECT name FROM organizations WHERE id = oidc_providers.scope_id), '?')
       WHEN 'project' THEN COALESCE((SELECT o.name || ' / ' || p.name FROM projects p
                                     LEFT JOIN organizations o ON o.id = p.organization_id
                                     WHERE p.id = oidc_providers.scope_id), '?')
       ELSE '' END";

impl Database {
    pub(super) fn migrate_sso(&self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute_batch(SSO_SCHEMA)?;
        tx.commit()?;
        Ok(())
    }

    /// Providers declared from the UI (enabled or not)
    pub fn list_sso_providers(&self) -> Result<Vec<Provider>> {
        let mut stmt = self
            .conn()
            .prepare(&format!("SELECT {PROVIDER_COLUMNS} FROM oidc_providers ORDER BY name COLLATE NOCASE"))?;
        let rows = stmt
            .query_map([], |r| provider_row(self, r))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_sso_provider(&self, slug: &str) -> Result<Option<Provider>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {PROVIDER_COLUMNS} FROM oidc_providers WHERE slug = ?1"),
                params![slug],
                |r| provider_row(self, r),
            )
            .optional()?)
    }

    /// Creates the provider, or updates it when the slug exists. An empty
    /// secret keeps the stored one on update.
    pub fn save_sso_provider(&self, p: &Provider) -> Result<()> {
        if p.slug == CONFIG_PROVIDER {
            return Err(anyhow!("This identifier is reserved"));
        }
        let domains = p.allowed_domains.join(",");
        let existing = self.get_sso_provider(&p.slug)?;
        let exists = existing.is_some();
        // The stored secret is never sent to another issuer
        if existing.is_some_and(|e| e.issuer != p.issuer) && p.client_secret.is_empty() {
            return Err(anyhow!("Enter the client secret again when the issuer changes"));
        }
        // An empty secret means "keep the stored one"
        let sealed_secret = if p.client_secret.is_empty() { String::new() } else { self.seal(&p.client_secret) };
        if exists {
            self.conn().execute(
                "UPDATE oidc_providers SET name = ?2, issuer = ?3, client_id = ?4,
                        client_secret = CASE WHEN ?5 = '' THEN client_secret ELSE ?5 END,
                        scopes = ?6, auto_create = ?7, link_existing = ?8, admin_group = ?9, allowed_domains = ?10,
                        scope = ?11, scope_id = ?12, default_role = ?13
                 WHERE slug = ?1",
                params![
                    p.slug,
                    p.name,
                    p.issuer,
                    p.client_id,
                    sealed_secret,
                    p.scopes,
                    p.auto_create as i32,
                    p.link_existing_accounts as i32,
                    p.admin_group,
                    domains,
                    p.scope.level(),
                    p.scope.id(),
                    p.default_role
                ],
            )?;
        } else {
            if p.client_secret.is_empty() {
                return Err(anyhow!("The client secret is required"));
            }
            self.conn().execute(
                "INSERT INTO oidc_providers
                    (slug, name, issuer, client_id, client_secret, scopes, auto_create, link_existing, admin_group,
                     allowed_domains, enabled, scope, scope_id, default_role)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    p.slug,
                    p.name,
                    p.issuer,
                    p.client_id,
                    sealed_secret,
                    p.scopes,
                    p.auto_create as i32,
                    p.link_existing_accounts as i32,
                    p.admin_group,
                    domains,
                    p.enabled as i32,
                    p.scope.level(),
                    p.scope.id(),
                    p.default_role
                ],
            )?;
        }
        Ok(())
    }

    pub fn set_sso_provider_enabled(&self, slug: &str, enabled: bool) -> Result<bool> {
        Ok(self.conn().execute(
            "UPDATE oidc_providers SET enabled = ?1 WHERE slug = ?2",
            params![enabled as i32, slug],
        )? > 0)
    }

    /// Removes the provider. Accounts created through it are kept (they can
    /// no longer sign in with it; an administrator may give them a password).
    pub fn delete_sso_provider(&self, slug: &str) -> Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM oidc_providers WHERE slug = ?1", params![slug])?
            > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(slug: &str) -> Provider {
        Provider {
            slug: slug.into(),
            name: "Example".into(),
            issuer: "https://id.example.org".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            scopes: "openid email".into(),
            auto_create: true,
            link_existing_accounts: false,
            admin_group: None,
            allowed_domains: vec!["example.org".into()],
            enabled: true,
            from_config: false,
            scope: Scope::Instance,
            scope_label: String::new(),
            default_role: None,
        }
    }

    #[test]
    fn providers_are_created_updated_and_removed() {
        let db = Database::open_in_memory().unwrap();
        db.save_sso_provider(&provider("corp")).unwrap();
        assert!(db.save_sso_provider(&provider(CONFIG_PROVIDER)).is_err());

        // Update: an empty secret keeps the stored one
        let mut updated = provider("corp");
        updated.name = "Corp".into();
        updated.client_secret = String::new();
        updated.allowed_domains = vec![];
        db.save_sso_provider(&updated).unwrap();
        let stored = db.get_sso_provider("corp").unwrap().unwrap();
        assert_eq!((stored.name.as_str(), stored.client_secret.as_str()), ("Corp", "secret"));
        assert!(stored.allowed_domains.is_empty());

        // Changing the issuer requires the secret again
        let mut moved = provider("corp");
        moved.issuer = "https://other.example.org".into();
        moved.client_secret = String::new();
        assert!(db.save_sso_provider(&moved).is_err());
        assert_eq!(db.get_sso_provider("corp").unwrap().unwrap().issuer, "https://id.example.org");

        // A new provider needs a secret
        let mut no_secret = provider("other");
        no_secret.client_secret = String::new();
        assert!(db.save_sso_provider(&no_secret).is_err());

        assert!(db.set_sso_provider_enabled("corp", false).unwrap());
        assert!(!db.list_sso_providers().unwrap()[0].enabled);
        assert!(!db.set_sso_provider_enabled("nope", false).unwrap());
        assert!(db.delete_sso_provider("corp").unwrap());
        assert!(db.list_sso_providers().unwrap().is_empty());
    }

    #[test]
    fn domains_are_normalized() {
        assert_eq!(
            normalize_domains(" Example.org, @corp.example ;example.org\n"),
            ["corp.example", "example.org"]
        );
        assert!(normalize_domains("  ").is_empty());
    }
}
