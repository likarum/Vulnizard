//! Web Push: notifications delivered to a browser even when no Vulnizard
//! tab is open.
//!
//! The push message itself carries **no content**: it only wakes the service
//! worker, which then fetches the user's pending messages from this server
//! with its own session. Nothing about vulnerabilities transits through the
//! browser vendor's push service, and no payload encryption is needed; the
//! request is authenticated with VAPID (RFC 8292), an ES256-signed token.

use anyhow::{anyhow, Result};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use std::time::Duration;

use crate::config::Config;
use crate::db::Database;

const KEY_VAPID: &str = "push.vapid_private_key";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Signing key of this instance, created on first use
fn signing_key(db: &Database) -> Result<SigningKey> {
    if let Some(hex_key) = db.get_secret(KEY_VAPID)? {
        let bytes = hex::decode(hex_key).map_err(|_| anyhow!("invalid VAPID key"))?;
        return SigningKey::from_slice(&bytes).map_err(|_| anyhow!("invalid VAPID key"));
    }
    let key = SigningKey::random(&mut rand::rngs::OsRng);
    db.set_secret(KEY_VAPID, &hex::encode(key.to_bytes()))?;
    Ok(key)
}

fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())
}

/// Public key the browser needs to subscribe (`applicationServerKey`)
pub fn public_key(db: &Database) -> Result<String> {
    Ok(public_key_b64(&signing_key(db)?))
}

/// `Authorization` header value for a push endpoint
fn vapid_authorization(key: &SigningKey, endpoint: &reqwest::Url, subject: &str, now: i64) -> String {
    let audience = endpoint.origin().ascii_serialization();
    let header = B64.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = B64.encode(
        serde_json::json!({ "aud": audience, "exp": now + 12 * 3600, "sub": subject }).to_string(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "vapid t={signing_input}.{}, k={}",
        B64.encode(signature.to_bytes()),
        public_key_b64(key)
    )
}

/// Who the push service may contact about this sender. The standard asks for
/// a `mailto:` or `https:` URI and some services refuse anything else: the
/// configured contact, else the public URL when it is https, else a
/// placeholder address (an instance reached over plain http has no better).
fn vapid_subject(config: &Config) -> String {
    match config.web.push_contact.as_deref().map(str::trim) {
        Some(contact) if contact.starts_with("mailto:") || contact.starts_with("https://") => contact.to_string(),
        _ if config.web.base_url.starts_with("https://") => config.web.base_url.clone(),
        _ => "mailto:admin@vulnizard.invalid".to_string(),
    }
}

/// A push endpoint is given by the browser, hence by the user: it must be an
/// https URL of a public host, whatever the "private targets" setting.
pub fn check_endpoint(base: &Config, endpoint: &str) -> Result<crate::notify::Target> {
    let mut strict = base.clone();
    strict.web.allow_private_webhooks = false;
    if !endpoint.starts_with("https://") || endpoint.len() > 1000 {
        return Err(anyhow!("push endpoints must be https URLs"));
    }
    crate::notify::check_webhook_url(&strict, endpoint)
}

/// Wakes every subscribed browser of the user. Subscriptions the push
/// service reports as gone are forgotten. Returns the number of browsers reached.
pub fn notify_user(db: &Database, config: &Config, user_id: i64) -> usize {
    let Ok(key) = signing_key(db) else {
        return 0;
    };
    let subject = vapid_subject(config);
    let now = chrono::Utc::now().timestamp();
    let mut reached = 0;
    for (endpoint, _) in db.list_push_subscriptions(user_id).unwrap_or_default() {
        let Ok(target) = check_endpoint(config, &endpoint) else {
            let _ = db.forget_push_endpoint(&endpoint);
            continue;
        };
        let Ok(client) = crate::notify::client_for(&target) else {
            continue;
        };
        let response = client
            .post(target.url.clone())
            .timeout(Duration::from_secs(5))
            .header("Authorization", vapid_authorization(&key, &target.url, &subject, now))
            .header("TTL", "86400")
            .header("Content-Length", "0")
            .send();
        match response {
            Ok(r) if r.status().is_success() => reached += 1,
            // The browser unsubscribed or the subscription expired
            Ok(r) if matches!(r.status().as_u16(), 404 | 410) => {
                let _ = db.forget_push_endpoint(&endpoint);
            }
            Ok(r) => tracing::warn!("web push refused: HTTP {}", r.status()),
            Err(e) => tracing::warn!("web push failed: {}", e.without_url()),
        }
    }
    reached
}

/// Queues a message for a user and wakes their browsers
pub fn deliver(db: &Database, config: &Config, user_id: i64, title: &str, body: &str, url: &str) -> Result<usize> {
    db.push_enqueue(user_id, title, body, url)?;
    Ok(notify_user(db, config, user_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn key_is_created_once_and_token_is_a_valid_es256_jwt() {
        let db = Database::open_in_memory().unwrap();
        let public = public_key(&db).unwrap();
        assert_eq!(public, public_key(&db).unwrap());
        // Uncompressed P-256 point: 65 bytes starting with 0x04
        let point = B64.decode(&public).unwrap();
        assert_eq!((point.len(), point[0]), (65, 4));

        let key = signing_key(&db).unwrap();
        let endpoint = reqwest::Url::parse("https://push.example.org/send/abc?x=1").unwrap();
        let header = vapid_authorization(&key, &endpoint, "https://vulnizard.example.org", 1_700_000_000);
        let token = header.strip_prefix("vapid t=").unwrap().split(", k=").next().unwrap();
        assert!(header.ends_with(&format!(", k={public}")));
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        // The audience is the origin of the push service only
        assert_eq!(claims["aud"], "https://push.example.org");
        assert_eq!(claims["exp"], 1_700_000_000i64 + 12 * 3600);
        let signature = Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
        let signed = format!("{}.{}", parts[0], parts[1]);
        assert!(key.verifying_key().verify(signed.as_bytes(), &signature).is_ok());
    }

    #[test]
    fn endpoints_must_be_public_https_even_when_private_targets_are_allowed() {
        let mut config = Config::default();
        config.web.allow_private_webhooks = true;
        assert!(check_endpoint(&config, "http://8.8.8.8/push").is_err());
        assert!(check_endpoint(&config, "https://127.0.0.1/push").is_err());
        assert!(check_endpoint(&config, "https://10.0.0.5/push").is_err());
        assert!(check_endpoint(&config, "https://8.8.8.8/push").is_ok());
    }

    #[test]
    fn the_contact_given_to_push_services_is_a_mailto_or_https_uri() {
        let mut config = Config::default(); // http://127.0.0.1:8000
        assert_eq!(vapid_subject(&config), "mailto:admin@vulnizard.invalid");
        config.web.base_url = "https://vulnizard.example.org".into();
        assert_eq!(vapid_subject(&config), "https://vulnizard.example.org");
        config.web.push_contact = Some("mailto:secops@example.org".into());
        assert_eq!(vapid_subject(&config), "mailto:secops@example.org");
        config.web.push_contact = Some("not a uri".into());
        assert_eq!(vapid_subject(&config), "https://vulnizard.example.org");
    }
}
