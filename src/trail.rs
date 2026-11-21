//! Tamper-evident logs. The security log and the audit of decisions are
//! chained: each entry stores a hash of its content and of the previous
//! entry, so that changing, removing or reordering an entry breaks the chain
//! from there on. An export carries the entries, the last hash (the head) and
//! a signature of the head by a key of the instance; it can be checked
//! offline, by this program or by anyone following this file.
//!
//! What it proves: the exported entries are those the instance signed, in
//! that order, with nothing changed or missing in between.
//! What it does not prove: that the instance itself was honest. Whoever
//! controls the server holds the signing key and can rewrite the log and
//! sign it again. The protection against that is to keep exports (or just
//! their heads) somewhere else: a later export must start with the same
//! entries and reach the same hashes.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const FORMAT: &str = "vulnizard-log/1";
pub const SECURITY: &str = "security";
pub const AUDIT: &str = "audit";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A signed export of a log, from its first entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub format: String,
    /// `security` or `audit`
    pub log: String,
    /// What the log covers: `instance`, or `organization:<name>`
    pub scope: String,
    pub exported_at: String,
    pub count: usize,
    /// Hash of the last entry (empty for an empty log)
    pub head: String,
    pub entries: Vec<Value>,
    pub signature: ExportSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSignature {
    /// ECDSA P-256 with SHA-256 over `signed_message`
    pub algorithm: String,
    /// Public key (SEC1 uncompressed point, base64url)
    pub public_key: String,
    /// Signature (r || s, base64url)
    pub value: String,
}

/// Fields of an entry that are hashed, in this order (everything but `chain`)
pub fn hashed_fields(log: &str) -> &'static [&'static str] {
    match log {
        SECURITY => &["id", "at", "actor_id", "actor", "user_id", "username", "event", "detail"],
        _ => &[
            "id", "organization_id", "project", "entry_id", "cve_id", "app_name", "app_version", "at", "kind", "status",
            "previous", "actor", "comment",
        ],
    }
}

/// Hash of an entry given the hash of the previous one (empty for the first):
/// SHA-256 of the previous hash, a line feed, and the JSON array of the
/// hashed fields in order, as serialized by `serde_json` (no spaces).
pub fn link(log: &str, previous: &str, entry: &Value) -> String {
    let fields: Vec<Value> = hashed_fields(log).iter().map(|f| entry.get(*f).cloned().unwrap_or(Value::Null)).collect();
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(b"\n");
    hasher.update(Value::Array(fields).to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// What the signature covers
pub fn signed_message(log: &str, scope: &str, count: usize, head: &str, exported_at: &str) -> String {
    format!("{FORMAT}|{log}|{scope}|{count}|{head}|{exported_at}")
}

pub fn public_key_of(key: &SigningKey) -> String {
    use base64::Engine;
    B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())
}

/// Short identifier of a public key, to compare with the one the
/// administration page shows
pub fn fingerprint(public_key: &str) -> String {
    hex::encode(Sha256::digest(public_key.as_bytes()))[..16].to_string()
}

/// Builds the signed export of entries already chained
pub fn sign_export(key: &SigningKey, log: &str, scope: &str, entries: Vec<Value>) -> Export {
    use base64::Engine;
    let exported_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let head = entries.last().and_then(|e| e.get("chain")).and_then(Value::as_str).unwrap_or("").to_string();
    let signature: Signature = key.sign(signed_message(log, scope, entries.len(), &head, &exported_at).as_bytes());
    Export {
        format: FORMAT.to_string(),
        log: log.to_string(),
        scope: scope.to_string(),
        exported_at,
        count: entries.len(),
        head,
        entries,
        signature: ExportSignature {
            algorithm: "ES256".to_string(),
            public_key: public_key_of(key),
            value: B64.encode(signature.to_bytes()),
        },
    }
}

/// Result of a successful verification
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub log: String,
    pub scope: String,
    pub count: usize,
    pub head: String,
    pub exported_at: String,
    /// Fingerprint of the key that signed: it must be the instance's
    pub key_fingerprint: String,
}

/// Checks an export: every entry chains to the previous one, the head and
/// the count are those signed, and the signature is valid for the key the
/// export carries. The caller still has to compare the key fingerprint with
/// the instance's (shown in its administration), or pass it as `expected_key`.
pub fn verify(export: &Export, expected_key: Option<&str>) -> Result<Verified, String> {
    use base64::Engine;
    if export.format != FORMAT {
        return Err(format!("unknown format '{}'", export.format));
    }
    if export.log != SECURITY && export.log != AUDIT {
        return Err(format!("unknown log '{}'", export.log));
    }
    if export.count != export.entries.len() {
        return Err(format!("the export announces {} entries and holds {}", export.count, export.entries.len()));
    }
    let mut previous = String::new();
    let mut last_id = 0i64;
    for (position, entry) in export.entries.iter().enumerate() {
        let id = entry.get("id").and_then(Value::as_i64).unwrap_or(0);
        let stored = entry.get("chain").and_then(Value::as_str).unwrap_or("");
        if id <= last_id {
            return Err(format!("entry {} (id {id}) is out of order", position + 1));
        }
        if link(&export.log, &previous, entry) != stored {
            return Err(format!(
                "entry {} (id {id}) does not chain to the previous one: it was changed, or an entry before it was changed or removed",
                position + 1
            ));
        }
        previous = stored.to_string();
        last_id = id;
    }
    if previous != export.head {
        return Err("the head does not match the last entry".to_string());
    }
    if export.signature.algorithm != "ES256" {
        return Err(format!("unknown signature algorithm '{}'", export.signature.algorithm));
    }
    let key_bytes = B64.decode(&export.signature.public_key).map_err(|_| "unreadable public key".to_string())?;
    let key = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| "invalid public key".to_string())?;
    let signature_bytes = B64.decode(&export.signature.value).map_err(|_| "unreadable signature".to_string())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| "invalid signature".to_string())?;
    let message = signed_message(&export.log, &export.scope, export.count, &export.head, &export.exported_at);
    key.verify(message.as_bytes(), &signature).map_err(|_| "the signature does not match the content".to_string())?;
    let key_fingerprint = fingerprint(&export.signature.public_key);
    if let Some(expected) = expected_key.map(str::trim).filter(|k| !k.is_empty()) {
        if expected != key_fingerprint && expected != export.signature.public_key {
            return Err(format!("signed by key {key_fingerprint}, not by the expected one"));
        }
    }
    Ok(Verified {
        log: export.log.clone(),
        scope: export.scope.clone(),
        count: export.count,
        head: export.head.clone(),
        exported_at: export.exported_at.clone(),
        key_fingerprint,
    })
}

/// The same entries as CSV, for reading in a spreadsheet. The CSV carries the
/// hashes but is not the verifiable format: use the JSON export for that.
pub fn to_csv(export: &Export) -> String {
    let mut columns: Vec<&str> = hashed_fields(&export.log).to_vec();
    columns.push("chain");
    let cell = |value: &Value| -> String {
        let text = match value {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        // Spreadsheets run cells starting with these as formulas
        let text = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{text}") } else { text };
        format!("\"{}\"", text.replace('"', "\"\""))
    };
    let mut out = columns.join(",");
    out.push('\n');
    for entry in &export.entries {
        let row: Vec<String> = columns.iter().map(|c| cell(entry.get(*c).unwrap_or(&Value::Null))).collect();
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chained(log: &str, entries: Vec<Value>) -> Vec<Value> {
        let mut previous = String::new();
        entries
            .into_iter()
            .map(|mut e| {
                previous = link(log, &previous, &e);
                e["chain"] = json!(previous);
                e
            })
            .collect()
    }

    fn sample() -> (SigningKey, Export) {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entries = chained(
            SECURITY,
            (1..=3)
                .map(|i| json!({ "id": i, "at": "2026-01-01 00:00:00", "actor_id": 1, "actor": "root", "user_id": 2, "username": "bob", "event": "totp_enabled", "detail": null }))
                .collect(),
        );
        let export = sign_export(&key, SECURITY, "instance", entries);
        (key, export)
    }

    #[test]
    fn an_untouched_export_verifies_and_names_its_key() {
        let (key, export) = sample();
        let verified = verify(&export, None).unwrap();
        assert_eq!((verified.count, verified.scope.as_str()), (3, "instance"));
        assert_eq!(verified.key_fingerprint, fingerprint(&public_key_of(&key)));
        assert!(verify(&export, Some(&verified.key_fingerprint)).is_ok());
        assert!(verify(&export, Some("0000000000000000")).is_err());
        // It survives a round trip through its file form
        let reread: Export = serde_json::from_str(&serde_json::to_string_pretty(&export).unwrap()).unwrap();
        assert!(verify(&reread, None).is_ok());
        // An empty log is a valid export too
        assert!(verify(&sign_export(&key, AUDIT, "organization:acme", Vec::new()), None).is_ok());
    }

    #[test]
    fn any_change_is_detected() {
        let (key, export) = sample();
        let broken = |change: &dyn Fn(&mut Export)| {
            let mut e = export.clone();
            change(&mut e);
            verify(&e, None).unwrap_err()
        };
        // A field changed, an entry removed in the middle or at the end, entries swapped
        assert!(broken(&|e| e.entries[1]["actor"] = json!("mallory")).contains("entry 2"));
        assert!(broken(&|e| { e.entries.remove(1); e.count = 2; }).contains("entry 2"));
        assert!(!broken(&|e| { e.entries.pop(); e.count = 2; }).is_empty());
        assert!(broken(&|e| e.entries.swap(0, 1)).contains("entry 1"));
        // Head, count, scope or date changed: the signature no longer matches
        assert!(!broken(&|e| e.scope = "organization:other".into()).is_empty());
        assert!(!broken(&|e| e.exported_at = "2020-01-01T00:00:00Z".into()).is_empty());
        assert!(!broken(&|e| e.count = 4).is_empty());
        // Rewritten and chained again, but signed by someone else: valid in itself, another key
        let other = SigningKey::random(&mut rand::rngs::OsRng);
        let mut entries = export.entries.clone();
        entries[1]["actor"] = json!("mallory");
        let forged = sign_export(&other, SECURITY, "instance", chained(SECURITY, entries));
        let verified = verify(&forged, None).unwrap();
        assert_ne!(verified.key_fingerprint, fingerprint(&public_key_of(&key)));
        assert!(verify(&forged, Some(&fingerprint(&public_key_of(&key)))).is_err());
    }

    #[test]
    fn csv_is_readable_and_inert_in_a_spreadsheet() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let entries = chained(
            SECURITY,
            vec![json!({ "id": 1, "at": "2026-01-01 00:00:00", "actor_id": null, "actor": "=cmd|' /C calc'!A0", "user_id": 2, "username": "a \"b\"", "event": "x", "detail": "line, with comma" })],
        );
        let csv = to_csv(&sign_export(&key, SECURITY, "instance", entries));
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), "id,at,actor_id,actor,user_id,username,event,detail,chain");
        let row = lines.next().unwrap();
        assert!(row.contains("\"'=cmd|") && row.contains("\"a \"\"b\"\"\"") && row.contains("\"line, with comma\""));
    }
}
