//! Secrets at rest. The database holds values that must be read back in
//! clear to be used (second-factor seeds, SMTP passwords, SSO client secrets,
//! tokens of Git sources, webhook URLs, the Web Push signing key). They are
//! stored encrypted with a key kept in a file next to the database, so that
//! a copy of the database alone (a backup, a dump) does not reveal them.
//!
//! This does not protect against someone who reads both files: the key must
//! be readable by the server. Keep the key file out of database backups, or
//! back it up separately, and keep it: without it the secrets are lost and
//! must be entered again.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub type Key = [u8; 32];

const PREFIX: &str = "enc:v1:";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD_NO_PAD;
/// Environment variable naming the key file (default: `<database>.key`)
const KEY_FILE_ENV: &str = "VULNIZARD_KEY_FILE";

pub fn random_key() -> Key {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with(PREFIX)
}

/// Encrypts a value for storage
pub fn seal(key: &Key, plain: &str) -> String {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    // Encrypting in memory with a valid key and nonce cannot fail
    let sealed = cipher.encrypt(XNonce::from_slice(&nonce), plain.as_bytes()).unwrap_or_default();
    let mut bytes = nonce.to_vec();
    bytes.extend(sealed);
    format!("{PREFIX}{}", B64.encode(bytes))
}

/// Reads a stored value back. A value stored before encryption existed (no
/// prefix) is returned as it is.
pub fn open(key: &Key, stored: &str) -> Result<String> {
    let Some(encoded) = stored.strip_prefix(PREFIX) else {
        return Ok(stored.to_string());
    };
    let bytes = B64.decode(encoded).map_err(|_| anyhow!("stored secret is damaged"))?;
    if bytes.len() < 24 {
        return Err(anyhow!("stored secret is damaged"));
    }
    let (nonce, sealed) = bytes.split_at(24);
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), sealed)
        .map_err(|_| anyhow!("stored secret cannot be read with this key (is the key file the one of this database?)"))?;
    String::from_utf8(plain).map_err(|_| anyhow!("stored secret is damaged"))
}

/// Name of the key among the credentials systemd hands to the service
/// (`LoadCredential=vulnizard.key:/path/to/secret`)
const CREDENTIAL_NAME: &str = "vulnizard.key";

/// Where the key of a database lives: the file named by `VULNIZARD_KEY_FILE`,
/// else a credential passed by systemd, else `<database>.key`.
pub fn key_path(db_path: &Path) -> PathBuf {
    resolve_key_path(std::env::var_os(KEY_FILE_ENV), std::env::var_os("CREDENTIALS_DIRECTORY"), db_path)
}

fn resolve_key_path(named: Option<std::ffi::OsString>, credentials: Option<std::ffi::OsString>, db_path: &Path) -> PathBuf {
    if let Some(path) = named.filter(|p| !p.is_empty()) {
        return PathBuf::from(path);
    }
    if let Some(dir) = credentials.filter(|d| !d.is_empty()) {
        let credential = Path::new(&dir).join(CREDENTIAL_NAME);
        if credential.exists() {
            return credential;
        }
    }
    PathBuf::from(format!("{}.key", db_path.display()))
}

/// The key as it is written in its file, for a backup. Never creates one.
pub fn export_key(db_path: &Path) -> Result<String> {
    let path = key_path(db_path);
    let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read the key file {}", path.display()))?;
    let bytes = hex::decode(text.trim()).map_err(|_| anyhow!("{} is not a key file", path.display()))?;
    Key::try_from(bytes.as_slice()).map_err(|_| anyhow!("{} is not a key file", path.display()))?;
    Ok(text.trim().to_string())
}

/// Key of a database, read from its file and created on first use (readable
/// by its owner only). Read once per process.
pub fn key_for(db_path: &Path) -> Result<Key> {
    static KEYS: Mutex<Option<HashMap<PathBuf, Key>>> = Mutex::new(None);
    let path = key_path(db_path);
    let mut keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    let keys = keys.get_or_insert_with(HashMap::new);
    if let Some(key) = keys.get(&path) {
        return Ok(*key);
    }
    let key = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim()).map_err(|_| anyhow!("{} is not a key file", path.display()))?;
            Key::try_from(bytes.as_slice()).map_err(|_| anyhow!("{} is not a key file", path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = random_key();
            match write_key_file(&path, &key) {
                Ok(()) => {
                    tracing::info!("created the key of the stored secrets: {} (keep it; back it up apart from the database)", path.display());
                    key
                }
                // Another process created it meanwhile: use that one
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read the key file {}", path.display()))?;
                    let bytes = hex::decode(text.trim()).map_err(|_| anyhow!("{} is not a key file", path.display()))?;
                    Key::try_from(bytes.as_slice()).map_err(|_| anyhow!("{} is not a key file", path.display()))?
                }
                Err(e) => return Err(e).with_context(|| format!("cannot create the key file {}", path.display())),
            }
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read the key file {}", path.display())),
    };
    keys.insert(path, key);
    Ok(key)
}

fn write_key_file(path: &Path, key: &Key) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    writeln!(file, "{}", hex::encode(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_reads_back_only_with_its_key() {
        let key = random_key();
        let sealed = seal(&key, "s3cret value");
        assert!(is_sealed(&sealed) && !sealed.contains("s3cret"));
        assert_ne!(sealed, seal(&key, "s3cret value")); // a fresh nonce each time
        assert_eq!(open(&key, &sealed).unwrap(), "s3cret value");
        assert!(open(&random_key(), &sealed).is_err());
        // Tampering is detected
        let mut damaged = sealed.clone();
        damaged.pop();
        damaged.push(if sealed.ends_with('A') { 'B' } else { 'A' });
        assert!(open(&key, &damaged).is_err());
        // What was stored before encryption is still readable
        assert_eq!(open(&key, "plain old value").unwrap(), "plain old value");
        assert_eq!(open(&key, &seal(&key, "")).unwrap(), "");
    }

    #[test]
    fn the_key_file_is_created_once_and_private() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("x.db");
        let key = key_for(&db).unwrap();
        assert_eq!(key_for(&db).unwrap(), key);
        let file = key_path(&db);
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), hex::encode(key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_database_holding_secrets_does_not_start_without_its_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vulnizard.db");
        drop(crate::db::Database::open(&path).unwrap());
        let key_file = key_path(&path);
        assert!(key_file.exists());
        // Reopening with the key works; without it the server refuses instead of making a new key
        drop(crate::db::Database::open(&path).unwrap());
        std::fs::remove_file(&key_file).unwrap();
        let refused = crate::db::Database::open(&path).err().expect("must refuse");
        assert!(refused.to_string().contains("key file"));
        assert!(!key_file.exists());
    }

    #[test]
    fn the_key_comes_from_the_named_file_then_a_credential_then_beside_the_database() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("v.db");
        let beside = PathBuf::from(format!("{}.key", db.display()));
        assert_eq!(resolve_key_path(None, None, &db), beside);
        assert_eq!(resolve_key_path(Some("".into()), Some("".into()), &db), beside);
        // A credentials directory only counts if it holds the key
        let credentials = dir.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        assert_eq!(resolve_key_path(None, Some(credentials.clone().into()), &db), beside);
        std::fs::write(credentials.join("vulnizard.key"), hex::encode(random_key())).unwrap();
        assert_eq!(resolve_key_path(None, Some(credentials.clone().into()), &db), credentials.join("vulnizard.key"));
        // The named file wins over everything
        assert_eq!(resolve_key_path(Some("/keys/k".into()), Some(credentials.into()), &db), PathBuf::from("/keys/k"));
    }

    #[test]
    fn exporting_never_creates_a_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("v.db");
        assert!(export_key(&db).is_err());
        assert!(!key_path(&db).exists());
        let key = key_for(&db).unwrap();
        assert_eq!(export_key(&db).unwrap(), hex::encode(key));
    }
}
