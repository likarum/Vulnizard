//! First-run setup: while no account exists, the instance can be set up from
//! the web with a one-time code that only someone with access to the server
//! can read (its log, or `vulnizard setup-code`). The code is stored sealed
//! and disappears with the creation of the administrator.

use anyhow::Result;
use rand::RngCore;
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::Database;

const KEY_SETUP_CODE: &str = "setup.code";
/// No 0/O, 1/I/L: the code is read from a log and typed by hand
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Refusal of a setup that is no longer open
#[derive(Debug)]
pub struct SetupClosed;

impl std::fmt::Display for SetupClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this instance is already set up")
    }
}

impl std::error::Error for SetupClosed {}

fn new_code() -> String {
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut code = String::new();
    for (i, mut byte) in bytes.into_iter().enumerate() {
        // Rejection sampling keeps every character equally likely
        while byte as usize >= 256 - 256 % ALPHABET.len() {
            let mut again = [0u8; 1];
            rand::rngs::OsRng.fill_bytes(&mut again);
            byte = again[0];
        }
        if i > 0 && i % 5 == 0 {
            code.push('-');
        }
        code.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
    }
    code
}

/// What is compared: letters and digits only, in capitals
fn normalized(code: &str) -> String {
    code.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}

impl Database {
    /// The setup is open while no account exists
    pub fn setup_is_open(&self) -> Result<bool> {
        Ok(self.count_accounts()? == 0)
    }

    /// The one-time setup code, created on first use. None once an account exists.
    pub fn setup_code(&self) -> Result<Option<String>> {
        if !self.setup_is_open()? {
            return Ok(None);
        }
        if let Some(code) = self.get_secret(KEY_SETUP_CODE)? {
            return Ok(Some(code));
        }
        let code = new_code();
        self.set_secret(KEY_SETUP_CODE, &code)?;
        Ok(Some(code))
    }

    /// Whether `given` is the setup code (spaces, dashes and case do not matter)
    pub fn setup_code_matches(&self, given: &str) -> Result<bool> {
        let Some(expected) = self.setup_code()? else {
            return Ok(false);
        };
        // Compared through digests, so that timing tells nothing of the code
        let a = Sha256::digest(normalized(&expected).as_bytes());
        let b = Sha256::digest(normalized(given).as_bytes());
        Ok(a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0)
    }

    /// Creates the administrator if, and only if, no account exists yet; the
    /// setup code is forgotten in the same transaction.
    pub fn create_first_administrator(&self, username: &str, email: Option<&str>, password_hash: &str) -> Result<i64> {
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        let result = self.count_accounts().and_then(|n| {
            if n != 0 {
                return Err(anyhow::Error::new(SetupClosed));
            }
            let id = self.create_account(username, email, password_hash, true)?;
            self.conn().execute("DELETE FROM metadata WHERE key = ?1", params![KEY_SETUP_CODE])?;
            Ok(id)
        });
        match &result {
            Ok(_) => self.conn().execute_batch("COMMIT")?,
            Err(_) => self.conn().execute_batch("ROLLBACK")?,
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_opens_the_setup_once() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.setup_is_open().unwrap());
        let code = db.setup_code().unwrap().unwrap();
        // Four groups of five characters, the same code until it is used
        assert_eq!(code.len(), 23);
        assert!(code.split('-').all(|g| g.len() == 5 && g.bytes().all(|b| ALPHABET.contains(&b))));
        assert_eq!(db.setup_code().unwrap().unwrap(), code);
        // Stored sealed, not in clear
        let stored: String = db.conn().query_row("SELECT value FROM metadata WHERE key = 'setup.code'", [], |r| r.get(0)).unwrap();
        assert!(!stored.contains(&code));

        assert!(db.setup_code_matches(&code).unwrap());
        assert!(db.setup_code_matches(&format!(" {} ", code.to_lowercase().replace('-', " "))).unwrap());
        assert!(!db.setup_code_matches("").unwrap());
        assert!(!db.setup_code_matches(&code[..22]).unwrap());

        let admin = db.create_first_administrator("root", None, "hash").unwrap();
        assert!(db.get_account(admin).unwrap().unwrap().is_admin);
        // Closed for good: no code, nothing matches, no second administrator
        assert!(!db.setup_is_open().unwrap());
        assert_eq!(db.setup_code().unwrap(), None);
        assert!(!db.setup_code_matches(&code).unwrap());
        let again = db.create_first_administrator("mallory", None, "hash").unwrap_err();
        assert!(again.downcast_ref::<SetupClosed>().is_some());
        assert_eq!(db.count_accounts().unwrap(), 1);
        let left: i64 = db.conn().query_row("SELECT count(*) FROM metadata WHERE key = 'setup.code'", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn codes_differ_and_use_the_whole_alphabet() {
        let codes: Vec<String> = (0..200).map(|_| new_code()).collect();
        let distinct: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(distinct.len(), 200);
        let seen: std::collections::HashSet<char> = codes.iter().flat_map(|c| c.chars()).filter(|c| *c != '-').collect();
        assert_eq!(seen.len(), ALPHABET.len());
    }
}
