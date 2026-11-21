pub mod cisa_kev;
pub mod distros;
pub mod epss;
pub mod exploitdb;
pub mod metasploit;
pub mod nuclei;
pub mod nvd;
pub mod osv;
pub mod vulnrichment;

use anyhow::Result;
use chrono::{DateTime, Utc};
use crate::db::Database;

/// Options de synchronisation
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Nombre de mois d'historique (pour sync initial)
    pub months: u32,
    /// Date du dernier sync réussi (pour sync incrémental)
    pub last_sync: Option<DateTime<Utc>>,
    /// Forcer un sync complet même si un sync précédent existe
    pub force_full: bool,
    /// Run even if the source was synchronized recently (asked for by name)
    pub ignore_freshness: bool,
}

impl SyncOptions {
    pub fn new(months: u32) -> Self {
        Self {
            months,
            last_sync: None,
            force_full: false,
            ignore_freshness: false,
        }
    }

    pub fn with_last_sync(mut self, last_sync: Option<DateTime<Utc>>) -> Self {
        self.last_sync = last_sync;
        self
    }

    pub fn force_full(mut self) -> Self {
        self.force_full = true;
        self
    }

    pub fn ignore_freshness(mut self, ignore: bool) -> Self {
        self.ignore_freshness = ignore;
        self
    }

    /// True if a source that ran recently may skip this run. Sources that
    /// download everything each time use it to avoid doing so every cycle.
    pub fn may_skip_if_fresh(&self) -> bool {
        !self.force_full && !self.ignore_freshness
    }

    /// Retourne true si on doit faire un sync incrémental
    pub fn is_incremental(&self) -> bool {
        !self.force_full && self.last_sync.is_some()
    }
}

/// Trait commun pour toutes les sources de CVE
pub trait CveSource {
    /// Nom de la source
    #[allow(dead_code)]
    fn name(&self) -> &'static str;

    /// Synchronise les CVE depuis cette source
    fn sync(&self, db: &Database, opts: &SyncOptions) -> Result<SyncResult>;
}

/// Résultat d'une synchronisation
#[derive(Debug, Default)]
pub struct SyncResult {
    pub added: i64,
    pub updated: i64,
    pub errors: i64,
    /// Nothing was fetched: the source ran recently enough (or has nothing to
    /// do). Such a run is not a synchronization and must not count as one.
    pub skipped: bool,
}

impl SyncResult {
    pub fn skipped() -> Self {
        Self { skipped: true, ..Default::default() }
    }
}

impl SyncResult {
    #[allow(dead_code)]
    pub fn total(&self) -> i64 {
        self.added + self.updated
    }
}
