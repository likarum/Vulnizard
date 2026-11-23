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

/// How each source is read: the hours a periodic run leaves between two
/// downloads (0: at every cycle), and what one download fetches. One place
/// for the sources, which obey it, and for the administration page, which
/// shows it.
pub const PACES: [(&str, i64, &str); 9] = [
    ("nvd", 0, "only the CVEs changed since the last run"),
    ("cisa_kev", 6, "the whole catalog, about 2 MB"),
    ("epss", 12, "the whole file of scores, about 3 MB"),
    ("vulnrichment", 24, "only the records changed since the last run; the whole archive the first time or after a long stop"),
    ("osv", 12, "the whole archive of five ecosystems, about 290 MB"),
    ("distros", 12, "the whole archive of Debian advisories, about 85 MB"),
    ("exploitdb", 12, "the whole index, about 10 MB"),
    ("metasploit", 24, "the whole index, about 11 MB"),
    ("nuclei", 24, "the whole index, about 2 MB"),
];

/// Hours a periodic run leaves between two downloads of a source
pub fn min_hours(source: &str) -> i64 {
    PACES.iter().find(|(name, _, _)| *name == source).map_or(0, |(_, hours, _)| *hours)
}

/// What one download of a source fetches
pub fn fetches(source: &str) -> &'static str {
    PACES.iter().find(|(name, _, _)| *name == source).map_or("", |(_, _, what)| what)
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_source_says_how_often_and_what_it_downloads() {
        for (key, _, _) in crate::settings::SOURCES {
            assert!(super::PACES.iter().any(|(name, _, what)| *name == key && !what.is_empty()), "{key}");
        }
        // Only the sources that read changes run at every cycle
        assert_eq!(super::min_hours("nvd"), 0);
        for whole in ["cisa_kev", "epss", "osv", "distros", "exploitdb", "metasploit", "nuclei"] {
            assert!(super::min_hours(whole) >= 6, "{whole}");
        }
    }
}
