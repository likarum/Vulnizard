//! In-process scheduler (no external job runner): periodically syncs
//! the sources, routes the detected changes to project reports and sends the
//! notifications. Runs on a dedicated thread since sources use blocking I/O.
//!
//! The sources, the interval and the delivery settings are read again at
//! every cycle, so changes made in the administration UI apply without a
//! restart.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::db::Database;
use crate::{notify, settings, sync};

/// What to sync when the scheduler is woken up
#[derive(Debug, Clone, PartialEq)]
pub enum SyncRequest {
    /// Every enabled source
    All,
    /// One source, enabled or not
    Source(String),
    /// Some sources (what is left of a request once those that just ran are set aside)
    Sources(Vec<String>),
}

/// A sync asked by someone (`by` = user id) or by the clock (`by` = None)
#[derive(Debug, Clone, PartialEq)]
pub struct SyncOrder {
    pub request: SyncRequest,
    pub by: Option<i64>,
}

/// Sources requested but not started yet, shared with the web UI so that a
/// click on "Sync now" is visible at once.
pub type SyncQueue = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// How often the scheduler checks whether a periodic sync is due
const TICK: Duration = Duration::from_secs(20);

/// Starts the scheduler thread. A message on `trigger` runs a cycle immediately.
pub fn spawn(db_path: PathBuf, base: Config, trigger: Receiver<SyncOrder>, queue: SyncQueue) {
    std::thread::Builder::new()
        .name("scheduler".into())
        .spawn(move || {
            // Runs cut short by a previous stop would show as "in progress" forever
            match Database::connect(&db_path).and_then(|db| db.fail_interrupted_syncs()) {
                Ok(0) => {}
                Ok(n) => tracing::info!("scheduler: {n} interrupted sync run(s) marked as failed"),
                Err(e) => tracing::warn!("scheduler: cannot clean interrupted syncs: {e:#}"),
            }
            // First cycle at startup when periodic sync is on; otherwise only
            // initialise the change marker
            let startup = interval(&db_path, &base).is_some();
            run_cycle(&db_path, &base, startup.then_some(SyncOrder { request: SyncRequest::All, by: None }), &queue);
            let mut last_run = Instant::now();
            loop {
                match trigger.recv_timeout(TICK) {
                    Ok(request) => {
                        run_cycle(&db_path, &base, Some(request), &queue);
                        last_run = Instant::now();
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if interval(&db_path, &base).is_some_and(|every| last_run.elapsed() >= every) {
                            run_cycle(&db_path, &base, Some(SyncOrder { request: SyncRequest::All, by: None }), &queue);
                            last_run = Instant::now();
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("failed to start scheduler thread");
}

/// Current period between two syncs (None = periodic sync disabled)
fn interval(db_path: &Path, base: &Config) -> Option<Duration> {
    let minutes = Database::connect(db_path)
        .and_then(|db| settings::effective(base, &db))
        .map(|c| c.web.sync_interval_minutes)
        .unwrap_or(base.web.sync_interval_minutes);
    (minutes > 0).then(|| Duration::from_secs(minutes * 60))
}

fn run_cycle(db_path: &Path, base: &Config, order: Option<SyncOrder>, queue: &SyncQueue) {
    let db = match Database::connect(db_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("scheduler: cannot open database: {e:#}");
            return;
        }
    };
    let config = match settings::effective(base, &db) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("scheduler: cannot read settings: {e:#}");
            base.clone()
        }
    };
    if let Some(order) = order {
        let began: String = db.conn().query_row("SELECT datetime('now')", [], |r| r.get(0)).unwrap_or_default();
        // A source asked for by name runs even if it was synchronized recently
        let by_name = matches!(order.request, SyncRequest::Source(_));
        let sources = match order.request {
            SyncRequest::All => config.sync.sources.clone(),
            SyncRequest::Source(source) => vec![source],
            SyncRequest::Sources(sources) => sources,
        };
        tracing::info!("scheduler: sync cycle started ({})", sources.join(", "));
        let started = |source: &str| {
            let mut queued = queue.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(position) = queued.iter().position(|s| s == source) {
                queued.remove(position);
            }
        };
        if let Err(e) = sync::run_sources(&db, &config, &sources, by_name, &started) {
            tracing::error!("scheduler: sync failed: {e:#}");
        }
        // Whatever happened, nothing of this request stays "queued"
        for source in &sources {
            started(source);
        }
        // Keep the watchlist of tracked applications up to date
        match db.rescan_all_applications() {
            Ok(n) => tracing::info!("scheduler: watchlist rescan, {n} new entries"),
            Err(e) => tracing::error!("scheduler: watchlist rescan failed: {e:#}"),
        }
        // Inventories read from Git repositories
        let git_sources = if config.inventory.enabled { db.list_git_sources().unwrap_or_default() } else { Vec::new() };
        for source in git_sources {
            match crate::inventory::pull(&db, &config, &source) {
                Ok(o) => tracing::info!(
                    "inventory '{}': {} components, {} added, {} updated, {} removed",
                    source.name, o.received, o.added, o.updated, o.removed
                ),
                Err(e) => tracing::warn!("inventory '{}' failed: {e:#}", source.name),
            }
        }
        // A sync started by someone tells them (and the instance destinations) when it is over
        if let Some(user_id) = order.by {
            notify_sync_finished(&db, &config, user_id, &sources, &began);
        }
    }
    match db.process_changes() {
        Ok(dispatches) => {
            for d in &dispatches {
                match notify::send(&config, &db, d) {
                    Ok(()) => tracing::info!(
                        "notification '{}' sent ({}/{}, {} changes)",
                        d.notification.name,
                        d.org,
                        d.project,
                        d.changes.len()
                    ),
                    Err(e) => tracing::warn!(
                        "notification '{}' ({}/{}) failed: {e:#}",
                        d.notification.name,
                        d.org,
                        d.project
                    ),
                }
            }
        }
        Err(e) => tracing::error!("scheduler: change processing failed: {e:#}"),
    }
}

/// Summary of the last run of each synchronized source
/// What a cycle did, source by source. `since` is when the cycle began: a
/// source whose last run is older did not run in it (it was up to date).
fn sync_summary(db: &Database, sources: &[String], since: &str) -> (String, String) {
    let runs = db.last_sync_runs().unwrap_or_default();
    let mut failed = false;
    let lines: Vec<String> = sources
        .iter()
        .map(|source| match runs.iter().find(|r| &r.source == source) {
            Some(r) if r.started_at.as_str() < since => format!("{source}: already up to date"),
            Some(r) if r.status == "completed" => format!("{source}: {} added, {} updated", r.added, r.updated),
            None => format!("{source}: already up to date"),
            _ => {
                failed = true;
                format!("{source}: failed")
            }
        })
        .collect();
    let title = if failed {
        "Synchronization finished with errors"
    } else {
        "Synchronization finished"
    };
    (title.to_string(), lines.join("\n"))
}

fn notify_sync_finished(db: &Database, config: &Config, user_id: i64, sources: &[String], since: &str) {
    let (title, body) = sync_summary(db, sources, since);
    // The browsers of whoever asked for it
    if let Err(e) = crate::push::deliver(db, config, user_id, &title, &body, "/admin/sources") {
        tracing::warn!("scheduler: browser notification failed: {e:#}");
    }
    // Enabled instance destinations that want instance events
    for destination in db.list_system_destinations().unwrap_or_default() {
        if let Err(e) = notify::send_system(config, &destination, &title, &body) {
            tracing::warn!("scheduler: notification to '{}' failed: {e:#}", destination.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_summary_reports_each_source_and_failures() {
        let db = Database::open_in_memory().unwrap();
        let ok = db.start_sync("nvd").unwrap();
        db.complete_sync(ok, 3, 1, 0).unwrap();
        let ko = db.start_sync("epss").unwrap();
        db.fail_sync(ko, "timeout").unwrap();
        let (title, body) = sync_summary(&db, &["nvd".into()], "2000-01-01 00:00:00");
        assert_eq!((title.as_str(), body.as_str()), ("Synchronization finished", "nvd: 3 added, 1 updated"));
        // A source that did not run in this cycle was up to date: that is not a failure
        let (title, body) = sync_summary(&db, &["nvd".into(), "epss".into(), "osv".into()], "2000-01-01 00:00:00");
        assert_eq!(title, "Synchronization finished with errors");
        assert_eq!(body, "nvd: 3 added, 1 updated\nepss: failed\nosv: already up to date");
        let (title, body) = sync_summary(&db, &["nvd".into(), "epss".into()], "2999-01-01 00:00:00");
        assert_eq!((title.as_str(), body.as_str()), ("Synchronization finished", "nvd: already up to date\nepss: already up to date"));
    }

    #[test]
    fn a_skipped_run_is_not_a_synchronization() {
        // A source that waits hours between two downloads skips most cycles. If each skip
        // counted as a sync, "last synchronized" would move at every cycle and the source
        // would never be due again.
        let db = Database::open_in_memory().unwrap();
        let real = db.start_sync("epss").unwrap();
        db.complete_sync(real, 10, 0, 0).unwrap();
        db.conn().execute("UPDATE sync_history SET started_at = datetime('now', '-13 hours'), completed_at = datetime('now', '-13 hours')", []).unwrap();
        let last = db.get_last_sync("epss").unwrap().unwrap();
        let skipped = db.start_sync("epss").unwrap();
        db.discard_sync(skipped).unwrap();
        assert_eq!(db.get_last_sync("epss").unwrap().unwrap(), last);
        assert!((chrono::Utc::now() - last).num_hours() >= 12);
        // Only a run still in progress can be discarded
        db.discard_sync(real).unwrap();
        assert_eq!(db.get_last_sync("epss").unwrap().unwrap(), last);

        // The date kept is when the run started: what changed upstream while it ran is not lost
        let long = db.start_sync("nvd").unwrap();
        db.conn().execute("UPDATE sync_history SET started_at = datetime('now', '-2 hours') WHERE id = ?1", [long]).unwrap();
        db.complete_sync(long, 1, 0, 0).unwrap();
        let age = (chrono::Utc::now() - db.get_last_sync("nvd").unwrap().unwrap()).num_minutes();
        assert!((115..=125).contains(&age), "{age}");

        let opts = crate::sources::SyncOptions::new(6);
        assert!(opts.may_skip_if_fresh());
        assert!(!opts.clone().ignore_freshness(true).may_skip_if_fresh());
        assert!(!opts.force_full().may_skip_if_fresh());
    }

    #[test]
    fn a_manual_sync_reaches_the_requester_inbox() {
        let db = Database::open_in_memory().unwrap();
        let admin = db.create_account("root", None, "h", true).unwrap();
        let run = db.start_sync("nvd").unwrap();
        db.complete_sync(run, 2, 0, 0).unwrap();
        notify_sync_finished(&db, &Config::default(), admin, &["nvd".into()], "2000-01-01 00:00:00");
        let inbox = db.push_take(admin).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!((inbox[0].title.as_str(), inbox[0].url.as_str()), ("Synchronization finished", "/admin/sources"));
    }
}
