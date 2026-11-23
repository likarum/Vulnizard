//! Source synchronization shared by the CLI (`sync`) and the server scheduler.

use anyhow::Result;

use crate::config::Config;
use crate::db::Database;
use crate::sources::cisa_kev::CisaKevSource;
use crate::sources::distros::DistrosSource;
use crate::sources::epss::EpssSource;
use crate::sources::exploitdb::ExploitDbSource;
use crate::sources::metasploit::MetasploitSource;
use crate::sources::nuclei::NucleiSource;
use crate::sources::nvd::NvdSource;
use crate::sources::osv::OsvSource;
use crate::sources::vulnrichment::VulnrichmentSource;
use crate::sources::{CveSource, SyncOptions, SyncResult};

/// Runs one source. Returns `None` for an unknown source name.
pub fn run_source(
    db: &Database,
    config: &Config,
    source: &str,
    opts: &SyncOptions,
) -> Option<Result<SyncResult>> {
    Some(match source {
        "nvd" => NvdSource::new(config.nvd.api_key.clone()).sync(db, opts),
        "cisa_kev" => CisaKevSource::new().sync(db, opts),
        "epss" => EpssSource::new().sync(db, opts),
        "exploitdb" => ExploitDbSource::new().sync(db, opts),
        "metasploit" => MetasploitSource::new().sync(db, opts),
        "nuclei" => NucleiSource::new().sync(db, opts),
        "osv" => OsvSource::new().sync(db, opts),
        "distros" => DistrosSource::new().sync(db, opts),
        "vulnrichment" => VulnrichmentSource::new().sync(db, opts),
        _ => return None,
    })
}

/// Syncs the given sources (incremental), recording each run in
/// `sync_history`, then refreshes the vendor/product catalog.
///
/// `by_name` is set when the sources were asked for explicitly: they then run
/// even if they were synchronized recently.
pub fn run_sources(
    db: &Database,
    config: &Config,
    sources: &[String],
    by_name: bool,
    started: &dyn Fn(&str),
) -> Result<()> {
    for source in sources {
        started(source);
        let opts = SyncOptions::new(config.sync.history_months)
            .with_last_sync(db.get_last_sync(source)?)
            .ignore_freshness(by_name);
        let sync_id = db.start_sync(source)?;
        match run_source(db, config, source, &opts) {
            // A source that had nothing to do did not synchronize: recording it as a run
            // would move its "last synchronized" date forward at every cycle, and a source
            // that waits 12 hours between downloads would then never be due again.
            Some(Ok(r)) if r.skipped => {
                db.discard_sync(sync_id)?;
                tracing::debug!("sync {source}: skipped, synchronized recently");
            }
            // Asked, and nothing new upstream: nothing was downloaded. It counts for the time
            // to wait before asking again, and shows as such.
            Some(Ok(r)) if r.unchanged => {
                db.unchanged_sync(sync_id)?;
                tracing::info!("sync {source}: unchanged upstream, nothing downloaded");
            }
            Some(Ok(r)) => {
                db.complete_sync(sync_id, r.added, r.updated)?;
                tracing::info!("sync {}: {} added, {} updated, {} errors", source, r.added, r.updated, r.errors);
            }
            Some(Err(e)) => {
                db.fail_sync(sync_id, &e.to_string())?;
                tracing::warn!("sync {} failed: {}", source, e);
            }
            None => {
                db.fail_sync(sync_id, "unknown source")?;
                tracing::warn!("unknown source: {}", source);
            }
        }
    }
    db.rebuild_catalog()?;
    Ok(())
}
