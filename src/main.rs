mod auth;
mod changes;
mod completions;
mod config;
mod db;
mod extraction;
mod inventory;
mod mfa;
mod secrets;
mod trail;
mod versions;
mod mcp;
mod models;
mod notify;
mod push;
mod rbac;
mod scheduler;
mod settings;
mod sources;
mod sync;
mod web;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::io;
use std::path::PathBuf;

use crate::config::Config;
use crate::db::{Database, SearchQuery, SortBy};
use crate::models::{Application, CveStatus, Priority, Project};
use crate::sources::SyncOptions;

#[derive(Parser)]
#[command(name = "vulnizard")]
#[command(about = "Lightweight Vulnerability Intelligence Platform", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Database path (overrides config)
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the web server: UI, REST API and background sync/notifications
    Serve {
        /// Listen address (overrides config, default 127.0.0.1:8000)
        #[arg(long)]
        bind: Option<String>,
    },
    /// Run an MCP server on stdio (read-only tools for AI assistants)
    Mcp {
        /// Also expose tools that modify the monitoring configuration
        /// (create projects, subscribe, add applications)
        #[arg(long)]
        allow_write: bool,
    },
    /// Manage web accounts
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Print the one-time code that opens the first-run setup page (while no account exists)
    SetupCode,
    /// The key that encrypts the secrets stored in the database
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Signed log exports (security log, audit of decisions)
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
    /// Synchronize CVE data from all sources
    Sync {
        /// How far back the NVD is read, in months (0: the whole history; default: the configuration)
        #[arg(long)]
        months: Option<u32>,

        /// Only sync specific source (nvd, cisa_kev, epss, exploitdb, metasploit, nuclei, osv, vulnrichment, distros)
        #[arg(long)]
        source: Option<String>,

        /// Force a full sync instead of incremental (re-download everything)
        #[arg(long)]
        full: bool,
    },

    /// Extract affected products from descriptions for CVEs missing them
    UpdateProducts,

    /// Search CVEs
    Search {
        /// Search text (CVE ID, keyword, vendor, product)
        query: Option<String>,

        /// Minimum CVSS score
        #[arg(long)]
        min_cvss: Option<f64>,

        /// Minimum EPSS score
        #[arg(long)]
        min_epss: Option<f64>,

        /// Only show KEV (Known Exploited Vulnerabilities)
        #[arg(long)]
        kev: bool,

        /// Filter by vendor
        #[arg(long)]
        vendor: Option<String>,

        /// Filter by product name
        #[arg(long)]
        product: Option<String>,

        /// Filter by version (requires --product)
        #[arg(long)]
        version: Option<String>,

        /// Only show CVEs with public exploits
        #[arg(long)]
        has_exploit: bool,
        /// Only CVEs a source has data on (nvd, cisa_kev, epss, vulnrichment, osv, exploitdb, metasploit, nuclei)
        #[arg(long = "from-source")]
        from_source: Option<String>,

        /// Filter by package ecosystem (npm, PyPI, Go, Maven, crates.io)
        #[arg(long)]
        ecosystem: Option<String>,

        /// Filter by package name (requires --ecosystem)
        #[arg(long, name = "package")]
        package_name: Option<String>,

        /// Filter by SSVC exploitation status (none, poc, active)
        #[arg(long)]
        ssvc_exploitation: Option<String>,

        /// Filter by SSVC automatable (yes, no)
        #[arg(long)]
        ssvc_automatable: Option<String>,

        /// Sort by: cvss, epss, published, modified
        #[arg(long, default_value = "published")]
        sort: String,

        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Output format: table, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Show database statistics
    Stats,

    /// Show details for a specific CVE
    Info {
        /// CVE ID (e.g., CVE-2024-1234)
        cve_id: String,
    },

    /// Project management
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },

    /// Application management
    App {
        #[command(subcommand)]
        action: AppAction,
    },

    /// Watchlist management
    Watch {
        #[command(subcommand)]
        action: WatchAction,
    },

    /// Shell completions
    Completions {
        #[command(subcommand)]
        action: CompletionsAction,
    },
}

#[derive(Subcommand)]
enum LogAction {
    /// Check a signed export: nothing changed, removed or reordered, and who signed it
    Verify {
        /// The JSON export
        file: PathBuf,
        /// Fingerprint of the key expected to have signed (shown by the instance)
        #[arg(long)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Print where the key file is
    Path,
    /// Print the key, to back it up (it is a secret)
    Export,
}

#[derive(Subcommand)]
enum UserAction {
    /// Create a web account (password is prompted)
    Create {
        username: String,
        #[arg(long)]
        email: Option<String>,
        /// Grant administrator rights
        #[arg(long)]
        admin: bool,
        /// Read the password from standard input instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Reset the password of a web account
    Passwd {
        username: String,
        /// Read the password from standard input instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove the second factors of a web account (lost device) and close its sessions
    ResetMfa { username: String },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Add a new project
    Add {
        /// Project name
        name: String,
        /// Project description
        #[arg(long)]
        description: Option<String>,
    },
    /// List all projects
    List,
    /// Delete a project
    Delete {
        /// Project name
        name: String,
    },
}

#[derive(Subcommand)]
enum AppAction {
    /// Add an application to a project
    Add {
        /// Application name
        name: String,
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
        /// Application version
        #[arg(long)]
        version: Option<String>,
        /// Vendor name
        #[arg(long)]
        vendor: Option<String>,
        /// Package ecosystem (npm, PyPI, Maven, Go, crates.io, etc.)
        #[arg(long)]
        ecosystem: Option<String>,
    },
    /// List applications in a project
    List {
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
    },
    /// Update application version
    Update {
        /// Application name
        name: String,
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
        /// New version
        #[arg(long)]
        version: String,
        /// Current version (if multiple versions exist)
        #[arg(long)]
        current_version: Option<String>,
    },
    /// Delete an application
    Delete {
        /// Application name
        name: String,
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
        /// Version (if multiple versions exist)
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(Subcommand)]
enum WatchAction {
    /// Scan applications for CVEs
    Scan {
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
        /// Specific application (optional, scans all if not specified)
        #[arg(long)]
        app: Option<String>,
    },
    /// List watchlist entries
    List {
        /// Project name (optional, lists all if not specified)
        #[arg(long)]
        project: Option<String>,
        /// Application name (optional)
        #[arg(long)]
        app: Option<String>,
        /// Filter by status: untreated, treated, not_applicable
        #[arg(long)]
        status: Option<String>,
        /// Output format: table, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Update CVE status for an application
    Status {
        /// CVE ID
        cve_id: String,
        /// Application name
        #[arg(long)]
        app: String,
        /// Project name (default: "default")
        #[arg(long, default_value = "default")]
        project: String,
        /// New status: treated, not_applicable, untreated
        #[arg(long)]
        status: String,
        /// Notes
        #[arg(long)]
        notes: Option<String>,
    },
    /// Show watchlist summary
    Summary {
        /// Project name (optional)
        #[arg(long)]
        project: Option<String>,
    },
}

#[derive(Subcommand)]
enum CompletionsAction {
    /// Generate shell completions
    Generate {
        /// Shell type
        #[arg(value_enum)]
        shell: Shell,
    },
    /// List projects (for dynamic completion)
    Projects,
    /// List applications (for dynamic completion)
    Apps {
        /// Project name
        #[arg(long)]
        project: Option<String>,
    },
    /// List CVE IDs in watchlist (for dynamic completion)
    Cves {
        /// Project name
        #[arg(long)]
        project: Option<String>,
        /// Application name
        #[arg(long)]
        app: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        // stdout is reserved for the protocol in MCP mode
        .with_writer(std::io::stderr)
        .init();

    // Load config
    let config = Config::load_or_default(cli.config.as_deref())?;

    // Determine DB path
    // Checking an export file needs no database: nothing is opened, created or migrated
    if let Commands::Log { action } = cli.command {
        match action {
            LogAction::Verify { file, key } => {
                let text = std::fs::read_to_string(&file).with_context(|| format!("cannot read {}", file.display()))?;
                let export: trail::Export = serde_json::from_str(&text).context("this is not a signed log export (JSON)")?;
                match trail::verify(&export, key.as_deref()) {
                    Ok(v) => {
                        println!("OK: {} log of {} — {} entries, exported {}", v.log, v.scope, v.count, v.exported_at);
                        println!("    every entry chains to the previous one; head {}", if v.head.is_empty() { "(empty log)" } else { &v.head });
                        match key {
                            Some(_) => println!("    signed by the expected key {}", v.key_fingerprint),
                            None => println!(
                                "    signed by key {} — compare it with the one shown by the instance, or pass --key",
                                v.key_fingerprint
                            ),
                        }
                    }
                    Err(reason) => {
                        eprintln!("INVALID: {reason}");
                        std::process::exit(1);
                    }
                }
            }
        }
        return Ok(());
    }

    let db_path = cli.db.unwrap_or(config.db_path.clone());

    // Open database (auto-creates if not exists)
    let db = Database::open(&db_path)?;

    match cli.command {
        Commands::Sync { months, source, full } => {
            cmd_sync(&db, &config, months, source, full)?;
        }
        Commands::Search {
            query,
            min_cvss,
            min_epss,
            kev,
            vendor,
            product,
            version,
            has_exploit,
            from_source,
            ecosystem,
            package_name,
            ssvc_exploitation,
            ssvc_automatable,
            sort,
            limit,
            format,
        } => {
            cmd_search(&db, query, min_cvss, min_epss, kev, vendor, product, version, has_exploit, from_source, ecosystem, package_name, ssvc_exploitation, ssvc_automatable, sort, limit, format)?;
        }
        Commands::Serve { bind } => {
            let mut config = config;
            if let Some(bind) = bind {
                config.web.bind = bind;
            }
            // Migrations are done: the server opens its own connections
            drop(db);
            web::serve(db_path, config)?;
        }
        Commands::Mcp { allow_write } => {
            mcp::serve(&db, allow_write, config.inventory.enabled)?;
        }
        Commands::User { action } => {
            cmd_user(&db, action)?;
        }
        // Handled before the database is opened (see above)
        Commands::Log { .. } => unreachable!("log commands do not open the database"),
        Commands::SetupCode => match db.setup_code()? {
            Some(code) => {
                println!("{code}");
                eprintln!("Enter it at {}/setup to create the administrator.", config.web.base_url.trim_end_matches('/'));
            }
            None => {
                eprintln!("This instance is already set up: an account exists, the setup page is closed.");
                std::process::exit(1);
            }
        },
        Commands::Key { action } => match action {
            KeyAction::Path => println!("{}", secrets::key_path(&db_path).display()),
            KeyAction::Export => {
                eprintln!(
                    "Key of the secrets stored in {}. Keep it apart from the database backups: \
                     together they reveal the stored secrets.",
                    db_path.display()
                );
                println!("{}", secrets::export_key(&db_path)?);
            }
        },
        Commands::Stats => {
            cmd_stats(&db)?;
        }
        Commands::Info { cve_id } => {
            cmd_info(&db, &cve_id)?;
        }
        Commands::UpdateProducts => {
            cmd_update_products(&db)?;
        }
        Commands::Project { action } => {
            cmd_project(&db, action)?;
        }
        Commands::App { action } => {
            cmd_app(&db, action)?;
        }
        Commands::Watch { action } => {
            cmd_watch(&db, action)?;
        }
        Commands::Completions { action } => {
            cmd_completions(&db, action)?;
        }
    }

    Ok(())
}

fn cmd_sync(db: &Database, config: &Config, months: Option<u32>, source: Option<String>, force_full: bool) -> Result<()> {
    let history_months = months.unwrap_or(config.sync.history_months);

    let sources_to_sync: Vec<&str> = match source {
        Some(ref s) => vec![s.as_str()],
        None => config.sync.sources.iter().map(|s| s.as_str()).collect(),
    };

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║         VULNIZARD - Vulnerability Intelligence           ║");
    if force_full {
        let history = if history_months == 0 { "whole history".to_string() } else { format!("{history_months} months history") };
        println!("║{:^58}║", format!("FULL SYNC ({history})"));
    } else {
        println!("║              INCREMENTAL SYNC                            ║");
    }
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    for source_name in sources_to_sync {
        // Récupérer la date du dernier sync réussi
        let last_sync = db.get_last_sync(source_name)?;

        // Construire les options de sync. A source named on the command line
        // runs even if it was synchronized recently.
        let mut opts = SyncOptions::new(history_months)
            .with_last_sync(last_sync)
            .ignore_freshness(source.is_some());

        if force_full {
            opts = opts.force_full();
        }

        // Afficher le mode de sync
        if let Some(last) = last_sync {
            if !force_full {
                println!("  ℹ Last sync: {}", last.format("%Y-%m-%d %H:%M UTC"));
            }
        } else {
            println!("  ℹ First sync for this source");
        }

        let sync_id = db.start_sync(source_name)?;

        let result = match sync::run_source(db, config, source_name, &opts) {
            Some(r) => r,
            None => {
                db.fail_sync(sync_id, "unknown source")?;
                println!("  ⚠ Unknown source: {}\n", source_name);
                continue;
            }
        };

        match result {
            // Nothing was fetched: not a synchronization (see sync::run_sources)
            Ok(sync_result) if sync_result.skipped => {
                db.discard_sync(sync_id)?;
                println!("  └─ Up to date: synchronized recently (name the source with --source to run it anyway)\n");
            }
            Ok(sync_result) if sync_result.unchanged => {
                db.unchanged_sync(sync_id)?;
                println!("  └─ Unchanged upstream since the last run: nothing downloaded\n");
            }
            Ok(sync_result) => {
                db.complete_sync(sync_id, sync_result.added, sync_result.updated, sync_result.same)?;
                if sync_result.errors > 0 {
                    println!(
                        "  └─ Result: {} added, {} updated, {} unchanged, {} errors\n",
                        sync_result.added, sync_result.updated, sync_result.same, sync_result.errors
                    );
                } else {
                    println!(
                        "  └─ Result: {} added, {} updated, {} unchanged ✓\n",
                        sync_result.added, sync_result.updated, sync_result.same
                    );
                }
            }
            Err(e) => {
                db.fail_sync(sync_id, &format!("{e:#}"))?;
                println!("  └─ FAILED: {}\n", e);
            }
        }
    }

    // Show final stats
    let stats = db.stats()?;
    println!("════════════════════════════════════════════════════════════");
    println!("Database: {} CVEs | {} with CVSS | {} KEV",
             stats.total_cves, stats.with_cvss, stats.kev_count);
    println!("════════════════════════════════════════════════════════════");

    Ok(())
}

fn cmd_search(
    db: &Database,
    query: Option<String>,
    min_cvss: Option<f64>,
    min_epss: Option<f64>,
    only_kev: bool,
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    has_exploit: bool,
    source: Option<String>,
    ecosystem: Option<String>,
    package_name: Option<String>,
    ssvc_exploitation: Option<String>,
    ssvc_automatable: Option<String>,
    sort: String,
    limit: usize,
    format: String,
) -> Result<()> {
    // Warn if version is specified without product
    if version.is_some() && product.is_none() {
        println!("Warning: --version requires --product to be specified");
    }

    // Warn if package is specified without ecosystem
    if package_name.is_some() && ecosystem.is_none() {
        println!("Warning: --package requires --ecosystem to be specified");
    }

    let sort_by = match sort.to_lowercase().as_str() {
        "cvss" => SortBy::Cvss,
        "epss" => SortBy::Epss,
        "published" => SortBy::Published,
        "modified" => SortBy::Modified,
        _ => SortBy::Cvss,
    };

    // Clone for display use after move into SearchQuery
    let version_display = version.clone();
    let product_display = product.clone();

    let search_query = SearchQuery {
        text: query,
        min_cvss,
        min_epss,
        only_kev,
        vendor,
        product,
        version,
        has_exploit,
        source,
        ecosystem,
        package_name,
        ssvc_exploitation,
        ssvc_automatable,
        sort_by,
        limit,
    };

    let results = db.search(&search_query)?;

    if results.is_empty() {
        println!("No CVEs found matching your criteria.");
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&results)?;
            println!("{}", json);
        }
        _ => {
            // Table format - add VER column when version filter is used
            if version_display.is_some() {
                println!(
                    "{:<16} {:>6} {:>8} {:>5} {:>4} {:>10} {}",
                    "CVE ID", "CVSS", "EPSS", "KEV", "VER", "Published", "Description"
                );
                println!("{}", "-".repeat(105));
            } else {
                println!(
                    "{:<16} {:>6} {:>8} {:>5} {:>10} {}",
                    "CVE ID", "CVSS", "EPSS", "KEV", "Published", "Description"
                );
                println!("{}", "-".repeat(100));
            }

            for cve in results {
                let cvss = cve
                    .cvss_v3_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "-".to_string());

                let epss = cve
                    .epss_score
                    .map(|s| format!("{:.4}", s))
                    .unwrap_or_else(|| "-".to_string());

                let kev = if cve.kev_known_exploited { "YES" } else { "-" };

                let published = cve
                    .published_at
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "-".to_string());

                let desc = cve
                    .description
                    .as_ref()
                    .map(|d| {
                        if d.len() > 50 {
                            format!("{}...", &d[..47])
                        } else {
                            d.clone()
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());

                if let Some(ref ver) = version_display {
                    // Determine version match certainty
                    let ver_match = get_version_match_indicator(&cve, ver, product_display.as_deref());
                    println!(
                        "{:<16} {:>6} {:>8} {:>5} {:>4} {:>10} {}",
                        cve.cve_id, cvss, epss, kev, ver_match, published, desc
                    );
                } else {
                    println!(
                        "{:<16} {:>6} {:>8} {:>5} {:>10} {}",
                        cve.cve_id, cvss, epss, kev, published, desc
                    );
                }
            }

            // Legend when version filter is used
            if version_display.is_some() {
                println!();
                println!("VER: ✓ = confirmed affected, ? = unknown version range");
            }
        }
    }

    Ok(())
}

fn read_password(from_stdin: bool, username: &str) -> Result<String> {
    let password = if from_stdin {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        let password = rpassword::prompt_password("Password: ")?;
        if rpassword::prompt_password("Confirm password: ")? != password {
            anyhow::bail!("Passwords do not match");
        }
        password
    };
    auth::check_new_password(&password, username).map_err(|why| anyhow::anyhow!(why))?;
    Ok(password)
}

fn cmd_user(db: &Database, action: UserAction) -> Result<()> {
    match action {
        UserAction::Create { username, email, admin, password_stdin } => {
            if !auth::valid_slug(&username, 3, 32) {
                anyhow::bail!("Username: 3 to 32 letters, digits, '-', '_' or '.'");
            }
            let hash = auth::hash_password(&read_password(password_stdin, &username)?)?;
            db.create_account(&username, email.as_deref(), &hash, admin)?;
            println!("Account '{}' created{}", username, if admin { " (admin)" } else { "" });
        }
        UserAction::Passwd { username, password_stdin } => {
            let (account, _) = db
                .get_credentials(&username)?
                .ok_or_else(|| anyhow::anyhow!("No web account named '{}'", username))?;
            db.set_password(account.id, &auth::hash_password(&read_password(password_stdin, &account.username)?)?)?;
            println!("Password updated for '{}'", account.username);
        }
        UserAction::ResetMfa { username } => {
            let (account, _) = db
                .get_credentials(&username)?
                .ok_or_else(|| anyhow::anyhow!("No web account named '{}'", username))?;
            db.reset_mfa(account.id)?;
            db.log_security_event(&db::Actor::system("cli"), Some(account.id), "mfa_reset", None)?;
            println!("Two-step sign-in reset for '{}'", account.username);
        }
    }
    Ok(())
}

fn cmd_stats(db: &Database) -> Result<()> {
    let stats = db.stats()?;

    println!("Database Statistics");
    println!("===================");
    println!("Total CVEs:           {}", stats.total_cves);
    println!("With CVSS score:      {}", stats.with_cvss);
    println!("With EPSS score:      {}", stats.with_epss);
    println!("Known Exploited (KEV):{}", stats.kev_count);
    println!("Critical (CVSS >= 9): {}", stats.critical_count);

    Ok(())
}

fn cmd_info(db: &Database, cve_id: &str) -> Result<()> {
    // Normalize CVE ID
    let cve_id = cve_id.to_uppercase();

    match db.get_cve(&cve_id)? {
        Some(cve) => {
            println!("{}", cve.cve_id);
            println!("{}", "=".repeat(cve.cve_id.len()));
            println!();

            if let Some(ref desc) = cve.description {
                println!("Description:");
                println!("  {}", desc);
                println!();
            }

            println!("Scores:");
            if let Some(cvss) = cve.cvss_v3_score {
                println!("  CVSS v3: {:.1}", cvss);
                if let Some(ref vector) = cve.cvss_v3_vector {
                    println!("  Vector:  {}", vector);
                }
            }
            if let Some(epss) = cve.epss_score {
                println!(
                    "  EPSS:    {:.4} (percentile: {:.2}%)",
                    epss,
                    cve.epss_percentile.unwrap_or(0.0) * 100.0
                );
            }
            println!();

            if cve.kev_known_exploited {
                println!("⚠️  KNOWN EXPLOITED VULNERABILITY (CISA KEV)");
                if let Some(ref date) = cve.kev_date_added {
                    println!("  Added to KEV: {}", date);
                }
                println!();
            }

            // Exploit information
            if let Some(ref template) = cve.nuclei_template {
                println!("Detection:");
                println!("  Nuclei template: {}", template);
                println!();
            }
            if cve.exploit_public || !cve.exploit_urls.is_empty() || cve.metasploit_module.is_some() {
                println!("Exploits:");
                if cve.exploit_public {
                    println!("  Public exploit available: YES");
                }
                if let Some(ref msf) = cve.metasploit_module {
                    println!("  Metasploit module: {}", msf);
                }
                for url in cve.exploit_urls.iter().take(5) {
                    println!("  - {}", url);
                }
                if cve.exploit_urls.len() > 5 {
                    println!("  ... and {} more", cve.exploit_urls.len() - 5);
                }
                println!();
            }

            // SSVC Assessment (CISA Vulnrichment)
            if cve.ssvc_exploitation.is_some() || cve.ssvc_automatable.is_some() || cve.ssvc_technical_impact.is_some() {
                println!("SSVC Assessment (CISA):");
                if let Some(ref exploitation) = cve.ssvc_exploitation {
                    println!("  Exploitation:     {}", exploitation);
                }
                if let Some(ref automatable) = cve.ssvc_automatable {
                    println!("  Automatable:      {}", automatable);
                }
                if let Some(ref technical_impact) = cve.ssvc_technical_impact {
                    println!("  Technical Impact: {}", technical_impact);
                }
                println!();
            }

            // Affected packages (from OSV)
            if !cve.affected_packages.is_empty() {
                println!("Affected Packages:");
                for pkg in cve.affected_packages.iter().take(10) {
                    let range = pkg.vulnerable_range.as_deref().unwrap_or("*");
                    let fixed = pkg.fixed_version.as_ref()
                        .map(|v| format!(" (fixed: {})", v))
                        .unwrap_or_default();
                    println!("  - [{}] {}: {}{}", pkg.ecosystem, pkg.name, range, fixed);
                }
                if cve.affected_packages.len() > 10 {
                    println!("  ... and {} more", cve.affected_packages.len() - 10);
                }
                println!();
            }

            if !cve.cwe_ids.is_empty() {
                println!("CWE:");
                for cwe in &cve.cwe_ids {
                    println!("  - {}", cwe);
                }
                println!();
            }

            if !cve.affected_products.is_empty() {
                println!("Affected Products:");
                for product in cve.affected_products.iter().take(10) {
                    let vendor = product.vendor.as_deref().unwrap_or("unknown");
                    let prod = product.product.as_deref().unwrap_or("unknown");
                    let version = product.version.as_deref().unwrap_or("*");
                    println!("  - {}:{} ({})", vendor, prod, version);
                }
                if cve.affected_products.len() > 10 {
                    println!("  ... and {} more", cve.affected_products.len() - 10);
                }
                println!();
            }

            println!("Dates:");
            if let Some(published) = cve.published_at {
                println!("  Published: {}", published.format("%Y-%m-%d %H:%M UTC"));
            }
            if let Some(modified) = cve.modified_at {
                println!("  Modified:  {}", modified.format("%Y-%m-%d %H:%M UTC"));
            }
            println!();

            if !cve.references.is_empty() {
                println!("References:");
                for r in cve.references.iter().take(5) {
                    println!("  - {}", r.url);
                }
                if cve.references.len() > 5 {
                    println!("  ... and {} more", cve.references.len() - 5);
                }
            }
        }
        None => {
            println!("CVE {} not found in database.", cve_id);
            println!("Try running 'vulnizard sync' first.");
        }
    }

    Ok(())
}

fn cmd_update_products(db: &Database) -> Result<()> {
    println!("Extracting affected products from CVE descriptions...");

    let updated = db.update_products_from_descriptions()?;

    println!("Updated {} CVEs with extracted product information.", updated);

    Ok(())
}

/// Determine version match certainty for display
/// Returns "✓" if version is confirmed affected, "?" if unknown
fn get_version_match_indicator(cve: &models::Cve, query_version: &str, product_filter: Option<&str>) -> &'static str {
    for ap in &cve.affected_products {
        // Skip if product filter is set and doesn't match
        if let Some(prod_filter) = product_filter {
            if let Some(ref prod) = ap.product {
                if !prod.contains(prod_filter) {
                    continue;
                }
            } else {
                continue;
            }
        }

        // Nothing recorded about versions: unknown
        if ap.version.as_deref().is_none_or(|v| v == "*" || v == "-") && ap.version_start.is_none() && ap.version_end.is_none() {
            continue;
        }
        if versions::product_affects(
            Some(query_version),
            versions::cpe_version(ap.version.as_deref(), ap.cpe.as_deref()).as_deref(),
            ap.version_start.as_deref(),
            ap.version_start_excluded,
            ap.version_end.as_deref(),
            ap.version_end_included,
        ) {
            return "✓";
        }
    }

    "?"
}

// ==========================================
// Project Commands
// ==========================================

fn cmd_project(db: &Database, action: ProjectAction) -> Result<()> {
    match action {
        ProjectAction::Add { name, description } => {
            let user_id = db.get_default_user_id()?;
            let mut project = Project::new(user_id, name.clone());
            project.description = description;

            match db.create_project(&project) {
                Ok(_) => println!("Project '{}' created.", name),
                Err(e) => {
                    if e.to_string().contains("UNIQUE constraint") {
                        println!("Error: Project '{}' already exists.", name);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        ProjectAction::List => {
            let user_id = db.get_default_user_id()?;
            let projects = db.list_projects(user_id)?;

            if projects.is_empty() {
                println!("No projects found. Create one with: vulnizard project add <name>");
            } else {
                println!("{:<30} {:<40} {}", "Name", "Description", "Created");
                println!("{}", "-".repeat(90));
                for project in projects {
                    let desc = project.description.as_deref().unwrap_or("-");
                    let desc_truncated = if desc.chars().count() > 37 {
                        format!("{}...", desc.chars().take(34).collect::<String>())
                    } else {
                        desc.to_string()
                    };
                    let created = project.created_at.as_deref().unwrap_or("-");
                    println!("{:<30} {:<40} {}", project.name, desc_truncated, created);
                }
            }
        }
        ProjectAction::Delete { name } => {
            let user_id = db.get_default_user_id()?;
            if db.delete_project(user_id, &name)? {
                println!("Project '{}' deleted.", name);
            } else {
                println!("Project '{}' not found.", name);
            }
        }
    }
    Ok(())
}

// ==========================================
// Application Commands
// ==========================================

fn cmd_app(db: &Database, action: AppAction) -> Result<()> {
    match action {
        AppAction::Add { name, project, version, vendor, ecosystem } => {
            let project_id = db.resolve_project(&project)?;

            let mut app = Application::new(project_id, name.clone());
            app.version = version.clone();
            app.vendor = vendor;
            app.ecosystem = ecosystem;

            match db.create_application(&app) {
                Ok(_) => {
                    let ver_str = version.map(|v| format!(" v{}", v)).unwrap_or_default();
                    println!("Application '{}'{} added to project '{}'.", name, ver_str, project);
                }
                Err(e) => {
                    if e.to_string().contains("UNIQUE constraint") {
                        println!("Error: Application '{}' already exists in project '{}'.", name, project);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        AppAction::List { project } => {
            let project_id = db.resolve_project(&project)?;
            let apps = db.list_applications(project_id)?;

            if apps.is_empty() {
                println!("No applications in project '{}'.", project);
            } else {
                println!("Applications in project '{}':", project);
                println!();
                println!("{:<25} {:<12} {:<15} {:<15}", "Name", "Version", "Vendor", "Ecosystem");
                println!("{}", "-".repeat(70));
                for app in apps {
                    let version = app.version.as_deref().unwrap_or("-");
                    let vendor = app.vendor.as_deref().unwrap_or("-");
                    let ecosystem = app.ecosystem.as_deref().unwrap_or("-");
                    println!("{:<25} {:<12} {:<15} {:<15}", app.name, version, vendor, ecosystem);
                }
            }
        }
        AppAction::Update { name, project, version, current_version } => {
            let app = db.resolve_application(&project, &name, current_version.as_deref())?;
            let app_id = app.id.expect("Application must have ID");

            if db.update_application_version(app_id, &version)? {
                println!("Application '{}' updated to version '{}'.", name, version);
            } else {
                println!("Failed to update application.");
            }
        }
        AppAction::Delete { name, project, version } => {
            let project_id = db.resolve_project(&project)?;
            if db.delete_application(project_id, &name, version.as_deref())? {
                println!("Application '{}' deleted.", name);
            } else {
                println!("Application '{}' not found in project '{}'.", name, project);
            }
        }
    }
    Ok(())
}

// ==========================================
// Watch Commands
// ==========================================

fn cmd_watch(db: &Database, action: WatchAction) -> Result<()> {
    match action {
        WatchAction::Scan { project, app } => {
            let project_id = db.resolve_project(&project)?;

            let apps_to_scan = if let Some(app_name) = app {
                let app = db.resolve_application(&project, &app_name, None)?;
                vec![app]
            } else {
                db.list_applications(project_id)?
            };

            if apps_to_scan.is_empty() {
                println!("No applications to scan in project '{}'.", project);
                return Ok(());
            }

            println!("Scanning {} application(s) in project '{}'...", apps_to_scan.len(), project);
            println!();

            let mut total_new = 0i64;
            let mut total_existing = 0i64;

            for app in apps_to_scan {
                let ver_str = app.version.as_ref().map(|v| format!(" v{}", v)).unwrap_or_default();
                print!("  {}{}: ", app.name, ver_str);

                match db.scan_app_for_cves(&app) {
                    Ok((new, existing)) => {
                        total_new += new;
                        total_existing += existing;
                        if new > 0 {
                            println!("{} new CVE(s) found, {} already tracked", new, existing);
                        } else if existing > 0 {
                            println!("no new CVEs ({} already tracked)", existing);
                        } else {
                            println!("no CVEs found");
                        }
                        // Entries to review that no longer match (sources corrected) are set aside
                        match db.settle_stale_entries(&app) {
                            Ok((0, 0)) => {}
                            Ok((aside, back)) => println!("    {aside} entr(ies) no longer matching set aside, {back} brought back"),
                            Err(e) => println!("    error: {e}"),
                        }
                    }
                    Err(e) => println!("error: {}", e),
                }
            }

            println!();
            println!("Scan complete: {} new entries, {} already tracked", total_new, total_existing);
        }

        WatchAction::List { project, app, status, format } => {
            let user_id = db.get_default_user_id()?;
            let project_id = if let Some(ref proj) = project {
                Some(db.resolve_project(proj)?)
            } else {
                None
            };

            let status_filter = status.and_then(|s| CveStatus::from_str(&s));

            let entries = db.list_watchlist_entries(Some(user_id), project_id, app.as_deref(), status_filter)?;

            if entries.is_empty() {
                println!("No watchlist entries found.");
                return Ok(());
            }

            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&entries)?;
                    println!("{}", json);
                }
                _ => {
                    println!(
                        "{:<16} {:>6} {:<14} {:<10} {:<10} {:<20} {}",
                        "CVE ID", "CVSS", "Status", "Priority", "KEV", "Application", "Project"
                    );
                    println!("{}", "-".repeat(100));

                    for entry in entries {
                        let cvss = entry.cve_cvss
                            .map(|s| format!("{:.1}", s))
                            .unwrap_or_else(|| "-".to_string());

                        let status_str = match entry.entry.status {
                            CveStatus::Untreated => "Untreated",
                            CveStatus::Treated => "Treated",
                            CveStatus::NotApplicable => "N/A",
                            CveStatus::Accepted => "Accepted",
                        };

                        let priority_str = match entry.entry.priority {
                            Priority::Critical => "CRITICAL",
                            Priority::High => "High",
                            Priority::Medium => "Medium",
                            Priority::Low => "Low",
                        };

                        let kev = if entry.cve_kev { "YES" } else { "-" };

                        let app_str = if let Some(ref ver) = entry.app_version {
                            format!("{} v{}", entry.app_name, ver)
                        } else {
                            entry.app_name.clone()
                        };

                        println!(
                            "{:<16} {:>6} {:<14} {:<10} {:<10} {:<20} {}",
                            entry.entry.cve_id,
                            cvss,
                            status_str,
                            priority_str,
                            kev,
                            if app_str.chars().count() > 18 { format!("{}...", app_str.chars().take(15).collect::<String>()) } else { app_str },
                            entry.project_name
                        );
                    }
                }
            }
        }

        WatchAction::Status { cve_id, app, project, status, notes } => {
            let app_obj = db.resolve_application(&project, &app, None)?;
            let app_id = app_obj.id.expect("Application must have ID");

            let cve_status = CveStatus::from_str(&status)
                .ok_or_else(|| anyhow::anyhow!("Invalid status '{}'. Use: treated, accepted, not_applicable, untreated", status))?;

            // Check if entry exists
            if db.get_watchlist_entry(app_id, &cve_id)?.is_none() {
                println!("No watchlist entry found for {} on application '{}'.", cve_id, app);
                println!("Run 'vulnizard watch scan' first to discover CVEs.");
                return Ok(());
            }

            if db.update_watchlist_status(app_id, &cve_id, cve_status, notes.as_deref())? {
                println!("{} marked as '{}' for application '{}'.", cve_id, cve_status, app);
            } else {
                println!("Failed to update status.");
            }
        }

        WatchAction::Summary { project } => {
            let user_id = db.get_default_user_id()?;
            let project_id = if let Some(ref proj) = project {
                Some(db.resolve_project(proj)?)
            } else {
                None
            };

            let summary = db.get_watchlist_summary(Some(user_id), project_id)?;

            let scope = if let Some(ref proj) = project {
                format!("project '{}'", proj)
            } else {
                "all projects".to_string()
            };

            println!("Watchlist Summary for {}", scope);
            println!("{}", "=".repeat(50));
            println!();
            println!("Total CVE entries: {}", summary.total_entries);
            println!();
            println!("By Status:");
            println!("  Untreated:      {} ({:.1}%)",
                summary.untreated,
                if summary.total_entries > 0 { summary.untreated as f64 / summary.total_entries as f64 * 100.0 } else { 0.0 }
            );
            println!("  Treated:        {} ({:.1}%)",
                summary.treated,
                if summary.total_entries > 0 { summary.treated as f64 / summary.total_entries as f64 * 100.0 } else { 0.0 }
            );
            println!("  Not Applicable: {} ({:.1}%)",
                summary.not_applicable,
                if summary.total_entries > 0 { summary.not_applicable as f64 / summary.total_entries as f64 * 100.0 } else { 0.0 }
            );
            println!();
            println!("By Priority:");
            println!("  Critical: {}", summary.critical);
            println!("  High:     {}", summary.high);
            println!("  Medium:   {}", summary.medium);
            println!("  Low:      {}", summary.low);
        }
    }
    Ok(())
}

// ==========================================
// Completions Commands
// ==========================================

fn cmd_completions(db: &Database, action: CompletionsAction) -> Result<()> {
    match action {
        CompletionsAction::Generate { shell } => {
            match shell {
                Shell::Bash => print!("{}", completions::BASH_COMPLETION),
                Shell::Zsh => print!("{}", completions::ZSH_COMPLETION),
                _ => {
                    // Fallback to clap_complete for other shells
                    let mut cmd = Cli::command();
                    let name = cmd.get_name().to_string();
                    generate(shell, &mut cmd, name, &mut io::stdout());
                }
            }
        }
        CompletionsAction::Projects => {
            // Output project names (one per line) for dynamic completion
            if let Ok(names) = db.list_project_names() {
                for name in names {
                    println!("{}", name);
                }
            }
        }
        CompletionsAction::Apps { project } => {
            // Output app names (one per line) for dynamic completion
            if let Ok(names) = db.list_app_names(project.as_deref()) {
                for name in names {
                    println!("{}", name);
                }
            }
        }
        CompletionsAction::Cves { project, app } => {
            // Output CVE IDs (one per line) for dynamic completion
            if let Ok(cves) = db.list_watchlist_cve_ids(project.as_deref(), app.as_deref()) {
                for cve in cves {
                    println!("{}", cve);
                }
            }
        }
    }
    Ok(())
}
