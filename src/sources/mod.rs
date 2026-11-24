pub mod cisa_kev;
pub mod distros;
pub mod epss;
pub mod exploitdb;
pub mod metasploit;
pub mod nuclei;
pub mod nvd;
pub mod osv;
pub mod vulnrichment;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use crate::db::Database;

/// What the sources announce themselves as: the real version, so that an
/// upstream that sees a problem can tell which release causes it
pub const USER_AGENT: &str = concat!("vulnizard/", env!("CARGO_PKG_VERSION"));

/// A file downloaded because it changed upstream; `remember` it once what
/// it holds is stored, so that it is not downloaded again until it changes
pub struct Download {
    pub response: reqwest::blocking::Response,
    pub mark: Mark,
}

/// What tells a file that was downloaded from its next version: the
/// fingerprint the server gave (`ETag`) and the date it gave (`Last-Modified`)
pub struct Mark {
    key: String,
    etag: Option<String>,
    modified: Option<String>,
}

impl Mark {
    /// To be called once the content is stored: a download whose content was
    /// lost on the way (network cut, database error) must be made again
    pub fn remember(&self, db: &Database) -> Result<()> {
        if self.etag.is_none() && self.modified.is_none() {
            return db.delete_metadata(&etag_key(&self.key));
        }
        let stored = serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "etag": self.etag, "modified": self.modified });
        db.set_metadata(&etag_key(&self.key), &stored.to_string())
    }

    /// What was remembered of a file, by this release
    fn known(db: &Database, key: &str) -> Result<Option<Self>> {
        let Some(stored) = db.get_metadata(&etag_key(key))? else {
            return Ok(None);
        };
        let Ok(stored) = serde_json::from_str::<serde_json::Value>(&stored) else {
            return Ok(None);
        };
        if stored["version"].as_str() != Some(env!("CARGO_PKG_VERSION")) {
            return Ok(None);
        }
        let text = |name: &str| stored[name].as_str().map(str::to_string);
        Ok(Some(Self { key: key.to_string(), etag: text("etag"), modified: text("modified") }))
    }
}

fn etag_key(key: &str) -> String {
    format!("etag.{key}")
}

/// Downloads a file unless it is the one already read: the fingerprint and
/// the date the server gave last time are sent back (some servers only heed
/// one of the two), and a server that still has the same file answers with
/// nothing (`304`). `None` then.
///
/// They are kept with the version that read the file: after an upgrade the
/// file is read again once, a release may read it differently. A forced
/// full synchronization always downloads.
pub fn download_if_changed(
    client: &reqwest::blocking::Client,
    db: &Database,
    key: &str,
    url: &str,
    opts: &SyncOptions,
) -> Result<Option<Download>> {
    let known = if opts.force_full { None } else { Mark::known(db, key)? };
    let mut request = client.get(url);
    if let Some(known) = &known {
        if let Some(etag) = &known.etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(modified) = &known.modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, modified);
        }
    }
    let response = request.send().with_context(|| format!("cannot fetch {key}"))?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED && known.is_some() {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("{key}: the server answered HTTP {}", response.status());
    }
    let header = |name| response.headers().get(name).and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok()).map(str::to_string);
    let mark = Mark { key: key.to_string(), etag: header(reqwest::header::ETAG), modified: header(reqwest::header::LAST_MODIFIED) };
    Ok(Some(Download { response, mark }))
}

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
    /// The source was asked and has nothing new since the last run: nothing
    /// was downloaded. It was asked all the same, and waits its turn again.
    pub unchanged: bool,
}

impl SyncResult {
    pub fn skipped() -> Self {
        Self { skipped: true, ..Default::default() }
    }

    pub fn unchanged() -> Self {
        Self { unchanged: true, ..Default::default() }
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
    ("cisa_kev", 6, "the whole catalog, about 2 MB, when it changed"),
    ("epss", 24, "the whole file of scores, about 3 MB, when it changed"),
    ("vulnrichment", 24, "only the records changed since the last run; the whole archive the first time or after a long stop"),
    ("osv", 12, "only the advisories changed since the last run; the whole archives (about 290 MB) the first time, then once a month"),
    ("distros", 12, "the whole archive of Debian advisories, about 85 MB, when it changed"),
    ("exploitdb", 12, "the whole index, about 10 MB, when it changed"),
    ("metasploit", 24, "the whole index, about 11 MB, when it changed"),
    ("nuclei", 24, "the whole index, about 2 MB, when it changed"),
];

/// Hours a periodic run leaves between two downloads of a source
pub fn min_hours(source: &str) -> i64 {
    PACES.iter().find(|(name, _, _)| *name == source).map_or(0, |(_, hours, _)| *hours)
}

/// What one download of a source fetches
pub fn fetches(source: &str) -> &'static str {
    PACES.iter().find(|(name, _, _)| *name == source).map_or("", |(_, _, what)| what)
}

/// A local HTTP server for the tests of the sources: it answers what the
/// test decides and remembers what it was asked.
#[cfg(test)]
pub mod testserver {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// What was asked: the path and the headers (names in lower case)
    #[derive(Debug, Clone)]
    pub struct Asked {
        pub path: String,
        pub headers: Vec<(String, String)>,
    }

    impl Asked {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
        }
    }

    /// What is answered: the status, headers, and the body
    pub struct Answer {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Answer {
        pub fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self { status: 200, headers: Vec::new(), body: body.into() }
        }

        pub fn status(status: u16) -> Self {
            Self { status, headers: Vec::new(), body: Vec::new() }
        }

        pub fn with(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
    }

    pub struct Server {
        pub url: String,
        asked: Arc<Mutex<Vec<Asked>>>,
    }

    impl Server {
        /// Starts a server that answers every request with `answer`
        pub fn start(answer: impl Fn(&Asked) -> Answer + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let asked = Arc::new(Mutex::new(Vec::new()));
            let log = asked.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                    let mut headers = Vec::new();
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                            break;
                        }
                        if let Some((name, value)) = header.split_once(':') {
                            headers.push((name.trim().to_lowercase(), value.trim().to_string()));
                        }
                    }
                    let request = Asked { path, headers };
                    let answer = answer(&request);
                    log.lock().unwrap().push(request);
                    let reason = if answer.status == 304 { "Not Modified" } else { "OK" };
                    let mut head = format!("HTTP/1.1 {} {reason}\r\nConnection: close\r\n", answer.status);
                    if answer.status != 304 {
                        head.push_str(&format!("Content-Length: {}\r\n", answer.body.len()));
                    }
                    for (name, value) in &answer.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");
                    // The client may hang up before the end: it reads a list only as far as it needs
                    let _ = stream.write_all(head.as_bytes());
                    if answer.status != 304 {
                        let _ = stream.write_all(&answer.body);
                    }
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let _ = reader.read(&mut [0u8; 64]);
                }
            });
            Self { url, asked }
        }

        /// Every request received so far, in order
        pub fn asked(&self) -> Vec<Asked> {
            self.asked.lock().unwrap().clone()
        }

        /// The paths asked so far, in order
        pub fn paths(&self) -> Vec<String> {
            self.asked().into_iter().map(|a| a.path).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testserver::{Answer, Server};
    use super::*;

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder().user_agent(USER_AGENT).build().unwrap()
    }

    #[test]
    fn a_file_is_downloaded_again_only_once_it_changed() {
        let server = Server::start(|asked| match asked.header("if-none-match") {
            Some("\"v1\"") => Answer::status(304),
            _ => Answer::ok("content").with("ETag", "\"v1\""),
        });
        let db = Database::open_in_memory().unwrap();
        let opts = SyncOptions::new(0);

        // First time: downloaded. Not remembered yet: a download that was not stored is made again
        let first = download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().unwrap();
        let Download { response, mark } = first;
        assert_eq!(response.text().unwrap(), "content");
        assert!(download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().is_some());

        // Once remembered, the fingerprint is sent back and nothing is downloaded
        mark.remember(&db).unwrap();
        assert!(download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().is_none());
        assert_eq!(server.asked().last().unwrap().header("if-none-match"), Some("\"v1\""));
        // The server is told which release asks
        assert_eq!(server.asked()[0].header("user-agent"), Some(USER_AGENT));

        // A forced full synchronization downloads whatever is remembered
        assert!(download_if_changed(&client(), &db, "file", &server.url, &SyncOptions::new(0).force_full()).unwrap().is_some());
        assert_eq!(server.asked().last().unwrap().header("if-none-match"), None);

        // A fingerprint kept by another release is not trusted: that release may have read the file differently
        db.set_metadata("etag.file", r#"{"version": "0.0.1", "etag": "\"v1\"", "modified": null}"#).unwrap();
        assert!(download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().is_some());
        assert_eq!(server.asked().last().unwrap().header("if-none-match"), None);
    }

    #[test]
    fn a_server_that_only_heeds_the_date_is_asked_with_the_date() {
        // Some servers give a fingerprint and then ignore it, but answer "unchanged" to the date
        let server = Server::start(|asked| match asked.header("if-modified-since") {
            Some("Mon, 23 Nov 2026 19:43:55 GMT") => Answer::status(304),
            _ => Answer::ok("content").with("ETag", "\"ignored\"").with("Last-Modified", "Mon, 23 Nov 2026 19:43:55 GMT"),
        });
        let db = Database::open_in_memory().unwrap();
        let opts = SyncOptions::new(0);
        let first = download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().unwrap();
        first.mark.remember(&db).unwrap();
        assert!(download_if_changed(&client(), &db, "file", &server.url, &opts).unwrap().is_none());
        let asked = server.asked();
        assert_eq!(asked[1].header("if-none-match"), Some("\"ignored\""));
        assert_eq!(asked[1].header("if-modified-since"), Some("Mon, 23 Nov 2026 19:43:55 GMT"));
    }

    #[test]
    fn a_server_that_fails_is_an_error_and_remembers_nothing() {
        let server = Server::start(|_| Answer::status(503));
        let db = Database::open_in_memory().unwrap();
        let failed = download_if_changed(&client(), &db, "file", &server.url, &SyncOptions::new(0)).err().unwrap();
        assert!(failed.to_string().contains("503"), "{failed}");
        assert_eq!(db.get_metadata("etag.file").unwrap(), None);
    }

    /// A source that downloads one file: read once, not read again while the
    /// file is the same, read again once it changed
    fn reads_its_file_only_when_it_changed(name: &str, source: impl Fn(&str) -> Box<dyn CveSource>, body: Vec<u8>, cve: &str) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let version = Arc::new(AtomicUsize::new(1));
        let current = version.clone();
        let server = Server::start(move |asked| {
            let etag = format!("\"v{}\"", current.load(Ordering::SeqCst));
            if asked.header("if-none-match") == Some(etag.as_str()) {
                Answer::status(304)
            } else {
                Answer::ok(body.clone()).with("ETag", &etag)
            }
        });
        let db = Database::open_in_memory().unwrap();
        let source = source(&server.url);
        // Asked by name: the delay between two runs does not apply, the fingerprint does
        let opts = SyncOptions::new(0).ignore_freshness(true);

        let first = source.sync(&db, &opts).unwrap();
        assert!(!first.unchanged && !first.skipped, "{name}: first run");
        assert!(db.get_cve(cve).unwrap().is_some(), "{name}: the content was stored");

        let second = source.sync(&db, &opts).unwrap();
        assert!(second.unchanged, "{name}: an unchanged file is not read again");
        assert_eq!(second.added + second.updated, 0, "{name}");
        assert!(server.asked().last().unwrap().header("if-none-match").is_some(), "{name}: the fingerprint is sent back");

        version.store(2, Ordering::SeqCst);
        let third = source.sync(&db, &opts).unwrap();
        assert!(!third.unchanged && third.added + third.updated > 0, "{name}: a changed file is read");
        assert_eq!(server.asked().len(), 3, "{name}: one request per run");
    }

    #[test]
    fn whole_file_sources_download_only_what_changed() {
        use std::io::Write;
        reads_its_file_only_when_it_changed(
            "cisa_kev",
            |url| Box::new(cisa_kev::CisaKevSource::at(url)),
            br#"{"title": "t", "catalogVersion": "1", "dateReleased": "d", "count": 1, "vulnerabilities": [
                {"cveID": "CVE-2024-1", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "n", "dateAdded": "2024-01-01",
                 "shortDescription": "s", "requiredAction": "a", "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"}]}"#
                .to_vec(),
            "CVE-2024-1",
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"#model_version:v1\ncve,epss,percentile\nCVE-2024-2,0.5,0.9\n").unwrap();
        reads_its_file_only_when_it_changed("epss", |url| Box::new(epss::EpssSource::at(url)), gz.finish().unwrap(), "CVE-2024-2");
        reads_its_file_only_when_it_changed(
            "exploitdb",
            |url| Box::new(exploitdb::ExploitDbSource::at(url)),
            b"id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes\n1,f,d,2024-01-01,a,remote,linux,,2024-01-01,2024-01-01,1,CVE-2024-3\n".to_vec(),
            "CVE-2024-3",
        );
        reads_its_file_only_when_it_changed(
            "metasploit",
            |url| Box::new(metasploit::MetasploitSource::at(url)),
            br#"{"exploit_x": {"references": ["CVE-2024-4"], "path": "/modules/exploits/x.rb", "fullname": "exploit/x", "type": "exploit"}}"#.to_vec(),
            "CVE-2024-4",
        );
        reads_its_file_only_when_it_changed(
            "nuclei",
            |url| Box::new(nuclei::NucleiSource::at(url)),
            br#"{"ID":"CVE-2024-5","Info":{},"file_path":"http/cves/2024/CVE-2024-5.yaml"}"#.to_vec(),
            "CVE-2024-5",
        );
    }

    #[test]
    fn every_source_says_how_often_and_what_it_downloads() {
        for (key, _, _) in crate::settings::SOURCES {
            assert!(PACES.iter().any(|(name, _, what)| *name == key && !what.is_empty()), "{key}");
        }
        // Only the sources that read changes run at every cycle
        assert_eq!(min_hours("nvd"), 0);
        for whole in ["cisa_kev", "epss", "distros", "exploitdb", "metasploit", "nuclei"] {
            assert!(min_hours(whole) >= 6, "{whole}");
        }
    }
}
