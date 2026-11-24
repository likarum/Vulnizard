//! Notification delivery: generic webhook, Slack incoming webhook, email (SMTP).

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::config::Config;
use crate::db::{ChangeRow, Database, Dispatch, Notification};

/// Maximum number of changes detailed in a Slack/email message
const MAX_LISTED: usize = 30;

/// Sends a batch of changes of a project through one destination covering it
pub fn send(config: &Config, db: &Database, d: &Dispatch) -> Result<()> {
    let n = &d.notification;
    match n.kind.as_str() {
        "webhook" => post_json(config, url_of(n)?, &webhook_payload(config, d)),
        "slack" => post_json(config, url_of(n)?, &json!({ "text": text_summary(config, d) })),
        "ntfy" => post_ntfy(config, url_of(n)?, &title_of(d), &text_summary(config, d), worst_cvss(d), d
            .changes
            .first()
            .map(|c| cve_url(config, &c.cve_id))),
        "email" => send_email(config, n, &format!("[Vulnizard] {}", title_of(d)), &text_summary(config, d)),
        "browser" => {
            // Every member who can read the project, on each of their subscribed browsers
            let url = format!("/product/{}/{}?view=history", d.org, d.project);
            for user_id in db.users_with_project_access(d.project_id)? {
                crate::push::deliver(db, config, user_id, &title_of(d), &browser_summary(d), &url)?;
            }
            Ok(())
        }
        other => bail!("unknown notification type: {other}"),
    }
}

/// Sends a project event that is not a CVE change (a new probable service…)
/// through the destinations covering the project that send this kind of event. `view` is
/// the project view the message points to.
pub fn project_event(
    config: &Config,
    db: &Database,
    project_id: i64,
    kind: &str,
    title: &str,
    body: &str,
    view: &str,
) -> Result<()> {
    let (org, project): (String, String) = db.conn().query_row(
        "SELECT COALESCE(o.name, ''), p.name FROM projects p
         LEFT JOIN organizations o ON o.id = p.organization_id WHERE p.id = ?1",
        [project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let title = format!("{org}/{project}: {title}");
    for n in db.list_notifications(project_id)? {
        if !n.enabled || !n.events.iter().any(|e| e == kind) {
            continue;
        }
        let sent = match n.kind.as_str() {
            "browser" => {
                let url = format!("/product/{org}/{project}?view={view}");
                db.users_with_project_access(project_id).and_then(|users| {
                    for user_id in users {
                        crate::push::deliver(db, config, user_id, &title, body, &url)?;
                    }
                    Ok(())
                })
            }
            "webhook" => url_of(&n).and_then(|url| {
                post_json(config, url, &json!({ "event": kind, "organization": org, "project": project, "title": title, "message": body }))
            }),
            "slack" => url_of(&n).and_then(|url| post_json(config, url, &json!({ "text": format!("{title}\n{body}") }))),
            "ntfy" => url_of(&n).and_then(|url| post_ntfy(config, url, &title, body, 0.0, None)),
            "email" => send_email(config, &n, &format!("[Vulnizard] {title}"), body),
            other => Err(anyhow!("unknown notification type: {other}")),
        };
        if let Err(e) = sent {
            tracing::warn!("notification to '{}' failed: {e:#}", n.name);
        }
    }
    Ok(())
}

/// Sends an instance event (sync finished…) to a destination
pub fn send_system(config: &Config, destination: &crate::db::Destination, title: &str, body: &str) -> Result<()> {
    let n = destination.notification();
    match n.kind.as_str() {
        "webhook" => post_json(config, url_of(&n)?, &json!({ "event": "system", "title": title, "message": body })),
        "slack" => post_json(config, url_of(&n)?, &json!({ "text": format!("{title}\n{body}") })),
        "ntfy" => post_ntfy(config, url_of(&n)?, title, body, 0.0, None),
        "email" => send_email(config, &n, &format!("[Vulnizard] {title}"), body),
        // Browsers are addressed per user by the caller
        _ => Ok(()),
    }
}

fn url_of(n: &Notification) -> Result<&str> {
    n.config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("destination has no URL"))
}

fn title_of(d: &Dispatch) -> String {
    format!("{}/{}: {} CVE change(s)", d.org, d.project, d.changes.len())
}

fn worst_cvss(d: &Dispatch) -> f64 {
    d.changes.iter().filter_map(|c| c.cvss).fold(0.0, f64::max)
}

fn browser_summary(d: &Dispatch) -> String {
    let ids: Vec<&str> = d.changes.iter().take(4).map(|c| c.cve_id.as_str()).collect();
    let more = d.changes.len().saturating_sub(ids.len());
    if more > 0 {
        format!("{} and {more} more", ids.join(", "))
    } else {
        ids.join(", ")
    }
}

fn cve_url(config: &Config, cve_id: &str) -> String {
    format!("{}/cve/{}", config.web.base_url.trim_end_matches('/'), cve_id)
}

fn webhook_payload(config: &Config, d: &Dispatch) -> serde_json::Value {
    json!({
        "organization": d.org,
        "project": d.project,
        "notification": d.notification.name,
        "changes": d.changes.iter().map(|c| json!({
            "cve_id": c.cve_id,
            "url": cve_url(config, &c.cve_id),
            "cvss": c.cvss,
            "description": c.description,
            "created_at": c.created_at,
            "events": c.events,
        })).collect::<Vec<_>>(),
    })
}

fn change_line(config: &Config, c: &ChangeRow) -> String {
    let events: Vec<&str> = c.events.iter().map(|e| e.label()).collect();
    let cvss = c.cvss.map(|s| format!(" (CVSS {s:.1})")).unwrap_or_default();
    format!("- {}{} — {} — {}", c.cve_id, cvss, events.join(", "), cve_url(config, &c.cve_id))
}

fn text_summary(config: &Config, d: &Dispatch) -> String {
    let mut out = format!(
        "[{}/{}] {} CVE change(s) matching your subscriptions\n",
        d.org,
        d.project,
        d.changes.len()
    );
    for c in d.changes.iter().take(MAX_LISTED) {
        out.push_str(&change_line(config, c));
        out.push('\n');
    }
    if d.changes.len() > MAX_LISTED {
        out.push_str(&format!("… and {} more\n", d.changes.len() - MAX_LISTED));
    }
    out
}

/// A validated webhook target: the URL and, for a host name, the addresses it
/// was resolved to. Delivery connects to exactly these addresses, so a second
/// DNS answer cannot redirect the request elsewhere (DNS rebinding).
pub struct Target {
    pub url: reqwest::Url,
    pinned: Option<(String, Vec<SocketAddr>)>,
}

const NOT_ALLOWED: &str = "target must be a public http(s) URL";

/// Validates a webhook URL: http(s) only and, unless explicitly allowed,
/// not pointing to a loopback/private/link-local/reserved address (SSRF guard).
/// The error is deliberately the same whatever the reason, so that it cannot
/// be used to probe internal DNS names.
pub fn check_webhook_url(config: &Config, target: &str) -> Result<Target> {
    let url = reqwest::Url::parse(target).map_err(|_| anyhow!(NOT_ALLOWED))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!(NOT_ALLOWED);
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!(NOT_ALLOWED);
    }
    let allow_private = config.web.allow_private_webhooks;
    let port = url.port_or_known_default().unwrap_or(443);
    let pinned = match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            if !allow_private && is_internal(IpAddr::V4(ip)) {
                bail!(NOT_ALLOWED);
            }
            None
        }
        Some(url::Host::Ipv6(ip)) => {
            if !allow_private && is_internal(IpAddr::V6(ip)) {
                bail!(NOT_ALLOWED);
            }
            None
        }
        Some(url::Host::Domain(host)) => {
            let addrs: Vec<SocketAddr> = (host, port)
                .to_socket_addrs()
                .map_err(|_| anyhow!(NOT_ALLOWED))?
                .collect();
            if addrs.is_empty() || (!allow_private && addrs.iter().any(|a| is_internal(a.ip()))) {
                bail!(NOT_ALLOWED);
            }
            Some((host.to_string(), addrs))
        }
        None => bail!(NOT_ALLOWED),
    };
    Ok(Target { url, pinned })
}

fn is_internal_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || o[0] == 0 // "this network" 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18.0.0/15
        || o[0] >= 224 // multicast, reserved 240.0.0.0/4, broadcast
}

/// True if the host resolves (or fails to resolve) to an internal address
pub fn resolves_to_internal(host: &str, port: u16) -> bool {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            addrs.is_empty() || addrs.iter().any(|a| is_internal(a.ip()))
        }
        Err(_) => true,
    }
}

fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // Addresses embedding an IPv4 one: mapped/compatible ::/96,
            // NAT64 64:ff9b::/96, 6to4 2002::/16
            let embedded = if s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0 || s[5] == 0xffff) {
                Some(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
            } else if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                Some(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
            } else if s[0] == 0x2002 {
                Some(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8))
            } else {
                None
            };
            if let Some(v4) = embedded {
                // covers ::1 and :: as well (0.0.0.1 and 0.0.0.0 are internal)
                return is_internal_v4(v4);
            }
            (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xff00) == 0xff00 // multicast ff00::/8
        }
    }
}

/// HTTP client connecting only to the validated addresses of the target
pub fn client_for(target: &Target) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("vulnizard/", env!("CARGO_PKG_VERSION")));
    if let Some((host, addrs)) = &target.pinned {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    Ok(builder.build()?)
}

fn check_response(result: reqwest::Result<reqwest::blocking::Response>) -> Result<()> {
    // Errors are logged: strip the URL, which may embed a secret (Slack webhooks)
    let resp = result.map_err(|e| anyhow!("{}", e.without_url()))?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    Ok(())
}

fn post_json(config: &Config, target: &str, body: &serde_json::Value) -> Result<()> {
    let target = check_webhook_url(config, target)?;
    check_response(client_for(&target)?.post(target.url.clone()).json(body).send())
}

/// ntfy: the topic URL receives the message as plain text, with a title,
/// a priority following the worst CVSS and an optional click-through.
fn post_ntfy(config: &Config, url: &str, title: &str, body: &str, worst: f64, click: Option<String>) -> Result<()> {
    let target = check_webhook_url(config, url)?;
    let priority = if worst >= 9.0 {
        "urgent"
    } else if worst >= 7.0 {
        "high"
    } else {
        "default"
    };
    // Header values must stay ASCII
    let ascii = |s: &str| s.chars().filter(|c| c.is_ascii() && !c.is_ascii_control()).collect::<String>();
    let mut request = client_for(&target)?
        .post(target.url.clone())
        .header("Title", format!("Vulnizard {}", ascii(title)))
        .header("Priority", priority)
        .header("Tags", "shield");
    if let Some(click) = click {
        request = request.header("Click", ascii(&click));
    }
    check_response(request.body(body.to_string()).send())
}

/// Sample batch used by the "send a test" buttons
pub fn test_dispatch(notification: Notification, project_id: i64, org: &str, project: &str) -> Dispatch {
    Dispatch {
        notification,
        project_id,
        org: org.to_string(),
        project: project.to_string(),
        changes: vec![ChangeRow {
            id: 0,
            cve_id: "CVE-0000-0000".to_string(),
            created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            events: vec![crate::changes::Event::Created],
            cvss: Some(7.5),
            description: Some("Test notification sent from Vulnizard.".to_string()),
        }],
    }
}

/// SMTP server of an email destination: its own, else the one of the configuration file
fn smtp_of(config: &Config, n: &Notification) -> Result<crate::config::SmtpConfig> {
    if let Some(own) = n.config.get("smtp").filter(|s| !s.is_null()) {
        return serde_json::from_value(own.clone()).context("invalid SMTP settings of the destination");
    }
    config
        .smtp
        .clone()
        .ok_or_else(|| anyhow!("this email destination has no SMTP server"))
}

/// SMTP server of a destination: standard mail ports only, and no internal
/// address unless the instance allows private targets.
pub fn check_smtp_host(config: &Config, host: &str, port: u16) -> Result<()> {
    if !matches!(port, 25 | 465 | 587 | 2525) {
        bail!("SMTP port must be 25, 465, 587 or 2525");
    }
    if !config.web.allow_private_webhooks && resolves_to_internal(host, port) {
        bail!("this SMTP server is on a private network, which the instance does not allow");
    }
    Ok(())
}

/// Same rule when the destination is saved, without a DNS lookup: the port,
/// and an address written as an IP. Names are resolved when sending.
/// Address to connect to for a destination's own SMTP server, resolved once:
/// every address of the name must be public. `None` when the instance allows
/// private targets (nothing to protect then).
fn pinned_smtp_address(config: &Config, host: &str, port: u16) -> Result<Option<IpAddr>> {
    if config.web.allow_private_webhooks {
        return Ok(None);
    }
    let addresses: Vec<IpAddr> = (host.trim_matches(|c| c == '[' || c == ']'), port)
        .to_socket_addrs()
        .map_err(|_| anyhow!("this SMTP server cannot be resolved"))?
        .map(|a| a.ip())
        .collect();
    if addresses.is_empty() || addresses.iter().any(|ip| is_internal(*ip)) {
        bail!("this SMTP server is on a private network, which the instance does not allow");
    }
    Ok(addresses.first().copied())
}

pub fn check_smtp_settings(config: &Config, host: &str, port: u16) -> Result<()> {
    let literal = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok();
    if literal || host.eq_ignore_ascii_case("localhost") {
        return check_smtp_host(config, host.trim_matches(|c| c == '[' || c == ']'), port);
    }
    if !matches!(port, 25 | 465 | 587 | 2525) {
        bail!("SMTP port must be 25, 465, 587 or 2525");
    }
    Ok(())
}

fn send_email(config: &Config, n: &Notification, subject: &str, body: &str) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    use lettre::transport::smtp::client::{Tls, TlsParameters};

    let smtp = smtp_of(config, n)?;
    // A server chosen in a destination obeys the same rule as webhook targets;
    // the one of the configuration file is the operator's choice. The address
    // that was checked is the one connected to: a name that answers a public
    // address to the check and a private one to the connection gains nothing.
    let pinned = if n.config.get("smtp").is_some_and(|v| v.is_object()) {
        check_smtp_host(config, &smtp.host, smtp.port)?;
        pinned_smtp_address(config, &smtp.host, smtp.port)?
    } else {
        None
    };
    let to = n
        .config
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("destination has no recipient"))?;

    let message = Message::builder()
        .from(smtp.from.parse().context("invalid sender address")?)
        .to(to.parse().context("invalid recipient")?)
        .subject(subject)
        .body(body.to_string())?;

    let builder = match pinned {
        // Connect to the checked address; TLS still verifies the name of the server
        Some(address) => {
            let tls = match smtp.port {
                25 => Tls::None,
                465 => Tls::Wrapper(TlsParameters::new(smtp.host.clone())?),
                _ => Tls::Required(TlsParameters::new(smtp.host.clone())?),
            };
            SmtpTransport::builder_dangerous(address.to_string()).tls(tls)
        }
        None => match smtp.port {
            25 => SmtpTransport::builder_dangerous(&smtp.host),
            465 => SmtpTransport::relay(&smtp.host)?,
            _ => SmtpTransport::starttls_relay(&smtp.host)?,
        },
    }
    .port(smtp.port)
    .timeout(Some(Duration::from_secs(30)));
    let builder = match (&smtp.username, &smtp.password) {
        (Some(u), Some(p)) => builder.credentials(Credentials::new(u.clone(), p.clone())),
        _ => builder,
    };
    builder.build().send(&message)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_internal_targets() {
        let config = Config::default();
        assert!(check_webhook_url(&config, "http://127.0.0.1:9000/hook").is_err());
        assert!(check_webhook_url(&config, "http://10.0.0.5/hook").is_err());
        assert!(check_webhook_url(&config, "http://[::1]/hook").is_err());
        assert!(check_webhook_url(&config, "http://169.254.169.254/latest").is_err());
        assert!(check_webhook_url(&config, "file:///etc/passwd").is_err());
        for url in [
            "http://0.0.0.0/",
            "http://0.1.2.3/",
            "http://2130706433/",          // decimal 127.0.0.1
            "http://0x7f.0.0.1/",
            "http://100.64.1.1/",
            "http://198.18.0.1/",
            "http://240.0.0.1/",
            "http://224.0.0.1/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::10.0.0.1]/",
            "http://[64:ff9b::7f00:1]/",   // NAT64 of 127.0.0.1
            "http://[2002:7f00:1::]/",     // 6to4 of 127.0.0.1
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://[ff02::1]/",
            "http://user:pass@8.8.8.8/",
            "http://localhost/",
        ] {
            assert!(check_webhook_url(&config, url).is_err(), "{url} should be refused");
        }
    }

    #[test]
    fn public_literals_are_accepted_and_errors_are_generic() {
        let config = Config::default();
        assert!(check_webhook_url(&config, "https://8.8.8.8/hook").is_ok());
        assert!(check_webhook_url(&config, "https://[2606:4700:4700::1111]/hook").is_ok());
        let private = check_webhook_url(&config, "http://10.0.0.1/").err().unwrap().to_string();
        let unresolvable = check_webhook_url(&config, "http://does-not-exist.invalid/").err().unwrap().to_string();
        assert_eq!(private, unresolvable);
    }

    #[test]
    fn private_targets_can_be_allowed() {
        let mut config = Config::default();
        config.web.allow_private_webhooks = true;
        assert!(check_webhook_url(&config, "http://127.0.0.1:9000/hook").is_ok());
        assert!(check_webhook_url(&config, "ftp://127.0.0.1/").is_err());
    }
}
