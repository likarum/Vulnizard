//! Remediation deadlines: how long an entry of the watchlist may stay to
//! review, and where it stands against that.
//!
//! The rule lives here and nowhere else:
//!
//! - one delay in days per CVSS severity, plus a delay for the CVEs known to
//!   be exploited (CISA KEV) which applies when it is the shorter one; a CVE
//!   without a score follows the medium delay ([`Delays::days`]);
//! - the clock starts the day the entry was detected and never moves: a
//!   version change keeps it, and an entry reopened is due at its first
//!   deadline again;
//! - any decision (closed, not applicable, risk accepted) stops it: a decided
//!   entry is never overdue;
//! - the severity is the one the CVE has today, so nothing is stored per
//!   entry: a deadline is computed when it is read.
//!
//! Days are calendar days in UTC, as every timestamp of the database.
//!
//! Three ways in, from the nearest to the data to the most general:
//!
//! - the lists of entries already carry it: `TriageItem::deadline` (filled by
//!   `Database::scoped_triage`), for the entries to review as for the decided
//!   ones, in one project, in all of them or in those of one organization;
//! - [`Policies::deadline`] answers for any entry given its organization, its
//!   detection, its decision if any and the CVE's score;
//! - [`tracks`] replays the lifecycle events (`Database::lifecycle_events_for`)
//!   into one [`EntryTrack`] per entry, which also knows the past:
//!   [`EntryTrack::overdue_on`] a given day, [`overdue_per_day`] over a window.
//!
//! The executive figures ([`Figures`]: what is open, what is overdue, how long
//! a decision takes) are computed in one place, [`figures`], from those
//! tracks; `Database::figures` reads them for a scope. The overview, the REST
//! API and the MCP server all answer with it.
//!
//! The delays differ from one organization to the next: a view mixing
//! organizations must go through [`Policies`] (`Database::deadline_policies`),
//! which picks the delays of the organization of each entry, and never apply
//! one [`Delays`] to all of them.

use chrono::{Duration, NaiveDate};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

use crate::db::LifecycleEvent;

/// Longest delay that can be set, in days (ten years)
pub const MAX_DAYS: u32 = 3650;

/// Severity band of a CVSS score, as shown everywhere else (9, 7 and 4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    /// Band of a score; `None` when the CVE has no score (or a score of 0)
    pub fn of(cvss: Option<f64>) -> Option<Severity> {
        match cvss {
            Some(s) if s >= 9.0 => Some(Severity::Critical),
            Some(s) if s >= 7.0 => Some(Severity::High),
            Some(s) if s >= 4.0 => Some(Severity::Medium),
            Some(s) if s > 0.0 => Some(Severity::Low),
            _ => None,
        }
    }
}

/// The five values of a set of delays: (form field and storage name, label)
pub const FIELDS: [(&str, &str); 5] = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("kev", "Exploited (CISA KEV)"),
];

/// Delays in days, complete: what applies to an entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Delays {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    /// CVEs known to be exploited: applies when shorter than the delay of the severity
    pub kev: u32,
}

impl Default for Delays {
    fn default() -> Self {
        Delays { critical: 7, high: 30, medium: 90, low: 180, kev: 14 }
    }
}

/// What an organization replaces: `None` follows the instance
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DelayOverride {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub kev: Option<u32>,
}

impl DelayOverride {
    /// Nothing replaced: the organization follows the instance entirely
    pub fn is_empty(&self) -> bool {
        *self == DelayOverride::default()
    }

    /// Value of a field of [`FIELDS`]
    pub fn get(&self, field: &str) -> Option<u32> {
        match field {
            "critical" => self.critical,
            "high" => self.high,
            "medium" => self.medium,
            "low" => self.low,
            "kev" => self.kev,
            _ => None,
        }
    }

    /// Sets a field of [`FIELDS`]; an unknown name is ignored
    pub fn set(&mut self, field: &str, value: Option<u32>) {
        match field {
            "critical" => self.critical = value,
            "high" => self.high = value,
            "medium" => self.medium = value,
            "low" => self.low = value,
            "kev" => self.kev = value,
            _ => {}
        }
    }

    /// "critical 3, kev 5", or "inherited" when nothing is replaced
    pub fn describe(&self) -> String {
        let set: Vec<String> =
            FIELDS.iter().filter_map(|(field, _)| self.get(field).map(|days| format!("{field} {days}"))).collect();
        if set.is_empty() {
            "inherited from the instance".into()
        } else {
            set.join(", ")
        }
    }
}

/// Reads a delay typed in a form: a whole number of days from 1 to [`MAX_DAYS`]
pub fn parse_days(label: &str, value: &str) -> Result<u32, String> {
    match value.trim().parse::<u32>() {
        Ok(days) if (1..=MAX_DAYS).contains(&days) => Ok(days),
        _ => Err(format!("{label}: the delay must be a whole number of days, from 1 to {MAX_DAYS}")),
    }
}

impl Delays {
    /// Value of a field of [`FIELDS`]
    pub fn get(&self, field: &str) -> u32 {
        match field {
            "critical" => self.critical,
            "high" => self.high,
            "low" => self.low,
            "kev" => self.kev,
            _ => self.medium,
        }
    }

    /// These delays with the values an organization replaces
    pub fn with(self, replaced: &DelayOverride) -> Delays {
        Delays {
            critical: replaced.critical.unwrap_or(self.critical),
            high: replaced.high.unwrap_or(self.high),
            medium: replaced.medium.unwrap_or(self.medium),
            low: replaced.low.unwrap_or(self.low),
            kev: replaced.kev.unwrap_or(self.kev),
        }
    }

    /// As an override replacing every value (to store the instance delays in one shape)
    pub fn as_override(&self) -> DelayOverride {
        DelayOverride {
            critical: Some(self.critical),
            high: Some(self.high),
            medium: Some(self.medium),
            low: Some(self.low),
            kev: Some(self.kev),
        }
    }

    /// Delay of a severity
    pub fn of(&self, severity: Severity) -> u32 {
        self.get(severity.as_str())
    }

    /// Days a CVE with this score may stay to review: the delay of its
    /// severity (medium without a score), or the delay of exploited CVEs when
    /// it is known exploited and that delay is shorter.
    pub fn days(&self, cvss: Option<f64>, kev: bool) -> u32 {
        let by_severity = self.of(Severity::of(cvss).unwrap_or(Severity::Medium));
        if kev {
            by_severity.min(self.kev)
        } else {
            by_severity
        }
    }

    /// The whole answer for one entry: detected on `detected`, decided on
    /// `decided` if it is (`None`: still to review), for a CVE scored `cvss`
    /// today and known exploited or not, as of `today`.
    pub fn assess(&self, detected: NaiveDate, decided: Option<NaiveDate>, cvss: Option<f64>, kev: bool, today: NaiveDate) -> Deadline {
        let delay_days = self.days(cvss, kev);
        let due = detected + Duration::days(i64::from(delay_days));
        let state = match decided {
            None => DeadlineState::Open { days_left: (due - today).num_days() },
            Some(on) => DeadlineState::Decided {
                took_days: (on - detected).num_days().max(0),
                late_days: (on - due).num_days().max(0),
            },
        };
        Deadline { delay_days, detected, due, state }
    }
}

/// Where an entry stands against its deadline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Deadline {
    /// Delay that applies, in days
    pub delay_days: u32,
    /// Day the clock started
    pub detected: NaiveDate,
    /// Last day to decide: `detected` + `delay_days`. Overdue from the day after.
    pub due: NaiveDate,
    pub state: DeadlineState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeadlineState {
    /// Still to review. `days_left` is 0 on the due day and negative once overdue.
    Open { days_left: i64 },
    /// Decided: never overdue. `took_days` from detection to the decision;
    /// `late_days` is how long after the deadline it was taken (0 when in time).
    Decided { took_days: i64, late_days: i64 },
}

impl Deadline {
    /// To review and past its due day
    pub fn is_overdue(&self) -> bool {
        self.overdue_days() > 0
    }

    /// Days past the due day for an entry to review; 0 when in time or decided
    pub fn overdue_days(&self) -> i64 {
        match self.state {
            DeadlineState::Open { days_left } => (-days_left).max(0),
            DeadlineState::Decided { .. } => 0,
        }
    }

    /// Days until the due day (negative once overdue); `None` for a decided entry
    pub fn days_left(&self) -> Option<i64> {
        match self.state {
            DeadlineState::Open { days_left } => Some(days_left),
            DeadlineState::Decided { .. } => None,
        }
    }

    /// Days from detection to the decision; `None` while to review
    pub fn resolved_in_days(&self) -> Option<i64> {
        match self.state {
            DeadlineState::Open { .. } => None,
            DeadlineState::Decided { took_days, .. } => Some(took_days),
        }
    }

    /// "in 12 days", "tomorrow", "today", "overdue by 5 days"; "decided in 3 days" once decided
    pub fn label(&self) -> String {
        let days = |n: i64| if n == 1 { "1 day".to_string() } else { format!("{n} days") };
        match self.state {
            DeadlineState::Open { days_left: 0 } => "today".into(),
            DeadlineState::Open { days_left: 1 } => "tomorrow".into(),
            DeadlineState::Open { days_left } if days_left > 0 => format!("in {}", days(days_left)),
            DeadlineState::Open { days_left } => format!("overdue by {}", days(-days_left)),
            DeadlineState::Decided { took_days, .. } => format!("decided in {}", days(took_days)),
        }
    }

    /// Adds the deadline to the JSON of an entry (REST API and MCP): `due_at`
    /// (YYYY-MM-DD), `days_left` (negative once overdue) and `overdue_days`
    /// on an entry to review; `resolved_in_days` on a decided one.
    pub fn annotate(&self, entry: &mut serde_json::Value) {
        match self.state {
            DeadlineState::Open { days_left } => {
                entry["due_at"] = self.due.to_string().into();
                entry["days_left"] = days_left.into();
                entry["overdue_days"] = self.overdue_days().into();
            }
            DeadlineState::Decided { took_days, .. } => entry["resolved_in_days"] = took_days.into(),
        }
    }
}

/// Watchlist entries as the REST API and the MCP server give them: each with
/// its deadline ([`Deadline::annotate`]), computed with the delays of its
/// organization. `only_overdue` keeps the entries to review that are past
/// their deadline, most overdue first. `description_chars` cuts the CVE
/// descriptions (lists read by an assistant).
pub fn entries_json(
    entries: Vec<crate::models::WatchlistEntryWithContext>,
    policies: &Policies,
    only_overdue: bool,
    description_chars: Option<usize>,
) -> Vec<serde_json::Value> {
    let today = chrono::Utc::now().date_naive();
    let mut out: Vec<(i64, serde_json::Value)> = Vec::new();
    for mut e in entries {
        let decided = (e.entry.status != crate::models::CveStatus::Untreated)
            .then(|| e.entry.treated_at.as_deref().or(e.entry.updated_at.as_deref()).unwrap_or(""));
        let deadline = e
            .entry
            .created_at
            .as_deref()
            .and_then(|detected| policies.deadline(&e.organization, detected, decided, e.cve_cvss, e.cve_kev, today));
        let overdue_days = deadline.map_or(0, |d| d.overdue_days());
        if only_overdue && overdue_days == 0 {
            continue;
        }
        if let Some(chars) = description_chars {
            e.cve_description = e.cve_description.map(|d| match d.char_indices().nth(chars) {
                Some((cut, _)) => format!("{}…", &d[..cut]),
                None => d,
            });
        }
        let mut value = serde_json::to_value(&e).unwrap_or_default();
        if let Some(deadline) = deadline {
            deadline.annotate(&mut value);
        }
        out.push((overdue_days, value));
    }
    if only_overdue {
        out.sort_by_key(|(days, _)| std::cmp::Reverse(*days));
    }
    out.into_iter().map(|(_, value)| value).collect()
}

/// Day of a `YYYY-MM-DD…` timestamp of the database
pub fn day_of(timestamp: &str) -> Option<NaiveDate> {
    timestamp.get(..10).and_then(|day| NaiveDate::parse_from_str(day, "%Y-%m-%d").ok())
}

/// Delays of the instance and of every organization that replaces some:
/// what a view needs to answer for entries of several organizations at once.
/// Read once per request with `Database::deadline_policies`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policies {
    pub instance: Delays,
    /// Effective delays of the organizations replacing at least one value, by name
    orgs: HashMap<String, Delays>,
}

impl Policies {
    /// The same delays for everyone (tests, instance without organization)
    pub fn uniform(instance: Delays) -> Self {
        Policies { instance, orgs: HashMap::new() }
    }

    /// Records what an organization replaces
    pub fn replace(&mut self, org: &str, replaced: &DelayOverride) {
        if replaced.is_empty() {
            self.orgs.remove(org);
        } else {
            self.orgs.insert(org.to_string(), self.instance.with(replaced));
        }
    }

    /// Delays applying to the projects of an organization (by its name)
    pub fn of_org(&self, org: &str) -> &Delays {
        self.orgs.get(org).unwrap_or(&self.instance)
    }

    /// Deadline of an entry of the organization `org`, from the timestamps
    /// the database holds: `detected_at` (`watchlist_entries.created_at`) and,
    /// for a decided entry, `decided_at` (`treated_at`). `None` only if the
    /// detection timestamp cannot be read.
    pub fn deadline(
        &self,
        org: &str,
        detected_at: &str,
        decided_at: Option<&str>,
        cvss: Option<f64>,
        kev: bool,
        today: NaiveDate,
    ) -> Option<Deadline> {
        let detected = day_of(detected_at)?;
        // A decision whose day cannot be read still stops the clock
        let decided = decided_at.map(|at| day_of(at).unwrap_or(today));
        Some(self.of_org(org).assess(detected, decided, cvss, kev, today))
    }
}

/// An entry over time, rebuilt from its lifecycle events: enough to say
/// where it stood against its deadline on any day, including after the
/// entry, its application or its project were removed.
#[derive(Debug, Clone, Serialize)]
pub struct EntryTrack {
    pub entry_id: i64,
    pub org: String,
    pub project: String,
    pub app_name: String,
    pub cve_id: String,
    /// Score and exploitation of the CVE as they are today
    pub cvss: Option<f64>,
    pub kev: bool,
    pub detected: NaiveDate,
    pub delay_days: u32,
    pub due: NaiveDate,
    /// Periods during which the entry was to review: from a day (included) to
    /// the day it was decided or removed (excluded); `None` while it still is
    pub open: Vec<(NaiveDate, Option<NaiveDate>)>,
    /// Status after the last event; `None` once removed
    pub status: Option<String>,
    /// Day of the decision in force, when the entry is decided
    pub decided: Option<NaiveDate>,
}

impl EntryTrack {
    /// To review at the end of that day
    pub fn open_on(&self, day: NaiveDate) -> bool {
        self.open.iter().any(|(from, until)| *from <= day && until.is_none_or(|until| until > day))
    }

    /// To review at the end of that day, and past its deadline
    pub fn overdue_on(&self, day: NaiveDate) -> bool {
        day > self.due && self.open_on(day)
    }

    /// Where the entry stands today. An entry removed with its application
    /// keeps the decision it left with; removed while to review it stands
    /// nowhere (`None`): nobody decided, and nothing is left to decide.
    pub fn deadline(&self, today: NaiveDate) -> Option<Deadline> {
        let state = match (self.status.as_deref(), self.decided) {
            (None, None) => return None,
            (Some("untreated"), _) | (Some(_), None) => DeadlineState::Open { days_left: (self.due - today).num_days() },
            (_, Some(on)) => DeadlineState::Decided {
                took_days: (on - self.detected).num_days().max(0),
                late_days: (on - self.due).num_days().max(0),
            },
        };
        Some(Deadline { delay_days: self.delay_days, detected: self.detected, due: self.due, state })
    }
}

/// One track per entry, from lifecycle events given oldest first (as
/// `Database::lifecycle_events_for` returns them: for a user or not, one
/// project or all; narrow to an organization by keeping its events). Each
/// entry gets the delays of its own organization.
pub fn tracks(events: &[LifecycleEvent], policies: &Policies) -> Vec<EntryTrack> {
    let mut tracks: BTreeMap<i64, EntryTrack> = BTreeMap::new();
    for e in events {
        let Some(day) = day_of(&e.at) else { continue };
        let track = tracks.entry(e.entry_id).or_insert_with(|| {
            let delay_days = policies.of_org(&e.org).days(e.cvss, e.kev);
            EntryTrack {
                entry_id: e.entry_id,
                org: e.org.clone(),
                project: e.project.clone(),
                app_name: e.app_name.clone(),
                cve_id: e.cve_id.clone(),
                cvss: e.cvss,
                kev: e.kev,
                detected: day,
                delay_days,
                due: day + Duration::days(i64::from(delay_days)),
                open: Vec::new(),
                status: None,
                decided: None,
            }
        });
        let close = |track: &mut EntryTrack| {
            if let Some(last) = track.open.last_mut().filter(|(_, until)| until.is_none()) {
                last.1 = Some(day);
            }
        };
        match (e.kind.as_str(), e.status.as_deref()) {
            ("removed", _) => {
                close(track);
                track.status = None;
            }
            (_, Some("untreated")) => {
                if track.open.last().is_none_or(|(_, until)| until.is_some()) {
                    track.open.push((day, None));
                }
                track.status = Some("untreated".into());
                track.decided = None;
            }
            (_, Some(status)) => {
                close(track);
                track.status = Some(status.to_string());
                track.decided = Some(day);
            }
            _ => {}
        }
    }
    tracks.into_values().collect()
}

/// Number of overdue entries at the end of each day, from `from` to `to` included
pub fn overdue_per_day(tracks: &[EntryTrack], from: NaiveDate, to: NaiveDate) -> Vec<(NaiveDate, i64)> {
    from.iter_days()
        .take_while(|day| *day <= to)
        .map(|day| (day, tracks.iter().filter(|t| t.overdue_on(day)).count() as i64))
        .collect()
}

/// Keys of the severity bands, most severe first; `none`: CVEs without a score
pub const BANDS: [&str; 5] = ["critical", "high", "medium", "low", "none"];

/// Position in [`BANDS`] of the band of a score
pub fn band(cvss: Option<f64>) -> usize {
    match Severity::of(cvss) {
        Some(Severity::Critical) => 0,
        Some(Severity::High) => 1,
        Some(Severity::Medium) => 2,
        Some(Severity::Low) => 3,
        None => 4,
    }
}

/// One value per severity band, and one for all of them together
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct BySeverity<T> {
    pub total: T,
    pub critical: T,
    pub high: T,
    pub medium: T,
    pub low: T,
    /// CVEs without a score
    pub none: T,
}

impl<T> BySeverity<T> {
    fn new(total: T, [critical, high, medium, low, none]: [T; 5]) -> Self {
        BySeverity { total, critical, high, medium, low, none }
    }

    /// The values of the bands, in the order of [`BANDS`]
    pub fn bands(&self) -> [&T; 5] {
        [&self.critical, &self.high, &self.medium, &self.low, &self.none]
    }
}

/// Lateness of the entries that are overdue today, in days past their deadline
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Lateness {
    pub avg: Option<f64>,
    pub max: Option<i64>,
}

/// The executive figures of a scope. Counts are of watchlist entries (one
/// CVE on one application); the severity is the one the CVE has today. An
/// average over nothing is `None`, never 0.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Figures {
    /// Day the figures are those of (UTC)
    pub as_of: NaiveDate,
    /// Entries to review
    pub open: BySeverity<i64>,
    /// Entries to review that are past their remediation deadline
    pub overdue: BySeverity<i64>,
    /// How late the overdue entries are
    pub overdue_days: Lateness,
    /// Length of the period the two figures below are taken over, ending on `as_of`
    pub period_days: i64,
    /// Entries resolved during the period: any decision (closed, not
    /// applicable, risk accepted) taken then and still in force, or in force
    /// when the entry left with its application. A decision reopened since
    /// does not count.
    pub resolved: BySeverity<i64>,
    /// Average number of days from the detection of those entries to their decision
    pub resolved_avg_days: BySeverity<Option<f64>>,
}

/// Mean of whole days, to one decimal; `None` of nothing
fn mean(days: &[i64]) -> Option<f64> {
    if days.is_empty() {
        return None;
    }
    Some((days.iter().sum::<i64>() as f64 / days.len() as f64 * 10.0).round() / 10.0)
}

/// The executive figures of these entries as of `today`, the averages of
/// resolution being taken over the `period_days` days ending today (at least
/// one, at most [`MAX_DAYS`]). The only place they are computed: narrow the
/// tracks to the scope wanted before calling (`Database::figures` does).
pub fn figures(tracks: &[EntryTrack], today: NaiveDate, period_days: i64) -> Figures {
    let period_days = period_days.clamp(1, i64::from(MAX_DAYS));
    let since = today - Duration::days(period_days - 1);
    let (mut open, mut overdue) = ([0i64; 5], [0i64; 5]);
    let mut late: Vec<i64> = Vec::new();
    let mut took: [Vec<i64>; 5] = Default::default();
    for track in tracks {
        let Some(deadline) = track.deadline(today) else { continue };
        let band = band(track.cvss);
        match deadline.resolved_in_days() {
            None => {
                open[band] += 1;
                if deadline.is_overdue() {
                    overdue[band] += 1;
                    late.push(deadline.overdue_days());
                }
            }
            Some(days) => {
                if track.decided.is_some_and(|on| on >= since && on <= today) {
                    took[band].push(days);
                }
            }
        }
    }
    let every: Vec<i64> = took.iter().flatten().copied().collect();
    Figures {
        as_of: today,
        open: BySeverity::new(open.iter().sum(), open),
        overdue: BySeverity::new(overdue.iter().sum(), overdue),
        overdue_days: Lateness { avg: mean(&late), max: late.iter().copied().max() },
        period_days,
        resolved: BySeverity::new(every.len() as i64, took.each_ref().map(|days| days.len() as i64)),
        resolved_avg_days: BySeverity::new(mean(&every), took.each_ref().map(|days| mean(days))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn each_severity_has_its_delay_and_exploited_cves_the_shorter_one() {
        let d = Delays::default();
        assert_eq!((d.critical, d.high, d.medium, d.low, d.kev), (7, 30, 90, 180, 14));
        for (cvss, expected) in [(Some(9.8), 7), (Some(9.0), 7), (Some(8.9), 30), (Some(7.0), 30), (Some(6.9), 90), (Some(4.0), 90), (Some(3.9), 180), (Some(0.1), 180)] {
            assert_eq!(d.days(cvss, false), expected, "{cvss:?}");
        }
        // No score (or 0): the medium delay
        assert_eq!(d.days(None, false), 90);
        assert_eq!(d.days(Some(0.0), false), 90);
        // Known exploited: 14 days where that is shorter…
        assert_eq!(d.days(Some(8.0), true), 14);
        assert_eq!(d.days(Some(5.0), true), 14);
        assert_eq!(d.days(Some(2.0), true), 14);
        assert_eq!(d.days(None, true), 14);
        // …and never longer than the delay of the severity
        assert_eq!(d.days(Some(9.8), true), 7);
        assert_eq!(Delays { kev: 400, ..d }.days(Some(8.0), true), 30);
    }

    #[test]
    fn an_entry_is_due_from_its_detection_and_a_decision_stops_the_clock() {
        let d = Delays::default();
        let detected = day("2026-03-01");
        // High: 30 days, due on the 31st
        let open = |today: &str| d.assess(detected, None, Some(7.5), false, day(today));
        assert_eq!(open("2026-03-01").due, day("2026-03-31"));
        assert_eq!((open("2026-03-19").days_left(), open("2026-03-19").label()), (Some(12), "in 12 days".into()));
        assert_eq!(open("2026-03-30").label(), "tomorrow");
        let last = open("2026-03-31");
        assert_eq!((last.label(), last.is_overdue(), last.overdue_days()), ("today".into(), false, 0));
        let late = open("2026-04-05");
        assert_eq!((late.label(), late.is_overdue(), late.overdue_days(), late.days_left()), ("overdue by 5 days".into(), true, 5, Some(-5)));
        assert_eq!(open("2026-04-01").label(), "overdue by 1 day");
        assert_eq!(late.resolved_in_days(), None);

        // Decided, even long after the deadline: never overdue, and how long it took is known
        let decided = d.assess(detected, Some(day("2026-04-10")), Some(7.5), false, day("2026-06-01"));
        assert!(!decided.is_overdue());
        assert_eq!((decided.overdue_days(), decided.days_left(), decided.resolved_in_days()), (0, None, Some(40)));
        assert_eq!(decided.state, DeadlineState::Decided { took_days: 40, late_days: 10 });
        assert_eq!(decided.label(), "decided in 40 days");
        let in_time = d.assess(detected, Some(day("2026-03-02")), Some(7.5), false, day("2026-06-01"));
        assert_eq!(in_time.state, DeadlineState::Decided { took_days: 1, late_days: 0 });

        // The severity is the one of today: a score raised to critical shortens the deadline of the same entry
        assert_eq!(d.assess(detected, None, Some(9.1), false, day("2026-03-19")).label(), "overdue by 11 days");
    }

    #[test]
    fn an_organization_replaces_some_delays_and_follows_the_instance_for_the_rest() {
        let mut policies = Policies::uniform(Delays { critical: 5, ..Delays::default() });
        policies.replace("strict", &DelayOverride { high: Some(10), kev: Some(2), ..Default::default() });
        policies.replace("plain", &DelayOverride::default());
        assert_eq!(*policies.of_org("strict"), Delays { critical: 5, high: 10, medium: 90, low: 180, kev: 2 });
        assert_eq!(*policies.of_org("plain"), policies.instance);
        assert_eq!(*policies.of_org("unknown"), policies.instance);
        // The same entry, in two organizations
        let today = day("2026-03-15");
        let of = |org: &str| policies.deadline(org, "2026-03-01 08:00:00", None, Some(8.0), false, today).unwrap();
        assert_eq!((of("strict").overdue_days(), of("plain").days_left()), (4, Some(16)));
        assert!(policies.deadline("plain", "garbage", None, None, false, today).is_none());
        // Back to the instance
        policies.replace("strict", &DelayOverride::default());
        assert_eq!(*policies.of_org("strict"), policies.instance);

        assert_eq!(DelayOverride { critical: Some(3), kev: Some(5), ..Default::default() }.describe(), "critical 3, kev 5");
        assert_eq!(DelayOverride::default().describe(), "inherited from the instance");
        assert_eq!(parse_days("High", " 30 "), Ok(30));
        for bad in ["0", "-1", "3651", "1.5", "", "ten"] {
            assert!(parse_days("High", bad).is_err(), "{bad}");
        }
    }

    fn event(id: i64, entry_id: i64, at: &str, kind: &str, status: Option<&str>, org: &str, cvss: Option<f64>) -> LifecycleEvent {
        LifecycleEvent {
            id,
            entry_id,
            org: org.into(),
            project: "p".into(),
            cve_id: format!("CVE-2026-{entry_id}"),
            app_name: "app".into(),
            app_version: None,
            at: format!("{at} 10:00:00"),
            kind: kind.into(),
            status: status.map(String::from),
            previous: None,
            actor: "t".into(),
            automatic: false,
            project_deleted: false,
            comment: None,
            cvss,
            kev: false,
        }
    }

    #[test]
    fn tracks_replay_the_history_of_each_entry() {
        let mut policies = Policies::uniform(Delays::default());
        policies.replace("strict", &DelayOverride { critical: Some(2), ..Default::default() });
        let events = vec![
            // 1: critical, due on the 8th; closed on the 12th, reopened on the 20th
            event(1, 1, "2026-03-01", "detected", Some("untreated"), "acme", Some(9.8)),
            // 2: the same day in a stricter organization: due on the 3rd, never decided
            event(2, 2, "2026-03-01", "detected", Some("untreated"), "strict", Some(9.8)),
            // 3: decided in time
            event(3, 3, "2026-03-01", "detected", Some("untreated"), "acme", Some(9.8)),
            event(4, 3, "2026-03-04", "status", Some("accepted"), "acme", Some(9.8)),
            event(5, 1, "2026-03-12", "status", Some("treated"), "acme", Some(9.8)),
            event(6, 1, "2026-03-20", "status", Some("untreated"), "acme", Some(9.8)),
            // 4: removed while overdue
            event(7, 4, "2026-03-01", "detected", Some("untreated"), "acme", Some(9.8)),
            event(8, 4, "2026-03-10", "removed", None, "acme", Some(9.8)),
        ];
        let tracks = tracks(&events, &policies);
        assert_eq!(tracks.len(), 4);
        let (one, two, three, four) = (&tracks[0], &tracks[1], &tracks[2], &tracks[3]);
        assert_eq!((one.due, two.due), (day("2026-03-08"), day("2026-03-03")));
        assert_eq!(one.open, vec![(day("2026-03-01"), Some(day("2026-03-12"))), (day("2026-03-20"), None)]);
        // Overdue from the day after the deadline, not while decided, and again at once when reopened:
        // the deadline is the first one
        for (d, expected) in [("2026-03-08", false), ("2026-03-09", true), ("2026-03-11", true), ("2026-03-12", false), ("2026-03-19", false), ("2026-03-20", true)] {
            assert_eq!(one.overdue_on(day(d)), expected, "{d}");
        }
        let today = day("2026-03-25");
        assert_eq!(one.deadline(today).unwrap().overdue_days(), 17);
        assert_eq!(two.deadline(today).unwrap().overdue_days(), 22);
        assert_eq!(three.deadline(today).unwrap().state, DeadlineState::Decided { took_days: 3, late_days: 0 });
        assert!(!three.overdue_on(today));
        // Removed: overdue until then, nothing after
        assert!(four.overdue_on(day("2026-03-09")) && !four.overdue_on(day("2026-03-10")));
        assert!(four.deadline(today).is_none());
        // Removed after a decision: the decision it left with stays
        let mut left = three.clone();
        left.status = None;
        assert_eq!(left.deadline(today).unwrap().resolved_in_days(), Some(3));

        let per_day = overdue_per_day(&tracks, day("2026-03-03"), day("2026-03-12"));
        assert_eq!(per_day.len(), 10);
        let counts: Vec<i64> = per_day.iter().map(|(_, n)| *n).collect();
        //                  3  4  5  6  7  8  9  10 11 12
        assert_eq!(counts, [0, 1, 1, 1, 1, 1, 3, 2, 2, 1]);
    }

    #[test]
    fn the_figures_count_what_is_open_overdue_and_resolved() {
        let mut policies = Policies::uniform(Delays::default());
        policies.replace("strict", &DelayOverride { high: Some(5), ..Default::default() });
        let today = day("2026-06-30");
        // Nothing tracked: counts are zero, averages are unknown
        let empty = figures(&[], today, 90);
        assert_eq!((empty.open, empty.overdue, empty.resolved), (BySeverity::default(), BySeverity::default(), BySeverity::default()));
        assert_eq!((empty.overdue_days, empty.resolved_avg_days), (Lateness { avg: None, max: None }, BySeverity::default()));
        assert_eq!((empty.as_of, empty.period_days), (today, 90));

        let kev = |mut e: LifecycleEvent| {
            e.kev = true;
            e
        };
        let events = vec![
            // 1 critical, detected 06-10, due 06-17: 13 days late
            event(1, 1, "2026-06-10", "detected", Some("untreated"), "acme", Some(9.8)),
            // 2 high, detected 06-10, due 07-10 in acme: in time…
            event(2, 2, "2026-06-10", "detected", Some("untreated"), "acme", Some(7.5)),
            // 3 …and due 06-15 in the stricter organization: 15 days late
            event(3, 3, "2026-06-10", "detected", Some("untreated"), "strict", Some(7.5)),
            // 4 medium but known exploited: 14 days, due 06-24, 6 days late
            kev(event(4, 4, "2026-06-10", "detected", Some("untreated"), "acme", Some(5.0))),
            // 5 low, in time; 6 without a score follows the medium delay: in time
            event(5, 5, "2026-06-10", "detected", Some("untreated"), "acme", Some(2.0)),
            event(6, 6, "2026-06-10", "detected", Some("untreated"), "acme", None),
            // 7 critical closed after 4 days, 8 critical accepted after 11 days: in the period
            event(7, 7, "2026-06-01", "detected", Some("untreated"), "acme", Some(9.8)),
            event(8, 7, "2026-06-05", "status", Some("treated"), "acme", Some(9.8)),
            event(9, 8, "2026-06-01", "detected", Some("untreated"), "acme", Some(9.8)),
            event(10, 8, "2026-06-12", "status", Some("accepted"), "acme", Some(9.8)),
            // 9 without a score, not applicable after 2 days
            event(11, 9, "2026-06-20", "detected", Some("untreated"), "acme", None),
            event(12, 9, "2026-06-22", "status", Some("not_applicable"), "acme", None),
            // 10 high decided long ago: out of a 30 day period, in a 365 day one (took 9 days)
            event(13, 10, "2026-01-01", "detected", Some("untreated"), "acme", Some(8.0)),
            event(14, 10, "2026-01-10", "status", Some("treated"), "acme", Some(8.0)),
            // 11 medium closed then reopened: open again, due at its first deadline, and not resolved
            event(15, 11, "2026-03-01", "detected", Some("untreated"), "acme", Some(5.0)),
            event(16, 11, "2026-06-02", "status", Some("treated"), "acme", Some(5.0)),
            event(17, 11, "2026-06-25", "status", Some("untreated"), "acme", Some(5.0)),
            // 12 low closed after 20 days, then its application was removed: the decision stays
            event(18, 12, "2026-06-01", "detected", Some("untreated"), "acme", Some(2.0)),
            event(19, 12, "2026-06-21", "status", Some("treated"), "acme", Some(2.0)),
            event(20, 12, "2026-06-28", "removed", None, "acme", Some(2.0)),
            // 13 critical removed while overdue: counts nowhere
            event(21, 13, "2026-06-01", "detected", Some("untreated"), "acme", Some(9.8)),
            event(22, 13, "2026-06-28", "removed", None, "acme", Some(9.8)),
        ];
        let tracked = tracks(&events, &policies);
        let f = figures(&tracked, today, 30);
        assert_eq!(f.open, BySeverity { total: 7, critical: 1, high: 2, medium: 2, low: 1, none: 1 });
        // 11 was due on 05-30: 31 days late
        assert_eq!(f.overdue, BySeverity { total: 4, critical: 1, high: 1, medium: 2, low: 0, none: 0 });
        assert_eq!(f.overdue_days, Lateness { avg: Some(16.3), max: Some(31) });
        assert_eq!(f.resolved, BySeverity { total: 4, critical: 2, high: 0, medium: 0, low: 1, none: 1 });
        assert_eq!(
            f.resolved_avg_days,
            BySeverity { total: Some(9.3), critical: Some(7.5), high: None, medium: None, low: Some(20.0), none: Some(2.0) }
        );
        // A longer period reaches the older decision; the state of today does not depend on it
        let year = figures(&tracked, today, 365);
        assert_eq!((year.open, year.overdue, year.overdue_days), (f.open, f.overdue, f.overdue_days));
        assert_eq!((year.resolved.total, year.resolved.high, year.resolved_avg_days.high), (5, 1, Some(9.0)));
        assert_eq!(year.resolved_avg_days.total, Some(9.2));
        // The period ends today and starts `period_days - 1` days before: 06-22 is the first day of 9 days
        assert_eq!(figures(&tracked, today, 9).resolved.total, 1);
        assert_eq!(figures(&tracked, today, 8).resolved.total, 0);
        assert_eq!((figures(&tracked, today, 0).period_days, figures(&tracked, today, 99_999).period_days), (1, i64::from(MAX_DAYS)));
        // Narrowed to one organization
        let strict: Vec<EntryTrack> = tracked.iter().filter(|t| t.org == "strict").cloned().collect();
        let s = figures(&strict, today, 30);
        assert_eq!((s.open.total, s.overdue.high, s.overdue_days), (1, 1, Lateness { avg: Some(15.0), max: Some(15) }));
        // The bands come in the order of their keys, and the answer is plain JSON
        assert_eq!(f.open.bands().map(|n| *n), [1, 2, 2, 1, 1]);
        assert_eq!([Some(9.5), Some(7.0), Some(4.0), Some(0.1), None].map(band), [0, 1, 2, 3, 4]);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["as_of"], "2026-06-30");
        assert_eq!(json["resolved_avg_days"]["high"], serde_json::Value::Null);
        assert_eq!((json["overdue_days"]["max"].as_i64(), json["open"]["none"].as_i64()), (Some(31), Some(1)));
        assert!(!json.to_string().contains("CVE-") && !json.to_string().contains("app"));
    }
}
