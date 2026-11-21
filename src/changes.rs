//! CVE change tracking: compares the stored state of a CVE before and after
//! an upsert and produces the list of events (change history of a CVE).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Event types that can be subscribed to in notifications.
pub const EVENT_TYPES: &[(&str, &str)] = &[
    ("created", "New CVE"),
    ("description", "Description changed"),
    ("metrics", "CVSS changed"),
    ("vendors", "Vendors/products changed"),
    ("references", "References changed"),
    ("weaknesses", "Weaknesses changed"),
    ("kev", "Added to CISA KEV"),
    // Not a CVE change: a component that looks like a network service was discovered
    ("service", "New probable service discovered"),
];

/// Tracked state of a CVE at a given time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub description: Option<String>,
    pub cvss: Option<f64>,
    pub cwes: BTreeSet<String>,
    /// "vendor:product" pairs
    pub products: BTreeSet<String>,
    pub references: BTreeSet<String>,
    pub kev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Created,
    Description {
        old: Option<String>,
        new: Option<String>,
    },
    Metrics {
        old: Option<f64>,
        new: Option<f64>,
    },
    Vendors {
        added: Vec<String>,
        removed: Vec<String>,
    },
    References {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Weaknesses {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Kev,
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Created => "created",
            Event::Description { .. } => "description",
            Event::Metrics { .. } => "metrics",
            Event::Vendors { .. } => "vendors",
            Event::References { .. } => "references",
            Event::Weaknesses { .. } => "weaknesses",
            Event::Kev => "kev",
        }
    }

    pub fn label(&self) -> &'static str {
        let kind = self.kind();
        EVENT_TYPES
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, l)| *l)
            .unwrap_or(kind)
    }
}

fn set_diff(old: &BTreeSet<String>, new: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        new.difference(old).cloned().collect(),
        old.difference(new).cloned().collect(),
    )
}

/// Computes the events between two states of a CVE.
///
/// A CVE without description is a stub (e.g. created by an EPSS-only sync):
/// it produces no event, and the first state with a description is "created".
pub fn diff(old: Option<&Snapshot>, new: &Snapshot) -> Vec<Event> {
    if new.description.is_none() {
        return Vec::new();
    }
    let old = match old {
        Some(o) if o.description.is_some() => o,
        _ => return vec![Event::Created],
    };

    let mut events = Vec::new();
    if old.description != new.description {
        events.push(Event::Description {
            old: old.description.clone(),
            new: new.description.clone(),
        });
    }
    if old.cvss != new.cvss {
        events.push(Event::Metrics {
            old: old.cvss,
            new: new.cvss,
        });
    }
    if old.products != new.products {
        let (added, removed) = set_diff(&old.products, &new.products);
        events.push(Event::Vendors { added, removed });
    }
    if old.references != new.references {
        let (added, removed) = set_diff(&old.references, &new.references);
        events.push(Event::References { added, removed });
    }
    if old.cwes != new.cwes {
        let (added, removed) = set_diff(&old.cwes, &new.cwes);
        events.push(Event::Weaknesses { added, removed });
    }
    if !old.kev && new.kev {
        events.push(Event::Kev);
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(desc: Option<&str>) -> Snapshot {
        Snapshot {
            description: desc.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn stub_produces_no_event() {
        assert!(diff(None, &snap(None)).is_empty());
    }

    #[test]
    fn first_description_is_created() {
        assert_eq!(diff(None, &snap(Some("x"))), vec![Event::Created]);
        assert_eq!(diff(Some(&snap(None)), &snap(Some("x"))), vec![Event::Created]);
    }

    #[test]
    fn identical_states_produce_no_event() {
        assert!(diff(Some(&snap(Some("x"))), &snap(Some("x"))).is_empty());
    }

    #[test]
    fn detects_field_changes() {
        let old = snap(Some("x"));
        let mut new = snap(Some("y"));
        new.cvss = Some(9.8);
        new.kev = true;
        new.products.insert("apache:httpd".into());
        let kinds: Vec<_> = diff(Some(&old), &new).iter().map(|e| e.kind()).collect();
        assert_eq!(kinds, vec!["description", "metrics", "vendors", "kev"]);
    }

    #[test]
    fn events_roundtrip_json() {
        let events = vec![
            Event::Created,
            Event::Metrics { old: None, new: Some(7.5) },
        ];
        let json = serde_json::to_string(&events).unwrap();
        assert!(json.contains(r#""type":"created""#));
        assert_eq!(serde_json::from_str::<Vec<Event>>(&json).unwrap(), events);
    }
}
