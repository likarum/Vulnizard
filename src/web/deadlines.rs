//! Remediation deadlines: the delays of the instance (administrators) and
//! what an organization replaces for its projects (its owners).

use axum::extract::{Form, Path, State};
use maud::{html, Markup};
use std::collections::HashMap;

use super::admin::{admin_tabs, require_admin};
use super::pages::{load_org, redirect, ActionResult, HtmlResult};
use super::views::{self, enc, layout, Nav};
use super::{blocking, AppError, St, User};
use crate::db::{Actor, Database, Org};
use crate::deadlines::{parse_days, DelayOverride, Delays, FIELDS, MAX_DAYS};
use crate::rbac::Permission;

/// What the delays mean, said the same way on both pages
fn rule() -> Markup {
    html! {
        p.muted {
            "An entry of the watchlist is due that many days after its detection, according to the severity its CVE has today. "
            "A CVE without a score follows the medium delay. A CVE known to be exploited (CISA KEV) follows the exploited delay when it is shorter than the one of its severity. "
            "Any decision — closed, not applicable, risk accepted — stops the clock: a decided entry is never overdue. "
            "Reopening an entry or changing the version of its application does not move its deadline."
        }
    }
}

pub async fn admin(State(st): St, User(user): User) -> HtmlResult {
    require_admin(&user)?;
    blocking(|| {
        let db = st.db()?;
        let delays = db.instance_delays()?;
        let defaults = Delays::default();
        Ok(layout(
            Nav::Admin,
            "Deadlines",
            Some(&user),
            html! {
                h1 { "Administration" }
                (admin_tabs("deadlines"))
                h2 { "Remediation deadlines" }
                (rule())
                form.stack.card method="post" action="/admin/deadlines" {
                    @for (field, label) in FIELDS {
                        label {
                            (label) " — days (default " (defaults.get(field)) ")"
                            input type="number" name=(field) value=(delays.get(field)) min="1" max=(MAX_DAYS) step="1" required;
                        }
                    }
                    button type="submit" { "Save" }
                }
                p.muted {
                    "These delays apply to every project. The owners of an organization may replace them for its projects, on the page of the organization. "
                    "Changes are written to the " a href="/admin/security" { "security log" } "."
                }
            },
        ))
    })
}

pub async fn admin_save(State(st): St, User(user): User, Form(form): Form<HashMap<String, String>>) -> ActionResult {
    require_admin(&user)?;
    blocking(|| {
        let mut delays = DelayOverride::default();
        for (field, label) in FIELDS {
            let value = form.get(field).map(String::as_str).unwrap_or("");
            delays.set(field, Some(parse_days(label, value).map_err(AppError::Bad)?));
        }
        let delays = Delays::default().with(&delays);
        st.db()?.set_instance_delays(&delays, &Actor::user(user.id, &user.username))?;
        Ok(redirect("/admin/deadlines".into()))
    })
}

/// Section of the page of an organization: the delays its projects follow,
/// and the form replacing them for who may manage the organization
pub(super) fn org_section(db: &Database, org: &Org) -> Result<Markup, AppError> {
    let instance = db.instance_delays()?;
    let replaced = db.org_delay_override(org.id)?;
    let effective = instance.with(&replaced);
    let manage = org.can(Permission::ManageMembers);
    Ok(html! {
        h2 id="deadlines" { "Remediation deadlines" }
        p.muted {
            "Days an entry of this organization's projects may stay to review, from its detection."
            (views::info(rule()))
        }
        table.list.fit {
            (views::columns("name num -", true))
            thead { tr { th { "Severity" } th { "Days" } th { "Set by" } } }
            tbody {
                @for (field, label) in FIELDS {
                    tr {
                        td { (label) }
                        td { (effective.get(field)) }
                        td { @if replaced.get(field).is_some() { "this organization" } @else { span.muted { "the instance" } } }
                    }
                }
            }
        }
        @if manage {
            form.stack.card method="post" action={ "/orgs/" (enc(&org.name)) "/deadlines" } {
                @for (field, label) in FIELDS {
                    label {
                        (label) " — days (instance: " (instance.get(field)) ")"
                        input type="number" name=(field) value=[replaced.get(field)] placeholder={ "inherited: " (instance.get(field)) }
                            min="1" max=(MAX_DAYS) step="1";
                    }
                }
                button type="submit" { "Save" }
            }
            p.muted { "Leave a field empty to follow the instance for that value; empty them all to follow it entirely." }
        }
    })
}

pub async fn org_save(
    State(st): St,
    User(user): User,
    Path(org): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> ActionResult {
    blocking(|| {
        let db = st.db()?;
        let org = load_org(&db, &user, &org)?;
        if !org.can(Permission::ManageMembers) {
            return Err(AppError::Forbidden);
        }
        let mut replaced = DelayOverride::default();
        for (field, label) in FIELDS {
            let value = form.get(field).map(|v| v.trim()).unwrap_or("");
            if !value.is_empty() {
                replaced.set(field, Some(parse_days(label, value).map_err(AppError::Bad)?));
            }
        }
        db.set_org_delay_override(org.id, &replaced, &Actor::user(user.id, &user.username))?;
        Ok(redirect(format!("/orgs/{}#deadlines", enc(&org.name))))
    })
}
