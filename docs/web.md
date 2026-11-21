# Web interface

`vulnizard serve` turns the same binary and SQLite database into a self-hosted
vulnerability monitoring platform, with no external service (no PostgreSQL,
Redis, Airflow or JS build): pages are compiled into the binary and the
scheduler runs in-process.

![Overview of all projects: counters, charts by project and severity, CVEs to review first](overview.png)

```bash
vulnizard sync                      # initial import (once)
vulnizard user create alice --admin # prompts for the password (or --password-stdin)
vulnizard serve                     # http://127.0.0.1:8000
```

The navigation has two visibly separate sides, and the header always shows when the
database was last synchronized (administrators can start a sync from there):

- **My products** — what you run and follow. A project selector (all projects `*` by default)
  filters every view:
  - *Overview*: counters and charts. With all projects, each project has its own color and each
    severity level its own bar; for a single project, severity levels are told apart by color
  - *To review*: CVEs affecting the deployed versions — **close** once fixed, **accept the risk**
    with a justification, or mark **not applicable**
  - *Applications*: what you run and in which version (rescanned after every sync; changing the
    version closes the CVEs it fixes), the **inventory sources** of the project and the checklist of
    what they discovered (see *Collecting what is deployed*)
  - *Subscriptions*: vendors or products whose every CVE change you follow
  - *Evolution*: stock and daily activity (new, accepted, closed) over 30/90/365 days, and the
    state of every tracked CVE **at any past date**
  - *Audit*: who decided what, when and why — accepted risks first
  - *Settings* (per project): the project's own notification **destinations** (email with its own
    SMTP server, ntfy, Slack, webhook, browser) and the **rules** saying which destination is told
    about which events, from which CVSS; members with a right on the project only
- **CVE database** — reference information: CVEs (keyword, CVE-ID, vendor, product, CVSS, CWE,
  KEV, personal tags) with their change history, vendors & products, weaknesses
- **Background scheduler**: periodic incremental sync, then reports, watchlist rescan and
  notifications (`web.sync_interval_minutes`)
- **Read-only REST API** under `/api` (`Authorization: Bearer <token>` created in *Settings*, or HTTP Basic):
  `/api/cve`, `/api/cve/{id}`, `/api/vendors`, `/api/vendors/{vendor}/products`, `/api/weaknesses`,
  `/api/organizations`, `/api/organizations/{org}/projects[/{project}[/reports[/{day}]]]`,
  `/api/organizations/{org}/audit` and `/api/security-log` (signed log exports, see *Administration*)

Charts are SVG rendered by the server. The JavaScript shipped is a handful of small same-origin
files: browser notifications (Web Push), passkeys, and filters that apply while typing. Every list
can be sorted (click a column header, click again to reverse) and filtered with its search box;
everything works without JavaScript except notifications and passkeys.

---
[← Back to the README](../README.md)
