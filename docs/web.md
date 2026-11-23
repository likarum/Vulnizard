# Web interface

`vulnizard serve` turns the same binary and SQLite database into a self-hosted
vulnerability monitoring platform, with no external service (no PostgreSQL,
Redis, Airflow or JS build): pages are compiled into the binary and the
scheduler runs in-process.

![Overview of all projects: counters, charts by project and severity, CVEs to review first](overview.png)

```bash
vulnizard sync                      # initial import (once)
vulnizard serve                     # http://127.0.0.1:8000
vulnizard setup-code                # code asked by the setup page at first visit
# or, without the page: vulnizard user create alice --admin
```

The navigation has two visibly separate sides, and the header always shows when the
database was last synchronized (administrators can start a sync from there):

- **My products** — what you run and follow. A project selector (all projects `*` by default)
  filters every view:
  - *Overview*: counters and charts. With all projects, each project has its own color and each
    severity level its own bar; for a single project, severity levels are told apart by color
  - *Vulnerabilities*: CVEs affecting the deployed versions. Those still to review are listed
    first (the default filter); the other filter lists those already decided. **Close** once
    fixed, **accept the risk** with a justification, or mark **not applicable**
  - *Applications*: what you run and in which version (rescanned after every sync; changing the
    version closes the CVEs it fixes, and an entry still to review that no longer matches after a
    source corrected its data is set aside as not applicable). The name is the product name of
    the CVE database, matched exactly (case and separators aside: `home_assistant` is
    `home-assistant`, `podman` is not `podman_desktop`; with a vendor, the products of that vendor
    named after the application count too, as `nginx_open_source` for `nginx`); a package ecosystem (Go, npm, PyPI,
    crates.io, Maven) also matches the advisories of the package of that name, at the version.
    When the sources disagree on a CVE, the one that gives versions decides; a CVE for which
    no source gives any version matches every version (better a false alert than a missed one)
    and is marked *version not given* in the list to review: read it before deciding.
    An application marked *unknown to the sources* has no CVE recorded under its name at any
    version, which is not the same as having none at its version. Then the **inventory sources** of the project and the checklist of
    what they discovered (see *Collecting what is deployed*)
  - *Subscriptions*: vendors or products whose every CVE change you follow
  - *History*: stock and daily activity (new, accepted, closed) over 30/90/365 days, and the
    state of every tracked CVE **at any past date**: click a day in a chart, or pick it in the
    date field. A past state is marked as such, with a link back to today
  - *Audit*: who decided what, when and why — accepted risks first
  - *Settings* (per project): the project's own notification **destinations** (email with its own
    SMTP server, ntfy, Slack, webhook, browser) and the **rules** saying which destination is told
    about which events, from which CVSS; members with a right on the project only
- **CVE database** — reference information: CVEs (keyword, CVE-ID, vendor, product, CVSS, CWE,
  KEV, personal tags) with their change history, vendors & products, weaknesses
- **Background scheduler**: periodic incremental sync, then reports, watchlist rescan and
  notifications (`web.sync_interval_minutes`). Only the NVD and Vulnrichment read what changed since
  the last run. The other sources download a whole file and wait between two downloads, whatever
  the interval: 6 h for the KEV catalog (2 MB), 12 h for EPSS (3 MB), OSV (290 MB), the Debian
  advisories (85 MB) and Exploit-DB (10 MB), 24 h for Metasploit (11 MB) and Nuclei (2 MB).
  *Admin → Sources* shows it per source; "Sync now" there downloads at once, without waiting
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
