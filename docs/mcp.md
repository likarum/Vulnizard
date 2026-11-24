# MCP server

Vulnizard exposes its data to AI assistants through the
[Model Context Protocol](https://modelcontextprotocol.io), in two ways sharing the same tools.

**Over HTTP**, from the running server (enable it in *Admin → MCP*). The assistant authenticates with
a user's API token and acts **as that user**: it only sees that user's organizations and has that
user's role.

```bash
claude mcp add --transport http vulnizard https://vulnizard.example.org/mcp \
  --header "Authorization: Bearer <api token>"
```

**Locally over stdio**, on the machine holding the database, without the web server and with full
access to every project. There is no account there: what is changed this way is recorded in the
audit under the name `mcp-stdio` (over HTTP, under the account of the token):

```bash
claude mcp add vulnizard -- /path/to/vulnizard --db /path/to/vulnizard.db mcp
```

Read tools: `search_cves`, `get_cve`, `list_vendors`, `list_products`, `list_weaknesses`,
`list_projects`, `list_reports`, `get_report`, `list_applications`, `list_watchlist`, `get_evolution`,
`get_summary`, `get_state_at`, `get_audit_log`, `list_inventory`, `list_notifications`,
`get_security_log` (administrators), `database_status`.

`get_summary` gives the figures of the *Overview* and nothing else — no CVE, no application, no
name — for one project (`org`, `project`), for every project the caller can read (no argument), or
for those of one organization (`org` alone; an organization the caller reads nothing of gives
figures of nothing). As of today: `open` (entries to review) and `overdue` (those past their
remediation deadline), each with a `total` and a count per severity (`critical`, `high`, `medium`,
`low`, `none` for CVEs without a score; the severity is the one the CVE has today), and
`overdue_days` (`avg` and `max` days past the deadline). Over the last `period_days` days (`days`,
1 to 365, 90 by default): `resolved`, the entries decided then (closed, not applicable or risk
accepted) whose decision still stands, and `resolved_avg_days`, the average number of days from
their detection to that decision. An average over nothing is `null`, never 0. The REST API answers
the same at `/api/summary`.

`get_evolution` gives one object per day; `open_by_severity` splits its `open` (entries to review
at the end of the day) into five counts, in this order: critical, high, medium, low, no score. The
severity is the one each CVE has today.

`list_watchlist` and `get_audit_log` answer one page at a time: `{ total, offset, limit, entries }`
(`events` for the audit log), 50 entries or 100 events by default and 500 at most; pass `offset` for
the next page. In the list, a CVE description is cut after 200 characters (`get_cve` gives it whole).
A `limit` outside 1 to 500 is refused. The `application` filter of `list_watchlist` matches the name
whatever its case. An entry to review carries its remediation deadline: `due_at` (a day, UTC),
`days_left` (negative once overdue) and `overdue_days`; a decided one carries `resolved_in_days`
(from its detection to the decision). `overdue: true` keeps the entries to review that are past
their deadline, most overdue first. `get_state_at` gives `due_at` and `overdue_days` (as of that
day) for the entries that were to review then. The delays are those of the organization of each
project (see *Administration*).
`get_audit_log` lists every decision by default (`decision: accepted` keeps the accepted risks only); `event: detected`, `removed` or `all` adds the entries a
scan brought in and those that left with their application. `database_status` gives the version of
the software and of the database schema. In `list_applications`, `source` is `manual` for an
application added by hand and `inventory` for one brought by an inventory source.
`list_notifications` gives the destinations of the project with what each sends: `destination`,
`kind`, `scope` (`project`), `events` (none = it sends nothing), `min_cvss`, `enabled`. Instance
administrators and the local operator also get the destinations of the organization and of the
instance (`scope` `organization` or `instance`), which receive the project's notifications too.
The target of a destination (address, URL, topic) is never returned.

Write tools (off by default: *Admin → MCP* for HTTP, `--allow-write` for stdio): `create_project`,
`subscribe`, `unsubscribe`, `add_application`, `update_application_version`, `choose_components`
(monitor or ignore discovered components), `request_sync` (administrators, HTTP only) and
`set_cve_status` (close, accept a risk with a justification, mark not applicable). Decisions made
through MCP are recorded in the audit history under the user's name.

---
[← Back to the README](../README.md)
