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
`get_state_at`, `get_audit_log`, `list_inventory`, `list_notifications`, `get_security_log` (administrators),
`database_status`.

`list_watchlist` and `get_audit_log` answer one page at a time: `{ total, offset, limit, entries }`
(`events` for the audit log), 50 entries or 100 events by default and 500 at most; pass `offset` for
the next page. In the list, a CVE description is cut after 200 characters (`get_cve` gives it whole).
`get_audit_log` lists decisions by default; `event: detected`, `removed` or `all` adds the entries a
scan brought in and those that left with their application. `database_status` gives the version of
the software and of the database schema. In `list_applications`, `source` is `manual` for an
application added by hand and `inventory` for one brought by an inventory source.

Write tools (off by default: *Admin → MCP* for HTTP, `--allow-write` for stdio): `create_project`,
`subscribe`, `unsubscribe`, `add_application`, `update_application_version`, `choose_components`
(monitor or ignore discovered components), `request_sync` (administrators, HTTP only) and
`set_cve_status` (close, accept a risk with a justification, mark not applicable). Decisions made
through MCP are recorded in the audit history under the user's name.

---
[← Back to the README](../README.md)
