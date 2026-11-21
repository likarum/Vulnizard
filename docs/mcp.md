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
access to every project:

```bash
claude mcp add vulnizard -- /path/to/vulnizard --db /path/to/vulnizard.db mcp
```

Read tools: `search_cves`, `get_cve`, `list_vendors`, `list_products`, `list_weaknesses`,
`list_projects`, `list_reports`, `get_report`, `list_applications`, `list_watchlist`, `get_evolution`,
`get_state_at`, `get_audit_log`, `list_inventory`, `list_notifications`, `database_status`.

Write tools (off by default: *Admin → MCP* for HTTP, `--allow-write` for stdio): `create_project`,
`subscribe`, `unsubscribe`, `add_application`, `update_application_version`, `choose_components`
(monitor or ignore discovered components), `request_sync` (administrators, HTTP only) and
`set_cve_status` (close, accept a risk with a justification, mark not applicable). Decisions made
through MCP are recorded in the audit history under the user's name.

---
[← Back to the README](../README.md)
