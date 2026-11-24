# Collecting what is deployed (preview)

> **Preview — not part of the first release.** This feature is closed by default: the interface shows
> it greyed out, and its endpoints and MCP tools answer "not found". To try it, set
> `[inventory] enabled = true` in the configuration file.

Instead of typing versions by hand, a project can have **inventory sources** (*Applications* view):

- **Pushed by a collector** — the source has a token that can do one thing: deliver the inventory of
  that source (`POST /api/inventory`). Vulnizard reads nothing on your infrastructure.
- **A file in a Git repository** — Vulnizard downloads **one file** over HTTPS at each sync (Forgejo,
  Gitea, GitHub, GitLab, or a direct URL), with an optional read-only token. It never clones the
  repository, reads nothing else and never writes.

The inventory is either `{"components":[{"name":"nginx","version":"1.30.6","vendor":"f5","exposed":true}]}`
or a CycloneDX JSON SBOM. Each delivery replaces the previous list of the source.

**Groups.** A source belongs to a group — a tag shared by the sources that are triaged together.
Ten identical web servers in the group `web` show each package once ("2 sources", "10 sources"), and
a decision on a CVE (close, accept the risk, not applicable) holds for the whole group; the same
package can be accepted for `web` and still to review for `db`. When one machine of a group is
upgraded before the others, both versions are shown until the last one follows. Without a group, a
source is its own group.

**System packages.** Machines send only the list "package, version, release" (a few kilobytes); no
scanner and no vulnerability database is installed on them. Vulnizard decides on the server, with
the distribution's own advisories and version ordering — distributions backport fixes, so upstream
version ranges would be wrong. Debian is supported (source *Distribution advisories*, fetched from
OSV as soon as an inventory reports Debian packages). A source can **monitor everything it reports**,
so that the packages of a machine do not have to be ticked one by one; packages with nothing to
review stay hidden in the *Applications* view.

Discovered components appear in a **checklist**, most likely to matter first: exposed on the network,
well-known service (ssh, nginx…), product with a CVE history. Ticked components become tracked
applications that follow the source (a new version closes the CVEs it fixes, a removed component
stops being tracked). A **new probable service** is announced through the destinations
that receive the project's notifications and send the event *New probable service discovered*.

Any tool producing a CycloneDX JSON SBOM can feed a source, for instance
[Syft](https://github.com/anchore/syft) (`syft <image or dir> -o cyclonedx-json`),
[Trivy](https://github.com/aquasecurity/trivy) or, on NixOS, [sbomnix](https://github.com/tiiuae/sbomnix).
They list every package they find; mark what listens on the network with the component property
`vulnizard:exposed = true`.

`vulnizard-collector` is the minimal alternative: a separate small binary that collects **only what its configuration lists**
and sends names and versions, nothing else (unknown configuration keys are refused):

```toml
[[collect]]
type = "images"                        # image = "…" references in these files
files = ["hosts/*/services/*.nix"]

[[collect]]
type = "dpkg"                          # installed Debian packages: source package + version

[[collect]]
type = "listening"                     # programs listening on a non-loopback address → exposed

[[collect]]
type = "command"                       # JSON {"name": "version"} or a list of components
run = ["my-inventory-script"]

[filter]
include = ["nginx", "open*"]           # optional allow-list
exclude = ["internal-*"]

[rename]                               # collected name → name in the CVE database
sshd = "openssh"
[vendor]
openssh = "openbsd"
```

```bash
vulnizard-collector --config collector.toml --dry-run            # show what would be sent
vulnizard-collector --config collector.toml --output inv.json    # write the file of a Git source
VULNIZARD_TOKEN=… vulnizard-collector --config collector.toml --server https://vulnizard.example.org
```

---
[← Back to the README](../README.md)
