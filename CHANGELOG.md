# Changelog

All notable changes to Vulnizard. Versions follow [semantic versioning](https://semver.org);
before 1.0, a minor version may change behaviour.

## 0.2.0

### Things to know before upgrading

- The database moves to schema v23 at first start (the existing log entries are chained, version
  ranges record whether their bounds are included). Back it up first; an older version does not
  open it afterwards.
- **The first synchronization after the upgrade reads the whole history of the NVD again**: about
  half an hour without an NVD API key, a few minutes with one, during which the other sources
  wait. It goes on where it stopped if it is interrupted. An instance installed with the former
  default only knew the last six months of the NVD: expect many applications to get their first
  matches, and notifications for them. `sync.history_months` limits the history again (0, the
  new default, reads everything).
- **An application now matches the product of its exact name** (case and separators aside), no
  longer every product whose name contains it: `nginx` no longer matches `ingress-nginx` or
  `nginxui`. When the vendor is given, the products of that vendor named after the application
  count too (`nginx_open_source`, `nginx_plus` for `nginx` of `f5`): give the vendor, or declare
  such a variant as an application of its own.
- New passwords need 15 characters (10 before) and easy ones are refused. Existing passwords
  keep working until they are changed.
- With open registration, the first account is no longer the administrator for whoever registers
  first: it takes the setup code (see below) or the command line. Existing instances, which have
  accounts, are not affected.
- The Nuclei templates source is not enabled on an existing instance: *Admin → Vulnerability
  sources*.
- After the first synchronization, entries still to review that no longer match their
  application are set aside as *not applicable* by the system (see *Fixed*): expect the list to
  shrink. The audit records each of them.
- What is changed through MCP over stdio is recorded under the name `mcp-stdio` (`mcp` before);
  entries already written keep `mcp`.

### Added

- **Password rules follow NIST SP 800-63B rev. 4**: at least 15 characters, no composition rule,
  and a refusal of what is guessed first (repetitions, the alphabet or a keyboard row, very
  common words, the username). Same rules wherever a password is chosen, command line included.
- **First-run setup page.** While no account exists, the instance leads to `/setup`, which
  creates the administrator for whoever holds a one-time setup code. The code is written in the
  server log at start and printed by `vulnizard setup-code`: it proves access to the server, so
  the page cannot be used by whoever reaches the instance first. The code is random and changes
  at every start of the server while no account exists. Wrong codes are limited per address, and
  the page is gone for good once an account exists. `vulnizard user create --admin` still works,
  for automated deployments.
- **Logs that show tampering.** The security log and the audit of decisions are chained, entry
  after entry, and export as signed JSON (and CSV for reading) from their pages and from the API
  (`/api/security-log`, `/api/organizations/{org}/audit`). `vulnizard log verify <file>` checks an
  export offline. MCP gains `get_security_log` for administrators.
- **Nuclei templates** as a source (`nuclei`): a CVE page, `vulnizard info`, the API and MCP say
  when a ready-made detection template exists, with a link to it. A template is a check, not an
  exploit. Not enabled by default on an existing instance: *Admin → Vulnerability sources*.
- **CVEs by source**: the CVE list narrows to the CVEs a source has data on (web filter,
  `?source=` in the API, `source` in MCP `search_cves`, `search --from-source` on the command
  line), and a CVE page names its sources. Which source wrote what is not recorded: it is told
  from the fields only that source fills.
- **Applications unknown to the sources are told apart**: the list of applications, the API and
  MCP (`known_cves`) say how many CVEs the sources hold under the name of an application at any
  version. Zero means the name is unknown (wrong name, or software the NVD does not describe),
  not that the version is safe. The web form now takes the package ecosystem, as MCP and the
  command line did.
- A page footer: links to the source, the disclaimer and the issue tracker; the version, for
  signed-in users only.
- **A layout for phones**: below 760 px the navigation, forms and tables fit the screen.
- **Synchronizations cannot be requested over and over**: a source already waiting, running, or
  started less than `web.min_manual_sync_minutes` ago (5 by default) is not synchronized again,
  from the web or through MCP, and the answer says so.
- `web.push_contact`: the contact given to browser push services.

### Fixed

- **An application declared with an ecosystem (Go, npm, crates.io, PyPI, Maven) was matched
  without its version**, and with every package whose name contained its own: n8n 3.1.0 got
  168 CVEs, most of them fixed long before or belonging to other packages. The version is now
  checked against the ranges of the advisory, the package must be the application itself (or the
  last part of its path, `traefik` for `github.com/traefik/traefik/v3`), and a Go module of
  another major version is left out. Ranges given as Git commits are no longer read as versions,
  and the ranges of an advisory are updated when it is corrected (they were kept as first seen).
- **Versions with a letter were compared without it**: OpenSSL 1.0.1f was not matched by a flaw
  fixed in 1.0.1g. Pre-releases (`-rc1`, `b2`) now come before their release.
- A product recorded as affected *from* a version, without an end, matched older versions too.
- **The NVD was only read six months back by default**, so older CVEs existed only as records
  left by CISA KEV or EPSS, without version ranges: such a record matched every version
  (Heartbleed for OpenSSL 3.x), and most applications matched nothing. The whole history is now
  read, once, without recording it as changes of the CVEs; requests respect the rate of the NVD
  and a refusal is tried again instead of failing the run.
- **"Up to 1.4 included" was read as "before 1.4"** (and "after 1.2" as "from 1.2"): the last
  affected version of such a range was not matched. Each bound now records whether it is
  included (schema v23); the NVD is read again once to fill it in.
- **Product names were matched as substrings**: `docker` matched `mailcow-dockerized`, `podman`
  matched `podman_desktop`. The product is now the application itself, case and separators aside
  (`home_assistant` now matches `home-assistant`, which it did not); with a vendor, the products
  of that vendor named after it are kept (`nginx_open_source` for `nginx`).
- `search --version` compared versions as text (`3.7.16` before `3.7.3`, `10.0` before `9.0`); it
  now uses the same comparison as tracked applications, and works without `--product`.
- **Entries no longer matching stayed to review for ever.** After each synchronization (and with
  `watch scan`), an entry still to review whose CVE no longer matches the application, because a
  source corrected its data, is set aside as *not applicable* with a comment saying so, and
  comes back if it matches again. Decisions taken by a person are never changed.
- `/push/inbox` answered an empty list without a session; it now refuses. Found by a new test
  that reads every route from the source and calls each one with five methods and five kinds
  of missing or forged credentials: nothing but sign-in pages and static files may answer.
- **Signed out, a page no longer shows the menus, the state of the last synchronization or the
  "Sync now" button.** The pages behind them already required a session; the header did not.
- **Sources that skipped a cycle were never synchronized again.** A source that found itself up
  to date was recorded as synchronized, which pushed its next download back at every cycle: CISA
  KEV, EPSS, OSV, Exploit-DB and Metasploit stopped being refreshed while the server ran.
- **NVD**: a full import left one day out every hundred days, and a period that could not be read
  was skipped silently. Periods are now contiguous and an unreadable one fails the run, which is
  then tried again from the same date.
- **Vulnrichment**: after a long interruption only the first hundred changes were read, and
  changes that could not be read were ignored; both now trigger a full read.
- The product filter of the CVE list did nothing without a vendor (web, API, MCP).
- Browser notifications: the test says what is missing (no browser registered, or the push
  service refusing) instead of "sent to 0 of your browsers"; enabling reports the real error.
- *Admin → Notifications* shows how many projects a shared destination serves instead of a bare
  count of rules.

### Changed

- A source asked for by name (its button, MCP `request_sync` with a source, `sync --source`) runs
  even if it was synchronized recently.

### Also in this release (prepared as 0.1.3, never published separately)

- The key that encrypts the stored secrets can come from a secret manager: `VULNIZARD_KEY_FILE`,
  a systemd credential, or the new NixOS option `services.vulnizard.keyFile` (sops-nix, agenix).
- `vulnizard key path` and `vulnizard key export` tell where the key is and print it for a backup;
  *Admin → Status* shows where it is. It is not downloadable from the web interface.
- Docker: the image has a `/keys` directory for a separate key volume (commented example in
  `docker-compose.yml`).
- The old enrichment plan file is removed from the repository; what remains of it is tracked as
  an issue.

## 0.1.2 — first public release

No functional change from 0.1.1. The repository is published with a fresh history; issue numbers
start again from 1.

## 0.1.1 — security release

Fixes for the findings of the first security audit of 0.1.0. Upgrading is recommended for
everyone. The database is migrated at first start (schema v21): **back it up before upgrading**.

### Things to know before upgrading

- **A key file appears next to the database** (`<database>.key`). It encrypts the secrets stored
  in the database. Keep it and back it up apart from the database: without it, second factors
  must be reset and stored passwords, client secrets and tokens entered again.
- **Nothing is readable without signing in any more**: the CVE, vendor and weakness pages now
  require a session, like the rest.
- **Creating an API token asks for the password again.**
- **A project's email destination needs its own SMTP server.** Sending through the server of the
  instance is reserved to destinations created by an administrator. Existing destinations keep
  working.
- **An organization requiring two-step sign-in** no longer confines its members' whole account:
  members without a second factor cannot open that organization, and nothing else changes for
  them. Turning the requirement on needs a second factor of one's own.
- **Behind a reverse proxy**, make it send `X-Forwarded-For`: failed sign-ins are now counted per
  client address. A proxy on the same machine is trusted; name any other one in
  `web.trusted_proxies`.
- **The migration rewrites the database file** once, to erase the secrets that were stored in
  clear: on a large database the first start takes a few minutes and needs free disk space of
  about the size of the database. Backups taken before this release still hold those secrets in
  clear: delete them, or change the secrets.
- **A database that holds encrypted secrets does not start without its key file.**
- `vulnizard-collector` refuses to send its token over plain `http` (except to the local machine).
- Accounts provisioned by SCIM for an organization or a project get a local name marked with it
  (`jdoe.o3`, `jdoe.p7`); existing accounts keep their name.

### Security

- **High** — An application named `%`, `_` or a single letter matched about every CVE and created
  one entry per CVE, filling the disk. Names are now matched literally, need two letters or
  digits, and a name matching more than 20,000 CVEs is refused; a project holds at most 10,000
  applications and 200,000 CVE entries, and four such scans run at once.
- **High** — A keyword search read every CVE description, and each concurrent request held a
  thread: a small burst exhausted memory. Keywords need three characters, four keyword searches
  run at once, and the server answers "busy" beyond 128 requests in flight. Request bodies are
  read under a time limit before a request counts.
- The secret target (webhook URL, topic) of a destination shared by the instance or an
  organization was shown to the projects using it.
- The owner of any organization could add an account without its consent, require two-step
  sign-in, and lock that account — an administrator included — out of everything.
- A project owner could make the instance send mail, under its sender address, to any
  recipient.
- Ten wrong passwords locked an account for everyone, its owner included; a username shaped like
  an internal counter could lock someone's second step. Failures are counted per client address
  and account, with a higher limit per account across all clients; a browser that already signed
  in to the account is not affected by that limit.
- Filling the table of failed sign-ins unlocked every account at once.
- Anyone could fill the table of pending SSO sign-ins and block SSO for ten minutes. Starting a
  sign-in is now counted per client, and a full table makes room.
- SCIM could re-enable an account an administrator had disabled.
- A SCIM token of a project could take a plain local username before its real holder.
- `vulnizard-collector` accepted an `http://` server and sent its token in clear.
- Secrets stored in the database (second-factor seeds, SMTP passwords, webhook URLs, SSO client
  secrets, Git tokens) are encrypted at rest.

### Hardening

- Pages are served with `Cache-Control: no-store`; the database files are readable by their owner
  only; a warning is logged when listening beyond the machine without HTTPS.
- A destination's own SMTP server is connected at the address that was checked.
- MCP over HTTP accepts a browser `Origin` only if it is the public URL of the instance, and tells
  assistants that tool results are data, not instructions.
- Five browsers per account for notifications, each called with a 5 s timeout.
- Accounts holding a role on the whole instance are listed in a project only to those who manage
  its members. (partly: adding a member still tells whether the username exists)
- Anyone can leave an organization they were added to.

### Not fixed in this release

- An account can still be locked for clients that never signed in to it (the API with a
  password, a new browser) by 100 wrong passwords in ten minutes from several addresses. Use API
  tokens for programs.
- Slow clients are not timed out by the server itself: run it behind a reverse proxy.
- The history of decisions is not append-only at the database level, and deleting an organization
  deletes its history (documented behaviour).
- ID token signature verification through JWKS — the token comes from the provider's token
  endpoint over TLS, which OpenID Connect accepts.

## 0.1.0

First release: web interface (projects, applications, triage, subscriptions, notifications,
evolution, audit, CVE database), sign-in (passwords, OpenID Connect, SCIM, authenticator app,
passkeys, recovery codes), MCP server, read-only REST API, Docker image and NixOS module.
Inventory collection is present as a preview, off by default.
