# Changelog

All notable changes to Vulnizard. Versions follow [semantic versioning](https://semver.org);
before 1.0, a minor version may change behaviour.

## Unreleased

### Fixed

- An OSV advisory was dropped whole when one of its entries named no package and only gave
  commit ranges, as the OSV format allows (#107). Its other packages are read again.

## 0.3.1

### Fixed

- **"database is locked" and an error 500 once per sync cycle** (#99). At the end of a cycle
  the catalog of vendors and products was counted again inside one writing transaction,
  which held the database for as long as the count lasted (30 seconds and more on a modest
  machine): a request that had to write during it gave up. The count is now done aside and
  only the differences are written, which takes a fraction of a second.
- MCP `get_state_at` stopped at 500 entries without saying so (#104). It answers one page
  (`entries`, 100 by default) with `total`, `offset` and `limit`.
- **The address of a webhook or of an ntfy topic was shown in the lists of destinations**
  (#105), although it is a secret. Pages now show the service only (`https://host/…`).

## 0.3.0

### Added

- **Remediation deadlines** (#68). A delay in days per CVSS severity (critical 7, high 30,
  medium 90, low 180 by default) and one for exploited CVEs (CISA KEV, 14), which wins when
  it is shorter; a CVE without a score follows the medium delay. Set for the instance in
  Administration → Deadlines; the owners of an organization may replace any of them for its
  projects. The clock starts when the entry is detected and any decision (closed, not
  applicable, accepted risk) stops it. The Vulnerabilities view has a sortable "Due" column
  and an "Overdue" filter. MCP `list_watchlist` and the new REST
  `GET /api/organizations/{org}/projects/{project}/watchlist` give `due_at`, `days_left`
  and `overdue_days`, and can list the overdue entries only. Schema v29, automatic.
- **Invitations** (#10). Adding a member to an organization or a project by name no longer
  grants a role at once, and no longer says whether the name exists: it records an
  invitation, valid 14 days, which the person accepts or declines after signing in (a mark in
  the header, a section in Settings). An account created after the invitation can never take
  it. Changing the role of someone already in the list still applies at once, and so do the
  rights given from Administration → Users. Schema v30, automatic.

- **An "Overdue" view** (#77): the vulnerabilities past their deadline by application
  (number, average and worst lateness, each row opening the list narrowed to it), by week of
  detection and of deadline, and their number day by day, to tell a batch that arrived at
  once from a period without triage. The Vulnerabilities list can be narrowed by application
  and by severity.
- **History: open vulnerabilities by severity, day by day** (#69), stacked, with the accepted
  risks as a separate line; the severity is the one each CVE has today. MCP `get_evolution`
  gives the same breakdown per day.
- **An "executive" role** (#79), below viewer: it reads the Overview of what it holds (an
  organization, a project or the whole instance) and nothing else. Vulnerabilities,
  applications, history, audit, settings, the CVE database, every other page, API endpoint
  and MCP tool refuse it; `get_summary` and the summary endpoints are what it may call. It is
  given where the other roles are. An account that also holds viewer or more somewhere
  keeps, there, what that role gives. Schema v31, automatic.
- **Slack: the form gives the way to the webhook address** (#102): a link that opens Slack
  with the app already described (name, incoming webhooks on), the steps that follow, and
  the logo as a PNG to upload as the app's icon. Slack takes the name and the icon of a
  webhook from the app, not from the messages.
- MCP `get_summary` and REST `GET /api/summary` (and `…/projects/{project}/summary`): the
  figures of the Overview, without any CVE or application name.

### Changed

- **The Overview shows figures only** (#75): open vulnerabilities and overdue ones, by
  severity; average and worst lateness of the overdue ones; average time to resolve, by
  severity, over the last 30, 90 or 365 days. "Resolved" is any decision (closed, not
  applicable, accepted risk), counted from the detection. Each count opens the list behind
  it. The charts moved to History, which now follows the day shown; "To review first" and
  "Latest changes" are gone from the Overview (they are the Vulnerabilities list in its
  default order, and "Changes on subscribed products" in History).
- **An organization that requires two-step sign-in holds its members to it.** A member
  without a second factor used to keep the rest of their account and only lose that
  organization; they now can do nothing but set one up once signed in, as when the instance
  requires it. They can no longer leave the organization instead.
- A KEV or NVD answer that lacks a field Vulnizard does not use is no longer refused (#11).

## 0.2.6

The sources are asked for much less. With the default settings an instance downloaded about
800 MB a day; it now downloads a few hundred kilobytes on an ordinary day.

### Changed

- **OSV: only the advisories that changed are fetched.** Each of the five ecosystems was
  downloaded whole every 12 hours (about 290 MB in all). The whole archives are now read
  once; after that a run reads the top of the list of changed advisories that OSV publishes
  and fetches those only (a few to a few hundred small files). The archives are read again
  once a month, when more than 2,000 advisories changed at once, and on `sync --full`.
  **The first run after the upgrade reads the archives once** (schema v25, automatic).
- **A file that did not change is not downloaded again.** KEV, EPSS, Exploit-DB, Metasploit,
  Nuclei and the Debian advisories send back the fingerprint and the date the server gave
  last time; a server that still has the same file answers with nothing. This holds for
  "Sync now" too. Such a run shows as "unchanged upstream, nothing downloaded". After an
  upgrade each file is read once more, since a release may read it differently.
- EPSS is asked once a day instead of twice: it is published once a day.
- **The sources page says how often each source downloads, and what.** It said "enabled
  sources are synchronized at every cycle", which is only true of the NVD. Each source now
  shows its delay and what one download fetches, and the page warns that "Sync now" does not
  wait for that delay.
- The sources announce the real version (`vulnizard/0.2.6`) instead of `vulnizard/0.1`.
- **"To review" is now "Vulnerabilities".** The view shows every tracked vulnerability, not
  only those to review; "To review" remains its default filter. The old address
  (`view=review`) still works.
- **"Evolution" is now "History", and going back in time is visible.** The view says that a
  day of a chart is a link, a day shows as one under the pointer, and a card gives the day
  shown, with previous and next day, a date field, and, on a past day, a "Past state" mark
  and a way back to today. The old address (`view=evolution`) still works.
- **Administration → Users: the actions on the checked users are a toolbar above the list**,
  greyed out until a user is checked. Without JavaScript they stay usable and the server
  refuses an action without a selection, as before.
- Colours of the severity badges and tags were adjusted for contrast (the "medium" badge was
  white on amber, 2.8:1; it is now 8.3:1), in every theme, by day and by night.
- **A destination of the instance receives the notifications of every project, by itself**
  (#95); one of an organization, those of its projects. No project has to pick it any more.
  What it sends (event types, minimum CVSS, instance events, enabled or not) is set on the
  destination, behind the gear in Administration → Notifications → Destinations; a new
  destination has everything checked. Projects no longer see or set these destinations.
  **At the upgrade every existing destination of the instance or of an organization starts
  receiving everything for every project it covers**, and the per-project choices that
  pointed at it are discarded: review them with the gear. A destination with no event
  checked sends nothing (it used to mean "all"). Schema v27, automatic, no way back
  without a backup.
- **Project settings: notifications are one table** (#96), one destination of the project
  per row, one checkbox per event type and the minimum CVSS, saved together. A project
  destination that notified nothing before stays silent.
- MCP `list_notifications`: each entry carries its `scope`; destinations of the instance and
  of organizations are listed to instance administrators only.
- **Sources page: how often a source downloads and what** is in a bubble opened by a small
  "i" (pointer, keyboard, touch) instead of a paragraph under "enabled" (#94).

### Removed

- **Browser notifications (Web Push) are removed** (#101): the destination type, the
  "Browser notifications" box of the settings, the service worker and the `web.push_contact`
  option (ignored if still set). **At the upgrade the destinations of that type are deleted**
  with the registered browsers (schema v28, automatic, no way back without a backup).
  E-mail, ntfy, Slack and webhook destinations are unchanged. Whoever starts a manual sync
  is no longer told personally when it ends; destinations that receive instance events are.

### Added

- **An organization menu in the "My products" bar** (#97), for an account that sees
  projects of several organizations: it narrows the project menu and every "All projects"
  view to one organization. It only narrows what the account already sees.
- **A "+" button adds an application or a subscription from the page.** It sits at the top
  of the Applications and Subscriptions views and opens the form in place, without
  JavaScript too. On "All projects" the form asks for the project, among those the user may
  manage; the right is checked on the server for the project received. An empty list of
  subscriptions now says what a subscription is and how it differs from a tracked
  application.
- **Colour themes and a day/night button**, in the header of every page: Classic, Forest,
  Plum, Sand, Dracula, Nord, Noctis and High contrast. The choice is kept by the browser; without one, day or night
  follows the system. Without JavaScript the page is Classic and follows the system.

### Fixed

- **Withdrawn advisories were still counted.** An advisory that OSV marks as withdrawn kept
  giving its packages and versions to its CVE. On a real database this removes or corrects
  about 300 package entries, among them packages wrongly shown as affected in every version.
- **Packages of another ecosystem were filed under the wrong one.** An advisory that names
  an npm package and a Maven package was read with the npm archive and both were recorded as
  npm packages (about 1,500 entries on a real database, some from ecosystems that are not
  followed at all). Each package is now recorded with its own ecosystem only.
- An ecosystem of OSV that could not be read no longer passes silently: the run is recorded
  as failed, names the ecosystem, and the next cycle reads it again from the same point.
- **"Added" counted every CVE a run read** (#82). A run showed "174 added, 0 updated" when
  most of these CVEs were already known, and KEV, EPSS, Exploit-DB, Metasploit and Nuclei
  showed the size of their whole file as "added" each time. A run now counts apart the CVEs
  it made known, those of which something changed, and those it read again and found as
  they were, in the history of runs, on the sources page and in the logs. A CVE found as it
  was is no longer written again. Runs recorded before the upgrade keep their old figures
  (schema v26, automatic). Vulnrichment counted as "added" the CVEs it could not find.
- **Reading the KEV catalog replaced the description the NVD gave** (#92) with the catalog's
  own wording, every time, and recorded it as a change of the CVE; the NVD then put its text
  back at the next modification. The catalog now describes only a CVE nobody described yet.
  CVEs of the catalog already stored keep the catalog's wording until the NVD modifies them
  or the history is read again (`sync --source nvd --full`).
- A failed run now records the cause of the failure, not only "cannot fetch <source>".
- **The vulnerabilities list was wider than the window** (#90): at 1280 px on "All projects"
  the page was 1463 px wide and the action buttons were cut. Both lists (to review, decided)
  now fit any width; long names wrap or are cut with the full text under the pointer.
- **"Used by: 0 of 3 projects available to all"** (#87) is gone: the list of destinations
  says what each one covers and what it sends.
- **Other lists were wider than the window between 760 and 1200 px** (#93): applications,
  history, audit, project settings, CVE list, and most administration pages. No page scrolls
  sideways any more. Eight lists with many columns (history, audit, recent syncs, users,
  notifications of all projects, destinations, sign-in providers, inventory sources) scroll
  inside their own box below about 1000 px. Columns now have set widths, so tables look
  somewhat different on wide screens too.
- Action buttons of a list are aligned to the right, as the pages always asked.
- **After an upgrade a page could run with the scripts of the release before** for an hour.
  Scripts and the stylesheet are now checked at each use.
- **"database is locked" and an error 500 during a synchronization** (#99). An operation
  that read and then wrote was refused at once when the synchronization had written in
  between. Such operations now wait their turn.
- MCP `get_audit_log` without a filter returned the accepted risks only, which looked like
  an empty log (#100). It returns every decision; `decision: accepted` keeps the former
  answer.

## 0.2.5

### Changed

- MCP: the answers of every tool are written as compact JSON instead of indented JSON. Same
  content, about a quarter lighter: a default page of `list_watchlist` was still heavy for a
  client.

### Fixed

- MCP: a `limit` or an `offset` out of bounds on `list_watchlist` and `get_audit_log` is
  refused, with the bounds in the message. It was silently brought back within them
  (`limit: 0` gave one item, `limit: 501` gave 500), so the caller believed it got what it
  asked for.
- MCP: the `application` filter of `list_watchlist` matches the name whatever its case
  (`Tinyauth` found nothing for `tinyauth`).

## 0.2.4

### Changed

- **On a phone, a table is one card per row.** Below 760 px tables no longer scroll sideways
  inside their box, which hid most columns and squeezed long texts into rows several screens
  tall: each row is a card, its short cells on shared lines, each named after its column, and
  the list to review puts the score beside the CVE. Without JavaScript the cards are shown
  without the column names. The desktop layout is unchanged.
- **MCP: `list_watchlist` and `get_audit_log` answer one page.** Both returned everything at
  once (a few hundred events were more than a client could read) as a bare list. They now
  return `{ total, offset, limit, entries }` (`events` for the audit log), 50 entries or 100
  events by default and 500 at most, with `limit` and `offset` to go through the rest; in the
  list, a CVE description is cut after 200 characters (`get_cve` gives it whole). **A client that
  read the bare list must read `entries` / `events` instead.** `list_watchlist` can also be
  limited to one `application`.
- **MCP: `list_watchlist` names the organization, not an account.** Each entry carried a
  `username` field holding the account that created the project. It is replaced by
  `organization`, the organization the project belongs to.

### Added

- MCP: `database_status` gives the `version` of the software and the `schema_version` of the
  database, so that a client can check an upgrade.
- MCP: each event of `get_audit_log` carries the `version` of the application and its kind
  (`event`); with `event: detected`, `removed` or `all` the log also lists the entries a scan
  added and those that left with their application.
- MCP: `list_applications` says where each application comes from (`source`: `manual` or
  `inventory`).

### Fixed

- On a phone, the notification settings of a project were wider than the screen: a list of
  destinations with a long name, and the group of event checkboxes, made the form as wide as
  their content. A field no longer widens its form, and each checkbox sits on one line with
  its text (on a desktop too).
- A refused call to the API or to MCP over HTTP (401) announced HTTP Basic only. It now
  announces `Bearer` first, then `Basic`: a token is the way meant for programs, and the only
  one left once the account has a second factor.

## 0.2.3

### Fixed

- **An advisory that names a fix was read as "no fix".** When several entries of an advisory
  name the same package, their ranges are put one after the other (`>=0 <X >=0`); the last one
  made the whole advisory say "affected, no fix", which since 0.2.1 wins over "up to 5.0.2
  included" of the NVD. CVEs fixed long before came back to review.
- **Go pseudo-versions are no longer compared with versions.** A fix given as
  `1.0.1-20260311144920-9eb2d33064b7` names a commit and says nothing of where the releases
  stand: 5.2.0 was "after" it and 0.9 "before" it, both by accident. A fix named this way now
  counts as a fix whatever the version: the application is not matched, unless another source
  places its version in an affected range. An application older than that commit is therefore
  not alerted by such an advisory alone.

## 0.2.2

### Fixed

- **The *update* field of a CPE was ignored**: the NVD writes sudo 1.9.17p2 as `sudo:1.9.17:p2`,
  and only `1.9.17` was compared. An application on 1.9.17p2 did not match a CVE listing that
  exact CPE (missed alert), and an application on 5.16.9 matched a flaw of `5.16:rc1` only
  (false alert). The whole version is now compared. No new import is needed.
- **The priority of an entry now follows the score of its CVE.** It was computed once, when the
  entry was created: an entry created before the CVE had a CVSS score stayed "low". It is
  recomputed at every scan.

## 0.2.1

### Fixed

- **"Up to 5.2 included" no longer wins over an advisory saying no fix exists.** Since 0.2.0 a
  source that gives versions decides against one that says "every version". An included end
  names the last version known to be affected, not a fix (the NVD often writes the latest
  release of the day there): it is still enough when nothing else is said, but an application
  past it is kept when a package advisory declares the package affected without a fix. The entry
  is marked *version not given*. An excluded end ("before 5.2"), which names the fix, decides as
  before.
- **A vendor also matches its `<name>_project` form.** The NVD names many vendors that way
  (`sudo_project`) where the CISA KEV catalog writes `sudo`: an application declared with the
  vendor `sudo` only saw the KEV records.

## 0.2.0

### Things to know before upgrading

- The database moves to schema v24 at first start (the existing log entries are chained, version
  ranges record whether their bounds are included). Back it up first; an older version does not
  open it afterwards.
- **The first synchronization after the upgrade reads the whole history of the NVD again**: about
  half an hour without an NVD API key, a few minutes with one, during which the other sources
  wait. It goes on where it stopped if it is interrupted. An instance installed with the former
  default only knew the last six months of the NVD: expect many applications to get their first
  matches (no notification is sent for them: notifications follow subscriptions, not
  tracked applications). `sync.history_months` limits the history again (0, the
  new default, reads everything).
- **An application now matches the product of its exact name** (case and separators aside), no
  longer every product whose name contains it: `nginx` no longer matches `ingress-nginx` or
  `nginxui`. When the vendor is given, the products of that vendor named after the application
  count too (`nginx_open_source`, `nginx_plus` for `nginx` of `f5`): give the vendor, or declare
  such a variant as an application of its own. The vendor is no longer a part of a name either:
  give it as the CVE database writes it (`f5`, not `f5 networks`).
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
- **Entries kept without a version are marked.** When no source gives the versions a CVE
  affects (`*` or `-` in the NVD, an advisory without a range), the application is still matched
  out of caution; the entry now says *version not given* in the lists to review, and
  `version_unknown` in MCP `list_watchlist`: read the CVE before deciding. The mark goes when a
  source gives the versions.
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
  included; the NVD is read again once to fill it in.
- **Product names were matched as substrings**: `docker` matched `mailcow-dockerized`, `podman`
  matched `podman_desktop`. The product is now the application itself, case and separators aside
  (`home_assistant` now matches `home-assistant`, which it did not); with a vendor, the products
  of that vendor named after it are kept (`nginx_open_source` for `nginx`). The vendor is
  compared the same way: `openssl` is not `openssl.js_project`.
- **A source that gives versions now wins over one that says "every version".** For one CVE, the
  NVD and a package advisory often disagree: one gives a range, the other was left at "all
  versions, no fix" or gives no version at all. The precise one decides; "every version" only
  matches when no source says more. A Go module of an earlier major line that was fixed counts
  as fixed for the lines that followed.
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
