# Changelog

All notable changes to Vulnizard. Versions follow [semantic versioning](https://semver.org);
before 1.0, a minor version may change behaviour.

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
