# Administration, users and sign-in

## Administration

Administrators manage the instance from the *Admin* menu; settings saved there override the
configuration file and apply without restart.

- **Vulnerability sources**: enable or disable NVD, CISA KEV, EPSS, Vulnrichment, OSV, Exploit-DB,
  Metasploit and Nuclei templates; see the last run of each and sync one on demand — the page shows which sources are
  waiting, running or done, and refreshes until the sync ends; set the sync interval and the NVD API key
- **Notifications**, in three tabs: *Per project* (for each project, the destinations receiving its
  notifications, with a test), *Destinations* (every destination, of the instance, an
  organization or a project) and *Delivery* (whether targets may be on a private network).
  What a destination belongs to decides what it receives, by itself: a destination of the
  **instance** gets the notifications of every project, one of an **organization** those of its
  projects, one of a **project** those of that project. No project has to pick it. The **gear** of
  a destination opens what it sends: the event types (all checked on a new destination), a minimum
  CVSS (none by default), enabled or not, and for a destination of the instance the instance
  events (a manual synchronization finished)
- **Deadlines**: the remediation delays, in days from the detection of an entry: one per severity
  (critical 7, high 30, medium 90, low 180 by default) and one for the CVEs known to be exploited
  (CISA KEV, 14), which applies when it is shorter than the delay of the severity. A CVE without a
  score follows the medium delay. Each is a whole number of days from 1 to 3650. The **owners of an
  organization** may replace any of them for its projects, on the page of the organization
  (*Remediation deadlines*): a field left empty follows the instance, and keeps following it when
  the instance changes. Deadlines are computed when they are read, from the severity the CVE has
  then: changing a delay applies at once to every entry still to review. Every change, of the
  instance or of an organization, is written to the security log with its author
- **MCP**: turn on the MCP endpoint of the server, choose whether assistants may modify data, and see
  the list of tools
- **Users** and **Single sign-on**: see below

## Users, roles and single sign-on

- **Administrators** manage the instance and its accounts in *Admin → Users*: create (the form asks
  for the rights at once), disable/enable, reset passwords, act on several users at a time. A disabled
  account loses its sessions, API tokens and logins at once; the last enabled administrator cannot be removed.
- **Rights exist at three levels** — the whole instance, an organization (all its projects) or a single
  project — with the same three roles; the highest one applies:

  | Role | Read | Decide on CVEs | Manage applications, subscriptions, notifications, inventory | Manage members, delete |
  |---|---|---|---|---|
  | owner | ✓ | ✓ | ✓ | ✓ |
  | editor | ✓ | ✓ | ✓ | |
  | viewer | ✓ | | | |

  A right on one project gives nothing outside it: its holder does not see the other projects of the
  organization, and a project owner only manages the members of that project.

  The decision history (audit) is append-only and survives the deletion of a project; only deleting
  the whole organization removes it.

- **SSO (OpenID Connect)**: any number of providers, added by an administrator in
  *Admin → Single sign-on* — your own identity provider (Pocket-ID, Keycloak, Authentik, Entra ID…)
  or a public one such as Google or GitLab.com. Each provider gets a button on the login page and
  its own redirect URI, `<web.base_url>/auth/oidc/<identifier>/callback`.
  - Accounts are created at the first sign-in (optional), administrators can follow a provider group.
  - **Allowed email domains** restrict who may sign in (verified emails only); they are mandatory
    to create accounts from a public provider, where anybody can register.
  - An existing local account is only linked when asked (exact `preferred_username`, never an
    administrator or disabled account).
  - SSO sessions last 12 hours: a change at the provider applies at the next sign-in, and does not
    revoke API tokens or a local password — disable the account in *Admin → Users* to cut access at once.
  - A provider belongs to the **instance**, an **organization** or a **project**, with a default role
    given at the first sign-in. Accounts coming from a scoped provider can only hold rights inside that
    scope and can never be administrators.
  - A provider can also be declared in the configuration file (`[oidc]`, see `config.example.toml`).

- **SCIM 2.0** (`<web.base_url>/scim/v2`): your identity provider creates, updates and deactivates
  accounts and groups (Users, Groups, PATCH, filters, pagination). Tokens are created in
  *Admin → Single sign-on → Provisioning* and are scoped like providers; a group is given a role on
  the instance, an organization or a project.

Projects created with the CLI (`vulnizard project …`) live in the `default`
organization, which administrators can open from the UI.

Security defaults: the server listens on loopback only, self-registration is
off (`web.allow_registration`), webhooks cannot target private addresses
(`web.allow_private_webhooks`), logins are throttled per username, and changing
a password revokes sessions and API tokens.

Behind a reverse proxy with HTTPS, set `web.secure_cookies = true` and
`web.base_url`; the proxy must forward the original `Host` header.

## Passwords

- A new password has **at least 15 characters** (NIST SP 800-63B rev. 4, for a password that may
  be the only factor). There is no composition rule and no expiry.
- Passwords that are guessed first are refused whatever their length: the same few characters
  repeated, the alphabet or a keyboard row, very common words with digits around them
  (`passwordpassword1`), and the username with little else. The check is a built-in list of
  common words and a few rules; it runs offline and is not a database of leaked passwords.
- The rules apply when a password is chosen (setup, registration, change, creation or reset by an
  administrator, command line). Passwords chosen before stay valid until they are changed.
- **There is no password reset by email.** A lost password is reset by an administrator
  (*Admin → Users*) or on the server with `vulnizard user passwd <name>`; for the only
  administrator, the command line is the only way.

## Two-step sign-in

Accounts that sign in with a password can add a second step (*Settings → Two-step sign-in*):

- an **authenticator app** (TOTP codes), set up by scanning a QR code;
- **passkeys and security keys** (WebAuthn), as many as needed. A passkey also **signs in on its
  own** from the login page, without username or password: it requires the device and its PIN or
  biometrics, so it counts for both steps. Old security keys that cannot store accounts only serve
  as second step;
- ten single-use **recovery codes**, given with the first factor and renewable.

It can be **required**:

- for the **whole instance** (*Admin → Users*): an account without a second factor can do nothing
  but set one up, and cannot remove its last one;
- for **one organization** (its page, by whoever manages its members and has a second factor
  themselves): members without a second factor cannot open that organization — web, API and MCP
  alike — while the rest of their account keeps working. Anyone can leave an organization they
  were added to.

- Passkeys are bound to the host of `web.base_url`: browsers only allow them over HTTPS (or on
  `localhost`), never on a bare IP address. Otherwise only the authenticator app is offered.
- Accounts that only sign in through SSO are not concerned: their second step belongs to the
  identity provider.
- API tokens are not asked for a second step, but creating one asks for the password again.
  Signing in to the API with a password (HTTP Basic) is refused once a second factor is set or
  required by the instance.
- Wrong passwords are counted per client address: someone failing on purpose locks themselves
  out, not the account's owner. Behind a reverse proxy, make it send `X-Forwarded-For`.
- Lost device and no recovery code: an administrator resets the account from its page, or
  `vulnizard user reset-mfa <username>` on the server.
- Every change is recorded (*Admin → Security log*, and on the account's own page): factor set up or
  removed, recovery codes generated or used, lock after too many wrong answers, reset, change of
  the requirement. Entries cannot be changed or removed.

## Logs that show tampering

Two logs are chained: the **security log** (one chain for the instance) and the **audit of
decisions** (one chain per organization). Each entry stores a hash of its content and of the
previous entry, so changing, removing or reordering an entry breaks the chain from there on. The
pages (*Admin → Security log*, and an organization's page) say whether the chain is intact.

Both export as **signed JSON** — from the page, from the API (`/api/security-log`,
`/api/organizations/{org}/audit`) — and as CSV for reading. The JSON carries every entry, the last
hash and a signature by a key of the instance. Anyone can check it, offline:

```bash
vulnizard log verify vulnizard-security-log-2026-11-21.json --key 9960a4d6b9b1ce90
```

The key fingerprint is the one the page shows. The check fails if a field was changed, an entry
removed or inserted, the order changed, or if another key signed.

**What this proves, and what it does not.** It proves that an export is what the instance signed
and that nothing was altered in between. It does not protect against whoever controls the server:
they hold the signing key and could rewrite a log and sign it again. The defence is to **keep
exports elsewhere** (or have them fetched regularly through the API): a later export must begin
with the same entries and the same hashes, and a rewrite shows as soon as two exports disagree.
Deleting an organization deletes its audit.

---
[← Back to the README](../README.md)
