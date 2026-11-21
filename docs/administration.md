# Administration, users and sign-in

## Administration

Administrators manage the instance from the *Admin* menu; settings saved there override the
configuration file and apply without restart.

- **Vulnerability sources**: enable or disable NVD, CISA KEV, EPSS, Vulnrichment, OSV, Exploit-DB and
  Metasploit; see the last run of each and sync one on demand — the page shows which sources are
  waiting, running or done, and refreshes until the sync ends; set the sync interval and the NVD API key
- **Notifications**, in three tabs: *Enabled per project* (every rule of the instance: test, disable,
  delete), *Destinations* (every destination, of the instance, an organization or a project) and
  *Delivery* (whether targets may be on a private network). Whoever starts a manual sync is told when
  it ends. **Browser notifications** use Web Push: enable them per browser in *Settings*
  (requires HTTPS, or localhost)
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

---
[← Back to the README](../README.md)
