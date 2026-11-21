# Disclaimer

Read this before relying on Vulnizard for anything that matters.

## Why it exists

Vulnizard started from a personal need: follow the vulnerabilities of a small infrastructure with
something light in memory, self-hosted, and without paying extra for single sign-on. It is built
for that need first. Whether it fits yours is for you to judge.

## How this project is written

Most of the code, tests and documentation of Vulnizard were written by an AI coding assistant
(Claude Code), directed and reviewed by a human maintainer. The security reviews done so far were
also carried out with AI assistance. **No independent human security audit has taken place.**
Treat the code accordingly: read it before you trust it.

## No warranty, no liability

Vulnizard is provided "as is", without warranty of any kind, as stated in the [license](LICENSE).
The authors and contributors accept **no responsibility** for any damage, loss, missed
vulnerability, wrong decision, data loss or security incident arising from its use. You use it
entirely at your own risk.

## Do not expose it to the Internet

Vulnizard holds sensitive information: what you run, in which versions, which vulnerabilities are
still open and which risks you accepted. Run it on a trusted network, behind a VPN or an
authenticating reverse proxy with HTTPS. Exposing it directly to the Internet is not recommended.

## The data can be wrong, late or incomplete

- Vulnerability data comes from third parties (NVD, CISA KEV, EPSS, CISA Vulnrichment, OSV and
  others). Vulnizard does not verify it and inherits its errors, gaps and delays.
- Matching a product and a version to a CVE is approximate. There are false positives and, more
  importantly, **false negatives: no CVE listed does not mean not vulnerable.**
- Scores (CVSS, EPSS, SSVC) are indicators, not a risk assessment of your environment.

Vulnizard helps you follow vulnerabilities. It does not replace a patching policy, a vulnerability
scanner, a penetration test or professional security advice.

## Not tested at scale

No load or scale test has been done. Vulnizard has only run on small instances: a few users, a few
dozen applications, a few hundred thousand CVEs.

It stores everything in one SQLite file, on one machine. What this is expected to mean, untested:

- **Reading** is not the concern: many users can browse at the same time.
- **Writing happens one at a time.** While a synchronization imports data, other changes wait
  their turn, and many people deciding at the same moment would queue behind each other.
- **One machine only**: no replication, no failover, no spreading over several servers. If the
  machine is down, the service is down; the backup is a copy of the file.
- **Large inventories** (thousands of applications or components per project) and **large
  histories** have not been measured: pages and rescans may become slow.

If you need many concurrent writers or high availability, this is the wrong tool as it stands.

## Not everything was tested for real

Several features were only exercised by automated tests or against stand-ins written for the
purpose, never against the real thing. In particular, some features need an account at a
third-party service that the maintainer does not have: single sign-on with a real identity
provider (Google, Microsoft Entra ID, Okta…), SCIM provisioning, Slack, a real mail provider,
browser push services. They are written from the specifications and may not work as they are.

The wiki keeps an honest, feature-by-feature list:
[What has been tested](https://github.com/likarum/Vulnizard/wiki/What-has-been-tested).

## Early software

This is pre-release software. Features, configuration and the database schema may change without
notice or migration path between versions. Back up the database before every upgrade.

## Third parties

- This product uses the NVD API but is not endorsed or certified by the NVD.
- Vulnizard is an independent project. It is not affiliated with, or endorsed by, CISA, FIRST,
  MITRE, NIST, Debian, any other data provider, or any other vulnerability management product. Each source has its own terms of use, which
  remain yours to respect.
