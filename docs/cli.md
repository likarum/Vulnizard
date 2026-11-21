# Command line

## Installation from source

```bash
# Clone the repository
git clone https://github.com/likarum/Vulnizard.git
cd Vulnizard

# Build release binary
cargo build --release

# Binary will be at ./target/release/vulnizard
```

## Synchronize CVE data

```bash
# Sync all sources (NVD, CISA KEV, EPSS) with 2 years of history
vulnizard sync

# Sync with custom history depth
vulnizard sync --years 1

# Sync only a specific source
vulnizard sync --source nvd
vulnizard sync --source cisa_kev
vulnizard sync --source epss
```

## Search CVEs

```bash
# Search all CVEs (sorted by most recent)
vulnizard search

# Search by keyword
vulnizard search "apache"

# Filter by minimum CVSS score
vulnizard search --min-cvss 9.0

# Filter by minimum EPSS score
vulnizard search --min-epss 0.5

# Show only Known Exploited Vulnerabilities
vulnizard search --kev

# Filter by vendor
vulnizard search --vendor microsoft

# Combine filters
vulnizard search --kev --min-cvss 8.0 --limit 50

# Output as JSON
vulnizard search --kev --format json

# Sort by different criteria
vulnizard search --sort cvss      # by CVSS score
vulnizard search --sort epss      # by EPSS score
vulnizard search --sort published # by publication date (default)
vulnizard search --sort modified  # by modification date
```

## View CVE details

```bash
vulnizard info CVE-2024-1234
```

## Database statistics

```bash
vulnizard stats
```

## Example output

```
$ vulnizard search --kev --limit 5

CVE ID             CVSS     EPSS   KEV  Published Description
----------------------------------------------------------------------------------------------------
CVE-2026-1281       9.8        -   YES 2026-01-29 A code injection in Ivanti Endpoint Manager Mob...
CVE-2026-24858      9.8        -   YES 2026-01-27 An Authentication Bypass Using an Alternate Pat...
CVE-2026-21509      7.8        -   YES 2026-01-26 Reliance on untrusted inputs in a security deci...
CVE-2026-23760      9.8        -   YES 2026-01-22 SmarterTools SmarterMail versions prior to buil...
CVE-2026-20045      8.2        -   YES 2026-01-21 A vulnerability in Cisco Unified Communications...
```

---
[← Back to the README](../README.md)
