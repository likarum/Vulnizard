# Plan: Enrichissement multi-sources

## Objectif
Enrichir les CVE existantes avec des données complémentaires, pas dupliquer.

## Données actuelles

```
CVE
├── Identité: cve_id, description, published_at, modified_at
├── Scoring: cvss_v3_score, cvss_v3_vector, epss_score, epss_percentile
├── Classification: cwe_ids
├── Impact: affected_products (vendor, product, version, cpe)
├── Références: references (url, source, tags)
└── Exploitation: kev_known_exploited, kev_date_added
```

## Nouveaux champs à ajouter

```rust
pub struct Cve {
    // ... existant ...

    // Exploitation (enrichissement)
    pub exploit_public: bool,              // ExploitDB, PacketStorm
    pub exploit_urls: Vec<String>,         // Liens vers exploits
    pub metasploit_module: Option<String>, // Nom du module MSF
    pub nuclei_template: Option<String>,   // Template Nuclei disponible

    // Packages (enrichissement OSV/GitHub)
    pub affected_packages: Vec<AffectedPackage>,  // npm, pip, go, etc.

    // Contexte décisionnel (Vulnrichment)
    pub ssvc_decision: Option<String>,     // Track, Attend, Act
    pub stakeholder_actions: Vec<String>,  // Actions recommandées
}

pub struct AffectedPackage {
    pub ecosystem: String,      // npm, pip, go, maven, cargo, etc.
    pub name: String,           // Nom du package
    pub vulnerable_range: String, // >=1.0.0 <2.0.0
    pub fixed_version: Option<String>,
}
```

---

## Sources à intégrer (par priorité)

### Priorité 1: Exploitabilité (valeur immédiate)

#### 1.1 ExploitDB
- **URL**: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
- **Données**: exploit_public=true, exploit_urls
- **Matching**: CVE ID dans le CSV
- **Difficulté**: Facile (CSV ~50MB)

#### 1.2 Nuclei Templates
- **URL**: https://github.com/projectdiscovery/nuclei-templates
- **Données**: nuclei_template (nom du template)
- **Matching**: CVE ID dans les fichiers YAML
- **Difficulté**: Moyen (clone Git + parse YAML)

#### 1.3 Metasploit Modules
- **URL**: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json
- **Données**: metasploit_module (nom du module)
- **Matching**: CVE ID dans references
- **Difficulté**: Facile (JSON ~5MB)

### Priorité 2: Packages écosystème

#### 2.1 OSV (Open Source Vulnerabilities)
- **URL**: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
- **Écosystèmes**: npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems
- **Données**: affected_packages (ecosystem, name, ranges, fixed)
- **Matching**: aliases[] contient CVE ID
- **Difficulté**: Facile (JSON dans ZIP)

#### 2.2 GitHub Security Advisories
- **URL**: API GraphQL https://api.github.com/graphql
- **Données**: affected_packages + severity GitHub
- **Matching**: identifiers[].value = CVE ID
- **Difficulté**: Moyen (GraphQL, rate limit, token requis)
- **Note**: OSV inclut déjà GHSA, donc peut être redondant

### Priorité 3: Contexte décisionnel

#### 3.1 CISA Vulnrichment
- **URL**: https://github.com/cisagov/vulnrichment (repo Git)
- **Données**: ssvc_decision, stakeholder_actions, CWEs additionnels
- **Matching**: CVE ID = nom de fichier
- **Difficulté**: Moyen (clone Git + parse JSON)

---

## Plan d'implémentation

### Phase 1: Exploits publics (semaine 1)

```
src/sources/
├── exploitdb.rs    # NOUVEAU
└── metasploit.rs   # NOUVEAU
```

**ExploitDB** (~2h)
1. Télécharger CSV files_exploits.csv
2. Parser, extraire CVE → exploit mapping
3. Enrichir: `exploit_public = true`, `exploit_urls.push()`

**Metasploit** (~1h)
1. Télécharger modules_metadata_base.json
2. Parser, extraire CVE → module mapping
3. Enrichir: `metasploit_module = Some("exploit/...")`

**Résultat**: Nouveau flag de recherche `--has-exploit`

### Phase 2: Packages OSV (semaine 2)

```
src/sources/
└── osv.rs          # NOUVEAU
```

**OSV** (~3h)
1. Télécharger ZIPs par écosystème (npm, PyPI, Go prioritaires)
2. Parser JSON, extraire CVE → packages mapping
3. Enrichir: `affected_packages.push()`

**Résultat**: Nouveau filtre `--ecosystem npm` ou `--package lodash`

### Phase 3: Templates & Contexte (semaine 3)

```
src/sources/
├── nuclei.rs       # NOUVEAU
└── vulnrichment.rs # NOUVEAU
```

**Nuclei** (~2h)
1. Clone shallow du repo templates
2. Grep CVE-* dans les fichiers YAML
3. Enrichir: `nuclei_template = Some("cves/2024/CVE-2024-1234.yaml")`

**Vulnrichment** (~2h)
1. Clone shallow du repo
2. Parser JSON par CVE
3. Enrichir: `ssvc_decision`, CWEs additionnels

---

## Modifications DB

```sql
ALTER TABLE cves ADD COLUMN exploit_public INTEGER DEFAULT 0;
ALTER TABLE cves ADD COLUMN exploit_urls TEXT DEFAULT '[]';
ALTER TABLE cves ADD COLUMN metasploit_module TEXT;
ALTER TABLE cves ADD COLUMN nuclei_template TEXT;
ALTER TABLE cves ADD COLUMN ssvc_decision TEXT;

CREATE TABLE affected_packages (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    vulnerable_range TEXT,
    fixed_version TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE INDEX idx_pkg_ecosystem ON affected_packages(ecosystem);
CREATE INDEX idx_pkg_name ON affected_packages(name);
```

---

## Nouvelles commandes

```bash
# Sync enrichissement
cargo run sync --source exploitdb
cargo run sync --source metasploit
cargo run sync --source osv
cargo run sync --source nuclei
cargo run sync --source vulnrichment

# Recherche enrichie
cargo run search --has-exploit          # CVEs avec exploit public
cargo run search --has-metasploit       # CVEs avec module MSF
cargo run search --ecosystem npm        # CVEs affectant npm
cargo run search --package lodash       # CVEs affectant lodash
```

---

## Affichage enrichi

```
cargo run info CVE-2024-1234

CVE-2024-1234
=============
Description: ...

Scores:
  CVSS v3: 9.8
  EPSS:    0.97 (99th percentile)

⚠️  KNOWN EXPLOITED (CISA KEV)
🔴 EXPLOIT PUBLIC                    # NOUVEAU
   - https://exploit-db.com/exploits/12345
   - Metasploit: exploit/multi/http/...
   - Nuclei: cves/2024/CVE-2024-1234.yaml

Affected Products (CPE):
  - vendor:product (1.0 - 2.0)

Affected Packages:                    # NOUVEAU
  - npm: lodash <4.17.21 (fixed: 4.17.21)
  - pip: requests <2.28.0

SSVC Decision: Act                    # NOUVEAU
```

---

## Ordre d'implémentation recommandé

| # | Source | Valeur ajoutée | Effort |
|---|--------|---------------|--------|
| 1 | ExploitDB | Exploits publics | 2h |
| 2 | Metasploit | Modules MSF | 1h |
| 3 | OSV (npm, pip, go) | Packages vulnérables | 3h |
| 4 | Nuclei | Templates de scan | 2h |
| 5 | Vulnrichment | Contexte SSVC | 2h |
| 6 | GitHub Advisories | (skip si OSV suffit) | - |

**Total estimé: ~10h de dev**
