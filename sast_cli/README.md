# sastscan — Open-Source SAST Scanner

A multi-module **Static Application Security Testing (SAST)** scanner that analyses source code archives for security vulnerabilities, hardcoded secrets, misconfigurations, and malware patterns — with optional **AI-powered analysis** for deeper insights and remediation suggestions.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [AI Analysis](#ai-analysis)
- [Output Structure](#output-structure)
- [Report](#report)
- [Examples](#examples)
- [Updating Tools & Rules](#updating-tools--rules)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

`sastscan` accepts a `.zip` file of your source code, extracts it into a timestamped workspace, runs up to **10 security modules** in sequence, writes per-module CSV reports, and produces a single self-contained **HTML dashboard** combining all findings.

```
sastscan --zip project.zip --name MyApp
```

Optionally, add `--useAI` to have an AI endpoint analyse the top findings and populate a dedicated **Suggestions tab** in the report.

```
sastscan --zip project.zip --name MyApp --useAI --encKey 'my-passphrase'
```

---

## Architecture

```
sast_cli/
├── sastscan              # Main scanner binary (bash)
├── install               # Installer / updater binary (bash)
└── lib/
    ├── generate_report.py  # HTML report generator (Python 3)
    └── ai_scan.py          # AI analysis module (Python 3)
```

All external tools are installed under `/opt/tools/SASTScanner/`:

```
/opt/tools/SASTScanner/
├── bin/                  # Binary tools (gitleaks, trivy, yara, ...)
├── venv/                 # Python virtualenv (semgrep, bandit, checkov)
├── rules/
│   ├── semgrep/          # Semgrep rule sets (git clone)
│   └── yara/             # YARA community rules (git clone)
├── dependency-check/     # OWASP Dependency Check
├── codeql/               # GitHub CodeQL bundle
└── lib/                  # Copied library files
```

The encrypted AI configuration is stored in the user's home directory:

```
~/.sastscan_ai_config     # AES-encrypted AI endpoint credentials
```

---

## Modules

| Module | Description | Language Support |
|---|---|---|
| **Semgrep** | Semantic pattern analysis | Python, JS/TS, Java, Go, Ruby, PHP, C/C++, and more |
| **Bandit** | Python-specific security linter | Python |
| **Pattern** | 32 built-in regex rules (SQLi, XSS, weak crypto, hardcoded creds, cloud keys) | All text-based files |
| **Secrets** | 30 secret patterns (AWS keys, GitHub tokens, JWTs, DB URIs, private keys) | All text-based files |
| **Gitleaks** | Secret detection across source files and git history | All |
| **Trivy** | Filesystem, dependency, and IaC vulnerability scanner | All |
| **Dependency Check** | OWASP CVE-based dependency vulnerability analysis | Java, .NET, JS, Python, Ruby |
| **Checkov** | Infrastructure-as-Code security scanner | Terraform, K8s, Dockerfile, CloudFormation, ARM |
| **CodeQL** | Deep semantic/dataflow analysis (auto-detects language) | Python, JavaScript, Java, Go |
| **YARA** | Malware and suspicious pattern matching using community rules | All binary and text files |

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Linux | Any modern distro | Ubuntu 20.04+, Debian 11+, RHEL 8+, Arch |
| Bash | 4.0+ | Pre-installed on all modern Linux |
| Python 3 | 3.8+ | Required for Bandit, Semgrep, Checkov, report generation |
| Java (JRE) | 11+ | Required for OWASP Dependency Check only |
| curl / wget | Any | For downloading tools during install |
| git | Any | For cloning rule repositories |
| unzip | Any | For extracting scan targets |
| Internet access | — | Required during `install`; offline scanning supported after install |

**Additional prerequisite for `--useAI` / `--ConfigureAI`:**

| Requirement | Notes |
|---|---|
| `cryptography` Python package | `pip3 install cryptography` — used to encrypt/decrypt AI credentials |
| AI endpoint access | Azure OpenAI or any OpenAI-compatible API |

> **Note:** The `install` script handles all tool dependencies automatically. The `cryptography` package must be installed separately if you intend to use AI features.

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-org/sastscan.git
cd sastscan
```

### Step 2 — (Recommended) Get a free NVD API key

The OWASP Dependency Check module downloads its vulnerability data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

| | Without API key | With API key |
|---|---|---|
| **Rate limit** | 5 requests / 30 seconds | 50 requests / 30 seconds |
| **Initial DB download** | 30 – 60 minutes | 2 – 5 minutes |
| **Daily update** | 5 – 15 minutes | < 1 minute |

1. Go to **<https://nvd.nist.gov/developers/request-an-api-key>**
2. Enter your email address and submit the form
3. Check your inbox — the key arrives within a few minutes
4. Copy the UUID key (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### Step 3 — Run the installer

The installer must be run as **root** (or with `sudo`) because it writes to `/opt/tools/SASTScanner/` and creates symlinks in `/usr/local/bin/`.

```bash
# Recommended — with NVD API key for fast DB download
sudo ./install --nvd-api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Without API key (works, but NVD download will take 30–60 minutes)
sudo ./install
```

The installer will:
1. Detect your OS (Debian/Ubuntu, RHEL/CentOS, Arch)
2. Install system packages (`python3`, `openjdk`, `curl`, `git`, `unzip`, `jq`, ...)
3. Create a Python virtualenv and install `semgrep`, `bandit`, and `checkov`
4. Download and install `gitleaks`, `trivy`, and `yara` binaries
5. Download the OWASP Dependency Check (~50 MB) and update the NVD database
6. Download the CodeQL CLI bundle (~500 MB)
7. Clone community Semgrep and YARA rule sets
8. Create `/usr/local/bin/sastscan` symlink for system-wide access

#### Installer options

| Flag | Description |
|---|---|
| `--nvd-api-key <key>` | NVD API key for fast vulnerability DB download (strongly recommended) |
| `--skip-codeql` | Skip CodeQL download (saves ~500 MB) |
| `--skip-depcheck` | Skip OWASP Dependency Check installation |
| `--tools-only` | Install tools only; skip rule/template downloads |
| `--update-rules` | Update rules and templates only (tools already installed) |

```bash
# Full install with NVD API key
sudo ./install --nvd-api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Minimal install — skip large optional downloads
sudo ./install --skip-codeql --skip-depcheck

# Refresh rules + NVD database (tools already installed)
sudo ./install --update-rules --nvd-api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Step 4 — Verify installation

```
  Tool                           Status
  ──────────────────────────     ──────────────────────
  semgrep                        INSTALLED
  bandit                         INSTALLED
  checkov                        INSTALLED
  gitleaks                       INSTALLED
  trivy                          INSTALLED
  yara                           INSTALLED
  dependency-check               INSTALLED
  codeql                         INSTALLED
  YARA rules                     1842 rules
  Semgrep rules                  3200 rules
```

```bash
sastscan --version
```

### Step 5 — (Optional) Install AI prerequisites

```bash
pip3 install cryptography
```

---

## Usage

```
sastscan --zip <file.zip> --name <ScanName> [options]
sastscan --ConfigureAI
```

### Flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--zip <path>` | `-z` | Path to the `.zip` archive to scan | **required** |
| `--name <name>` | `-n` | Name for this scan session | **required** |
| `--modules <list>` | `-m` | Comma-separated module names or `all` | `all` |
| `--verbose <bool>` | `-v` | Enable verbose output (`true` / `false`) | `true` |
| `--version` | | Print version and exit | |
| `--help` | `-h` | Print help and exit | |
| `--ConfigureAI` | | Interactive AI setup wizard (standalone) | |
| `--useAI` | | Enable AI-powered analysis after the scan | |
| `--encKey <key>` | | Passphrase to decrypt the AI configuration | |

### Available module names

```
semgrep  bandit  pattern  secrets  gitleaks  trivy  dependency_check  checkov  codeql  yara
```

---

## AI Analysis

`sastscan` can optionally send the top findings from a scan to an AI endpoint (Azure OpenAI or any OpenAI-compatible API) for deeper analysis and targeted fix suggestions.

### Step 1 — Configure AI credentials

Run the interactive setup wizard once. This stores your credentials encrypted on disk — the passphrase you choose is **never stored**; it is required only at scan time to decrypt the config.

```bash
sastscan --ConfigureAI
```

You will be prompted for:

| Field | Description |
|---|---|
| **URL** | Base endpoint URL (e.g. `https://my-resource.openai.azure.com`) |
| **modelName** | Deployment or model name (e.g. `gpt-4o`, `gpt-4`) |
| **apiVersion** | API version for Azure OpenAI (e.g. `2024-02-15-preview`); leave blank for non-Azure |
| **subscriptionKey** | API key / subscription key for the endpoint |
| **encKey** | Your chosen passphrase — used to encrypt the config file |

The encrypted configuration is saved to `~/.sastscan_ai_config` using **AES-128 Fernet** with a **PBKDF2-HMAC-SHA256** derived key (100,000 iterations, random 16-byte salt). The raw credentials are never stored in plaintext.

**Supported endpoint formats:**

| Type | Detection | Auth header |
|---|---|---|
| Azure OpenAI | `apiVersion` is non-empty | `api-key: <subscriptionKey>` |
| OpenAI-compatible | `apiVersion` is blank | `Authorization: Bearer <subscriptionKey>` |

### Step 2 — Run a scan with AI analysis

```bash
sastscan --zip myapp.zip --name MyApp --useAI --encKey 'my-secret-passphrase'
```

What happens during AI analysis:

1. `~/.sastscan_ai_config` is decrypted using the provided `--encKey`
2. All findings are loaded and sorted by severity
3. Up to **100 CRITICAL/HIGH/MEDIUM** findings are selected (INFO skipped)
4. They are sent to the AI endpoint in **batches of 8** to minimise API calls
5. The AI returns for each finding: a root-cause analysis, a specific code-level fix suggestion, and a risk score (1–10)
6. Results are written to `<ScanDir>/Report/ai_findings.csv`
7. The HTML report gains an **AI Suggestions** tab

### AI findings CSV format

```
OriginalModule, File, Line, Severity, RuleID, Category, Title,
OriginalDescription, CWE, OriginalRecommendation,
AIAnalysis, AISuggestion, AIRiskScore
```

---

## Output Structure

Every scan creates a timestamped directory in the **current working directory**:

```
<ScanName>_YYYY-MM-DD_HH-MM-SS/
├── Extracted/                  # Contents of the zip file
├── Report/
│   ├── semgrep.csv             # Per-module findings (CSV)
│   ├── bandit.csv
│   ├── pattern.csv
│   ├── secrets.csv
│   ├── gitleaks.csv
│   ├── trivy.csv
│   ├── dependency_check.csv
│   ├── checkov.csv
│   ├── codeql.csv
│   ├── yara.csv
│   ├── ai_findings.csv         # AI analysis results (only with --useAI)
│   └── report.html             # Combined HTML dashboard
└── Debug/
    ├── error.txt               # Aggregated error / debug log
    └── <module>_raw.*          # Raw tool output (JSON, SARIF, etc.)
```

### Standard CSV format

Every module CSV shares the same header:

```
Module, File, Line, Severity, RuleID, Category, Title, Description, CWE, Recommendation
```

Severity values: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

---

## Report

After all modules complete, `sastscan` automatically invokes `lib/generate_report.py` to combine all CSVs into a single `report.html` file. Open it in any modern browser — no server needed.

```bash
xdg-open MyApp_2026-05-03_12-00-00/Report/report.html
```

### Tab navigation

The report uses a three-tab layout:

| Tab | Always shown | Description |
|---|---|---|
| **Overview** | Yes | Severity summary cards, charts, module breakdown, top files, top CWEs |
| **All Findings** | Yes | Full findings table with search, sort, and filters |
| **AI Suggestions** | Only with `--useAI` | AI-generated analysis and fix suggestions per finding |

### Overview tab

- **Severity summary cards** — total count per severity level plus a duplicate count card
- **Doughnut chart** — findings by severity
- **Horizontal bar chart** — findings by module
- **Module breakdown table** — count and share per module
- **Top affected files** — up to 15 files with the most findings
- **Top CWEs** — up to 10 most frequent weakness categories

### All Findings tab

- Full findings table sorted by severity (most critical first)
- **Duplicate detection** — findings with the same file + line + rule are automatically tagged:
  - First occurrence: shown normally (`ORIGINAL`)
  - Subsequent occurrences: shown with a purple **DUPLICATE** badge at reduced opacity
- **Hide / Show Duplicates** toggle button to suppress duplicate rows
- Column sorting — click any table header
- Full-text search across file path, rule ID, and description
- Severity filter dropdown
- Per-module filter buttons

### AI Suggestions tab *(visible only when `--useAI` is used)*

- AI analysis and fix suggestion for each prioritised finding
- Colour-coded **risk score badge** (1–10 scale):
  - Red — 8–10 (critical risk)
  - Orange — 6–7 (high risk)
  - Amber — 4–5 (medium risk)
  - Green — 1–3 (low risk)
- Full-text search and severity filter
- Disclaimer banner reminding that results are AI-generated and require human review

---

## Examples

### Scan everything

```bash
sastscan --zip myproject.zip --name MyProject
```

### Run specific modules only

```bash
sastscan -z app.zip -n WebApp --modules semgrep,bandit,secrets,pattern
```

### Suppress verbose output

```bash
sastscan --zip code.zip --name API --verbose false
```

### Scan only for IaC issues

```bash
sastscan -z infra.zip -n InfraAudit --modules checkov,trivy
```

### Scan for secrets and credentials only

```bash
sastscan -z repo.zip -n SecretScan --modules secrets,gitleaks,pattern
```

### Set up AI analysis (one-time)

```bash
sastscan --ConfigureAI
```

### Run a full scan with AI analysis

```bash
sastscan --zip myapp.zip --name MyApp --useAI --encKey 'my-secret-passphrase'
```

### AI analysis on specific modules only

```bash
sastscan -z app.zip -n MyApp \
  --modules semgrep,bandit,pattern,secrets \
  --useAI --encKey 'my-secret-passphrase'
```

### Run from a different directory

```bash
/opt/tools/SASTScanner/sastscan --zip /data/uploads/project.zip --name CI_Scan
```

---

## Updating Tools & Rules

### Update rules and templates only (no reinstall)

```bash
sudo ./install --update-rules
```

This re-clones / pulls the latest:
- Semgrep rule sets from `semgrep/semgrep-rules`
- YARA rules from `Yara-Rules/rules` and `Neo23x0/signature-base`

### Update all tools to latest versions

```bash
sudo ./install
```

The installer is idempotent — running it again upgrades everything in place.

### Update Trivy vulnerability database

```bash
/opt/tools/SASTScanner/bin/trivy image --download-db-only
```

### Update OWASP NVD database

```bash
# With NVD API key (fast — recommended)
sudo ./install --update-rules --nvd-api-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Or call dependency-check directly
/opt/tools/SASTScanner/dependency-check/bin/dependency-check.sh \
    --updateonly --nvdApiKey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Without API key (rate-limited, slow)
/opt/tools/SASTScanner/dependency-check/bin/dependency-check.sh --updateonly
```

### Re-configure AI credentials

Simply re-run the wizard. It will overwrite the existing `~/.sastscan_ai_config`:

```bash
sastscan --ConfigureAI
```

---

## Troubleshooting

### "Tool not found" warnings during scan

Run the installer first:

```bash
sudo ./install
```

### Permission denied on install

The installer requires root to write to `/opt/tools/` and `/usr/local/bin/`:

```bash
sudo ./install
```

### Scan exits with "Failed to extract ZIP"

- Ensure the file is a valid `.zip` archive (not `.tar.gz`, `.rar`, etc.)
- Install `unzip` if missing: `sudo apt-get install unzip`

### CodeQL database creation fails

CodeQL requires the source code to be compilable. If auto-detection fails, the module is skipped gracefully and logged in `Debug/error.txt`.

### HTML report not generated

Ensure `python3` is available and `lib/generate_report.py` exists:

```bash
python3 --version
ls lib/generate_report.py
```

### AI analysis fails — "cryptography package required"

```bash
pip3 install cryptography
```

### AI analysis fails — "Decryption failed — wrong encKey"

The passphrase provided with `--encKey` does not match the one used during `--ConfigureAI`. Re-run the configuration wizard to create a new encrypted config with a known passphrase:

```bash
sastscan --ConfigureAI
```

### AI analysis fails — network / API errors

- Verify the URL, model name, and API version set during `--ConfigureAI`
- Check that the subscription key has not expired or been revoked
- Confirm the endpoint is reachable from the machine running `sastscan`
- Partial results are still written to `ai_findings.csv` if some batches succeeded

### Viewing errors from a scan

```bash
cat <ScanName>_<datetime>/Debug/error.txt
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Contributions, issues, and pull requests are welcome.
