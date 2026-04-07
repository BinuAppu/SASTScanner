# SAST Scanner

A self-hosted **Static Application Security Testing (SAST)** web platform built with Flask. Upload source code as a ZIP archive, run it through multiple open-source security engines simultaneously in the background, and receive deduplicated, severity-sorted findings with CWE/CVE references — versioned, fully reportable, and tracked across re-uploads.

---

## Features

| Capability | Details |
|---|---|
| **Multi-engine scanning** | Bandit · Semgrep (OWASP Top 10) · SecretsScanner · PatternScanner — all run in parallel |
| **Background scanning** | Scans run in a daemon thread; the UI updates automatically when complete |
| **Deduplication** | Cross-engine findings are fingerprinted and merged; the richest entry wins |
| **Version tracking** | Each re-upload creates a new version; findings are tagged `NEW` · `RECURRING` · `FIXED` |
| **Engine status panel** | Per-engine status, duration, version string, and finding count shown post-scan |
| **Reporting** | Download findings as **CSV**, interactive **HTML** (with charts), or **PDF** |
| **CWE / CVE tagging** | Every finding links to the MITRE CWE database and NVD |
| **Delete controls** | Delete an entire scan (all versions) or a single version from the UI |
| **Auth & settings** | Login-protected, default admin account, password reset in Settings |
| **Modern dark UI** | Sidebar navigation, severity-coloured badges, doughnut charts, filter/search |

---

## Screenshots

> Dashboard · Scan Detail · Engine Status · Report Download

*(Add screenshots to `docs/screenshots/` and reference them here)*

---

## Scanning Engines

| Engine | Language Coverage | What it detects |
|---|---|---|
| **Bandit** | Python | Insecure functions, weak crypto, shell injection, hardcoded secrets, debug flags |
| **Semgrep** | Python · JS · Java · PHP · Go · Ruby · C# · more | OWASP Top 10, SQL injection, XSS, secrets, command injection (community rulesets) |
| **SecretsScanner** | All text files | AWS keys, API tokens, JWTs, GitHub tokens, Stripe keys, private keys, DB URIs |
| **PatternScanner** | Python · JS · PHP · Java · Go · Ruby · C# | CSRF, rate-limit gaps, path traversal, insecure file upload, open redirect, XXE, SSRF, mass assignment, timing attacks, deprecated APIs |

---

## Tech Stack

- **Backend** — Python 3.10+, Flask 3, SQLite (via stdlib `sqlite3`)
- **Auth** — Werkzeug password hashing, Flask session cookies
- **Scanning** — Bandit, Semgrep, custom regex engines (no external services)
- **Reports** — ReportLab (PDF), Jinja2 (HTML), stdlib `csv`
- **Frontend** — Bootstrap-free custom CSS (dark theme), Chart.js, vanilla JS

---

## Requirements

- Python **3.10** or later
- `pip`
- Internet access on first run (Semgrep downloads community rulesets)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/SASTScanner.git
cd SASTScanner

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start the application
python app.py
```

Open your browser at **http://localhost:5000**

> The SQLite database (`sast_scanner.db`) and the `scans/` folder are created automatically on first run.

---

## Default Credentials

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `pass@123` |

**Change the password immediately** via **Settings → Change Password** after your first login.

---

## Project Structure

```
SASTScanner/
├── app.py                     # Flask application — routes, auth, upload handling
├── requirements.txt
│
├── models/
│   └── database.py            # SQLite schema, CRUD helpers, engine-result storage
│
├── scanner/
│   ├── aggregator.py          # Orchestrates all engines, dedup, sort, version compare
│   ├── bandit_scanner.py      # Bandit integration + CWE mapping
│   ├── semgrep_scanner.py     # Semgrep integration (multi-ruleset)
│   ├── secrets_scanner.py     # Regex-based secrets / credential scanner
│   └── pattern_scanner.py     # 30+ custom vulnerability pattern rules
│
├── reports/
│   ├── csv_report.py          # CSV export
│   ├── html_report.py         # Interactive HTML report with Chart.js
│   └── pdf_report.py          # PDF export via ReportLab
│
├── templates/                 # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── new_scan.html
│   ├── scan_detail.html
│   └── settings.html
│
├── static/
│   ├── css/style.css          # Dark-theme stylesheet
│   └── js/main.js
│
└── scans/                     # Auto-created; stores extracted source + reports
    └── <scan-name>/
        ├── v1/
        │   ├── source/        # Extracted ZIP contents
        │   └── reports/       # report.csv · report.html · report.pdf
        └── v2/
            └── ...
```

---

## How It Works

### 1 · Upload
Navigate to **New Scan**, enter a scan name, and upload a `.zip` of your source code (drag-and-drop or click to browse). The name acts as a project identifier — uploading again under the same name creates a new version.

### 2 · Background Scan
The server extracts the ZIP and immediately starts a background thread that runs all four engines sequentially, collecting raw findings from each.

### 3 · Aggregation
```
Raw findings (all engines)
  └─ Normalise severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
  └─ Assign fingerprint  sha256(file_path + vuln_id + tool)[:16]
  └─ Deduplicate         keep richest entry per fingerprint
  └─ Compare versions    tag each finding NEW / RECURRING / FIXED
  └─ Sort                severity → file → line number
```

### 4 · Reports
CSV, HTML (interactive charts), and PDF are generated and saved inside `scans/<name>/v<N>/reports/` immediately after the scan completes. They remain available for download at any time.

### 5 · Version Comparison
| Status | Meaning |
|---|---|
| `NEW` | Finding appears in this version but not the previous one |
| `RECURRING` | Finding was present in the previous version too |
| `FIXED` | Finding was in the previous version but is gone now |

---

## Findings Format

Every finding includes:

| Field | Example |
|---|---|
| Severity | `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` |
| File & Line | `src/app.py:42` |
| Vulnerability | `Flask Route Without CSRF Protection` |
| Description | Human-readable explanation |
| CWE | `CWE-352` (links to MITRE) |
| CVE | `CVE-2023-XXXXX` (links to NVD, when applicable) |
| Tool | `Bandit` · `Semgrep` · `SecretsScanner` · `PatternScanner` |
| Recommendation | Specific remediation advice |
| Code Snippet | Redacted where secrets are involved |
| Status | `NEW` · `RECURRING` · `FIXED` |

---

## Supported Languages

Python · JavaScript · TypeScript · Java · PHP · Ruby · Go · C# · Kotlin · Swift
*(coverage varies by engine; Semgrep provides the widest multi-language support)*

---

## Configuration

| Environment Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET` | `sast-scanner-secret-key-2024-change-me` | Flask session signing key — **set this in production** |
| `PORT` | `5000` | Listening port (pass via `flask run --port`) |

> For production, set `FLASK_SECRET` to a long random string and run behind a reverse proxy (nginx / Caddy) with TLS.

---

## Security Notes

- All scan artefacts stay on your server — no code is sent to external services (except Semgrep downloading public rulesets on first use).
- Uploaded ZIPs are extracted with zip-slip protection (malicious `../` paths are discarded).
- Passwords are stored as Werkzeug `pbkdf2:sha256` hashes — never in plain text.
- The default secret key **must** be overridden via the `FLASK_SECRET` environment variable before exposing the app to a network.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Bandit](https://github.com/PyCQA/bandit) — PyCQA
- [Semgrep](https://semgrep.dev) — Semgrep Inc.
- [ReportLab](https://www.reportlab.com) — PDF generation
- [Chart.js](https://www.chartjs.org) — in-browser charting
- [Inter](https://rsms.me/inter/) & [JetBrains Mono](https://www.jetbrains.com/lp/mono/) — typefaces
