#!/usr/bin/env python3
"""
sastscan HTML Report Generator
Reads all CSV reports from the Report directory and produces a rich HTML report
with duplicate detection, tab navigation, and (optionally) an AI Suggestions tab.
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from collections import defaultdict

# ─── Parse CLI ────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Generate HTML report from sastscan CSV results")
    p.add_argument("--report-dir", required=True,  help="Path to the Report/ directory")
    p.add_argument("--scan-name",  required=True,  help="Scan name")
    p.add_argument("--scan-dir",   required=True,  help="Root scan directory")
    p.add_argument("--use-ai",     action="store_true", default=False,
                   help="Include AI Suggestions tab")
    p.add_argument("--ai-csv",     default="",
                   help="Path to ai_findings.csv produced by ai_scan.py")
    return p.parse_args()

# ─── Read CSVs ────────────────────────────────────────────────────────────────

def read_csv_reports(report_dir: str) -> list:
    findings = []
    for fname in sorted(os.listdir(report_dir)):
        if not fname.endswith(".csv") or fname == "ai_findings.csv":
            continue
        fpath = os.path.join(report_dir, fname)
        try:
            with open(fpath, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    row = {k.strip(): v.strip() for k, v in row.items() if k}
                    if "Module" in row and "Severity" in row:
                        findings.append(row)
        except Exception as exc:
            print(f"Warning: could not read {fpath}: {exc}", file=sys.stderr)
    return findings


def read_ai_csv(ai_csv_path: str) -> list:
    ai_findings = []
    if not ai_csv_path or not os.path.isfile(ai_csv_path):
        return ai_findings
    try:
        with open(ai_csv_path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                row = {k.strip(): v.strip() for k, v in row.items() if k}
                if "OriginalModule" in row or "AIAnalysis" in row:
                    ai_findings.append(row)
    except Exception as exc:
        print(f"Warning: could not read AI CSV {ai_csv_path}: {exc}", file=sys.stderr)
    return ai_findings

# ─── Duplicate detection ──────────────────────────────────────────────────────

def _dup_key(f: dict):
    """Composite key used to identify duplicate findings across modules."""
    file    = f.get("File",   "").lower().strip()
    line    = f.get("Line",   "").strip()
    rule_id = f.get("RuleID", "").lower().strip()
    title   = f.get("Title",  "").lower().strip()[:50]

    if rule_id and line:
        return (file, line, rule_id)
    if line:
        return (file, line, title)
    return (file, title)


def mark_duplicates(findings: list) -> list:
    """
    Tag each finding with IsDuplicate = 'ORIGINAL' or 'DUPLICATE'.
    The first occurrence of a key is the original; subsequent ones are duplicates.
    Duplicates are kept in the list — only marked, never removed.
    """
    seen: dict = {}
    for f in findings:
        key = _dup_key(f)
        if key in seen:
            f["IsDuplicate"]  = "DUPLICATE"
            f["DuplicateOf"]  = seen[key]
        else:
            f["IsDuplicate"]  = "ORIGINAL"
            f["DuplicateOf"]  = ""
            seen[key] = f"{f.get('Module','')}:{f.get('RuleID','')}"
    return findings

# ─── Stats helpers ────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "INFO":     "#0284c7",
}
SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f7fee7",
    "INFO":     "#f0f9ff",
}

def normalise_sev(raw: str) -> str:
    r = (raw or "INFO").upper().strip()
    return r if r in SEV_ORDER else "INFO"


def compute_stats(findings: list) -> dict:
    sev_counts    = defaultdict(int)
    module_counts = defaultdict(int)
    file_counts   = defaultdict(int)
    cat_counts    = defaultdict(int)
    cwe_counts    = defaultdict(int)
    dup_count     = 0

    for f in findings:
        sev  = normalise_sev(f.get("Severity", "INFO"))
        mod  = f.get("Module",   "Unknown")
        file = f.get("File",     "")
        cat  = f.get("Category", "unknown")
        cwe  = f.get("CWE",      "")

        sev_counts[sev]    += 1
        module_counts[mod] += 1
        if file:
            file_counts[file] += 1
        if cat:
            cat_counts[cat] += 1
        for c in (cwe or "").split(","):
            c = c.strip()
            if c:
                cwe_counts[c] += 1
        if f.get("IsDuplicate") == "DUPLICATE":
            dup_count += 1

    return {
        "total":        len(findings),
        "duplicates":   dup_count,
        "originals":    len(findings) - dup_count,
        "by_severity":  dict(sev_counts),
        "by_module":    dict(module_counts),
        "by_file":      dict(file_counts),
        "by_category":  dict(cat_counts),
        "by_cwe":       dict(cwe_counts),
        "top_files":    sorted(file_counts.items(), key=lambda x: -x[1])[:15],
        "top_cwes":     sorted(cwe_counts.items(), key=lambda x: -x[1])[:10],
    }

# ─── HTML escaping ────────────────────────────────────────────────────────────

def esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def sev_badge(sev: str) -> str:
    sev   = normalise_sev(sev)
    color = SEV_COLOR.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def dup_badge(is_dup: str) -> str:
    if is_dup == "DUPLICATE":
        return '<span class="dup-badge">DUPLICATE</span>'
    return ""

# ─── HTML builder ─────────────────────────────────────────────────────────────

def build_html(scan_name: str, scan_dir: str, findings: list,
               stats: dict, ai_findings: list, use_ai: bool) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Chart data ──
    sev_labels = json.dumps([s for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if s in stats["by_severity"]])
    sev_data   = json.dumps([stats["by_severity"].get(s,0) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if s in stats["by_severity"]])
    sev_colors = json.dumps([SEV_COLOR.get(s,"#ccc") for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if s in stats["by_severity"]])
    mod_labels = json.dumps(list(stats["by_module"].keys()))
    mod_data   = json.dumps(list(stats["by_module"].values()))

    # ── Findings table rows ──
    rows_html = []
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(normalise_sev(x.get("Severity","INFO")), 99)):
        sev     = normalise_sev(f.get("Severity","INFO"))
        is_dup  = f.get("IsDuplicate", "ORIGINAL")
        dup_cls = "dup-row" if is_dup == "DUPLICATE" else ""
        rows_html.append(f"""
        <tr class="finding-row {dup_cls}" data-sev="{sev}" data-module="{esc(f.get('Module',''))}" data-dup="{is_dup}">
          <td>{sev_badge(sev)}</td>
          <td><span class="module-tag">{esc(f.get('Module',''))}</span></td>
          <td class="code-cell" title="{esc(f.get('File',''))}">{esc(f.get('File',''))}</td>
          <td class="center">{esc(f.get('Line',''))}</td>
          <td><code class="rule-id">{esc(f.get('RuleID',''))}</code></td>
          <td>{esc(f.get('Title',''))} {dup_badge(is_dup)}</td>
          <td class="desc-cell">{esc(f.get('Description',''))}</td>
          <td><span class="cwe">{esc(f.get('CWE',''))}</span></td>
          <td class="rec-cell">{esc(f.get('Recommendation',''))}</td>
        </tr>""")
    rows_str = "\n".join(rows_html)

    # ── Severity summary cards ──
    sev_cards = []
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = stats["by_severity"].get(sev, 0)
        if cnt == 0:
            continue
        color = SEV_COLOR[sev]
        bg    = SEV_BG[sev]
        sev_cards.append(f"""
        <div class="stat-card" style="border-left:4px solid {color};background:{bg}">
          <div class="stat-num" style="color:{color}">{cnt}</div>
          <div class="stat-label">{sev}</div>
        </div>""")

    # ── Duplicate summary card ──
    dup_card = ""
    if stats["duplicates"] > 0:
        dup_card = f"""
        <div class="stat-card" style="border-left:4px solid #a855f7;background:#1e1b4b">
          <div class="stat-num" style="color:#c084fc">{stats['duplicates']}</div>
          <div class="stat-label">Duplicates</div>
        </div>"""

    # ── Module summary rows ──
    mod_rows = []
    for mod, cnt in sorted(stats["by_module"].items(), key=lambda x: -x[1]):
        pct = int(cnt / stats["total"] * 100) if stats["total"] else 0
        mod_rows.append(f"""
        <tr>
          <td><span class="module-tag">{esc(mod)}</span></td>
          <td class="center"><strong>{cnt}</strong></td>
          <td>
            <div class="prog-bar-wrap">
              <div class="prog-bar" style="width:{pct}%"></div>
            </div>
          </td>
        </tr>""")
    mod_rows_str = "\n".join(mod_rows)

    # ── Top files ──
    top_file_rows = "".join(
        f'<tr><td class="code-cell" title="{esc(fp)}">{esc(fp)}</td>'
        f'<td class="center"><strong>{cnt}</strong></td></tr>'
        for fp, cnt in stats["top_files"]
    )

    # ── Top CWEs ──
    top_cwe_rows = "".join(
        f'<tr><td><code>{esc(cwe)}</code></td><td class="center">{cnt}</td></tr>'
        for cwe, cnt in stats["top_cwes"]
    )

    # ── Module filter buttons ──
    modules = sorted(stats["by_module"].keys())
    mod_filters = " ".join(
        f'<button class="filter-btn" onclick="filterModule(\'{m}\')">{esc(m)}</button>'
        for m in modules
    )

    # ── AI Suggestions tab content ──
    ai_tab_btn = ""
    ai_tab_panel = ""
    if use_ai:
        ai_tab_btn = '<button class="tab-btn" id="tab-btn-suggestions" onclick="showTab(\'suggestions\', this)">&#x1F916; AI Suggestions</button>'

        sug_rows = []
        for a in ai_findings:
            sev      = normalise_sev(a.get("Severity", "INFO"))
            risk_raw = a.get("AIRiskScore", "")
            try:
                risk_int = int(risk_raw)
                risk_color = ("#dc2626" if risk_int >= 8 else
                              "#ea580c" if risk_int >= 6 else
                              "#d97706" if risk_int >= 4 else "#65a30d")
                risk_badge = f'<span class="risk-score" style="background:{risk_color}">{risk_int}/10</span>'
            except (ValueError, TypeError):
                risk_badge = ""

            sug_rows.append(f"""
            <tr class="sug-row" data-sev="{sev}">
              <td>{sev_badge(sev)}</td>
              <td><span class="module-tag">{esc(a.get('OriginalModule',''))}</span></td>
              <td class="code-cell" title="{esc(a.get('File',''))}">{esc(a.get('File',''))}</td>
              <td class="center">{esc(a.get('Line',''))}</td>
              <td>{esc(a.get('Title',''))}</td>
              <td class="ai-cell">{esc(a.get('AIAnalysis',''))}</td>
              <td class="ai-cell">{esc(a.get('AISuggestion',''))}</td>
              <td class="center">{risk_badge}</td>
            </tr>""")
        sug_rows_str = "\n".join(sug_rows)

        ai_tab_panel = f"""
  <!-- ── Tab: AI Suggestions ── -->
  <div id="tab-suggestions" class="tab-panel" style="display:none">
    <section>
      <div class="ai-banner">
        &#x1F916; AI analysis performed on <strong>{len(ai_findings)}</strong> finding(s)
        &nbsp;&mdash;&nbsp; results are AI-generated and should be reviewed by a human expert.
      </div>
      <div class="filter-bar" style="margin-top:1rem">
        <input type="text" id="sugSearchBox" placeholder="&#x1F50D;  Search suggestions…" oninput="applyAiFilters()"/>
        <select class="sev-select" id="sugSevFilter" onchange="applyAiFilters()">
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>
      <div class="table-wrap">
        <table id="suggestionsTable">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Module</th>
              <th>File</th>
              <th>Line</th>
              <th>Finding</th>
              <th>AI Analysis</th>
              <th>AI Suggestion</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody id="suggestionsBody">
{sug_rows_str}
          </tbody>
        </table>
        <div id="sugNoResults" class="no-results" style="display:none">&#x1F50D; No suggestions match your filters.</div>
      </div>
      <div id="sugVisibleCount" style="color:var(--muted);font-size:.8rem;margin-top:.5rem;padding:.25rem 1rem"></div>
    </section>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>SAST Report &ndash; {esc(scan_name)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #0f172a; --surface: #1e293b; --surface2: #273548;
      --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
      --accent: #38bdf8; --green: #4ade80; --red: #f87171;
    }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}
    a {{ color: var(--accent); text-decoration: none; }}

    /* ── Header ── */
    .header {{ background: linear-gradient(135deg,#1e3a5f 0%,#0f172a 100%); padding: 2rem 2.5rem; border-bottom: 1px solid var(--border); }}
    .header h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
    .header h1 span {{ color: var(--accent); }}
    .header-meta {{ display: flex; gap: 2rem; margin-top: .75rem; color: var(--muted); font-size:.85rem; flex-wrap: wrap; }}
    .header-meta b {{ color: var(--text); }}

    /* ── Tabs ── */
    .tab-nav {{
      display: flex; gap: 0; border-bottom: 2px solid var(--border);
      background: var(--surface); padding: 0 2.5rem;
    }}
    .tab-btn {{
      background: none; border: none; color: var(--muted);
      padding: .85rem 1.5rem; font-size: .9rem; font-weight: 600;
      cursor: pointer; border-bottom: 3px solid transparent; margin-bottom: -2px;
      transition: color .15s, border-color .15s;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}

    /* ── Layout ── */
    .container {{ max-width: 1600px; margin: 0 auto; padding: 2rem 2.5rem; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
    .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }}
    @media(max-width:900px) {{ .grid-2,.grid-3 {{ grid-template-columns: 1fr; }} }}

    /* ── Cards ── */
    .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }}
    .card h2 {{ font-size:1rem; font-weight:600; color: var(--muted); text-transform:uppercase; letter-spacing:.05em; margin-bottom:1rem; }}
    .stat-cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
    .stat-card {{ flex: 1; min-width: 120px; padding: 1.25rem 1.5rem; border-radius: 10px; }}
    .stat-num  {{ font-size: 2.25rem; font-weight: 800; line-height: 1; }}
    .stat-label{{ font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing:.08em; color: var(--muted); margin-top:.3rem; }}

    /* ── Charts ── */
    .chart-wrap {{ position: relative; height: 260px; }}

    /* ── Table ── */
    .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); margin-top: 1.5rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .83rem; }}
    thead th {{
      background: var(--surface2); color: var(--muted); font-weight: 600;
      text-transform: uppercase; font-size: .72rem; letter-spacing:.06em;
      padding: .75rem 1rem; border-bottom: 1px solid var(--border);
      position: sticky; top: 0; white-space: nowrap; cursor: pointer;
    }}
    thead th:hover {{ color: var(--accent); }}
    tbody tr {{ border-bottom: 1px solid var(--border); transition: background .15s; }}
    tbody tr:hover {{ background: var(--surface2); }}
    tbody td {{ padding: .65rem 1rem; vertical-align: top; }}

    /* ── Duplicate rows ── */
    .dup-row {{ opacity: 0.55; }}
    .dup-row.dup-visible {{ opacity: 1; }}
    .dup-badge {{
      display: inline-block; padding: .1rem .4rem; border-radius: 4px;
      font-size: .65rem; font-weight: 700; color: #c084fc;
      background: rgba(168,85,247,.15); border: 1px solid rgba(168,85,247,.35);
      vertical-align: middle; margin-left: .35rem;
    }}

    /* ── Badges ── */
    .badge {{
      display: inline-block; padding: .2rem .55rem; border-radius: 9999px;
      font-size: .7rem; font-weight: 700; color: #fff; white-space: nowrap;
    }}
    .module-tag {{
      display: inline-block; background: var(--surface2); color: var(--accent);
      padding: .15rem .5rem; border-radius: 6px; font-size: .72rem; font-weight: 600;
    }}
    .rule-id {{ color: var(--accent); font-size: .75rem; }}
    .cwe {{ color: #a78bfa; font-size: .75rem; }}
    .center {{ text-align: center; }}
    .code-cell {{ font-family: monospace; font-size: .78rem; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #93c5fd; }}
    .desc-cell {{ max-width: 320px; }}
    .rec-cell  {{ max-width: 240px; color: var(--muted); font-size: .78rem; }}
    .ai-cell   {{ max-width: 300px; font-size: .8rem; color: #d1fae5; }}
    .risk-score {{
      display: inline-block; padding: .2rem .55rem; border-radius: 9999px;
      font-size: .75rem; font-weight: 700; color: #fff;
    }}

    /* ── AI Banner ── */
    .ai-banner {{
      background: linear-gradient(90deg,#0c4a6e,#0f172a);
      border: 1px solid #0369a1; border-radius: 10px;
      padding: .9rem 1.25rem; color: #7dd3fc; font-size: .88rem;
    }}

    /* ── Progress bar ── */
    .prog-bar-wrap {{ background: var(--surface2); border-radius: 4px; height: 8px; min-width: 80px; }}
    .prog-bar {{ background: var(--accent); height: 8px; border-radius: 4px; transition: width .3s; }}

    /* ── Filters & Search ── */
    .filter-bar {{ display: flex; gap: .75rem; flex-wrap: wrap; align-items: center; margin-bottom: 1rem; }}
    .filter-bar input {{
      flex: 1; min-width: 200px; background: var(--surface2); border: 1px solid var(--border);
      color: var(--text); border-radius: 8px; padding: .5rem 1rem; font-size: .85rem; outline: none;
    }}
    .filter-bar input:focus {{ border-color: var(--accent); }}
    .filter-btn {{
      background: var(--surface2); border: 1px solid var(--border); color: var(--muted);
      padding: .35rem .85rem; border-radius: 20px; font-size: .75rem; cursor: pointer;
      transition: all .15s;
    }}
    .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
    .dup-toggle {{
      background: rgba(168,85,247,.15); border: 1px solid rgba(168,85,247,.4); color: #c084fc;
      padding: .35rem .85rem; border-radius: 20px; font-size: .75rem; cursor: pointer;
      transition: all .15s;
    }}
    .dup-toggle.hiding {{ background: rgba(168,85,247,.35); }}
    .sev-select {{
      background: var(--surface2); border: 1px solid var(--border); color: var(--text);
      padding: .45rem .75rem; border-radius: 8px; font-size: .82rem; cursor: pointer;
    }}

    /* ── No results ── */
    .no-results {{ text-align: center; padding: 3rem; color: var(--muted); }}

    /* ── Footer ── */
    .footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: .8rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
    .footer a {{ color: var(--accent); }}

    /* ── Section spacing ── */
    section {{ margin-bottom: 2rem; }}
    section h3 {{ font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; color: var(--text); }}
  </style>
</head>
<body>

<!-- ── Header ── -->
<div class="header">
  <h1>&#x1F6E1; SAST Report &mdash; <span>{esc(scan_name)}</span></h1>
  <div class="header-meta">
    <span><b>Generated:</b> {now}</span>
    <span><b>Workspace:</b> {esc(scan_dir)}</span>
    <span><b>Total Findings:</b> {stats['total']}</span>
    <span><b>Duplicates:</b> {stats['duplicates']}</span>
    <span><b>Modules:</b> {len(stats['by_module'])}</span>
  </div>
</div>

<!-- ── Tab Navigation ── -->
<div class="tab-nav">
  <button class="tab-btn active" id="tab-btn-overview"  onclick="showTab('overview',  this)">Overview</button>
  <button class="tab-btn"        id="tab-btn-findings"  onclick="showTab('findings',  this)">All Findings ({stats['total']})</button>
  {ai_tab_btn}
</div>

<div class="container">

  <!-- ── Tab: Overview ── -->
  <div id="tab-overview" class="tab-panel active">

    <!-- Severity Summary Cards -->
    <section>
      <h3>Severity Summary</h3>
      <div class="stat-cards">
        <div class="stat-card" style="border-left:4px solid #6366f1;background:#1e1b4b;min-width:140px">
          <div class="stat-num" style="color:#818cf8">{stats['total']}</div>
          <div class="stat-label">Total Findings</div>
        </div>
        {''.join(sev_cards)}
        {dup_card}
      </div>
    </section>

    <!-- Charts -->
    <section>
      <div class="grid-2">
        <div class="card">
          <h2>Findings by Severity</h2>
          <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
        </div>
        <div class="card">
          <h2>Findings by Module</h2>
          <div class="chart-wrap"><canvas id="modChart"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Module breakdown + Top files + Top CWEs -->
    <section>
      <div class="grid-3">
        <div class="card">
          <h2>Module Breakdown</h2>
          <div class="table-wrap" style="border:none">
            <table>
              <thead><tr><th>Module</th><th>Count</th><th>Share</th></tr></thead>
              <tbody>{mod_rows_str}</tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <h2>Top Affected Files</h2>
          <div class="table-wrap" style="border:none">
            <table>
              <thead><tr><th>File</th><th>Findings</th></tr></thead>
              <tbody>{top_file_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <h2>Top CWEs</h2>
          <div class="table-wrap" style="border:none">
            <table>
              <thead><tr><th>CWE</th><th>Count</th></tr></thead>
              <tbody>{top_cwe_rows}</tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

  </div><!-- /tab-overview -->

  <!-- ── Tab: Findings ── -->
  <div id="tab-findings" class="tab-panel" style="display:none">
    <section>
      <h3>All Findings</h3>
      <div class="filter-bar">
        <input type="text" id="searchBox" placeholder="&#x1F50D;  Search findings (file, rule, description)…" oninput="applyFilters()"/>
        <select class="sev-select" id="sevFilter" onchange="applyFilters()">
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
        <button class="filter-btn active" onclick="filterModule('')"  id="btn-all">All Modules</button>
        {mod_filters}
        <button class="dup-toggle" id="dupToggleBtn" onclick="toggleDuplicates()">Hide Duplicates</button>
      </div>
      <div class="table-wrap">
        <table id="findingsTable">
          <thead>
            <tr>
              <th onclick="sortTable(0)">Severity &#x25B4;&#x25BE;</th>
              <th onclick="sortTable(1)">Module &#x25B4;&#x25BE;</th>
              <th onclick="sortTable(2)">File &#x25B4;&#x25BE;</th>
              <th onclick="sortTable(3)">Line &#x25B4;&#x25BE;</th>
              <th onclick="sortTable(4)">Rule ID &#x25B4;&#x25BE;</th>
              <th onclick="sortTable(5)">Title &#x25B4;&#x25BE;</th>
              <th>Description</th>
              <th>CWE</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody id="findingsBody">
{rows_str}
          </tbody>
        </table>
        <div id="noResults" class="no-results" style="display:none">&#x1F50D; No findings match your filters.</div>
      </div>
      <div id="visibleCount" style="color:var(--muted);font-size:.8rem;margin-top:.5rem;padding:.25rem 1rem"></div>
    </section>
  </div><!-- /tab-findings -->

{ai_tab_panel}

</div><!-- /container -->

<!-- ── Footer ── -->
<div class="footer">
  Generated by <a href="https://github.com/your-org/sastscan" target="_blank">sastscan</a>
  &mdash; Open-Source SAST Scanner &mdash; {now}
</div>

<script>
// ── Tab switching ────────────────────────────────────────────────────────────
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.style.display = 'block';
  if (btn) btn.classList.add('active');
  if (name === 'findings') applyFilters();
  if (name === 'suggestions') applyAiFilters();
}}

// ── Charts ──────────────────────────────────────────────────────────────────
const DARK_GRID = 'rgba(255,255,255,0.07)';
const DARK_FONT = '#94a3b8';
Chart.defaults.color = DARK_FONT;

new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sev_labels},
    datasets: [{{ data: {sev_data}, backgroundColor: {sev_colors}, borderWidth: 2, borderColor: '#1e293b' }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'right', labels: {{ color: DARK_FONT, font: {{ size: 12 }} }} }} }}
  }}
}});

new Chart(document.getElementById('modChart'), {{
  type: 'bar',
  data: {{
    labels: {mod_labels},
    datasets: [{{
      label: 'Findings', data: {mod_data},
      backgroundColor: 'rgba(56,189,248,0.7)', borderColor: '#38bdf8', borderWidth: 1
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false, indexAxis: 'y',
    scales: {{
      x: {{ grid: {{ color: DARK_GRID }}, ticks: {{ color: DARK_FONT }} }},
      y: {{ grid: {{ color: DARK_GRID }}, ticks: {{ color: DARK_FONT, font: {{ size: 11 }} }} }}
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});

// ── Findings filtering ────────────────────────────────────────────────────────
let activeModule  = '';
let hideDups      = false;
const SEV_ORDER   = {{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}};

function filterModule(mod) {{
  activeModule = mod;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  const btn = mod
    ? document.querySelector(`.filter-btn[onclick="filterModule('${{mod}}')"]`)
    : document.getElementById('btn-all');
  if (btn) btn.classList.add('active');
  applyFilters();
}}

function toggleDuplicates() {{
  hideDups = !hideDups;
  const btn = document.getElementById('dupToggleBtn');
  btn.textContent  = hideDups ? 'Show Duplicates' : 'Hide Duplicates';
  btn.classList.toggle('hiding', hideDups);
  applyFilters();
}}

function applyFilters() {{
  const q   = document.getElementById('searchBox').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const rows = document.querySelectorAll('#findingsBody .finding-row');
  let visible = 0;
  rows.forEach(row => {{
    const isDup    = row.dataset.dup === 'DUPLICATE';
    const modMatch = !activeModule || row.dataset.module === activeModule;
    const sevMatch = !sev || row.dataset.sev === sev;
    const text     = row.textContent.toLowerCase();
    const qMatch   = !q || text.includes(q);
    const dupMatch = !hideDups || !isDup;
    const show = modMatch && sevMatch && qMatch && dupMatch;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('noResults').style.display   = visible === 0 ? 'block' : 'none';
  document.getElementById('visibleCount').textContent  = `Showing ${{visible}} of ${{rows.length}} findings`;
}}

// ── Sorting ──────────────────────────────────────────────────────────────────
let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('findingsBody');
  const rows  = Array.from(tbody.querySelectorAll('.finding-row'));
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    const av = a.cells[col]?.textContent.trim() || '';
    const bv = b.cells[col]?.textContent.trim() || '';
    if (col === 0) {{
      const ao = SEV_ORDER[av] ?? 99, bo = SEV_ORDER[bv] ?? 99;
      return sortDir[col] ? ao - bo : bo - ao;
    }}
    const cmp = av.localeCompare(bv, undefined, {{numeric:true}});
    return sortDir[col] ? cmp : -cmp;
  }});
  rows.forEach(r => tbody.appendChild(r));
  applyFilters();
}}

// ── AI Suggestions filtering ──────────────────────────────────────────────────
function applyAiFilters() {{
  const q   = (document.getElementById('sugSearchBox')?.value || '').toLowerCase();
  const sev = document.getElementById('sugSevFilter')?.value || '';
  const rows = document.querySelectorAll('#suggestionsBody .sug-row');
  let visible = 0;
  rows.forEach(row => {{
    const sevMatch = !sev || row.dataset.sev === sev;
    const text     = row.textContent.toLowerCase();
    const qMatch   = !q   || text.includes(q);
    const show     = sevMatch && qMatch;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  const noEl = document.getElementById('sugNoResults');
  const cntEl = document.getElementById('sugVisibleCount');
  if (noEl)  noEl.style.display  = visible === 0 ? 'block' : 'none';
  if (cntEl) cntEl.textContent   = `Showing ${{visible}} of ${{rows.length}} suggestions`;
}}

// Init
applyFilters();
applyAiFilters();
</script>
</body>
</html>"""

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not os.path.isdir(args.report_dir):
        print(f"Error: report directory not found: {args.report_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[report] Reading CSV files from: {args.report_dir}")
    findings = read_csv_reports(args.report_dir)
    print(f"[report] Total findings loaded: {len(findings)}")

    findings = mark_duplicates(findings)
    dup_count = sum(1 for f in findings if f.get("IsDuplicate") == "DUPLICATE")
    print(f"[report] Duplicates detected: {dup_count}")

    ai_findings: list = []
    if args.use_ai:
        ai_findings = read_ai_csv(args.ai_csv)
        print(f"[report] AI findings loaded: {len(ai_findings)}")

    stats = compute_stats(findings)

    html = build_html(args.scan_name, args.scan_dir, findings, stats, ai_findings, args.use_ai)

    out_path = os.path.join(args.report_dir, "report.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"[report] HTML report written: {out_path} ({size_kb:.1f} KB)")
    print(f"[report] Summary:")
    print(f"         Total      : {stats['total']}")
    print(f"         Originals  : {stats['originals']}")
    print(f"         Duplicates : {stats['duplicates']}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        cnt = stats["by_severity"].get(sev, 0)
        if cnt:
            print(f"         {sev:<10} : {cnt}")
    if args.use_ai:
        print(f"         AI Suggestions: {len(ai_findings)}")

if __name__ == "__main__":
    main()
