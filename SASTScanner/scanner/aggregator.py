"""
Scan orchestrator: runs all scanners, tracks per-engine status,
aggregates, deduplicates, and sorts results.
"""
import os
import time
import subprocess
import hashlib
import threading
import zipfile
import shutil
from datetime import datetime
from pathlib import Path

from models.database import (
    update_scan_status, save_findings, get_previous_scan_findings,
    compute_fingerprint, get_scan, save_engine_results
)
from scanner.bandit_scanner import run_bandit
from scanner.semgrep_scanner import run_semgrep
from scanner.secrets_scanner import run_secrets_scanner
from scanner.pattern_scanner import run_pattern_scanner
from reports.csv_report import generate_csv
from reports.html_report import generate_html
from reports.pdf_report import generate_pdf

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


# ─── Engine registry ──────────────────────────────────────────────────────────

def _get_tool_version(cmd):
    """Return version string for an external CLI tool, or '' if unavailable."""
    try:
        out = subprocess.run(
            [cmd, '--version'], capture_output=True, text=True, timeout=10
        )
        return (out.stdout or out.stderr or '').strip().split('\n')[0][:80]
    except Exception:
        return ''


def _is_tool_available(cmd):
    try:
        subprocess.run([cmd, '--version'], capture_output=True, timeout=8)
        return True
    except Exception:
        return False


# ─── Engine runner ────────────────────────────────────────────────────────────


def _run_engine(engine_name, version_cmd, engine_func, *args):
    """
    Run a single scanner engine and capture:
      - findings list
      - status (completed / failed / skipped)
      - duration
      - version string
      - error message (if any)
    """
    version = _get_tool_version(version_cmd) if version_cmd else engine_name
    t_start = time.time()
    ran_at  = datetime.utcnow().isoformat()
    try:
        findings = engine_func(*args)
        duration = round(time.time() - t_start, 2)
        return findings, {
            'engine_name':      engine_name,
            'status':           'completed',
            'findings_count':   len(findings),
            'duration_seconds': duration,
            'engine_version':   version,
            'error_message':    '',
            'ran_at':           ran_at,
        }
    except Exception as exc:
        duration = round(time.time() - t_start, 2)
        return [], {
            'engine_name':      engine_name,
            'status':           'failed',
            'findings_count':   0,
            'duration_seconds': duration,
            'engine_version':   version,
            'error_message':    str(exc)[:500],
            'ran_at':           ran_at,
        }


# ─── Dedup / sort helpers ─────────────────────────────────────────────────────

def _normalize_severity(s):
    s = (s or '').upper()
    return s if s in SEVERITY_ORDER else 'INFO'


def _deduplicate(findings):
    seen = {}
    for f in findings:
        fp = f['fingerprint']
        if fp not in seen:
            seen[fp] = f
        else:
            existing = seen[fp]
            if not existing.get('cwe_id') and f.get('cwe_id'):
                seen[fp] = f
            elif len(f.get('description', '')) > len(existing.get('description', '')):
                seen[fp] = f
    return list(seen.values())


def _sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(_normalize_severity(f.get('severity')), 5),
            f.get('file_path', ''),
            f.get('line_number') or 0,
        )
    )


def _assign_fingerprints(findings):
    for f in findings:
        f['fingerprint'] = compute_fingerprint(
            f.get('file_path', ''),
            f.get('vuln_id', f.get('vulnerability', '')),
            f.get('tool', '')
        )
    return findings


def _compare_with_previous(findings, previous_fps):
    for f in findings:
        f['status'] = 'recurring' if f['fingerprint'] in previous_fps else 'new'
    return findings


def _count_files(directory):
    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in
                   {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'dist', 'build'}]
        count += len(files)
    return count


# ─── ZIP extraction ───────────────────────────────────────────────────────────

def extract_zip(zip_path, target_dir):
    try:
        os.makedirs(target_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                member_path = os.path.realpath(os.path.join(target_dir, member.filename))
                if not member_path.startswith(os.path.realpath(target_dir)):
                    continue
                zf.extract(member, target_dir)
        return True
    except (zipfile.BadZipFile, OSError):
        return False


# ─── Language detection ───────────────────────────────────────────────────────

# Maps file extension → friendly language name
_EXT_LANGUAGE = {
    '.py':   'Python',
    '.js':   'JavaScript',
    '.ts':   'TypeScript',
    '.jsx':  'JavaScript',
    '.tsx':  'TypeScript',
    '.java': 'Java',
    '.php':  'PHP',
    '.rb':   'Ruby',
    '.go':   'Go',
    '.cs':   'C#',
    '.cpp':  'C++',
    '.c':    'C',
    '.rs':   'Rust',
    '.kt':   'Kotlin',
    '.swift':'Swift',
    '.sh':   'Shell',
    '.bash': 'Shell',
    '.html': 'HTML',
    '.htm':  'HTML',
    '.xml':  'XML',
    '.yaml': 'YAML',
    '.yml':  'YAML',
    '.json': 'JSON',
    '.sql':  'SQL',
    '.env':  'Env',
}

_SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'dist', 'build'}


def _detect_languages(source_dir):
    """
    Walk source_dir and return a dict of {language: file_count} for every
    recognised source-code extension found.
    """
    counts = {}
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            ext = Path(fname).suffix.lower()
            lang = _EXT_LANGUAGE.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return counts


def _has_python(source_dir):
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if any(f.endswith('.py') for f in files):
            return True
    return False


# ─── Core scan logic ──────────────────────────────────────────────────────────

def _run_scan(scan_id, scan_name, version, source_dir, reports_dir):
    update_scan_status(scan_id, 'running')
    total_files = _count_files(source_dir)

    # Detect languages present in the uploaded project
    detected_langs = _detect_languages(source_dir)
    has_python     = 'Python' in detected_langs

    # Build language summary string for display
    lang_str = ', '.join(
        f"{l} ({c} file{'s' if c != 1 else ''})"
        for l, c in sorted(detected_langs.items(), key=lambda x: -x[1])
    ) or 'unknown'

    raw_findings   = []
    engine_results = []

    # Bandit is Python-only — skip it when the project has no Python files
    if has_python:
        findings, result = _run_engine('Bandit', 'bandit', run_bandit, source_dir)
        result['engine_version'] = f"{result['engine_version']} | {lang_str}"
        raw_findings.extend(findings)
        engine_results.append(result)
    else:
        engine_results.append({
            'engine_name':      'Bandit',
            'status':           'skipped',
            'findings_count':   0,
            'duration_seconds': 0,
            'engine_version':   lang_str,
            'error_message':    'No Python files detected — Bandit is Python-only.',
            'ran_at':           datetime.utcnow().isoformat(),
        })

    # Remaining engines run on all projects
    for engine_name, version_cmd, func, farg in [
        ('Semgrep',        'semgrep', run_semgrep,         source_dir),
        ('SecretsScanner', None,      run_secrets_scanner, source_dir),
        ('PatternScanner', None,      run_pattern_scanner, source_dir),
    ]:
        findings, result = _run_engine(engine_name, version_cmd, func, farg)
        raw_findings.extend(findings)
        engine_results.append(result)

    # ── Post-process ──────────────────────────────────────────────────────────
    for f in raw_findings:
        f['severity'] = _normalize_severity(f.get('severity'))

    raw_findings    = _assign_fingerprints(raw_findings)
    previous_fps    = get_previous_scan_findings(scan_name, version)
    raw_findings    = _compare_with_previous(raw_findings, previous_fps)
    deduped         = _deduplicate(raw_findings)
    sorted_findings = _sort_findings(deduped)

    # Update engine findings counts after dedup (so totals reflect unique findings)
    _reconcile_engine_counts(engine_results, sorted_findings)

    # ── Persist ───────────────────────────────────────────────────────────────
    save_findings(scan_id, sorted_findings)
    save_engine_results(scan_id, engine_results)

    # ── Severity counts ───────────────────────────────────────────────────────
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in sorted_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    # ── Generate reports ──────────────────────────────────────────────────────
    os.makedirs(reports_dir, exist_ok=True)
    scan = get_scan(scan_id)
    generate_csv(sorted_findings, os.path.join(reports_dir, 'report.csv'))
    generate_html(sorted_findings, scan, os.path.join(reports_dir, 'report.html'))
    generate_pdf(sorted_findings, scan, os.path.join(reports_dir, 'report.pdf'))

    update_scan_status(
        scan_id, 'completed',
        total_files=total_files,
        total_findings=len(sorted_findings),
        critical=counts['CRITICAL'],
        high=counts['HIGH'],
        medium=counts['MEDIUM'],
        low=counts['LOW'],
        info=counts['INFO'],
    )


def _reconcile_engine_counts(engine_results, deduped_findings):
    """Update each engine's finding count to reflect post-dedup totals."""
    from collections import Counter
    tool_counts = Counter(f.get('tool', '') for f in deduped_findings)
    for r in engine_results:
        r['findings_count'] = tool_counts.get(r['engine_name'], 0)


# ─── Background thread ────────────────────────────────────────────────────────

def run_scan_background(scan_id, scan_name, version, source_dir, reports_dir):
    try:
        _run_scan(scan_id, scan_name, version, source_dir, reports_dir)
    except Exception as exc:
        update_scan_status(scan_id, 'failed', error=str(exc))


def start_scan_thread(scan_id, scan_name, version, source_dir, reports_dir):
    t = threading.Thread(
        target=run_scan_background,
        args=(scan_id, scan_name, version, source_dir, reports_dir),
        daemon=True
    )
    t.start()
    return t
