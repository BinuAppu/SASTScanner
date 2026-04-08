"""Semgrep SAST scanner – fully offline using local rule files."""
import subprocess
import json
import os
import re
from pathlib import Path

from scanner._tool_finder import find_tool

SEVERITY_MAP = {
    'ERROR':    'HIGH',
    'WARNING':  'MEDIUM',
    'INFO':     'LOW',
    'CRITICAL': 'CRITICAL',
}

CWE_PATTERN = re.compile(r'CWE-(\d+)', re.IGNORECASE)
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# Local rules directory — all YAML files here are loaded without internet access
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')


def _extract_cwe(text):
    match = CWE_PATTERN.search(text or '')
    return f"CWE-{match.group(1)}" if match else ''


def _extract_cve(text):
    match = CVE_PATTERN.search(text or '')
    return match.group(0).upper() if match else ''


def _build_recommendation(rule_id, message, metadata):
    references = metadata.get('references', [])
    fix = metadata.get('fix', '')
    parts = []
    if fix:
        parts.append(f"Suggested fix: {fix}")
    if references:
        parts.append(f"References: {'; '.join(references[:2])}")
    if not parts:
        parts.append(
            'Review the flagged code and apply the principle of least privilege '
            '/ secure coding practices.'
        )
    return ' '.join(parts)


def run_semgrep(source_dir):
    """Run Semgrep with local rule files only (no internet required)."""
    if not os.path.isdir(RULES_DIR):
        raise RuntimeError(
            f"Semgrep rules directory not found: {RULES_DIR}. "
            "Ensure scanner/rules/ is present in the repository."
        )

    # Confirm at least one rule file exists
    rule_files = list(Path(RULES_DIR).rglob('*.yaml')) + list(Path(RULES_DIR).rglob('*.yml'))
    if not rule_files:
        raise RuntimeError(f"No YAML rule files found in {RULES_DIR}.")

    semgrep_bin = find_tool('semgrep')

    cmd = [
        semgrep_bin,
        '--config', RULES_DIR,
        '--json',
        '--quiet',
        '--no-git-ignore',
        '--metrics=off',
        '--disable-version-check',
        '--timeout', '60',
        source_dir,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    stdout = result.stdout.strip()

    # Surface any semgrep errors so they appear in engine_results.error_message
    if result.returncode not in (0, 1):  # semgrep exits 1 when findings exist
        stderr_snippet = result.stderr.strip()[:400] if result.stderr else ''
        raise RuntimeError(
            f"Semgrep exited with code {result.returncode}. "
            f"Binary: {semgrep_bin}. "
            f"Stderr: {stderr_snippet}"
        )

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Semgrep returned non-JSON output. "
            f"Binary: {semgrep_bin}. "
            f"Output snippet: {stdout[:200]}"
        ) from exc

    all_results = []
    seen_rules = set()

    for r in data.get('results', []):
        rule_id  = r.get('check_id', '')
        rel_path = os.path.relpath(r.get('path', ''), source_dir)
        line     = r.get('start', {}).get('line')

        dedup_key = f"{rule_id}::{rel_path}::{line}"
        if dedup_key in seen_rules:
            continue
        seen_rules.add(dedup_key)

        meta         = r.get('extra', {}).get('metadata', {})
        message      = r.get('extra', {}).get('message', '')
        severity_raw = r.get('extra', {}).get('severity', 'WARNING')

        cwe_raw = meta.get('cwe', '') or meta.get('cwe-id', '')
        if isinstance(cwe_raw, list):
            cwe_raw = ' '.join(cwe_raw)
        cwe_id  = _extract_cwe(str(cwe_raw)) if cwe_raw else _extract_cwe(message)
        cve_id  = _extract_cve(str(meta.get('cve', '') or ''))

        all_results.append({
            'file_path':      rel_path,
            'line_number':    line,
            'end_line':       r.get('end', {}).get('line'),
            'vulnerability':  (
                rule_id.split('.')[-1]
                       .replace('-', ' ')
                       .replace('_', ' ')
                       .title()
            ),
            'description':    message,
            'cwe_id':         cwe_id,
            'cve_id':         cve_id,
            'severity':       SEVERITY_MAP.get(severity_raw.upper(), 'MEDIUM'),
            'confidence':     str(meta.get('confidence', 'MEDIUM')).upper(),
            'recommendation': _build_recommendation(rule_id, message, meta),
            'tool':           'Semgrep',
            'code_snippet':   r.get('extra', {}).get('lines', '').strip(),
            'vuln_id':        rule_id,
        })

    return all_results
