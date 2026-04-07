"""Semgrep SAST scanner integration."""
import subprocess
import json
import os
import re


SEVERITY_MAP = {
    'ERROR': 'HIGH',
    'WARNING': 'MEDIUM',
    'INFO': 'LOW',
    'CRITICAL': 'CRITICAL',
}

CWE_PATTERN = re.compile(r'CWE-(\d+)', re.IGNORECASE)
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# Semgrep rulesets to run
SEMGREP_CONFIGS = [
    'p/owasp-top-ten',
    'p/python',
    'p/javascript',
    'p/java',
    'p/php',
    'p/secrets',
    'p/sql-injection',
    'p/xss',
    'p/command-injection',
]


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
        parts.append('Review the flagged code and apply the principle of least privilege / secure coding practices.')
    return ' '.join(parts)


def run_semgrep(source_dir):
    """Run Semgrep with multiple rulesets and return normalized findings."""
    all_results = []
    seen_rules = set()

    for config in SEMGREP_CONFIGS:
        try:
            result = subprocess.run(
                [
                    'semgrep',
                    '--config', config,
                    '--json',
                    '--quiet',
                    '--no-git-ignore',
                    '--timeout', '60',
                    source_dir
                ],
                capture_output=True,
                text=True,
                timeout=180
            )
            if not result.stdout.strip():
                continue
            data = json.loads(result.stdout)
            for r in data.get('results', []):
                rule_id = r.get('check_id', '')
                rel_path = os.path.relpath(r.get('path', ''), source_dir)
                line = r.get('start', {}).get('line')

                # Dedup within semgrep runs
                dedup_key = f"{rule_id}::{rel_path}::{line}"
                if dedup_key in seen_rules:
                    continue
                seen_rules.add(dedup_key)

                meta = r.get('extra', {}).get('metadata', {})
                message = r.get('extra', {}).get('message', '')
                severity_raw = r.get('extra', {}).get('severity', 'WARNING')

                cwe_raw = meta.get('cwe', '') or meta.get('cwe-id', '')
                cwe_id = _extract_cwe(str(cwe_raw)) if cwe_raw else _extract_cwe(message)
                cve_id = _extract_cve(str(meta.get('cve', '') or ''))

                all_results.append({
                    'file_path': rel_path,
                    'line_number': line,
                    'end_line': r.get('end', {}).get('line'),
                    'vulnerability': rule_id.split('.')[-1].replace('-', ' ').replace('_', ' ').title(),
                    'description': message,
                    'cwe_id': cwe_id,
                    'cve_id': cve_id,
                    'severity': SEVERITY_MAP.get(severity_raw.upper(), 'MEDIUM'),
                    'confidence': 'HIGH',
                    'recommendation': _build_recommendation(rule_id, message, meta),
                    'tool': 'Semgrep',
                    'code_snippet': r.get('extra', {}).get('lines', '').strip(),
                    'vuln_id': rule_id,
                })
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            continue

    return all_results
