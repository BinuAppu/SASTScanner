"""Bandit SAST scanner integration."""
import subprocess
import json
import os

# Comprehensive CWE mapping for Bandit test IDs
BANDIT_CWE_MAP = {
    'B101': 'CWE-617', 'B102': 'CWE-78',  'B103': 'CWE-732', 'B104': 'CWE-605',
    'B105': 'CWE-259', 'B106': 'CWE-259', 'B107': 'CWE-259', 'B108': 'CWE-377',
    'B110': 'CWE-390', 'B112': 'CWE-390', 'B201': 'CWE-94',  'B202': 'CWE-94',
    'B301': 'CWE-502', 'B302': 'CWE-502', 'B303': 'CWE-327', 'B304': 'CWE-327',
    'B305': 'CWE-327', 'B306': 'CWE-377', 'B307': 'CWE-78',  'B308': 'CWE-79',
    'B310': 'CWE-88',  'B311': 'CWE-330', 'B312': 'CWE-319', 'B313': 'CWE-611',
    'B314': 'CWE-611', 'B315': 'CWE-611', 'B316': 'CWE-611', 'B317': 'CWE-611',
    'B318': 'CWE-611', 'B319': 'CWE-611', 'B320': 'CWE-611', 'B321': 'CWE-319',
    'B322': 'CWE-78',  'B323': 'CWE-295', 'B324': 'CWE-327', 'B325': 'CWE-377',
    'B401': 'CWE-319', 'B402': 'CWE-319', 'B403': 'CWE-502', 'B404': 'CWE-78',
    'B405': 'CWE-611', 'B406': 'CWE-611', 'B407': 'CWE-611', 'B408': 'CWE-611',
    'B409': 'CWE-611', 'B410': 'CWE-611', 'B411': 'CWE-94',  'B412': 'CWE-601',
    'B413': 'CWE-327', 'B501': 'CWE-295', 'B502': 'CWE-326', 'B503': 'CWE-326',
    'B504': 'CWE-326', 'B505': 'CWE-326', 'B506': 'CWE-502', 'B507': 'CWE-295',
    'B601': 'CWE-78',  'B602': 'CWE-78',  'B603': 'CWE-78',  'B604': 'CWE-78',
    'B605': 'CWE-78',  'B606': 'CWE-78',  'B607': 'CWE-78',  'B608': 'CWE-89',
    'B609': 'CWE-78',  'B610': 'CWE-89',  'B611': 'CWE-89',  'B701': 'CWE-79',
    'B702': 'CWE-79',  'B703': 'CWE-79',
}

BANDIT_RECOMMENDATIONS = {
    'B101': 'Avoid using assert in production code; use proper exception handling.',
    'B102': 'Avoid exec() calls; consider safer alternatives.',
    'B103': 'Ensure file permissions are restrictive (e.g., 0o600 for sensitive files).',
    'B104': 'Bind to specific interfaces instead of all (0.0.0.0).',
    'B105': 'Never hardcode passwords; use environment variables or a secrets manager.',
    'B106': 'Never hardcode passwords in function arguments; use config management.',
    'B107': 'Never hardcode passwords in function defaults; use secrets management.',
    'B108': 'Use tempfile.mkstemp() or tempfile.TemporaryFile() instead.',
    'B110': 'Avoid bare except clauses; catch specific exceptions.',
    'B112': 'Handle exceptions properly instead of silently continuing.',
    'B201': 'Never run Flask in debug mode in production.',
    'B301': 'Avoid pickle; use JSON or another safe serialization format.',
    'B302': 'Avoid marshal; use JSON or another safe serialization format.',
    'B303': 'Use SHA-256 or stronger hashing algorithms instead of MD5/SHA1.',
    'B304': 'Use AES in GCM mode or ChaCha20 instead of weak ciphers.',
    'B305': 'Use secure cipher modes; avoid ECB mode.',
    'B306': 'Use tempfile.mkstemp() to create temporary files securely.',
    'B307': 'Avoid eval(); use ast.literal_eval() for literals or restructure logic.',
    'B308': 'Avoid mark_safe(); validate and escape user input before rendering.',
    'B310': 'Validate and sanitize URLs before use to prevent SSRF.',
    'B311': 'Use secrets module for cryptographic randomness.',
    'B312': 'Use SSH or TLS instead of Telnet for remote connections.',
    'B313': 'Use defusedxml or lxml with safe settings to prevent XXE.',
    'B321': 'Use SFTP or SCP instead of FTP for file transfers.',
    'B322': 'Avoid input() in Python 2; use raw_input() or migrate to Python 3.',
    'B323': 'Always verify SSL certificates in production.',
    'B324': 'Avoid MD5/SHA1 for security purposes; use SHA-256 or better.',
    'B401': 'Use SSH instead of Telnet.',
    'B403': 'Avoid importing pickle; use JSON for data serialization.',
    'B404': 'Avoid subprocess with shell=True; pass arguments as a list.',
    'B501': 'Enable SSL/TLS certificate verification.',
    'B502': 'Use TLS 1.2 or higher; disable SSLv2/SSLv3/TLS 1.0.',
    'B506': 'Use yaml.safe_load() instead of yaml.load().',
    'B601': 'Avoid shell metacharacters in paramiko exec_command.',
    'B602': 'Pass subprocess arguments as a list, not a shell string.',
    'B608': 'Use parameterized queries or ORM to prevent SQL injection.',
    'B701': 'Enable Jinja2 autoescaping; use Environment(autoescape=True).',
    'B703': 'Avoid mark_safe(); sanitize all user-supplied content.',
}


def _severity_map(bandit_severity):
    mapping = {
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW',
    }
    return mapping.get(bandit_severity.upper(), 'INFO')


def run_bandit(source_dir):
    """Run Bandit on the source directory and return normalized findings."""
    findings = []
    try:
        result = subprocess.run(
            ['bandit', '-r', source_dir, '-f', 'json', '-ll', '--quiet'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if not result.stdout.strip():
            return findings
        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return findings

    for issue in data.get('results', []):
        test_id = issue.get('test_id', '')
        rel_path = os.path.relpath(issue.get('filename', ''), source_dir)
        cwe = issue.get('issue_cwe', {})
        cwe_id = f"CWE-{cwe.get('id', '')}" if cwe else BANDIT_CWE_MAP.get(test_id, '')

        findings.append({
            'file_path': rel_path,
            'line_number': issue.get('line_number'),
            'end_line': issue.get('end_col_offset'),
            'vulnerability': f"[{test_id}] {issue.get('test_name', '')}",
            'description': issue.get('issue_text', ''),
            'cwe_id': cwe_id,
            'cve_id': '',
            'severity': _severity_map(issue.get('issue_severity', 'LOW')),
            'confidence': issue.get('issue_confidence', 'MEDIUM'),
            'recommendation': BANDIT_RECOMMENDATIONS.get(test_id,
                'Review the code and apply security best practices.'),
            'tool': 'Bandit',
            'code_snippet': issue.get('code', '').strip(),
            'vuln_id': test_id,
        })
    return findings
