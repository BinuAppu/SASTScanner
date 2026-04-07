"""Custom secrets and hardcoded credential scanner."""
import os
import re
from pathlib import Path

# Pattern definitions: (name, regex, cwe_id, severity, recommendation)
SECRET_PATTERNS = [
    (
        'Hardcoded Fallback Secret Key in os.getenv',
        re.compile(
            r'os\.(?:getenv|environ\.get)\s*\(\s*["\'][^"\']*(?:SECRET|KEY|TOKEN|PASSWORD)[^"\']*["\']'
            r'\s*,\s*["\']([A-Za-z0-9_\-]{6,})["\']',
            re.I),
        'CWE-321', 'HIGH',
        'Never supply a hardcoded fallback for secrets. Use os.environ["KEY"] (raises if missing) '
        'so misconfigured deployments fail fast instead of running with a known-weak secret.'
    ),
    (
        'Hardcoded AWS Access Key',
        re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])', re.S),
        'CWE-798', 'CRITICAL',
        'Remove AWS credentials from code. Use IAM roles, environment variables, or AWS Secrets Manager.'
    ),
    (
        'Hardcoded AWS Secret Key',
        re.compile(r'aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', re.I),
        'CWE-798', 'CRITICAL',
        'Remove AWS secret keys from code. Use IAM roles or secrets management solutions.'
    ),
    (
        'Hardcoded Password',
        re.compile(r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\']([^"\']{6,})["\']', re.I),
        'CWE-259', 'HIGH',
        'Use environment variables or a secrets manager. Never hardcode passwords.'
    ),
    (
        'Hardcoded API Key',
        re.compile(r'(?:api[_\-]?key|apikey|api_secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', re.I),
        'CWE-798', 'HIGH',
        'Store API keys in environment variables or a secrets vault, not in source code.'
    ),
    (
        'Hardcoded Token',
        re.compile(r'(?:token|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']', re.I),
        'CWE-798', 'HIGH',
        'Store tokens securely using environment variables or a secrets management system.'
    ),
    (
        'Hardcoded Private Key',
        re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', re.S),
        'CWE-321', 'CRITICAL',
        'Never commit private keys to source control. Use key management services.'
    ),
    (
        'Generic Secret',
        re.compile(r'(?:secret|client_secret|app_secret)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{12,})["\']', re.I),
        'CWE-798', 'HIGH',
        'Move secrets to environment variables or a dedicated secrets manager.'
    ),
    (
        'Database Connection String',
        re.compile(r'(?:mysql|postgresql|mssql|mongodb|redis):\/\/[^\s"\'<>]+:[^\s"\'<>@]+@', re.I),
        'CWE-259', 'CRITICAL',
        'Use environment variables for database connection strings. Never hardcode credentials.'
    ),
    (
        'GitHub Token',
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}', re.S),
        'CWE-798', 'CRITICAL',
        'Revoke the exposed token immediately and use environment variables.'
    ),
    (
        'JWT Token',
        re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', re.S),
        'CWE-798', 'MEDIUM',
        'Do not embed JWT tokens in source code. Generate them at runtime.'
    ),
    (
        'Slack Token',
        re.compile(r'xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[A-Za-z0-9]{24}', re.S),
        'CWE-798', 'CRITICAL',
        'Revoke the token and use environment variables or a secrets manager.'
    ),
    (
        'Google API Key',
        re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.S),
        'CWE-798', 'HIGH',
        'Restrict the API key in the Google Cloud Console and move it to secure storage.'
    ),
    (
        'Stripe Secret Key',
        re.compile(r'sk_(?:live|test)_[0-9a-zA-Z]{24,}', re.S),
        'CWE-798', 'CRITICAL',
        'Revoke the key immediately and use environment variables.'
    ),
    (
        'SSH Password in Config',
        re.compile(r'StrictHostKeyChecking\s+no', re.I),
        'CWE-295', 'MEDIUM',
        'Enable host key checking to prevent MITM attacks.'
    ),
]

SKIP_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
    '.pdf', '.zip', '.tar', '.gz', '.bin', '.exe', '.dll',
    '.pyc', '.pyo', '.so', '.o', '.a',
    '.min.js', '.min.css',
    '.lock', '.sum',
}

SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'env', 'dist', 'build'}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def _should_skip(file_path: Path) -> bool:
    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    if any(part in SKIP_DIRS for part in file_path.parts):
        return True
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return True
    except OSError:
        return True
    return False


def run_secrets_scanner(source_dir: str):
    """Scan for hardcoded secrets and credentials."""
    findings = []
    source_path = Path(source_dir)

    for file_path in sorted(source_path.rglob('*')):
        if not file_path.is_file():
            continue
        if _should_skip(file_path):
            continue

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            continue

        lines = content.splitlines()
        rel_path = str(file_path.relative_to(source_path))

        for name, pattern, cwe_id, severity, recommendation in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                # Find the line number
                line_num = content[:match.start()].count('\n') + 1
                snippet = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ''
                # Redact actual secret value in snippet
                snippet = _redact(snippet)

                findings.append({
                    'file_path': rel_path,
                    'line_number': line_num,
                    'end_line': line_num,
                    'vulnerability': name,
                    'description': f"Potential {name} found in source code.",
                    'cwe_id': cwe_id,
                    'cve_id': '',
                    'severity': severity,
                    'confidence': 'HIGH',
                    'recommendation': recommendation,
                    'tool': 'SecretsScanner',
                    'code_snippet': snippet,
                    'vuln_id': name.replace(' ', '_').upper(),
                })

    return findings


def _redact(text: str) -> str:
    """Redact potential secret values from code snippets."""
    text = re.sub(r'(["\'])([A-Za-z0-9\-_./+]{8,})\1', r'\1[REDACTED]\1', text)
    return text
