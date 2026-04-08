"""Pattern-based SAST scanner for common vulnerability patterns across languages."""
import os
import re
from pathlib import Path

SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.venv', 'venv', 'env', 'dist', 'build'}
SKIP_EXTENSIONS = {'.pyc', '.pyo', '.so', '.bin', '.exe', '.dll', '.jpg', '.png', '.gif',
                   '.pdf', '.zip', '.tar', '.gz', '.min.js', '.min.css', '.lock'}
MAX_FILE_SIZE = 2 * 1024 * 1024

# Format: (rule_id, name, regex, langs, cwe_id, severity, recommendation)
PATTERN_RULES = [

    # ─── SQL Injection ────────────────────────────────────────────────────────
    (
        'PI-SQL-001', 'SQL Injection via String Concatenation',
        re.compile(
            r'(?:execute|query|cursor\.execute)\s*\(\s*["\'].*[\+%]|'
            r'(?:execute|query|cursor\.execute)\s*\(\s*f["\'].*\{',
            re.I),
        {'.py', '.php', '.java', '.cs', '.rb', '.go'},
        'CWE-89', 'HIGH',
        'Use parameterized queries or prepared statements. Never concatenate user input into SQL.'
    ),
    (
        'PI-SQL-002', 'Raw SQL with User Input',
        re.compile(
            r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*'
            r'(?:\+\s*(?:request|params|input|user|data|form|args)|'
            r'%\s*(?:request|params|input|user|data|form|args))',
            re.I),
        {'.py', '.php', '.java', '.cs', '.rb', '.js', '.ts'},
        'CWE-89', 'HIGH',
        'Use an ORM or parameterized queries. Never interpolate request data into raw SQL.'
    ),

    # ─── XSS ─────────────────────────────────────────────────────────────────
    (
        'PI-XSS-001', 'Cross-Site Scripting via innerHTML',
        re.compile(r'\.innerHTML\s*[+]?=\s*(?!["\'`][^"\'`<>]*["\'`]\s*[;,)])', re.I),
        {'.js', '.ts', '.jsx', '.tsx', '.html', '.php'},
        'CWE-79', 'HIGH',
        'Use textContent instead of innerHTML. Sanitize all user content with DOMPurify before rendering.'
    ),
    (
        'PI-XSS-002', 'Cross-Site Scripting via document.write',
        re.compile(r'document\.write\s*\(', re.I),
        {'.js', '.ts', '.jsx', '.tsx', '.html'},
        'CWE-79', 'MEDIUM',
        'Avoid document.write(). Use DOM methods such as createElement and appendChild.'
    ),
    (
        'PI-XSS-003', 'Unescaped User Output in PHP',
        re.compile(r'\becho\b.+\$_(GET|POST|REQUEST|SERVER|COOKIE)\b', re.I),
        {'.php'},
        'CWE-79', 'HIGH',
        'Wrap all user-supplied output in htmlspecialchars() or htmlentities().'
    ),
    (
        'PI-XSS-004', 'Flask Markup/Jinja2 |safe on Request Data',
        re.compile(r'(?:request\.\w+|g\.\w+).*\|\s*safe', re.I),
        {'.html', '.jinja', '.jinja2'},
        'CWE-79', 'HIGH',
        'Never mark request-derived data as |safe. Escape all user-controlled values.'
    ),

    # ─── Command Injection ────────────────────────────────────────────────────
    (
        'PI-CMD-001', 'Command Injection via os.system',
        re.compile(r'\bos\.system\s*\(', re.I),
        {'.py'},
        'CWE-78', 'HIGH',
        'Replace os.system() with subprocess.run(args_list, shell=False). Avoid shell=True.'
    ),
    (
        'PI-CMD-002', 'Command Injection via shell=True',
        re.compile(r'subprocess\.\w+\s*\(.*\bshell\s*=\s*True', re.I),
        {'.py'},
        'CWE-78', 'HIGH',
        'Pass arguments as a list and remove shell=True. Validate/whitelist any external input.'
    ),
    (
        'PI-CMD-003', 'Command Injection in PHP exec/shell_exec',
        re.compile(r'\b(?:exec|shell_exec|system|passthru|popen)\s*\(\s*\$', re.I),
        {'.php'},
        'CWE-78', 'HIGH',
        'Use escapeshellarg() on all input; prefer native PHP functions over shell calls.'
    ),
    (
        'PI-CMD-004', 'os.popen with Variable Input',
        re.compile(r'\bos\.popen\s*\(', re.I),
        {'.py'},
        'CWE-78', 'HIGH',
        'Replace os.popen() with subprocess.run() with a list of arguments.'
    ),

    # ─── Path Traversal ───────────────────────────────────────────────────────
    (
        'PI-PATH-001', 'Unsafe File Open with User Input',
        re.compile(
            r'\bopen\s*\(\s*(?:os\.path\.join\s*\()?'
            r'(?:[^,)]*(?:request\.|args\.|form\.|params\.|filename)[^,)]*)',
            re.I),
        {'.py', '.php', '.rb'},
        'CWE-22', 'HIGH',
        'Use werkzeug.utils.secure_filename() and validate the resolved path stays inside the allowed directory.'
    ),
    (
        'PI-PATH-002', 'send_from_directory with Unsanitised Path',
        re.compile(r'send_from_directory\s*\([^)]*(?:request\.|args\.|form\.|filename\b)[^)]*\)', re.I),
        {'.py'},
        'CWE-22', 'HIGH',
        'Always call secure_filename() before passing a user-supplied name to send_from_directory().'
    ),
    (
        'PI-PATH-003', 'File Upload Without secure_filename',
        re.compile(
            r'(?:file|f)\s*(?:\.\s*save|\.write)\s*\(\s*os\.path\.join\s*\([^)]*'
            r'(?:file(?:name)?|\.filename)\b',
            re.I),
        {'.py'},
        'CWE-22', 'HIGH',
        'Wrap the filename in werkzeug.utils.secure_filename() before using it in any path. '
        'Unsanitised filenames allow path traversal (e.g. ../../etc/passwd).'
    ),
    (
        'PI-PATH-004', 'Direct Use of request.files filename',
        re.compile(r'\.filename\b(?!\s*==\s*["\'])', re.I),
        {'.py'},
        'CWE-22', 'MEDIUM',
        'Always sanitise uploaded filenames with secure_filename() before constructing any file-system path.'
    ),
    (
        'PI-PATH-005', 'Path Traversal via startswith Check (Bypassable)',
        re.compile(
            r'(?:startswith|abspath)\s*\(.+\)\s*(?:and|or)?.*\n?.*'
            r'(?:send_from_directory|open|os\.path\.join)',
            re.I | re.MULTILINE),
        {'.py'},
        'CWE-22', 'MEDIUM',
        'startswith() path checks can be bypassed with symlinks or encoded paths. '
        'Use os.path.realpath() and compare with the real resolved base path.'
    ),

    # ─── Insecure Deserialization ─────────────────────────────────────────────
    (
        'PI-DESER-001', 'Insecure Deserialization via pickle.loads',
        re.compile(r'\bpickle\.loads?\s*\(', re.I),
        {'.py'},
        'CWE-502', 'HIGH',
        'Never deserialise untrusted data with pickle. Use JSON or a safer alternative.'
    ),
    (
        'PI-DESER-002', 'Unsafe YAML Load',
        re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', re.I),
        {'.py'},
        'CWE-502', 'HIGH',
        'Replace yaml.load() with yaml.safe_load() to prevent arbitrary code execution.'
    ),

    # ─── Cryptographic Issues ─────────────────────────────────────────────────
    (
        'PI-CRYPTO-001', 'Weak Hash Algorithm (MD5)',
        re.compile(r'\bhashlib\.md5\s*\(|\bMD5\s*\(|md5\s*=', re.I),
        {'.py', '.php', '.java', '.js', '.ts', '.cs', '.rb'},
        'CWE-327', 'MEDIUM',
        'Use SHA-256 (hashlib.sha256) for integrity and bcrypt/argon2 for passwords.'
    ),
    (
        'PI-CRYPTO-002', 'Weak Hash Algorithm (SHA-1)',
        re.compile(r'\bhashlib\.sha1\s*\(|\bSHA1\s*\(', re.I),
        {'.py', '.php', '.java', '.js', '.ts', '.cs', '.rb'},
        'CWE-327', 'MEDIUM',
        'SHA-1 is deprecated for security. Use SHA-256 or stronger.'
    ),
    (
        'PI-CRYPTO-003', 'Insecure Random Number Generation',
        re.compile(r'\brandom\.(?:random|randint|choice|shuffle|sample)\s*\(', re.I),
        {'.py'},
        'CWE-330', 'MEDIUM',
        'Use the secrets module for any security-sensitive randomness (tokens, keys, salts).'
    ),

    # ─── Hardcoded / Weak Secrets ─────────────────────────────────────────────
    (
        'PI-SEC-001', 'Hardcoded Fallback Secret Key',
        re.compile(
            r'(?:SECRET_KEY|secret_key|APP_SECRET)\s*[=,]\s*'
            r'(?:os\.(?:getenv|environ\.get)\s*\([^,)]+,\s*)?'
            r'["\'](?![\s]*\$|\s*{{)[A-Za-z0-9_\-]{6,}["\']',
            re.I),
        {'.py', '.js', '.ts', '.php', '.rb', '.go', '.env'},
        'CWE-321', 'HIGH',
        'Never hardcode or provide a fallback SECRET_KEY. Require it from the environment '
        'and fail fast if missing: os.environ["SECRET_KEY"] (no default).'
    ),
    (
        'PI-SEC-002', 'Debug Mode Enabled in Production Code',
        re.compile(r'\bapp\.run\s*\([^)]*\bdebug\s*=\s*True', re.I),
        {'.py'},
        'CWE-489', 'HIGH',
        'Set debug=False and control via environment variable. Debug mode exposes the '
        'interactive debugger and detailed stack traces to attackers.'
    ),
    (
        'PI-SEC-003', 'Hardcoded Database Password in URI',
        re.compile(
            r'(?:SQLALCHEMY_DATABASE_URI|DATABASE_URL|db_url)\s*=\s*'
            r'["\'](?!.*\$|\s*{{)(?:sqlite|mysql|postgresql|mssql)://[^"\']+["\']',
            re.I),
        {'.py', '.js', '.ts', '.php', '.go', '.env'},
        'CWE-259', 'MEDIUM',
        'Store the database URI in environment variables, not in source code.'
    ),

    # ─── CSRF ─────────────────────────────────────────────────────────────────
    (
        'PI-CSRF-001', 'Flask Route Without CSRF Protection',
        re.compile(
            r'@app\.route\s*\([^)]+methods\s*=\s*\[[^\]]*["\']POST["\'][^\]]*\]\s*\)'
            r'(?:(?!csrf|CSRFProtect|WTF_CSRF).){0,400}def\s+\w+',
            re.S),
        {'.py'},
        'CWE-352', 'HIGH',
        'Use Flask-WTF (CSRFProtect) or include a CSRF token in every state-changing form. '
        'Without CSRF protection, authenticated users can be tricked into unwanted actions.'
    ),

    # ─── Authentication / Brute Force ─────────────────────────────────────────
    (
        'PI-AUTH-001', 'Login Endpoint Without Rate Limiting',
        re.compile(
            r'@app\.route\s*\(["\']\/login["\'].*?\)'
            r'(?:(?!limiter|rate_limit|RateLimit|Limiter|login_attempts).){0,600}def\s+login',
            re.S),
        {'.py'},
        'CWE-307', 'HIGH',
        'Implement rate limiting on login (e.g. Flask-Limiter). Without it the endpoint is '
        'vulnerable to credential-stuffing and brute-force attacks.'
    ),
    (
        'PI-AUTH-002', 'Missing Authentication on Sensitive Route',
        re.compile(
            r'@app\.route\s*\([^)]+\)\s*\n(?!.*@login_required)(?!.*@admin_required)\s*def\s+'
            r'(?:delete|reset|admin|manage|create_user|remove)',
            re.M),
        {'.py'},
        'CWE-306', 'HIGH',
        'Ensure all sensitive routes are decorated with @login_required or @admin_required.'
    ),
    (
        'PI-AUTH-003', 'Password Reset Without Current Password Verification',
        re.compile(
            r'def\s+reset_password\s*\([^)]*\).*?'
            r'(?!.*check_password_hash|.*verify_password|.*current_password)'
            r'(?:password_hash|set_password|update_password)',
            re.S),
        {'.py'},
        'CWE-620', 'HIGH',
        'Admin password-reset routes should require the current password or use a '
        'time-limited signed token sent to the registered email.'
    ),

    # ─── SSRF ─────────────────────────────────────────────────────────────────
    (
        'PI-SSRF-001', 'Potential SSRF via User-Controlled URL',
        re.compile(
            r'(?:requests\.|urllib\.|httpx\.|aiohttp\.)\w+\s*\(\s*'
            r'(?:[^)]*(?:request\.|args\.|form\.|params\.|url\b)[^)]*)',
            re.I),
        {'.py'},
        'CWE-918', 'HIGH',
        'Validate and whitelist allowed URLs/hosts. Never forward raw user-supplied URLs.'
    ),

    # ─── Open Redirect ────────────────────────────────────────────────────────
    (
        'PI-REDIR-001', 'Open Redirect via User-Controlled URL',
        re.compile(
            r'\bredirect\s*\(\s*(?:request\.|args\.|form\.|params\.)',
            re.I),
        {'.py', '.php', '.rb'},
        'CWE-601', 'MEDIUM',
        'Validate redirect targets against an explicit allowlist before redirecting.'
    ),

    # ─── XXE ─────────────────────────────────────────────────────────────────
    (
        'PI-XXE-001', 'XML External Entity (XXE)',
        re.compile(r'(?:etree\.parse|minidom\.parse|SAXParser|XMLReader|parseString)\s*\(', re.I),
        {'.py', '.java', '.php'},
        'CWE-611', 'HIGH',
        'Disable external entity processing. Use defusedxml in Python.'
    ),

    # ─── Sensitive Data Exposure ───────────────────────────────────────────────
    (
        'PI-LOG-001', 'Sensitive Data in Logs / Print Statements',
        re.compile(
            r'(?:print|log(?:ger)?\.(?:info|debug|warning|error|critical))\s*\('
            r'.*(?:password|passwd|secret|token|key|credit|ssn|dob)',
            re.I),
        {'.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.cs'},
        'CWE-532', 'MEDIUM',
        'Never log credentials, tokens, or PII. Mask or omit sensitive fields.'
    ),
    (
        'PI-EXPO-001', 'Exception Details Exposed to End User',
        re.compile(r'(?:return|jsonify|render_template)\s*\([^)]*str\s*\(\s*e\s*\)', re.I),
        {'.py'},
        'CWE-209', 'MEDIUM',
        'Return generic error messages to users. Log full exception details server-side only.'
    ),

    # ─── Insecure File Handling ────────────────────────────────────────────────
    (
        'PI-FILE-001', 'No File Extension Validation on Upload',
        re.compile(
            r'request\.files\s*\[["\'](?:file|upload|attachment)["\']',
            re.I),
        {'.py'},
        'CWE-434', 'MEDIUM',
        'Validate file extension and MIME type. Use an allowlist of permitted extensions. '
        'Always call secure_filename() on the uploaded filename.'
    ),
    (
        'PI-FILE-002', 'Unrestricted File Upload Path',
        re.compile(
            r'\.save\s*\(\s*os\.path\.join\s*\([^)]*(?:UPLOAD_FOLDER|upload_folder|base_dir)[^)]*'
            r'(?:file(?:name)?|\.filename|path)',
            re.I),
        {'.py'},
        'CWE-434', 'HIGH',
        'Sanitise the filename with secure_filename(), verify the final path stays within '
        'the intended directory, and consider storing files with a generated UUID name.'
    ),

    # ─── Mass Assignment ──────────────────────────────────────────────────────
    (
        'PI-MASS-001', 'Mass Assignment via Request Data',
        re.compile(
            r'(?:update|create)\s*\(\s*(?:\*\*)?(?:request\.(?:form|json|get_json|data)|'
            r'request\.args)\b',
            re.I),
        {'.py', '.rb', '.php'},
        'CWE-915', 'HIGH',
        'Use an explicit allowlist of fields when binding request data to models.'
    ),

    # ─── Shared Link / Access Control ─────────────────────────────────────────
    (
        'PI-AC-001', 'Shared File Link Without Expiry Enforcement',
        re.compile(r'SharedLink|shared_link|share_token', re.I),
        {'.py'},
        'CWE-284', 'LOW',
        'Shared links should have a configurable expiry and be revocable. '
        'Enforce expiry server-side on every access.'
    ),
    (
        'PI-AC-002', 'Direct Object Reference Without Ownership Check',
        re.compile(
            r'(?:get|query\.get|get_or_404|session\.get)\s*\(\s*'
            r'(?:user_id|file_id|share_id|object_id)',
            re.I),
        {'.py'},
        'CWE-639', 'MEDIUM',
        'After fetching an object by ID, verify the current user owns or has access to it '
        'before returning or modifying it.'
    ),

    # ─── Timing Attacks ────────────────────────────────────────────────────────
    (
        'PI-TIMING-001', 'String Comparison for Secret Values (Timing Attack)',
        re.compile(
            r'(?:token|password|secret|key|hash)\s*==\s*(?:request\.|user\.|params\.)',
            re.I),
        {'.py', '.php', '.js', '.ts', '.rb'},
        'CWE-208', 'MEDIUM',
        'Use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison '
        'of secrets to prevent timing-based enumeration.'
    ),

    # ─── Deprecated / Dangerous Functions ─────────────────────────────────────
    (
        'PI-DEP-001', 'Deprecated SQLAlchemy Query.get()',
        re.compile(r'\b(?:Model|User|db\.session)\.(?:query\.get|query\.get_or_404)\s*\(', re.I),
        {'.py'},
        'CWE-477', 'LOW',
        'Replace Query.get() with db.session.get(Model, id) as per SQLAlchemy 2.0.'
    ),
    (
        'PI-DEP-002', 'Use of eval() or exec()',
        re.compile(r'\b(?:eval|exec)\s*\(', re.I),
        {'.py', '.js', '.ts', '.php', '.rb'},
        'CWE-78', 'HIGH',
        'Never use eval() or exec() with user-controlled data. Restructure the logic.'
    ),

    # ─── Flask-Specific ───────────────────────────────────────────────────────
    (
        'PI-FLASK-001', 'SQLALCHEMY_TRACK_MODIFICATIONS Enabled',
        re.compile(r'SQLALCHEMY_TRACK_MODIFICATIONS\s*=\s*True', re.I),
        {'.py'},
        'CWE-400', 'LOW',
        'Set SQLALCHEMY_TRACK_MODIFICATIONS = False to avoid unnecessary overhead and memory leaks.'
    ),
    (
        'PI-FLASK-002', 'Unprotected Admin Route',
        re.compile(
            r'@app\.route\s*\(["\'][^"\']*(?:admin|manage|delete|reset)[^"\']*["\'].*?\)'
            r'\s*\n(?!\s*@(?:login|admin)_required)',
            re.M),
        {'.py'},
        'CWE-284', 'HIGH',
        'All admin-only routes must be decorated with @admin_required or an equivalent guard.'
    ),
]


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


def run_pattern_scanner(source_dir: str):
    """Run pattern-based scanning on all source files."""
    findings = []
    source_path = Path(source_dir)

    for file_path in sorted(source_path.rglob('*')):
        if not file_path.is_file():
            continue
        if _should_skip(file_path):
            continue

        ext = file_path.suffix.lower()

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            continue

        lines = content.splitlines()
        rel_path = str(file_path.relative_to(source_path))

        for rule_id, name, pattern, lang_set, cwe_id, severity, recommendation in PATTERN_RULES:
            if lang_set and ext not in lang_set:
                continue

            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                snippet = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ''

                findings.append({
                    'file_path': rel_path,
                    'line_number': line_num,
                    'end_line': line_num,
                    'vulnerability': name,
                    'description': f"{name} detected at line {line_num}.",
                    'cwe_id': cwe_id,
                    'cve_id': '',
                    'severity': severity,
                    'confidence': 'MEDIUM',
                    'recommendation': recommendation,
                    'tool': 'PatternScanner',
                    'code_snippet': snippet[:200],
                    'vuln_id': rule_id,
                })

    return findings
