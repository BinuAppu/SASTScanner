import sqlite3
import os
import hashlib
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sast_scanner.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            folder_path TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT "pending",
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            total_files INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            end_line INTEGER,
            vulnerability TEXT NOT NULL,
            description TEXT,
            cwe_id TEXT,
            cve_id TEXT,
            severity TEXT NOT NULL,
            confidence TEXT,
            recommendation TEXT,
            tool TEXT NOT NULL,
            code_snippet TEXT,
            fingerprint TEXT NOT NULL,
            status TEXT DEFAULT "new",
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS scan_engines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            engine_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT "pending",
            findings_count INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0,
            engine_version TEXT,
            error_message TEXT,
            ran_at TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(name);
        CREATE INDEX IF NOT EXISTS idx_engines_scan_id ON scan_engines(scan_id);
    ''')

    existing = cur.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not existing:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ('admin', generate_password_hash('pass@123'))
        )

    conn.commit()
    conn.close()


# ─── User operations ──────────────────────────────────────────────────────────

def get_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def update_user_password(user_id, new_password):
    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()


def verify_password(user, password):
    return check_password_hash(user['password_hash'], password)


# ─── Scan operations ──────────────────────────────────────────────────────────

def create_scan(name, folder_path, version):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO scans (name, folder_path, version, status, created_at)
           VALUES (?, ?, ?, 'running', ?)""",
        (name, folder_path, version, datetime.utcnow().isoformat())
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan(scan_id):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return scan


def get_scans_by_name(name):
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scans WHERE name = ? ORDER BY version DESC",
        (name,)
    ).fetchall()
    conn.close()
    return scans


def get_all_scans():
    conn = get_db()
    scans = conn.execute("""
        SELECT s1.* FROM scans s1
        INNER JOIN (
            SELECT name, MAX(version) as max_v FROM scans GROUP BY name
        ) s2 ON s1.name = s2.name AND s1.version = s2.max_v
        ORDER BY s1.created_at DESC
    """).fetchall()
    conn.close()
    return scans


def update_scan_status(scan_id, status, total_files=None, total_findings=None,
                        critical=0, high=0, medium=0, low=0, info=0, error=None):
    conn = get_db()
    if status == 'completed':
        conn.execute("""
            UPDATE scans SET status=?, completed_at=?, total_files=?, total_findings=?,
            critical_count=?, high_count=?, medium_count=?, low_count=?, info_count=?
            WHERE id=?
        """, (status, datetime.utcnow().isoformat(), total_files, total_findings,
              critical, high, medium, low, info, scan_id))
    elif status == 'failed':
        conn.execute(
            "UPDATE scans SET status=?, error_message=?, completed_at=? WHERE id=?",
            (status, error, datetime.utcnow().isoformat(), scan_id)
        )
    else:
        conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    conn.commit()
    conn.close()


def get_latest_version(scan_name):
    conn = get_db()
    row = conn.execute(
        "SELECT MAX(version) as max_v FROM scans WHERE name = ?", (scan_name,)
    ).fetchone()
    conn.close()
    return row['max_v'] if row and row['max_v'] else 0


def scan_name_exists(scan_name):
    conn = get_db()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM scans WHERE name = ?", (scan_name,)
    ).fetchone()
    conn.close()
    return row['cnt'] > 0


def delete_scan_by_name(scan_name):
    """Delete all versions of a scan from DB and disk. Returns folder paths removed."""
    conn = get_db()
    scans = conn.execute(
        "SELECT id, folder_path FROM scans WHERE name = ?", (scan_name,)
    ).fetchall()
    scan_ids = [s['id'] for s in scans]
    folders  = list({s['folder_path'] for s in scans})

    for sid in scan_ids:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM scan_engines WHERE scan_id = ?", (sid,))
    conn.execute("DELETE FROM scans WHERE name = ?", (scan_name,))
    conn.commit()
    conn.close()

    # Remove from disk — delete the scan-name parent folder
    for folder in folders:
        # folder is e.g. scans/MyApp/v2  → parent is scans/MyApp
        parent = os.path.dirname(folder)
        if os.path.isdir(parent):
            shutil.rmtree(parent, ignore_errors=True)
        elif os.path.isdir(folder):
            shutil.rmtree(folder, ignore_errors=True)
    return scan_ids


def delete_scan_version(scan_id):
    """Delete a single scan version from DB and disk."""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return False
    conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scan_engines WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    folder = scan['folder_path']
    if os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)
    return True


# ─── Finding operations ───────────────────────────────────────────────────────

def save_findings(scan_id, findings):
    conn = get_db()
    for f in findings:
        conn.execute("""
            INSERT INTO findings
            (scan_id, file_path, line_number, end_line, vulnerability, description,
             cwe_id, cve_id, severity, confidence, recommendation, tool, code_snippet,
             fingerprint, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            f.get('file_path', ''),
            f.get('line_number'),
            f.get('end_line'),
            f.get('vulnerability', ''),
            f.get('description', ''),
            f.get('cwe_id', ''),
            f.get('cve_id', ''),
            f.get('severity', 'INFO'),
            f.get('confidence', 'MEDIUM'),
            f.get('recommendation', ''),
            f.get('tool', ''),
            f.get('code_snippet', ''),
            f.get('fingerprint', ''),
            f.get('status', 'new')
        ))
    conn.commit()
    conn.close()


def get_findings(scan_id):
    conn = get_db()
    findings = conn.execute("""
        SELECT * FROM findings WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            file_path, line_number
    """, (scan_id,)).fetchall()
    conn.close()
    return findings


def get_previous_scan_findings(scan_name, current_version):
    conn = get_db()
    prev_version = current_version - 1
    if prev_version < 1:
        conn.close()
        return set()
    prev_scan = conn.execute(
        "SELECT id FROM scans WHERE name = ? AND version = ?",
        (scan_name, prev_version)
    ).fetchone()
    if not prev_scan:
        conn.close()
        return set()
    fps = conn.execute(
        "SELECT fingerprint FROM findings WHERE scan_id = ?",
        (prev_scan['id'],)
    ).fetchall()
    conn.close()
    return {row['fingerprint'] for row in fps}


def compute_fingerprint(file_path, vulnerability_id, tool):
    raw = f"{file_path}::{vulnerability_id}::{tool}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── Engine-status operations ─────────────────────────────────────────────────

def save_engine_results(scan_id, engine_results):
    """Persist per-engine run metadata."""
    conn = get_db()
    for r in engine_results:
        conn.execute("""
            INSERT INTO scan_engines
            (scan_id, engine_name, status, findings_count, duration_seconds,
             engine_version, error_message, ran_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            r.get('engine_name', ''),
            r.get('status', 'completed'),
            r.get('findings_count', 0),
            r.get('duration_seconds', 0),
            r.get('engine_version', ''),
            r.get('error_message', ''),
            r.get('ran_at', datetime.utcnow().isoformat()),
        ))
    conn.commit()
    conn.close()


def get_engine_results(scan_id):
    conn = get_db()
    results = conn.execute(
        "SELECT * FROM scan_engines WHERE scan_id = ? ORDER BY id",
        (scan_id,)
    ).fetchall()
    conn.close()
    return results
