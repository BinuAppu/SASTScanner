"""
SAST Scanner – Flask web application.
Default credentials: admin / pass@123
"""
import os
import re
import uuid
import shutil
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, abort
)
from werkzeug.utils import secure_filename

from models.database import (
    init_db, get_user_by_username, get_user_by_id, verify_password,
    update_user_password, create_scan, get_scan, get_all_scans,
    get_scans_by_name, get_findings, update_scan_status,
    get_latest_version, scan_name_exists,
    delete_scan_by_name, delete_scan_version, get_engine_results
)
from scanner.aggregator import extract_zip, start_scan_thread

# ─── App Setup ────────────────────────────────────────────────────────────────

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR  = os.path.join(BASE_DIR, 'scans')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'sast-scanner-secret-key-2024-change-me')
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024   # 512 MB

os.makedirs(SCANS_DIR,  exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── Init DB ──────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def _current_user():
    uid = session.get('user_id')
    return get_user_by_id(uid) if uid else None


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _safe_scan_name(name: str) -> str:
    """Sanitize scan name for use as folder name."""
    name = re.sub(r'[^\w\-. ]', '_', name.strip())
    return name[:80]


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = get_user_by_username(username)
        if user and verify_password(user, password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    scans = get_all_scans()
    return render_template('dashboard.html', scans=scans, user=_current_user())


@app.route('/new-scan', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        raw_name   = request.form.get('scan_name', '').strip()
        scan_name  = _safe_scan_name(raw_name)
        zip_file   = request.files.get('zip_file')

        if not scan_name:
            flash('Scan name is required.', 'error')
            return render_template('new_scan.html', user=_current_user())

        if not zip_file or zip_file.filename == '':
            flash('Please upload a ZIP file.', 'error')
            return render_template('new_scan.html', user=_current_user())

        if not zip_file.filename.lower().endswith('.zip'):
            flash('Only .zip files are accepted.', 'error')
            return render_template('new_scan.html', user=_current_user())

        # Determine version
        version = get_latest_version(scan_name) + 1

        # Paths
        scan_folder   = os.path.join(SCANS_DIR, scan_name, f'v{version}')
        source_dir    = os.path.join(scan_folder, 'source')
        reports_dir   = os.path.join(scan_folder, 'reports')

        os.makedirs(scan_folder, exist_ok=True)
        os.makedirs(source_dir,  exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)

        # Save ZIP
        zip_path = os.path.join(scan_folder, secure_filename(zip_file.filename))
        zip_file.save(zip_path)

        # Extract
        if not extract_zip(zip_path, source_dir):
            shutil.rmtree(scan_folder, ignore_errors=True)
            flash('Failed to extract ZIP file. Make sure it is a valid archive.', 'error')
            return render_template('new_scan.html', user=_current_user())

        # Create scan record
        scan_id = create_scan(scan_name, scan_folder, version)

        # Kick off background scan
        start_scan_thread(scan_id, scan_name, version, source_dir, reports_dir)

        flash(f'Scan "{scan_name}" v{version} started successfully.', 'success')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    return render_template('new_scan.html', user=_current_user())


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)

    findings       = get_findings(scan_id) if scan['status'] == 'completed' else []
    versions       = get_scans_by_name(scan['name'])
    engine_results = get_engine_results(scan_id)

    return render_template(
        'scan_detail.html',
        scan=scan,
        findings=findings,
        versions=versions,
        engine_results=engine_results,
        user=_current_user(),
    )


@app.route('/api/scan/<int:scan_id>/status')
@login_required
def scan_status_api(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'not found'}), 404
    engines = get_engine_results(scan_id)
    return jsonify({
        'status':          scan['status'],
        'total_findings':  scan['total_findings'],
        'critical_count':  scan['critical_count'],
        'high_count':      scan['high_count'],
        'medium_count':    scan['medium_count'],
        'low_count':       scan['low_count'],
        'info_count':      scan['info_count'],
        'error_message':   scan['error_message'],
        'engines':         [dict(e) for e in engines],
    })


@app.route('/scan/<int:scan_id>/report/<fmt>')
@login_required
def download_report(scan_id, fmt):
    scan = get_scan(scan_id)
    if not scan or scan['status'] != 'completed':
        abort(404)

    reports_dir = os.path.join(scan['folder_path'], 'reports')
    ext_map = {'csv': 'report.csv', 'html': 'report.html', 'pdf': 'report.pdf'}
    if fmt not in ext_map:
        abort(404)

    file_path = os.path.join(reports_dir, ext_map[fmt])
    if not os.path.exists(file_path):
        abort(404)

    mime_map = {
        'csv':  'text/csv',
        'html': 'text/html',
        'pdf':  'application/pdf',
    }
    filename = f"sast_{scan['name']}_v{scan['version']}.{fmt}"
    return send_file(file_path, mimetype=mime_map[fmt],
                     as_attachment=(fmt != 'html'), download_name=filename)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = _current_user()
    if request.method == 'POST':
        current_pw  = request.form.get('current_password', '')
        new_pw      = request.form.get('new_password', '')
        confirm_pw  = request.form.get('confirm_password', '')

        if not verify_password(user, current_pw):
            flash('Current password is incorrect.', 'error')
        elif len(new_pw) < 6:
            flash('New password must be at least 6 characters.', 'error')
        elif new_pw != confirm_pw:
            flash('New passwords do not match.', 'error')
        else:
            update_user_password(user['id'], new_pw)
            flash('Password updated successfully.', 'success')

    return render_template('settings.html', user=user)


@app.route('/scan/<scan_name>/delete', methods=['POST'])
@login_required
def delete_scan(scan_name):
    """Delete all versions of a scan (DB records + files on disk)."""
    deleted = delete_scan_by_name(scan_name)
    if deleted:
        flash(f'Scan "{scan_name}" and all its versions have been deleted.', 'success')
    else:
        flash(f'Scan "{scan_name}" not found.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/scan/<int:scan_id>/delete-version', methods=['POST'])
@login_required
def delete_scan_version_route(scan_id):
    """Delete a single scan version."""
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    scan_name = scan['name']
    version   = scan['version']

    # If it's the only version, delete the whole scan
    versions = get_scans_by_name(scan_name)
    if len(versions) <= 1:
        delete_scan_by_name(scan_name)
        flash(f'Scan "{scan_name}" deleted (last version removed).', 'success')
        return redirect(url_for('dashboard'))

    delete_scan_version(scan_id)
    flash(f'Version v{version} of "{scan_name}" has been deleted.', 'success')
    # Redirect to the latest remaining version
    remaining = get_scans_by_name(scan_name)
    return redirect(url_for('scan_detail', scan_id=remaining[0]['id']))


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', user=_current_user()), 404


@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum upload size is 512 MB.', 'error')
    return redirect(url_for('new_scan'))


# ─── Template helpers ─────────────────────────────────────────────────────────

@app.template_filter('severity_class')
def severity_class(severity):
    return {
        'CRITICAL': 'sev-critical',
        'HIGH':     'sev-high',
        'MEDIUM':   'sev-medium',
        'LOW':      'sev-low',
        'INFO':     'sev-info',
    }.get(severity, 'sev-info')


@app.template_filter('status_class')
def status_class(status):
    return {
        'new':       'status-new',
        'recurring': 'status-recurring',
        'fixed':     'status-fixed',
    }.get(status, 'status-new')


@app.template_filter('format_dt')
def format_dt(value):
    if not value:
        return '—'
    try:
        return datetime.fromisoformat(str(value)).strftime('%d %b %Y %H:%M')
    except Exception:
        return str(value)[:16]


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
