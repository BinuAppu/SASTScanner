"""HTML report generator."""
import html
from collections import Counter
from datetime import datetime


SEVERITY_COLORS = {
    'CRITICAL': '#ff4757',
    'HIGH': '#ff6b35',
    'MEDIUM': '#ffa502',
    'LOW': '#2ed573',
    'INFO': '#1e90ff',
}

STATUS_COLORS = {
    'new': '#ff4757',
    'recurring': '#ffa502',
    'fixed': '#2ed573',
}


def _esc(text):
    return html.escape(str(text or ''))


def generate_html(findings: list, scan, output_path: str):
    scan_name = scan['name'] if scan else 'SAST Report'
    scan_version = scan['version'] if scan else 1
    created_at = scan['created_at'] if scan else datetime.utcnow().isoformat()

    severity_counts = Counter(f.get('severity', 'INFO') for f in findings)
    status_counts = Counter(f.get('status', 'new') for f in findings)

    rows = []
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'INFO')
        status = f.get('status', 'new')
        sev_color = SEVERITY_COLORS.get(sev, '#888')
        status_color = STATUS_COLORS.get(status, '#888')
        rows.append(f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:{sev_color}">{_esc(sev)}</span></td>
          <td><span class="badge" style="background:{status_color}">{_esc(status.upper())}</span></td>
          <td class="monospace">{_esc(f.get('file_path',''))}</td>
          <td style="text-align:center">{_esc(f.get('line_number',''))}</td>
          <td><strong>{_esc(f.get('vulnerability',''))}</strong><br>
              <small style="color:#aaa">{_esc(f.get('description',''))}</small></td>
          <td>{_esc(f.get('cwe_id',''))}</td>
          <td>{_esc(f.get('cve_id',''))}</td>
          <td>{_esc(f.get('tool',''))}</td>
          <td>{_esc(f.get('recommendation',''))}</td>
          <td><code>{_esc(f.get('code_snippet',''))}</code></td>
        </tr>""")

    rows_html = '\n'.join(rows)

    chart_labels = list(SEVERITY_COLORS.keys())
    chart_data = [severity_counts.get(s, 0) for s in chart_labels]
    chart_colors = list(SEVERITY_COLORS.values())

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Report – {_esc(scan_name)} v{scan_version}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
         background: #0f1117; color: #e0e0e0; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 2rem; color: #6c63ff; margin-bottom: 0.25rem; }}
  .subtitle {{ color: #888; margin-bottom: 2rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1a1d27; border-radius: 12px; padding: 1.2rem;
                border-left: 4px solid; text-align: center; }}
  .stat-card .count {{ font-size: 2rem; font-weight: bold; }}
  .stat-card .label {{ font-size: 0.8rem; color: #aaa; text-transform: uppercase; }}
  .section {{ background: #1a1d27; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }}
  .section h2 {{ font-size: 1.2rem; color: #6c63ff; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #12141e; color: #6c63ff; padding: 10px 12px;
        text-align: left; position: sticky; top: 0; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #252836; vertical-align: top; }}
  tr:hover td {{ background: #1e2130; }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px;
            font-size: 0.75rem; font-weight: bold; color: #fff; }}
  .monospace {{ font-family: monospace; font-size: 0.8rem; }}
  code {{ background: #12141e; padding: 2px 4px; border-radius: 3px; font-size: 0.8rem;
          word-break: break-all; }}
  .chart-container {{ max-width: 400px; margin: 0 auto; }}
  .status-row {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .status-card {{ background: #1a1d27; border-radius: 12px; padding: 1rem; text-align: center; }}
  .footer {{ text-align: center; color: #555; margin-top: 3rem; font-size: 0.85rem; }}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="container">
  <h1>SAST Security Report</h1>
  <p class="subtitle">Scan: <strong>{_esc(scan_name)}</strong> &nbsp;|&nbsp;
     Version: <strong>v{scan_version}</strong> &nbsp;|&nbsp;
     Generated: <strong>{_esc(created_at[:19].replace('T',' '))}</strong> &nbsp;|&nbsp;
     Total Findings: <strong>{len(findings)}</strong>
  </p>

  <div class="stats">
    {''.join(f"""<div class="stat-card" style="border-color:{SEVERITY_COLORS[s]}">
      <div class="count" style="color:{SEVERITY_COLORS[s]}">{severity_counts.get(s,0)}</div>
      <div class="label">{s}</div>
    </div>""" for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'])}
  </div>

  <div class="status-row">
    <div class="status-card">
      <div style="font-size:1.8rem;color:#ff4757;font-weight:bold">{status_counts.get('new',0)}</div>
      <div style="color:#aaa;font-size:0.85rem">NEW FINDINGS</div>
    </div>
    <div class="status-card">
      <div style="font-size:1.8rem;color:#ffa502;font-weight:bold">{status_counts.get('recurring',0)}</div>
      <div style="color:#aaa;font-size:0.85rem">RECURRING</div>
    </div>
    <div class="status-card">
      <div style="font-size:1.8rem;color:#2ed573;font-weight:bold">{status_counts.get('fixed',0)}</div>
      <div style="color:#aaa;font-size:0.85rem">FIXED</div>
    </div>
  </div>

  <div class="section">
    <h2>Severity Distribution</h2>
    <div class="chart-container">
      <canvas id="sevChart"></canvas>
    </div>
  </div>

  <div class="section">
    <h2>Findings ({len(findings)} total)</h2>
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>#</th><th>Severity</th><th>Status</th><th>File</th><th>Line</th>
          <th>Vulnerability</th><th>CWE</th><th>CVE</th><th>Tool</th>
          <th>Recommendation</th><th>Code Snippet</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
    </div>
  </div>

  <div class="footer">Generated by SAST Scanner &bull; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
</div>
<script>
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {chart_labels},
    datasets: [{{ data: {chart_data}, backgroundColor: {chart_colors}, borderWidth: 2, borderColor: '#0f1117' }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#e0e0e0' }} }} }}, cutout: '60%' }}
}});
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html_content)
