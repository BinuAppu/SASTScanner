"""PDF report generator using ReportLab."""
from collections import Counter
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Table, TableStyle,
        Spacer, HRFlowable, PageBreak
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


SEVERITY_RGB = {
    'CRITICAL': colors.HexColor('#ff4757'),
    'HIGH':     colors.HexColor('#ff6b35'),
    'MEDIUM':   colors.HexColor('#ffa502'),
    'LOW':      colors.HexColor('#2ed573'),
    'INFO':     colors.HexColor('#1e90ff'),
}

STATUS_RGB = {
    'new':       colors.HexColor('#ff4757'),
    'recurring': colors.HexColor('#ffa502'),
    'fixed':     colors.HexColor('#2ed573'),
}

BG_DARK  = colors.HexColor('#0f1117')
BG_CARD  = colors.HexColor('#1a1d27')
FG_TEXT  = colors.HexColor('#e0e0e0')
PURPLE   = colors.HexColor('#6c63ff')
GREY     = colors.HexColor('#aaaaaa')


def _severity_color(sev):
    return SEVERITY_RGB.get(sev, colors.grey)


def _status_color(status):
    return STATUS_RGB.get(status, colors.grey)


def generate_pdf(findings: list, scan, output_path: str):
    if not REPORTLAB_AVAILABLE:
        _generate_pdf_fallback(findings, scan, output_path)
        return

    scan_name = scan['name'] if scan else 'SAST Report'
    scan_version = scan['version'] if scan else 1
    created_at = (scan['created_at'] or '')[:19].replace('T', ' ')

    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"SAST Report – {scan_name}",
    )

    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle('Normal', parent=styles['Normal'],
                                   textColor=FG_TEXT, fontSize=8, leading=10)
    style_title = ParagraphStyle('Title', parent=styles['Title'],
                                  textColor=PURPLE, fontSize=20, leading=24)
    style_h2 = ParagraphStyle('H2', parent=styles['Heading2'],
                               textColor=PURPLE, fontSize=13, leading=16)
    style_small = ParagraphStyle('Small', parent=styles['Normal'],
                                  textColor=GREY, fontSize=7, leading=9)
    style_code = ParagraphStyle('Code', parent=styles['Code'],
                                 textColor=FG_TEXT, fontSize=7, leading=9,
                                 backColor=colors.HexColor('#12141e'))

    story = []

    # ── Title block ───────────────────────────────────────────────────────────
    story.append(Paragraph("SAST Security Report", style_title))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Scan: <b>{scan_name}</b> &nbsp;&nbsp; Version: <b>v{scan_version}</b> &nbsp;&nbsp; "
        f"Generated: <b>{created_at}</b> &nbsp;&nbsp; Total Findings: <b>{len(findings)}</b>",
        style_normal
    ))
    story.append(HRFlowable(width='100%', thickness=1, color=PURPLE, spaceAfter=8))

    # ── Summary stats ─────────────────────────────────────────────────────────
    severity_counts = Counter(f.get('severity', 'INFO') for f in findings)
    status_counts   = Counter(f.get('status', 'new') for f in findings)

    stat_data = [['Severity', 'Count']] + [
        [s, str(severity_counts.get(s, 0))]
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    ]
    stat_table = Table(stat_data, colWidths=[5*cm, 3*cm])
    stat_style = TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), BG_CARD),
        ('TEXTCOLOR',    (0, 0), (-1, 0), PURPLE),
        ('FONTSIZE',     (0, 0), (-1, -1), 9),
        ('ALIGN',        (1, 0), (1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [BG_DARK, BG_CARD]),
        ('TEXTCOLOR',    (0, 1), (-1, -1), FG_TEXT),
        ('BOX',          (0, 0), (-1, -1), 0.5, GREY),
        ('INNERGRID',    (0, 0), (-1, -1), 0.25, GREY),
    ])
    for i, sev in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], 1):
        stat_style.add('TEXTCOLOR', (1, i), (1, i), _severity_color(sev))
    stat_table.setStyle(stat_style)

    status_data = [['Status', 'Count'],
                   ['New',       str(status_counts.get('new', 0))],
                   ['Recurring', str(status_counts.get('recurring', 0))],
                   ['Fixed',     str(status_counts.get('fixed', 0))]]
    status_table = Table(status_data, colWidths=[5*cm, 3*cm])
    status_table.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), BG_CARD),
        ('TEXTCOLOR',    (0, 0), (-1, 0), PURPLE),
        ('FONTSIZE',     (0, 0), (-1, -1), 9),
        ('ALIGN',        (1, 0), (1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [BG_DARK, BG_CARD]),
        ('TEXTCOLOR',    (0, 1), (-1, -1), FG_TEXT),
        ('BOX',          (0, 0), (-1, -1), 0.5, GREY),
        ('INNERGRID',    (0, 0), (-1, -1), 0.25, GREY),
    ]))

    summary_outer = Table([[stat_table, status_table]], colWidths=['50%', '50%'])
    summary_outer.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
    story.append(summary_outer)
    story.append(Spacer(1, 6*mm))

    # ── Findings table ────────────────────────────────────────────────────────
    story.append(Paragraph(f"Findings ({len(findings)})", style_h2))
    story.append(Spacer(1, 2*mm))

    headers = ['#', 'Severity', 'Status', 'File', 'Line',
               'Vulnerability', 'CWE', 'Tool', 'Recommendation']
    col_widths = [1*cm, 2.5*cm, 2.5*cm, 5*cm, 1.5*cm, 6*cm, 2.5*cm, 3*cm, 6*cm]

    table_data = [headers]
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'INFO')
        status = f.get('status', 'new')
        rec = f.get('recommendation', '')[:120] + ('…' if len(f.get('recommendation','')) > 120 else '')
        vuln = f.get('vulnerability', '')
        desc = f.get('description', '')[:80]
        table_data.append([
            str(i),
            Paragraph(sev, style_small),
            Paragraph(status.upper(), style_small),
            Paragraph(f.get('file_path', ''), style_small),
            str(f.get('line_number', '')),
            Paragraph(f"<b>{vuln}</b><br/>{desc}", style_small),
            f.get('cwe_id', ''),
            f.get('tool', ''),
            Paragraph(rec, style_small),
        ])

    findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    ts = TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), BG_CARD),
        ('TEXTCOLOR',    (0, 0), (-1, 0), PURPLE),
        ('FONTSIZE',     (0, 0), (-1, 0), 8),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 1), (-1, -1), 7),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [BG_DARK, BG_CARD]),
        ('TEXTCOLOR',    (0, 1), (-1, -1), FG_TEXT),
        ('BOX',          (0, 0), (-1, -1), 0.5, GREY),
        ('INNERGRID',    (0, 0), (-1, -1), 0.25, GREY),
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
        ('ALIGN',        (4, 0), (4, -1), 'CENTER'),
    ])
    # Colour severity & status cells
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'INFO')
        status = f.get('status', 'new')
        ts.add('TEXTCOLOR', (1, i), (1, i), _severity_color(sev))
        ts.add('TEXTCOLOR', (2, i), (2, i), _status_color(status))
    findings_table.setStyle(ts)
    story.append(findings_table)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GREY))
    story.append(Paragraph(
        f"Generated by SAST Scanner &nbsp;&nbsp; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        ParagraphStyle('Footer', parent=style_small, alignment=TA_CENTER)
    ))

    doc.build(story)


def _generate_pdf_fallback(findings, scan, output_path):
    """Minimal plain-text PDF when reportlab is unavailable."""
    lines = [f"SAST Security Report\n{'='*60}\n"]
    if scan:
        lines.append(f"Scan: {scan['name']}  Version: v{scan['version']}\n")
    lines.append(f"Total Findings: {len(findings)}\n\n")
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f.get('severity','')}] {f.get('vulnerability','')} "
            f"@ {f.get('file_path','')}:{f.get('line_number','')}\n"
            f"   CWE: {f.get('cwe_id','')}\n"
            f"   {f.get('recommendation','')}\n\n"
        )
    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(''.join(lines))
