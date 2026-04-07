"""CSV report generator."""
import csv


HEADERS = [
    'Severity', 'Status', 'File', 'Line', 'Vulnerability',
    'Description', 'CWE', 'CVE', 'Tool', 'Confidence', 'Recommendation', 'Code Snippet'
]


def generate_csv(findings: list, output_path: str):
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for finding in findings:
            writer.writerow([
                finding.get('severity', ''),
                finding.get('status', '').upper(),
                finding.get('file_path', ''),
                finding.get('line_number', ''),
                finding.get('vulnerability', ''),
                finding.get('description', ''),
                finding.get('cwe_id', ''),
                finding.get('cve_id', ''),
                finding.get('tool', ''),
                finding.get('confidence', ''),
                finding.get('recommendation', ''),
                finding.get('code_snippet', '').replace('\n', ' '),
            ])
