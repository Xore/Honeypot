#!/usr/bin/env python3
"""
report.py — Xore/Honeypot PDF report generator

Reads all JSON reports from reports/scanner/ and produces:
  - one combined PDF at reports/pdf/scan-report-<date>.pdf
  - one per-sample PDF (payload name + date) under reports/pdf/samples/
using Jinja2 + WeasyPrint.

Usage:
  python3 report.py --input-dir reports/scanner/ \
                    --output    reports/scan-report-2026-07-26.pdf

Dependencies (installed by the workflow):
  pip install weasyprint jinja2 python-dateutil
  apt install libpango-1.0-0 libpangoft2-1.0-0  (WeasyPrint font rendering)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment, BaseLoader
    from weasyprint import HTML
except ImportError as e:
    print(f'Missing dependency: {e}', file=sys.stderr)
    sys.exit(1)

# ── HTML template ───────────────────────────────────────────────────────────

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  /* Print-safe light-mode snapshot of the canonical Xore/theme tokens. */
  :root {
    --app-bg: #f7f6f2;
    --surface-0: #fbfaf7;
    --surface-1: #f4f2ed;
    --surface-2: #ebe9e3;
    --border-subtle: rgba(34, 31, 28, 0.09);
    --border-strong: rgba(34, 31, 28, 0.18);
    --text-primary: #2f2b27;
    --text-secondary: #68615a;
    --text-muted: #918a82;
    --text-link: #2a78d6;
    --accent: #c76548;
    --success: #3f8764;
    --success-soft: rgba(63, 135, 100, 0.11);
    --warning: #9b6b25;
    --warning-soft: rgba(155, 107, 37, 0.11);
    --danger: #b34f4c;
    --danger-soft: rgba(179, 79, 76, 0.11);
  }
  @page {
    size: A4;
    margin: 22mm 18mm 18mm;
    background: var(--app-bg);
    @top-left { content: "XORE//HONEYPOT"; font-size: 7.5pt; font-weight: 700;
                letter-spacing: 0.08em; color: var(--text-primary); }
    @top-right { content: "MALWARE SCAN REPORT"; font-size: 7.5pt;
                 letter-spacing: 0.08em; color: var(--text-muted); }
    @bottom-left { content: "PRIVATE - HOSTILE-SOURCE TELEMETRY";
                   font-size: 7pt; color: var(--text-muted); }
    @bottom-right { content: "Page " counter(page) " of " counter(pages);
                    font-size: 7pt; color: var(--text-muted); }
  }
  * { box-sizing: border-box; }
  html, body { background: var(--app-bg); }
  body { margin: 0; font-family: 'DejaVu Sans', Arial, sans-serif;
         font-size: 9.5pt; line-height: 1.5; color: var(--text-primary); }
  h1 { margin: 0 0 2mm; font-family: 'DejaVu Serif', Georgia, serif;
       font-size: 24pt; font-weight: 400; letter-spacing: -0.025em;
       color: var(--text-primary); }
  h2 { margin: 9mm 0 3mm; padding: 0 0 2mm 4mm;
       border-bottom: 1px solid var(--border-strong);
       border-left: 3px solid var(--accent); font-size: 13pt;
       color: var(--text-primary); page-break-after: avoid; }
  h3 { margin: 0 0 3mm; font-size: 9.5pt; color: var(--text-primary);
       page-break-after: avoid; }
  .eyebrow { margin-bottom: 2mm; color: var(--accent); font-size: 7.5pt;
             font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; }
  .meta { padding: 3.5mm 4mm; border: 1px solid var(--border-subtle);
          border-radius: 9px; background: var(--surface-1);
          color: var(--text-secondary); font-size: 8pt; line-height: 1.65;
          margin-bottom: 6mm; }
  .classification { color: var(--danger); font-weight: 700; }
  .badge-clean, .badge-detected, .badge-unknown, .badge-error {
    display: inline-block; padding: 1px 7px; border-radius: 999px;
    font-size: 7pt; font-weight: 700; white-space: nowrap;
  }
  .badge-clean    { background: var(--success-soft); color: var(--success); }
  .badge-detected { background: var(--danger-soft); color: var(--danger); }
  .badge-unknown  { background: var(--surface-2); color: var(--text-secondary); }
  .badge-error    { background: var(--warning-soft); color: var(--warning); }
  table { width: 100%; border-collapse: collapse; margin-top: 3mm; font-size: 8.2pt; }
  th { border-bottom: 1px solid var(--border-strong); color: var(--text-muted);
       text-align: left; padding: 2.5mm 2mm; font-size: 7pt; font-weight: 700;
       letter-spacing: 0.055em; text-transform: uppercase; }
  td { padding: 2.5mm 2mm; border-bottom: 1px solid var(--border-subtle);
       color: var(--text-primary); vertical-align: top; }
  tr:nth-child(even) td { background: rgba(244, 242, 237, 0.65); }
  .mono  { font-family: 'DejaVu Sans Mono', monospace; font-size: 7.5pt; }
  .hash  { word-break: break-all; }
  .section-box { border: 1px solid var(--border-subtle); border-radius: 14px;
                 background: var(--surface-0); padding: 4mm; margin-top: 4mm;
                 page-break-inside: avoid; }
  .section-box h3::before { content: ""; display: inline-block; width: 5px;
                            height: 5px; margin-right: 2mm; border-radius: 2px;
                            background: var(--accent); vertical-align: 1px; }
  .error-box { border: 1px solid var(--warning); background: var(--warning-soft);
               border-radius: 9px; padding: 3mm; font-size: 8pt;
               color: var(--warning); }
  .toc li { margin: 1mm 0; }
  .toc a  { color: var(--text-link); text-decoration: none; }
  .summary-table { table-layout: fixed; }
  .summary-table td, .summary-table th { padding-left: 1.2mm; padding-right: 1.2mm;
                                         font-size: 6.5pt; overflow-wrap: anywhere; }
  .summary-table th:nth-child(1) { width: 22%; }
  .summary-table th:nth-child(2) { width: 19%; }
  .summary-table th:nth-child(3) { width: 8%; }
  .summary-table th:nth-child(4) { width: 9%; }
  .summary-table th:nth-child(5) { width: 12%; }
  .summary-table th:nth-child(6) { width: 14%; }
  .summary-table th:nth-child(7) { width: 16%; }
  .summary-table .mono { font-size: 6pt; }
  .permalink { font-size: 7pt; color: var(--text-link); word-break: break-all; }
  hr { border: none; border-top: 1px solid var(--border-strong); margin: 7mm 0; }
</style>
</head>
<body>

<div class="eyebrow">Defensive security operations</div>
<h1>Malware Scan Report</h1>
<div class="meta">
  Generated: {{ generated_at }}<br>
  Repository: {{ repo }}<br>
  Run: {{ run_id }}<br>
  Total samples: {{ reports | length }}<br>
  <span class="classification">Classification: PRIVATE - contains hostile-source telemetry and forensic indicators</span>
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<table class="summary-table">
  <tr>
    <th>File</th><th>SHA256</th><th>Size</th>
    <th>VT</th><th>MetaDefender</th><th>MalwareBazaar</th><th>Status</th>
  </tr>
  {% for r in reports %}
  {% set vt = r.results.get('VirusTotalScanner', {}) %}
  {% set md = r.results.get('MetaDefenderScanner', {}) %}
  {% set mb = r.results.get('MalwareBazaarScanner', {}) %}
  {% set vt_ok = vt.get('_ok', False) %}
  {% set md_ok = md.get('_ok', False) %}
  {% set mb_ok = mb.get('_ok', False) %}
  {% set pending_statuses = ('queued', 'pending', 'in_queue', 'in_progress', 'timeout') %}
  {% set vt_pending = vt.get('status', '') | lower in pending_statuses %}
  {% set md_pending = md.get('status', '') | lower in pending_statuses %}
  {% set mb_pending = mb.get('status', '') | lower in pending_statuses %}
  {% set vt_pos = vt.get('positives', 0) if vt_ok else None %}
  {% set any_ok = r.results.values() | selectattr('_ok') | list | length > 0 %}
  <tr>
    <td>{{ r.filename }}</td>
    <td class="mono hash">{{ r.sha256[:32] }}&hellip;</td>
    <td>{{ "{:,}".format(r.size) }} B</td>
    <td>
      {% if vt_pending %}
        <span class="badge-unknown">queued</span>
      {% elif vt_ok %}
        {% if vt_pos > 0 %}
          <span class="badge-detected">{{ vt_pos }}/{{ vt.get('total','?') }}</span>
        {% else %}
          <span class="badge-clean">0/{{ vt.get('total','?') }}</span>
        {% endif %}
      {% else %}
        <span class="badge-error">error</span>
      {% endif %}
    </td>
    <td>
      {% if md_pending %}
        <span class="badge-unknown">queued</span>
      {% elif md_ok %}
        {% set md_pos = md.get('positives', 0) %}
        {% if md_pos > 0 %}
          <span class="badge-detected">{{ md_pos }}/{{ md.get('total','?') }}</span>
        {% else %}
          <span class="badge-clean">0/{{ md.get('total','?') }}</span>
        {% endif %}
      {% else %}
        <span class="badge-error">error</span>
      {% endif %}
    </td>
    <td>
      {% if mb_pending %}
        <span class="badge-unknown">queued</span>
      {% elif mb_ok %}
        {% if mb.get('signature') %}
          <span class="badge-detected">{{ mb.signature }}</span>
        {% else %}
          <span class="badge-unknown">unknown</span>
        {% endif %}
      {% else %}
        <span class="badge-error">error</span>
      {% endif %}
    </td>
    <td>
      {% if vt_pending or md_pending or mb_pending %}
        <span class="badge-unknown">PENDING</span>
      {% elif any_ok %}
        <span class="badge-{% if vt_pos and vt_pos > 0 %}detected{% else %}clean{% endif %}">
          {% if vt_pos and vt_pos > 0 %}DETECTED{% else %}CLEAN / UNKNOWN{% endif %}
        </span>
      {% else %}
        <span class="badge-error">ALL FAILED</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>

<!-- Per-sample detail -->
{% for r in reports %}
<h2>{{ loop.index }}. {{ r.filename }}</h2>

<div class="section-box">
  <h3>Hashes</h3>
  <table>
    <tr><th>Algorithm</th><th>Value</th></tr>
    <tr><td>SHA256</td><td class="mono hash">{{ r.sha256 }}</td></tr>
    <tr><td>SHA1</td>  <td class="mono hash">{{ r.sha1 }}</td></tr>
    <tr><td>MD5</td>   <td class="mono hash">{{ r.md5 }}</td></tr>
    <tr><td>Size</td>  <td>{{ "{:,}".format(r.size) }} bytes</td></tr>
    <tr><td>Scanned</td><td>{{ r.scanned_at }}</td></tr>
  </table>
</div>

{% for scanner_name, result in r.results.items() %}
<div class="section-box">
  <h3>{{ scanner_name | replace('Scanner','') | replace('Scanner','') }}</h3>
  {% if result.get('status') == 'failed' or result.get('error') %}
    <div class="error-box">
      <strong>Error:</strong> {{ result.get('error', 'unknown error') }}
    </div>
  {% else %}
    <table>
      {% for k, v in result.items() %}
      {% if k not in ('source', '_ok', 'traceback', 'stats', 'file_info') %}
      <tr>
        <td style="width:30%; font-weight:bold">{{ k }}</td>
        <td>
          {% if k == 'permalink' and v %}
            <a class="permalink" href="{{ v }}">{{ v }}</a>
          {% elif v is mapping %}
            <span class="mono">{{ v | tojson }}</span>
          {% elif v is iterable and v is not string %}
            {{ v | join(', ') }}
          {% else %}
            {{ v }}
          {% endif %}
        </td>
      </tr>
      {% endif %}
      {% endfor %}
    </table>
    {% if result.get('stats') %}
    <h3 style="font-size:8.5pt; margin-top:3mm">Detection breakdown</h3>
    <table>
      {% for stat_k, stat_v in result.stats.items() %}
      <tr><td style="width:30%">{{ stat_k }}</td><td>{{ stat_v }}</td></tr>
      {% endfor %}
    </table>
    {% endif %}
  {% endif %}
</div>
{% endfor %}

{% if not loop.last %}<hr>{% endif %}
{% endfor %}

</body>
</html>
"""


def _safe_stem(name: str) -> str:
    stem = re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('_')
    return stem or 'sample'


def render_sample_pdfs(reports: list, out_dir: Path, generated_at: str,
                       repo: str, run_id: str) -> None:
    """One PDF per sample, named <payload-name>-<scan-date>.pdf.

    Reuses the same TEMPLATE as the combined report (rendered with a
    single-element `reports` list) so per-sample PDFs keep the same design —
    header/footer, executive summary badges, detection breakdown — instead of
    a different one-off layout.
    """
    env = Environment(loader=BaseLoader())
    env.filters['tojson'] = lambda v: json.dumps(v, indent=2)
    tmpl = env.from_string(TEMPLATE)
    out_dir.mkdir(parents=True, exist_ok=True)

    for r in reports:
        scan_date = (r.get('scanned_at') or '')[:10] or 'unknown-date'
        out_path = out_dir / f'{_safe_stem(r["filename"])}-{scan_date}.pdf'
        html = tmpl.render(reports=[r], generated_at=generated_at,
                           repo=repo, run_id=run_id)
        HTML(string=html, base_url=str(out_dir)).write_pdf(str(out_path))
        print(f'  Per-sample PDF: {out_path}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', default='reports/scanner/')
    parser.add_argument('--output',    required=True)
    parser.add_argument('--per-sample-dir', default='reports/pdf/samples/',
                        help='Directory for one PDF per sample (payload name + date)')
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    report_files = sorted(input_dir.glob('*.json'))

    if not report_files:
        print(f'No JSON reports found in {input_dir}', file=sys.stderr)
        sys.exit(0)  # not an error — nothing to report

    reports = []
    for f in report_files:
        try:
            reports.append(json.loads(f.read_text()))
        except Exception as e:
            print(f'WARNING: skipping {f}: {e}', file=sys.stderr)

    env = Environment(loader=BaseLoader())
    env.filters['tojson'] = lambda v: json.dumps(v, indent=2)
    tmpl = env.from_string(TEMPLATE)

    repo = os.environ.get('GITHUB_REPO', 'Xore/Honeypot')
    run_id = os.environ.get('GITHUB_RUN_ID', 'local')
    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    html = tmpl.render(
        reports=reports,
        generated_at=generated_at,
        repo=repo,
        run_id=run_id,
    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    print(f'Rendering PDF → {output} ({len(reports)} sample(s))...')
    HTML(string=html, base_url=str(output.parent)).write_pdf(str(output))
    size_kb = output.stat().st_size // 1024
    print(f'PDF written: {output} ({size_kb} KB)')

    render_sample_pdfs(reports, Path(args.per_sample_dir), generated_at, repo, run_id)


if __name__ == '__main__':
    main()
