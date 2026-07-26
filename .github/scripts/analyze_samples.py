#!/usr/bin/env python3
"""
Malware Analysis Pipeline
Submits samples to VirusTotal + JoeSandbox, generates PDF reports,
updates IOC CSV, and saves everything to reports/

Requires env vars: VT_API_KEY, JOESANDBOX_API_KEY
Requires packages: requests vt-py weasyprint jinja2
"""

import os
import sys
import csv
import time
import json
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

import requests
from jinja2 import Template

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

VT_API_KEY       = os.environ.get('VT_API_KEY', '')
JOE_API_KEY      = os.environ.get('JOESANDBOX_API_KEY', '')
VT_BASE          = 'https://www.virustotal.com/api/v3'
JOE_BASE         = 'https://jbxcloud.joesecurity.org/api'
REPORT_DIR       = Path('reports')
IOC_CSV          = Path('iocs/hashes.csv')
# Rate limits: VT public = 4 req/min, 500/day
VT_RATE_SLEEP    = 16   # seconds between VT requests (safe for public API)
JOE_POLL_SLEEP   = 60   # seconds between JoeSandbox status polls
JOE_MAX_WAIT     = 1800 # 30 min max wait for Joe analysis


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def md5_of(path: Path) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def sha1_of(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ─── VirusTotal ───────────────────────────────────────────────────────────────

def vt_headers() -> dict:
    return {'x-apikey': VT_API_KEY}


def vt_check_existing(sha256: str) -> dict | None:
    """Return existing VT report if the hash is already known."""
    r = requests.get(f'{VT_BASE}/files/{sha256}', headers=vt_headers(), timeout=30)
    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return None
    r.raise_for_status()


def vt_upload(path: Path) -> str:
    """Upload a file to VT. Returns analysis ID."""
    size = path.stat().st_size
    if size > 32 * 1024 * 1024:
        # Get large file upload URL
        r = requests.get(f'{VT_BASE}/files/upload_url', headers=vt_headers(), timeout=30)
        r.raise_for_status()
        upload_url = r.json()['data']
        time.sleep(VT_RATE_SLEEP)
    else:
        upload_url = f'{VT_BASE}/files'

    with open(path, 'rb') as f:
        r = requests.post(
            upload_url,
            headers=vt_headers(),
            files={'file': (path.name, f, 'application/octet-stream')},
            timeout=120
        )
    r.raise_for_status()
    analysis_id = r.json()['data']['id']
    log.info(f'VT upload complete, analysis_id={analysis_id}')
    return analysis_id


def vt_wait_for_analysis(analysis_id: str, max_wait: int = 300) -> dict:
    """Poll VT analysis endpoint until completed."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        time.sleep(VT_RATE_SLEEP)
        r = requests.get(
            f'{VT_BASE}/analyses/{analysis_id}',
            headers=vt_headers(),
            timeout=30
        )
        r.raise_for_status()
        data = r.json()
        status = data.get('data', {}).get('attributes', {}).get('status', '')
        if status == 'completed':
            return data
        log.info(f'VT analysis status: {status}, waiting...')
    raise TimeoutError(f'VT analysis {analysis_id} not completed within {max_wait}s')


def vt_get_file_report(sha256: str) -> dict:
    """Fetch full file report after analysis completes."""
    time.sleep(VT_RATE_SLEEP)
    r = requests.get(f'{VT_BASE}/files/{sha256}', headers=vt_headers(), timeout=30)
    r.raise_for_status()
    return r.json()


def vt_get_behaviour(sha256: str) -> dict | None:
    """Fetch sandbox behaviour summary (premium feature, gracefully skipped)."""
    try:
        time.sleep(VT_RATE_SLEEP)
        r = requests.get(
            f'{VT_BASE}/files/{sha256}/behaviour_summary',
            headers=vt_headers(),
            timeout=30
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log.warning(f'VT behaviour fetch skipped: {e}')
    return None


# ─── JoeSandbox ───────────────────────────────────────────────────────────────

def joe_headers() -> dict:
    return {'Accept': 'application/json'}


def joe_submit(path: Path) -> str | None:
    """Submit sample to JoeSandbox Cloud. Returns webid."""
    if not JOE_API_KEY:
        log.warning('JOESANDBOX_API_KEY not set, skipping JoeSandbox')
        return None
    with open(path, 'rb') as f:
        r = requests.post(
            f'{JOE_BASE}/v2/analysis/submit',
            headers=joe_headers(),
            data={
                'apikey': JOE_API_KEY,
                'accept-tac': '1',
                'report-cache': '1',   # reuse if already analysed
                'systems': 'ubuntu22x64',
                'comments': f'honeypot-stack auto-submit {datetime.now(timezone.utc).isoformat()}',
            },
            files={'sample': (path.name, f, 'application/octet-stream')},
            timeout=120
        )
    if r.status_code == 200:
        data = r.json()
        webid = data.get('data', {}).get('webid')
        log.info(f'JoeSandbox submitted, webid={webid}')
        return str(webid)
    log.warning(f'JoeSandbox submit failed: {r.status_code} {r.text[:200]}')
    return None


def joe_wait_and_download_pdf(webid: str, out_path: Path) -> bool:
    """Poll Joe until done, then download the PDF report."""
    deadline = time.time() + JOE_MAX_WAIT
    while time.time() < deadline:
        time.sleep(JOE_POLL_SLEEP)
        r = requests.post(
            f'{JOE_BASE}/v2/analysis/info',
            data={'apikey': JOE_API_KEY, 'webid': webid},
            headers=joe_headers(),
            timeout=30
        )
        if r.status_code != 200:
            log.warning(f'Joe status check failed: {r.status_code}')
            continue
        info = r.json().get('data', {})
        status = info.get('status', '')
        log.info(f'JoeSandbox status: {status}')
        if status == 'finished':
            # Download PDF
            pdf_r = requests.post(
                f'{JOE_BASE}/v2/analysis/download',
                data={'apikey': JOE_API_KEY, 'webid': webid, 'type': 'pdf'},
                headers=joe_headers(),
                timeout=120
            )
            if pdf_r.status_code == 200:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(pdf_r.content)
                log.info(f'JoeSandbox PDF saved: {out_path}')
                return True
            else:
                log.warning(f'Joe PDF download failed: {pdf_r.status_code}')
                return False
    log.warning(f'JoeSandbox analysis {webid} timed out')
    return False


# ─── PDF Report Generation (VirusTotal) ──────────────────────────────────────

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  body { font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 11px; margin: 2cm; color: #222; }
  h1   { color: #c0392b; font-size: 20px; border-bottom: 2px solid #c0392b; padding-bottom: 6px; }
  h2   { color: #2c3e50; font-size: 14px; margin-top: 20px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
  th   { background: #2c3e50; color: white; padding: 6px 8px; text-align: left; }
  td   { padding: 5px 8px; border-bottom: 1px solid #ddd; }
  tr:nth-child(even) td { background: #f9f9f9; }
  .malicious  { color: #c0392b; font-weight: bold; }
  .suspicious { color: #e67e22; font-weight: bold; }
  .clean      { color: #27ae60; }
  .badge-mal  { background:#c0392b; color:white; padding:2px 8px; border-radius:4px; }
  .badge-sus  { background:#e67e22; color:white; padding:2px 8px; border-radius:4px; }
  .badge-ok   { background:#27ae60; color:white; padding:2px 8px; border-radius:4px; }
  .meta       { background:#ecf0f1; padding:10px; border-radius:4px; margin-bottom:16px; }
  .footer     { margin-top: 30px; font-size:9px; color:#888; border-top:1px solid #ccc; padding-top:6px; }
</style>
</head>
<body>
<h1>🛡️ Malware Analysis Report</h1>
<div class="meta">
  <strong>Generated:</strong> {{ generated_at }}<br>
  <strong>Source:</strong> honeypot-stack automated pipeline<br>
  <strong>Repository:</strong> Xore/Honeypot
</div>

<h2>File Metadata</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>File Name</td><td>{{ name }}</td></tr>
  <tr><td>SHA-256</td><td><code>{{ sha256 }}</code></td></tr>
  <tr><td>MD5</td><td><code>{{ md5 }}</code></td></tr>
  <tr><td>SHA-1</td><td><code>{{ sha1 }}</code></td></tr>
  <tr><td>File Type</td><td>{{ file_type }}</td></tr>
  <tr><td>File Size</td><td>{{ file_size }} bytes</td></tr>
  <tr><td>Magic</td><td>{{ magic }}</td></tr>
  <tr><td>First Seen (VT)</td><td>{{ first_seen }}</td></tr>
  <tr><td>Last Analysis</td><td>{{ last_analysis }}</td></tr>
</table>

<h2>VirusTotal Detection Summary</h2>
<table>
  <tr><th>Verdict</th><th>Count</th><th>Out of</th><th>Detection Rate</th></tr>
  <tr>
    <td>
      {% if malicious > 5 %}<span class="badge-mal">MALICIOUS</span>
      {% elif malicious > 0 %}<span class="badge-sus">SUSPICIOUS</span>
      {% else %}<span class="badge-ok">CLEAN</span>{% endif %}
    </td>
    <td class="malicious">{{ malicious }}</td>
    <td>{{ total_engines }}</td>
    <td>{{ '%.1f'|format(malicious / total_engines * 100 if total_engines > 0 else 0) }}%</td>
  </tr>
</table>

<table>
  <tr><th>Category</th><th>Count</th></tr>
  <tr><td class="malicious">Malicious</td><td>{{ malicious }}</td></tr>
  <tr><td class="suspicious">Suspicious</td><td>{{ suspicious }}</td></tr>
  <tr><td>Undetected</td><td>{{ undetected }}</td></tr>
  <tr><td>Harmless</td><td>{{ harmless }}</td></tr>
  <tr><td>Timeout / Error</td><td>{{ timeout }}</td></tr>
</table>

{% if popular_threat_name %}
<h2>Threat Classification</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Suggested Threat Label</td><td><strong>{{ popular_threat_name }}</strong></td></tr>
  <tr><td>Threat Category</td><td>{{ threat_category }}</td></tr>
</table>
{% endif %}

{% if engine_results %}
<h2>Antivirus Engine Results (Detections Only)</h2>
<table>
  <tr><th>Engine</th><th>Category</th><th>Result</th><th>Engine Version</th></tr>
  {% for row in engine_results %}
  <tr>
    <td>{{ row.engine }}</td>
    <td class="{% if row.category == 'malicious' %}malicious{% elif row.category == 'suspicious' %}suspicious{% endif %}">{{ row.category }}</td>
    <td>{{ row.result or '—' }}</td>
    <td>{{ row.version or '—' }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if tags %}
<h2>Tags</h2>
<p>{{ tags | join(', ') }}</p>
{% endif %}

{% if vt_link %}
<h2>VirusTotal Link</h2>
<p><a href="{{ vt_link }}">{{ vt_link }}</a></p>
{% endif %}

<div class="footer">
  Generated by honeypot-stack analysis pipeline &bull; {{ generated_at }} &bull; Data source: VirusTotal API v3
</div>
</body>
</html>
"""


def build_pdf_from_vt(vt_report: dict, hashes: dict, out_path: Path) -> bool:
    """Render HTML from VT report and convert to PDF using weasyprint."""
    try:
        from weasyprint import HTML as WP_HTML
    except ImportError:
        log.warning('weasyprint not available, skipping PDF generation')
        return False

    attrs = vt_report.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    results = attrs.get('last_analysis_results', {})

    engine_rows = [
        {
            'engine': eng,
            'category': det.get('category', ''),
            'result': det.get('result', ''),
            'version': det.get('engine_version', ''),
        }
        for eng, det in results.items()
        if det.get('category') in ('malicious', 'suspicious')
    ]
    engine_rows.sort(key=lambda x: x['category'])

    total = sum(stats.values())
    popular = attrs.get('popular_threat_classification', {})

    ctx = {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'name': attrs.get('meaningful_name', hashes.get('sha256', '')[:16]),
        'sha256': hashes['sha256'],
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'file_type': attrs.get('type_description', attrs.get('type_tag', 'Unknown')),
        'file_size': attrs.get('size', '?'),
        'magic': attrs.get('magic', ''),
        'first_seen': attrs.get('first_submission_date', ''),
        'last_analysis': attrs.get('last_analysis_date', ''),
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0),
        'harmless': stats.get('harmless', 0),
        'timeout': stats.get('timeout', 0) + stats.get('type-unsupported', 0),
        'total_engines': total,
        'engine_results': engine_rows,
        'popular_threat_name': popular.get('suggested_threat_label', ''),
        'threat_category': popular.get('popular_threat_category', [{}])[0].get('value', '') if popular.get('popular_threat_category') else '',
        'tags': attrs.get('tags', []),
        'vt_link': f'https://www.virustotal.com/gui/file/{hashes["sha256"]}',
    }

    html = Template(HTML_TEMPLATE).render(**ctx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    WP_HTML(string=html).write_pdf(str(out_path))
    log.info(f'VT PDF report saved: {out_path}')
    return True


# ─── IOC CSV update ───────────────────────────────────────────────────────────

def update_ioc_csv(hashes: dict, family: str, sample_type: str,
                   vt_report: dict | None, joe_score: str = ''):
    IOC_CSV.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if IOC_CSV.exists():
        with open(IOC_CSV, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing[row['sha256']] = row

    if vt_report:
        attrs = vt_report.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        total = sum(stats.values())
        mal = stats.get('malicious', 0)
    else:
        total = mal = 0

    existing[hashes['sha256']] = {
        'sha256': hashes['sha256'],
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'family': family,
        'type': sample_type,
        'source': 'cowrie/dionaea',
        'date_captured': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'vt_detections': mal,
        'vt_total': total,
        'joesandbox_score': joe_score,
    }

    fieldnames = ['sha256','md5','sha1','family','type','source','date_captured',
                  'vt_detections','vt_total','joesandbox_score']
    with open(IOC_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(existing.values())
    log.info(f'IOC CSV updated: {IOC_CSV}')


# ─── Main ─────────────────────────────────────────────────────────────────────

def infer_type_and_family(path: Path) -> tuple[str, str]:
    parts = path.parts
    if 'ELF' in parts:     return 'ELF', 'unknown'
    if 'PE' in parts:      return 'PE',  'unknown'
    if 'Miori' in parts:   return 'ELF', 'Miori'
    if 'Scripts' in parts: return 'Script', 'dropper'
    return 'unknown', 'unknown'


def analyze_sample(sample_path: Path):
    if not sample_path.exists():
        log.warning(f'File not found: {sample_path}')
        return
    if sample_path.name == '.gitkeep':
        return

    log.info(f'--- Analyzing: {sample_path} ---')

    hashes = {
        'sha256': sha256_of(sample_path),
        'md5':    md5_of(sample_path),
        'sha1':   sha1_of(sample_path),
    }
    sample_type, family = infer_type_and_family(sample_path)
    sha = hashes['sha256']

    vt_report_path  = REPORT_DIR / 'virustotal' / f'{sha}.json'
    vt_pdf_path     = REPORT_DIR / 'virustotal' / f'{sha}.pdf'
    joe_pdf_path    = REPORT_DIR / 'joesandbox' / f'{sha}_joesandbox.pdf'

    # ── VirusTotal ──
    vt_report = None
    if VT_API_KEY:
        log.info(f'Checking VT for existing report: {sha}')
        vt_report = vt_check_existing(sha)

        if vt_report is None:
            log.info('Not found in VT, uploading...')
            try:
                analysis_id = vt_upload(sample_path)
                vt_wait_for_analysis(analysis_id)
                vt_report = vt_get_file_report(sha)
            except Exception as e:
                log.error(f'VT upload/analysis failed: {e}')
        else:
            log.info('VT report already exists (cache hit)')

        if vt_report:
            vt_report_path.parent.mkdir(parents=True, exist_ok=True)
            vt_report_path.write_text(json.dumps(vt_report, indent=2))
            build_pdf_from_vt(vt_report, hashes, vt_pdf_path)
    else:
        log.warning('VT_API_KEY not set, skipping VirusTotal')

    # ── JoeSandbox ──
    joe_score = ''
    if JOE_API_KEY:
        webid = joe_submit(sample_path)
        if webid:
            joe_wait_and_download_pdf(webid, joe_pdf_path)
            joe_score = webid  # store webid as reference
    else:
        log.warning('JOESANDBOX_API_KEY not set, skipping JoeSandbox')

    # ── IOC update ──
    update_ioc_csv(hashes, family, sample_type, vt_report, joe_score)

    log.info(f'Done: {sha}')


def main():
    parser = argparse.ArgumentParser(description='Malware Analysis Pipeline')
    parser.add_argument('--file-list', help='File with list of sample paths')
    parser.add_argument('--sample', help='Single sample path to analyze')
    args = parser.parse_args()

    paths = []
    if args.file_list:
        with open(args.file_list) as f:
            paths = [Path(line.strip()) for line in f if line.strip()]
    elif args.sample:
        paths = [Path(args.sample)]
    else:
        # Scan all samples directories
        for p in Path('samples').rglob('*'):
            if p.is_file() and p.name != '.gitkeep':
                paths.append(p)

    if not paths:
        log.info('No samples to analyze.')
        return

    for p in paths:
        try:
            analyze_sample(p)
        except Exception as e:
            log.error(f'Error analyzing {p}: {e}', exc_info=True)
        time.sleep(2)  # courtesy pause between samples


if __name__ == '__main__':
    main()
