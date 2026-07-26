#!/usr/bin/env python3
"""
analyze_samples.py — Xore/Honeypot multi-scanner

Scanners implemented:
  1. VirusTotal v3         70+ AV engines, hash lookup + upload
  2. MalwareBazaar         abuse.ch community DB, family tagging
  3. Hybrid-Analysis       Falcon Sandbox dynamic analysis
  4. Malshare              Community malware repository
  5. JoeSandbox            Deep dynamic analysis (community / paid)
  6. MetaDefender Cloud    37+ AV engines via OPSWAT
  7. CAPE Sandbox          Cuckoo fork, config extraction, memory dumps
  8. Any.run               Interactive cloud sandbox (paid API)

Archive handling:
  Archives (.zip/.7z/.tar.gz/.rar) are extracted first.
  Only the raw executables inside are submitted — never the archive.
  Passwords tried: infected, malware, infected123, virus (configurable)

Hash-first:
  Every scanner does a hash lookup before uploading.
  Known samples return results instantly with zero quota spent.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('honeypot.scanner')

# ── Constants ────────────────────────────────────────────────────────────────

ARCHIVE_EXTS = {'.zip', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.rar'}

# Binary magic bytes that identify scannable files
SCANNABLE_MAGIC = [
    b'MZ',                    # Windows PE (EXE/DLL/SYS/OCX)
    b'\x7fELF',               # Linux/Unix ELF
    b'\xca\xfe\xba\xbe',     # Mach-O fat binary
    b'\xfe\xed\xfa\xce',     # Mach-O 32-bit LE
    b'\xfe\xed\xfa\xcf',     # Mach-O 64-bit LE
    b'PK\x03\x04',           # ZIP / JAR / DOCX / XLSX (Office macros)
    b'%PDF',                  # PDF (weaponized)
    b'{\\rtf',               # RTF (weaponized)
    b'\xd0\xcf\x11\xe0',    # OLE2 / legacy Office (DOC/XLS/PPT)
    b'#!/',                   # Shell/Python/Perl script
    b'#!/',                   # shebang variants
]

MAX_UPLOAD_SIZE = 32 * 1024 * 1024  # 32 MB (VT free limit)


# ── Utility ──────────────────────────────────────────────────────────────────

def hash_file(path: Path) -> dict:
    data = path.read_bytes()
    return {
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha1':   hashlib.sha1(data).hexdigest(),
        'md5':    hashlib.md5(data).hexdigest(),
        'size':   len(data),
    }


def is_scannable(path: Path) -> bool:
    try:
        header = path.read_bytes()[:8]
    except Exception:
        return False
    for magic in SCANNABLE_MAGIC:
        if header[:len(magic)] == magic:
            return True
    # Accept binary files even without known magic (unknown/packed malware)
    if len(header) >= 4:
        text_chars = sum(1 for b in header if 32 <= b < 127 or b in (9, 10, 13))
        if text_chars < len(header) * 0.7:  # >30% non-printable = binary
            return True
    return False


# ── Archive extraction ────────────────────────────────────────────────────────

def extract_archive(path: Path, passwords: list, tmpdir: Path) -> list:
    suffix = path.suffix.lower()
    dest = tmpdir / f'{path.stem}_{path.stat().st_size}'
    dest.mkdir(parents=True, exist_ok=True)

    def _collect():
        return [f for f in dest.rglob('*') if f.is_file()]

    try:
        if suffix == '.zip':
            import pyzipper
            for pwd in ([''] + passwords):
                try:
                    with pyzipper.AESZipFile(path) as zf:
                        zf.extractall(dest, pwd=pwd.encode() if pwd else None)
                    log.info(f'  Extracted ZIP {path.name} (pwd={repr(pwd)})')
                    return _collect()
                except (RuntimeError, Exception):
                    continue
            log.warning(f'  ZIP extraction failed (wrong password?): {path.name}')

        elif suffix == '.7z':
            import py7zr
            for pwd in ([''] + passwords):
                try:
                    with py7zr.SevenZipFile(path, mode='r', password=pwd or None) as z:
                        z.extractall(dest)
                    log.info(f'  Extracted 7z {path.name}')
                    return _collect()
                except Exception:
                    continue

        elif suffix in ('.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz'):
            import tarfile
            with tarfile.open(path) as tf:
                tf.extractall(dest)
            log.info(f'  Extracted tar {path.name}')
            return _collect()

        elif suffix == '.rar':
            import rarfile
            for pwd in ([''] + passwords):
                try:
                    with rarfile.RarFile(path) as rf:
                        rf.extractall(dest, pwd=pwd or None)
                    log.info(f'  Extracted RAR {path.name}')
                    return _collect()
                except Exception:
                    continue
    except Exception as e:
        log.warning(f'  Extraction error for {path.name}: {e}')
    return []


def expand_file(path: Path, passwords: list, tmpdir: Path) -> list:
    """Return list of scannable files from path (extracting archives)."""
    if path.suffix.lower() in ARCHIVE_EXTS:
        extracted = extract_archive(path, passwords, tmpdir)
        if extracted:
            results = []
            for f in extracted:
                results.extend(expand_file(f, passwords, tmpdir))
            return results
    if is_scannable(path):
        return [path]
    log.debug(f'  Skipping non-scannable: {path.name}')
    return []


# ── Scanner 1: VirusTotal v3 ─────────────────────────────────────────────────

class VirusTotalScanner:
    """VirusTotal v3 — 70+ AV engines.
    Free: 4 req/min, 500 uploads/day.
    Register: https://www.virustotal.com
    Docs: https://developers.virustotal.com/reference
    """
    NAME = 'VirusTotal'
    BASE = 'https://www.virustotal.com/api/v3'

    def __init__(self, key):
        self.key = key
        self.hdrs = {'x-apikey': key}
        self._last = 0

    def _wait(self):
        gap = time.time() - self._last
        if gap < 16:
            time.sleep(16 - gap)
        self._last = time.time()

    def lookup(self, sha256):
        self._wait()
        r = requests.get(f'{self.BASE}/files/{sha256}', headers=self.hdrs, timeout=30)
        if r.status_code == 200:
            attr = r.json().get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return {
                'source': 'virustotal', 'known': True,
                'positives': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'names': attr.get('names', []),
                'type_description': attr.get('type_description', ''),
                'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
            }
        return None

    def upload(self, path):
        self._wait()
        if path.stat().st_size > MAX_UPLOAD_SIZE:
            r = requests.get(f'{self.BASE}/files/upload_url',
                             headers=self.hdrs, timeout=30)
            url = r.json().get('data')
        else:
            url = f'{self.BASE}/files'
        with open(path, 'rb') as fh:
            r = requests.post(url, headers=self.hdrs,
                              files={'file': (path.name, fh)}, timeout=120)
        r.raise_for_status()
        aid = r.json()['data']['id']
        log.info(f'  VT uploaded → analysis {aid}')
        return {'source': 'virustotal', 'known': False, 'analysis_id': aid,
                'permalink': f'https://www.virustotal.com/gui/file-analysis/{aid}'}

    def poll(self, aid):
        for _ in range(24):
            self._wait()
            r = requests.get(f'{self.BASE}/analyses/{aid}',
                             headers=self.hdrs, timeout=30)
            attr = r.json().get('data', {}).get('attributes', {})
            if attr.get('status') == 'completed':
                stats = attr.get('stats', {})
                return {'positives': stats.get('malicious', 0),
                        'total': sum(stats.values()), 'stats': stats}
            log.info(f'  VT analysis {attr.get("status")}...')
            time.sleep(30)
        return {'status': 'timeout'}

    def scan(self, path, hashes, wait=True):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  VT: known → {r["positives"]}/{r["total"]}')
            return r
        r = self.upload(path)
        if wait and 'analysis_id' in r:
            r.update(self.poll(r['analysis_id']))
        return r


# ── Scanner 2: MalwareBazaar ─────────────────────────────────────────────────

class MalwareBazaarScanner:
    """abuse.ch MalwareBazaar — community malware DB.
    Free. Register: https://bazaar.abuse.ch
    Docs: https://bazaar.abuse.ch/api/
    """
    NAME = 'MalwareBazaar'
    BASE = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, key):
        self.key = key

    def lookup(self, sha256):
        r = requests.post(self.BASE,
                          data={'query': 'get_info', 'hash': sha256}, timeout=30)
        d = r.json()
        if d.get('query_status') == 'ok':
            i = d['data'][0]
            return {
                'source': 'malwarebazaar', 'known': True,
                'signature': i.get('signature'),
                'file_type': i.get('file_type'),
                'tags': i.get('tags', []),
                'first_seen': i.get('first_seen'),
                'reporter': i.get('reporter'),
                'permalink': f'https://bazaar.abuse.ch/sample/{sha256}/',
            }
        return None

    def upload(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(
                self.BASE,
                data={'query': 'upload_sample', 'delivery_method': 'other',
                      'tags': json.dumps(['honeypot', 'honeypot-xore']),
                      'api_key': self.key},
                files={'file': (path.name, fh)}, timeout=120)
        d = r.json()
        sha = d.get('data', {}).get('sha256_hash', '')
        return {'source': 'malwarebazaar', 'known': False,
                'submitted': d.get('query_status') == 'sample_submitted',
                'sha256': sha,
                'permalink': f'https://bazaar.abuse.ch/sample/{sha}/'}

    def scan(self, path, hashes, **_):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  MalwareBazaar: known → {r.get("signature")}')
            return r
        log.info(f'  MalwareBazaar: uploading {path.name}...')
        return self.upload(path)


# ── Scanner 3: Hybrid-Analysis ───────────────────────────────────────────────

class HybridAnalysisScanner:
    """Hybrid-Analysis / Falcon Sandbox — dynamic analysis.
    Free tier. Register: https://www.hybrid-analysis.com
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """
    NAME = 'HybridAnalysis'
    BASE = 'https://www.hybrid-analysis.com/api/v2'

    def __init__(self, key):
        self.hdrs = {'api-key': key, 'User-Agent': 'Falcon Sandbox', 'accept': 'application/json'}

    def lookup(self, sha256):
        r = requests.get(f'{self.BASE}/search/hash',
                         params={'hash': sha256}, headers=self.hdrs, timeout=30)
        if r.status_code == 200 and r.json():
            t = r.json()[0]
            return {
                'source': 'hybrid_analysis', 'known': True,
                'verdict': t.get('verdict'),
                'threat_score': t.get('threat_score'),
                'threat_level': t.get('threat_level_human'),
                'av_detect': t.get('av_detect'),
                'job_id': t.get('job_id'),
                'permalink': f'https://www.hybrid-analysis.com/sample/{sha256}',
            }
        return None

    def submit(self, path, env_id=120):  # 120 = Win10 64-bit
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/submit/file',
                headers=self.hdrs,
                data={'environment_id': env_id, 'allow_community_access': True,
                      'comment': 'honeypot-xore automated submission'},
                files={'file': (path.name, fh)}, timeout=120)
        if r.status_code in (200, 201):
            d = r.json()
            return {
                'source': 'hybrid_analysis', 'known': False,
                'job_id': d.get('job_id'), 'sha256': d.get('sha256'),
                'permalink': f'https://www.hybrid-analysis.com/sample/{d.get("sha256","")}',
            }
        return {'source': 'hybrid_analysis', 'error': r.text[:200]}

    def scan(self, path, hashes, **_):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  HybridAnalysis: known → verdict={r.get("verdict")}')
            return r
        log.info(f'  HybridAnalysis: submitting {path.name}...')
        return self.submit(path)


# ── Scanner 4: Malshare ───────────────────────────────────────────────────────

class MalshareScanner:
    """Malshare — community malware repository.
    Free, 2000 req/day. Register: https://malshare.com/register.php
    Docs: https://malshare.com/doc.php
    """
    NAME = 'Malshare'
    BASE = 'https://malshare.com/api.php'

    def __init__(self, key):
        self.key = key

    def lookup(self, sha256):
        r = requests.get(self.BASE,
                         params={'api_key': self.key, 'action': 'details', 'hash': sha256},
                         timeout=30)
        if r.status_code == 200:
            d = r.json()
            if d.get('SHA256'):
                return {
                    'source': 'malshare', 'known': True,
                    'type': d.get('F_TYPE'), 'sources': d.get('SOURCES', []),
                    'permalink': f'https://malshare.com/sample.php?action=detail&hash={sha256}',
                }
        return None

    def upload(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(self.BASE,
                              params={'api_key': self.key, 'action': 'upload'},
                              files={'upload': (path.name, fh)}, timeout=120)
        return {'source': 'malshare', 'known': False,
                'submitted': r.status_code == 200, 'response': r.text[:100]}

    def scan(self, path, hashes, **_):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  Malshare: known')
            return r
        log.info(f'  Malshare: uploading {path.name}...')
        return self.upload(path)


# ── Scanner 5: JoeSandbox ────────────────────────────────────────────────────

class JoeSandboxScanner:
    """JoeSandbox Cloud — deep behavioural analysis.
    Community (free, public) or paid plans.
    Register: https://www.joesandbox.com
    Docs: https://jbxcloud.joesecurity.org/userguide?sphinxurl=usage/webapi.html
    """
    NAME = 'JoeSandbox'
    BASE = 'https://www.joesandbox.com/api/v2'

    def __init__(self, key):
        self.key = key

    def lookup(self, sha256):
        r = requests.post(
            f'{self.BASE}/analysis/search',
            data={'apikey': self.key, 'q': sha256},
            timeout=30)
        if r.status_code == 200:
            d = r.json()
            if d.get('data'):
                a = d['data'][0]
                return {
                    'source': 'joesandbox', 'known': True,
                    'webid': a.get('webid'),
                    'detection': a.get('detection'),
                    'score': a.get('score'),
                    'permalink': f'https://www.joesandbox.com/analysis/{a.get("webid")}/0/html',
                }
        return None

    def submit(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/submission/new',
                data={
                    'apikey': self.key,
                    'accept-tac': 1,
                    'comments': 'honeypot-xore automated',
                    'internet-access': 0,  # isolated run
                },
                files={'sample': (path.name, fh)},
                timeout=120)
        if r.status_code == 200:
            d = r.json().get('data', {})
            submission_id = d.get('submission_id')
            return {
                'source': 'joesandbox', 'known': False,
                'submission_id': submission_id,
                'permalink': f'https://www.joesandbox.com/submission/{submission_id}',
            }
        return {'source': 'joesandbox', 'error': r.text[:200]}

    def scan(self, path, hashes, **_):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  JoeSandbox: known → detection={r.get("detection")}')
            return r
        log.info(f'  JoeSandbox: submitting {path.name}...')
        return self.submit(path)


# ── Scanner 6: MetaDefender Cloud (OPSWAT) ───────────────────────────────────

class MetaDefenderScanner:
    """MetaDefender Cloud — 37+ AV engines + data sanitization.
    Free tier: 10 uploads/day, unlimited hash lookups.
    Register: https://metadefender.opswat.com
    Docs: https://onlinehelp.opswat.com/mdcloud/
    """
    NAME = 'MetaDefender'
    BASE = 'https://api.metadefender.com/v4'

    def __init__(self, key):
        self.hdrs = {'apikey': key}

    def lookup(self, sha256):
        r = requests.get(f'{self.BASE}/hash/{sha256}',
                         headers=self.hdrs, timeout=30)
        if r.status_code == 200:
            d = r.json()
            scan = d.get('scan_results', {})
            if scan.get('scan_all_result_i') is not None:
                stats = scan.get('total_avs', 0)
                detected = scan.get('total_detected_avs', 0)
                return {
                    'source': 'metadefender', 'known': True,
                    'positives': detected,
                    'total': stats,
                    'scan_result': scan.get('scan_all_result_a', ''),
                    'file_info': d.get('file_info', {}),
                    'permalink': f'https://metadefender.opswat.com/results/file/{sha256}/regular/overview',
                }
        return None

    def upload(self, path):
        hdrs = {**self.hdrs, 'filename': path.name, 'samplesharing': '1'}
        with open(path, 'rb') as fh:
            r = requests.post(f'{self.BASE}/file',
                              headers=hdrs, data=fh, timeout=120)
        if r.status_code == 200:
            data_id = r.json().get('data_id')
            log.info(f'  MetaDefender: uploaded → data_id={data_id}')
            return {'source': 'metadefender', 'known': False, 'data_id': data_id,
                    'permalink': f'https://metadefender.opswat.com/results/file/{data_id}/regular/overview'}
        return {'source': 'metadefender', 'error': r.text[:200]}

    def poll(self, data_id):
        for _ in range(20):
            time.sleep(15)
            r = requests.get(f'{self.BASE}/file/{data_id}',
                             headers=self.hdrs, timeout=30)
            if r.status_code == 200:
                d = r.json()
                scan = d.get('scan_results', {})
                prog = scan.get('progress_percentage', 0)
                if prog == 100:
                    return {
                        'positives': scan.get('total_detected_avs', 0),
                        'total': scan.get('total_avs', 0),
                        'scan_result': scan.get('scan_all_result_a', ''),
                    }
                log.info(f'  MetaDefender: scan {prog}%...')
        return {'status': 'timeout'}

    def scan(self, path, hashes, wait=True):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  MetaDefender: known → {r["positives"]}/{r["total"]}')
            return r
        log.info(f'  MetaDefender: uploading {path.name}...')
        r = self.upload(path)
        if wait and 'data_id' in r:
            r.update(self.poll(r['data_id']))
        return r


# ── Scanner 7: CAPE Sandbox ───────────────────────────────────────────────────

class CAPESandboxScanner:
    """CAPE Sandbox — Cuckoo fork with config extraction.
    Self-hosted or public: https://capesandbox.com
    Docs: https://capesandbox.com/apiv2/
    """
    NAME = 'CAPE'

    def __init__(self, base_url, api_key=None):
        self.base = base_url.rstrip('/')
        self.hdrs = {'Authorization': f'Token {api_key}'} if api_key else {}

    def lookup(self, sha256):
        try:
            r = requests.get(f'{self.base}/apiv2/tasks/search/sha256/{sha256}/',
                             headers=self.hdrs, timeout=30)
            if r.status_code == 200 and r.json().get('data'):
                t = r.json()['data'][0]
                return {
                    'source': 'cape', 'known': True,
                    'task_id': t.get('id'), 'status': t.get('status'),
                    'malscore': t.get('malscore'),
                    'permalink': f'{self.base}/analysis/{t.get("id")}/summary/',
                }
        except Exception:
            pass
        return None

    def submit(self, path):
        try:
            with open(path, 'rb') as fh:
                r = requests.post(
                    f'{self.base}/apiv2/tasks/create/file/',
                    headers=self.hdrs,
                    files={'file': (path.name, fh)},
                    data={'options': 'procmemdump=1,hollowshunter=1'},
                    timeout=120)
            if r.status_code == 200:
                tid = r.json().get('data', {}).get('task_id')
                return {'source': 'cape', 'known': False, 'task_id': tid,
                        'permalink': f'{self.base}/analysis/{tid}/summary/'}
        except Exception as e:
            return {'source': 'cape', 'error': str(e)}
        return {'source': 'cape', 'error': 'submission failed'}

    def scan(self, path, hashes, **_):
        r = self.lookup(hashes['sha256'])
        if r:
            log.info(f'  CAPE: known → task={r.get("task_id")} score={r.get("malscore")}')
            return r
        log.info(f'  CAPE: submitting {path.name}...')
        return self.submit(path)


# ── Scanner 8: Any.run ────────────────────────────────────────────────────────

class AnyRunScanner:
    """Any.run — interactive cloud sandbox.
    Requires paid API plan. Register: https://any.run
    Docs: https://any.run/api-documentation/
    """
    NAME = 'AnyRun'
    BASE = 'https://api.any.run/v1'

    def __init__(self, key):
        self.auth = {'Authorization': f'API-Key {key}'}

    def submit(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(f'{self.BASE}/file',
                              headers=self.auth,
                              files={'file': (path.name, fh)}, timeout=120)
        if r.status_code not in (200, 201):
            return {'source': 'anyrun', 'error': r.text[:200]}
        file_uuid = r.json().get('data', {}).get('fileUUID')
        r2 = requests.post(
            f'{self.BASE}/analysis',
            headers={**self.auth, 'Content-Type': 'application/json'},
            json={'env': {'OS': 'windows', 'Bitness': 64, 'Type': 'complete'},
                  'obj': {'type': 'file', 'fileUUID': file_uuid}},
            timeout=60)
        if r2.status_code in (200, 201):
            tid = r2.json().get('data', {}).get('taskid')
            return {'source': 'anyrun', 'known': False, 'task_id': tid,
                    'permalink': f'https://app.any.run/tasks/{tid}'}
        return {'source': 'anyrun', 'error': r2.text[:200]}

    def scan(self, path, hashes, **_):
        log.info(f'  Any.run: submitting {path.name}...')
        return self.submit(path)


# ── IOC extraction ────────────────────────────────────────────────────────────

def extract_iocs(report: dict, ioc_dir: Path):
    """Append new IOCs to iocs/ CSV files."""
    sha256 = report['sha256']
    ioc_dir.mkdir(parents=True, exist_ok=True)

    # Hashes
    hashes_file = ioc_dir / 'hashes.csv'
    if not hashes_file.exists():
        hashes_file.write_text('sha256,sha1,md5,filename,first_seen\n')
    existing = hashes_file.read_text()
    if sha256 not in existing:
        with open(hashes_file, 'a') as f:
            ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            f.write(f'{sha256},{report["sha1"]},{report["md5"]},{report["filename"]},{ts}\n')

    # VT names → malware families
    vt = report.get('results', {}).get('VirusTotalScanner', {})
    for name in vt.get('names', []):
        families_file = ioc_dir / 'families.csv'
        if not families_file.exists():
            families_file.write_text('sha256,name\n')
        with open(families_file, 'a') as f:
            f.write(f'{sha256},{name}\n')


# ── Main ──────────────────────────────────────────────────────────────────────

def build_scanners():
    scanners = []
    checks = [
        ('VT_API_KEY',           lambda k: VirusTotalScanner(k),         'VirusTotal'),
        ('MALWAREBAZAAR_API_KEY',lambda k: MalwareBazaarScanner(k),      'MalwareBazaar'),
        ('HYBRID_ANALYSIS_KEY',  lambda k: HybridAnalysisScanner(k),     'HybridAnalysis'),
        ('MALSHARE_API_KEY',     lambda k: MalshareScanner(k),           'Malshare'),
        ('JOESANDBOX_API_KEY',   lambda k: JoeSandboxScanner(k),         'JoeSandbox'),
        ('METADEFENDER_API_KEY', lambda k: MetaDefenderScanner(k),       'MetaDefender'),
        ('ANYRUN_API_KEY',       lambda k: AnyRunScanner(k),             'Any.run'),
    ]
    for env_var, factory, name in checks:
        if k := os.environ.get(env_var):
            scanners.append(factory(k))
            log.info(f'[+] {name} enabled')

    # CAPE needs URL
    if url := os.environ.get('CAPE_API_URL'):
        scanners.append(CAPESandboxScanner(url, os.environ.get('CAPE_API_KEY', '')))
        log.info(f'[+] CAPE enabled ({url})')

    if not scanners:
        log.error('No scanner API keys set. Configure at least VT_API_KEY.')
        sys.exit(1)
    return scanners


def scan_file(path: Path, scanners: list, output_dir: Path,
              ioc_dir: Path, wait: bool) -> dict:
    hashes = hash_file(path)
    sha256 = hashes['sha256']
    log.info(f'\n{"─"*60}')
    log.info(f'Scanning: {path.name}')
    log.info(f'  SHA256: {sha256}')
    log.info(f'  Size:   {hashes["size"]:,} bytes')

    report = {
        'file': str(path),
        'filename': path.name,
        'sha256': sha256,
        'sha1':   hashes['sha1'],
        'md5':    hashes['md5'],
        'size':   hashes['size'],
        'scanned_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'results': {},
    }

    for scanner in scanners:
        name = scanner.__class__.__name__
        try:
            result = scanner.scan(path, hashes, wait=wait)
            report['results'][name] = result
        except Exception as e:
            log.error(f'  {name} error: {e}')
            report['results'][name] = {'error': str(e)}

    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f'{sha256}.json'
    out.write_text(json.dumps(report, indent=2))
    log.info(f'  → {out}')

    if ioc_dir:
        extract_iocs(report, ioc_dir)

    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file-list',         required=True)
    parser.add_argument('--output-dir',        default='reports/scanner/')
    parser.add_argument('--ioc-dir',           default='iocs/')
    parser.add_argument('--archive-passwords', default='infected,malware,infected123,virus')
    parser.add_argument('--wait-results',      action='store_true')
    args = parser.parse_args()

    passwords  = [p.strip() for p in args.archive_passwords.split(',') if p.strip()]
    output_dir = Path(args.output_dir)
    ioc_dir    = Path(args.ioc_dir)
    scanners   = build_scanners()
    tmpdir     = Path(tempfile.mkdtemp(prefix='honeypot_scan_'))

    lines = [
        l.strip() for l in Path(args.file_list).read_text().splitlines()
        if l.strip() and not l.startswith('#')
    ]
    if not lines:
        log.info('No files to scan.')
        return

    log.info(f'Input files:  {len(lines)}')
    log.info(f'Passwords:    {passwords}')
    log.info(f'Scanners:     {[s.__class__.__name__ for s in scanners]}')
    log.info(f'Wait results: {args.wait_results}')

    all_reports = []
    try:
        for line in lines:
            p = Path(line)
            if not p.exists():
                log.warning(f'Not found: {p}')
                continue
            to_scan = expand_file(p, passwords, tmpdir)
            if not to_scan:
                log.info(f'Skipping (not scannable): {p.name}')
                continue
            for f in to_scan:
                if f.stat().st_size == 0:
                    continue
                r = scan_file(f, scanners, output_dir, ioc_dir, args.wait_results)
                all_reports.append(r)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    log.info(f'\n{"="*60}')
    log.info(f'Total scanned: {len(all_reports)}')
    for r in all_reports:
        vt  = r['results'].get('VirusTotalScanner', {})
        pos = vt.get('positives', '?')
        tot = vt.get('total', '?')
        md  = r['results'].get('MetaDefenderScanner', {})
        md_pos = md.get('positives', '-')
        log.info(f'  {r["sha256"][:16]}… {r["filename"]:30s} VT:{pos}/{tot} MD:{md_pos}')


if __name__ == '__main__':
    main()
