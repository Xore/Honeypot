#!/usr/bin/env python3
"""
analyze_samples.py — Xore/Honeypot multi-scanner

Failure-handling contract:
  - A single scanner API failure (network error, 4xx/5xx, timeout) is
    recorded as {"error": "...", "status": "failed"} in the report and
    scanning continues with the remaining scanners.
  - The JSON report is ALWAYS written, even if every scanner failed.
  - Hard exit(1) only when:
      a) No scanner API keys are configured at all, OR
      b) The file list is missing/unreadable (prerequisite failure)
  - The workflow exit code reflects whether at least one scanner
    returned a result (exit 0) vs. all scanners errored (exit 2).

Scanners:
  1. VirusTotal v3       70+ AV engines
  2. MalwareBazaar       abuse.ch community DB
  3. Hybrid-Analysis     Falcon Sandbox dynamic
  4. Malshare            Community repo
  5. JoeSandbox          Deep dynamic (community/paid)
  6. MetaDefender        37+ AV engines (OPSWAT)
  7. CAPE Sandbox        Cuckoo fork, config extraction
  8. Any.run             Interactive sandbox (paid API)
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
import traceback
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('honeypot.scanner')

# ── Constants ───────────────────────────────────────────────────────────────

ARCHIVE_EXTS = {'.zip', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.rar'}

SCANNABLE_MAGIC = [
    b'MZ',                 # Windows PE
    b'\x7fELF',            # Linux ELF
    b'\xca\xfe\xba\xbe',  # Mach-O fat
    b'\xfe\xed\xfa\xce',  # Mach-O 32
    b'\xfe\xed\xfa\xcf',  # Mach-O 64
    b'PK\x03\x04',        # ZIP/JAR/Office
    b'%PDF',               # PDF
    b'{\\rtf',            # RTF
    b'\xd0\xcf\x11\xe0',  # OLE2 / legacy Office
    b'#!/',                # shell/script shebang
]

MAX_UPLOAD_SIZE = 32 * 1024 * 1024  # 32 MB


# ── Result helpers ───────────────────────────────────────────────────────────

def _err(source: str, msg: str, exc: Exception = None) -> dict:
    """Uniform error result — never raises, always returns a dict."""
    result = {'source': source, 'status': 'failed', 'error': msg}
    if exc:
        result['traceback'] = traceback.format_exc(limit=5)
    log.error(f'  [{source}] {msg}')
    return result


# ── Utility ───────────────────────────────────────────────────────────────────

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
    if len(header) >= 4:
        text_chars = sum(1 for b in header if 32 <= b < 127 or b in (9, 10, 13))
        if text_chars < len(header) * 0.7:
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
                except Exception:
                    continue
            log.warning(f'  ZIP extraction failed: {path.name}')

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
        log.warning(f'  Extraction error {path.name}: {e}')
    return []


def expand_file(path: Path, passwords: list, tmpdir: Path) -> list:
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


# ── Scanner base ───────────────────────────────────────────────────────────────

class BaseScanner:
    """All scanners inherit this. scan() is the only public method.

    Contract:
      - scan() MUST return a dict.
      - scan() MUST NOT raise — all exceptions are caught internally.
      - On any error the dict contains {status: 'failed', error: '...'}.
    """
    NAME = 'base'

    def scan(self, path: Path, hashes: dict, wait: bool = True) -> dict:
        try:
            return self._scan(path, hashes, wait=wait)
        except Exception as e:
            return _err(self.NAME, str(e), e)

    def _scan(self, path, hashes, wait=True):
        raise NotImplementedError


# ── Scanner 1: VirusTotal v3 ─────────────────────────────────────────────────

class VirusTotalScanner(BaseScanner):
    """
    VirusTotal v3 — 70+ AV engines.
    Free: 4 req/min, 500 uploads/day.
    https://developers.virustotal.com/reference
    """
    NAME = 'VirusTotal'
    BASE = 'https://www.virustotal.com/api/v3'

    def __init__(self, key):
        self.hdrs = {'x-apikey': key}
        self._last = 0.0

    def _wait(self):
        elapsed = time.time() - self._last
        if elapsed < 16:
            time.sleep(16 - elapsed)
        self._last = time.time()

    def _lookup(self, sha256):
        self._wait()
        r = requests.get(f'{self.BASE}/files/{sha256}',
                         headers=self.hdrs, timeout=30)
        if r.status_code == 200:
            attr  = r.json().get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            return {
                'source': 'virustotal', 'known': True,
                'positives':  stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'total':      sum(stats.values()),
                'stats':      stats,
                'names':      attr.get('names', []),
                'type_description': attr.get('type_description', ''),
                'permalink':  f'https://www.virustotal.com/gui/file/{sha256}',
            }
        if r.status_code == 404:
            return None   # unknown — must upload
        # 429 rate-limit, 403 quota exceeded, etc. — return error, do NOT raise
        return _err(self.NAME, f'lookup HTTP {r.status_code}: {r.text[:120]}')

    def _upload(self, path):
        self._wait()
        if path.stat().st_size > MAX_UPLOAD_SIZE:
            r = requests.get(f'{self.BASE}/files/upload_url',
                             headers=self.hdrs, timeout=30)
            if r.status_code != 200:
                return _err(self.NAME, f'upload_url HTTP {r.status_code}')
            url = r.json().get('data')
        else:
            url = f'{self.BASE}/files'
        with open(path, 'rb') as fh:
            r = requests.post(url, headers=self.hdrs,
                              files={'file': (path.name, fh)}, timeout=120)
        # FIX: was raise_for_status() — now returns error dict instead of raising
        if r.status_code not in (200, 201):
            return _err(self.NAME, f'upload HTTP {r.status_code}: {r.text[:120]}')
        aid = r.json().get('data', {}).get('id')
        log.info(f'  VT uploaded → analysis_id={aid}')
        return {
            'source': 'virustotal', 'known': False,
            'analysis_id': aid,
            'permalink': f'https://www.virustotal.com/gui/file-analysis/{aid}',
        }

    def _poll(self, aid, permalink):
        """FIX: preserve analysis_id + permalink even on timeout."""
        base = {
            'source': 'virustotal', 'known': False,
            'analysis_id': aid, 'permalink': permalink,
        }
        for attempt in range(24):
            self._wait()
            r = requests.get(f'{self.BASE}/analyses/{aid}',
                             headers=self.hdrs, timeout=30)
            if r.status_code != 200:
                return {**base, 'status': 'poll_error',
                        'error': f'poll HTTP {r.status_code}'}
            attr   = r.json().get('data', {}).get('attributes', {})
            status = attr.get('status')
            if status == 'completed':
                stats = attr.get('stats', {})
                return {
                    **base, 'status': 'completed',
                    'positives': stats.get('malicious', 0),
                    'total':     sum(stats.values()),
                    'stats':     stats,
                }
            log.info(f'  VT poll [{attempt+1}/24] status={status}')
            time.sleep(30)
        # Timeout — return partial result with permalink intact
        return {**base, 'status': 'timeout',
                'note': 'Analysis queued; check permalink for results'}

    def _scan(self, path, hashes, wait=True):
        result = self._lookup(hashes['sha256'])
        if result is not None:
            if result.get('status') != 'failed':
                log.info(f'  VT: known → {result["positives"]}/{result["total"]}')
            return result
        # Hash unknown — upload
        log.info(f'  VT: uploading {path.name}...')
        upload = self._upload(path)
        if upload.get('status') == 'failed':
            return upload
        if wait and upload.get('analysis_id'):
            return self._poll(upload['analysis_id'], upload['permalink'])
        return upload


# ── Scanner 2: MalwareBazaar ───────────────────────────────────────────────

class MalwareBazaarScanner(BaseScanner):
    """
    abuse.ch MalwareBazaar — community malware DB.
    Free. https://bazaar.abuse.ch/api/
    """
    NAME = 'MalwareBazaar'
    BASE = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, key):
        self.key = key

    def _lookup(self, sha256):
        r = requests.post(self.BASE,
                          data={'query': 'get_info', 'hash': sha256},
                          timeout=30)
        r.raise_for_status()
        d = r.json()
        if d.get('query_status') == 'ok':
            i = d['data'][0]
            return {
                'source': 'malwarebazaar', 'known': True,
                'signature':  i.get('signature'),
                'file_type':  i.get('file_type'),
                'tags':       i.get('tags', []),
                'first_seen': i.get('first_seen'),
                'reporter':   i.get('reporter'),
                'permalink':  f'https://bazaar.abuse.ch/sample/{sha256}/',
            }
        return None

    def _upload(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(
                self.BASE,
                data={'query': 'upload_sample', 'delivery_method': 'other',
                      'tags': json.dumps(['honeypot', 'honeypot-xore']),
                      'api_key': self.key},
                files={'file': (path.name, fh)}, timeout=120)
        r.raise_for_status()
        d   = r.json()
        sha = d.get('data', {}).get('sha256_hash', '')
        return {
            'source': 'malwarebazaar', 'known': False,
            'submitted': d.get('query_status') == 'sample_submitted',
            'sha256': sha,
            'permalink': f'https://bazaar.abuse.ch/sample/{sha}/',
        }

    def _scan(self, path, hashes, **_):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info(f'  MalwareBazaar: known → {result.get("signature")}')
            return result
        log.info(f'  MalwareBazaar: uploading {path.name}...')
        return self._upload(path)


# ── Scanner 3: Hybrid-Analysis ───────────────────────────────────────────────

class HybridAnalysisScanner(BaseScanner):
    """
    Hybrid-Analysis / Falcon Sandbox — dynamic analysis.
    Free tier. https://www.hybrid-analysis.com/docs/api/v2
    """
    NAME = 'HybridAnalysis'
    BASE = 'https://www.hybrid-analysis.com/api/v2'

    def __init__(self, key):
        self.hdrs = {
            'api-key': key,
            'User-Agent': 'Falcon Sandbox',
            'accept': 'application/json',
        }

    def _lookup(self, sha256):
        r = requests.get(f'{self.BASE}/search/hash',
                         params={'hash': sha256},
                         headers=self.hdrs, timeout=30)
        r.raise_for_status()
        data = r.json()
        if data:
            t = data[0]
            return {
                'source': 'hybrid_analysis', 'known': True,
                'verdict':      t.get('verdict'),
                'threat_score': t.get('threat_score'),
                'threat_level': t.get('threat_level_human'),
                'av_detect':    t.get('av_detect'),
                'job_id':       t.get('job_id'),
                'permalink':    f'https://www.hybrid-analysis.com/sample/{sha256}',
            }
        return None

    def _submit(self, path, env_id=120):
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/submit/file',
                headers=self.hdrs,
                data={'environment_id': env_id,
                      'allow_community_access': True,
                      'comment': 'honeypot-xore automated'},
                files={'file': (path.name, fh)}, timeout=120)
        if r.status_code not in (200, 201):
            return _err(self.NAME, f'submit HTTP {r.status_code}: {r.text[:120]}')
        d = r.json()
        return {
            'source': 'hybrid_analysis', 'known': False,
            'job_id': d.get('job_id'), 'sha256': d.get('sha256'),
            'permalink': f'https://www.hybrid-analysis.com/sample/{d.get("sha256","")}',
        }

    def _scan(self, path, hashes, **_):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info(f'  HybridAnalysis: known → verdict={result.get("verdict")}')
            return result
        log.info(f'  HybridAnalysis: submitting {path.name}...')
        return self._submit(path)


# ── Scanner 4: Malshare ───────────────────────────────────────────────────────

class MalshareScanner(BaseScanner):
    """
    Malshare — community malware repository.
    Free, 2000 req/day. https://malshare.com/doc.php
    """
    NAME = 'Malshare'
    BASE = 'https://malshare.com/api.php'

    def __init__(self, key):
        self.key = key

    def _lookup(self, sha256):
        r = requests.get(self.BASE,
                         params={'api_key': self.key, 'action': 'details',
                                 'hash': sha256},
                         timeout=30)
        r.raise_for_status()
        d = r.json()
        if d.get('SHA256'):
            return {
                'source': 'malshare', 'known': True,
                'type': d.get('F_TYPE'), 'sources': d.get('SOURCES', []),
                'permalink': f'https://malshare.com/sample.php?action=detail&hash={sha256}',
            }
        return None

    def _upload(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(self.BASE,
                              params={'api_key': self.key, 'action': 'upload'},
                              files={'upload': (path.name, fh)}, timeout=120)
        return {
            'source': 'malshare', 'known': False,
            'submitted': r.status_code == 200,
            'response': r.text[:100],
        }

    def _scan(self, path, hashes, **_):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info('  Malshare: known')
            return result
        log.info(f'  Malshare: uploading {path.name}...')
        return self._upload(path)


# ── Scanner 5: JoeSandbox ────────────────────────────────────────────────────

class JoeSandboxScanner(BaseScanner):
    """
    JoeSandbox Cloud — deep behavioural analysis.
    Community (free/public) or paid.
    https://jbxcloud.joesecurity.org/userguide?sphinxurl=usage/webapi.html
    """
    NAME = 'JoeSandbox'
    BASE = 'https://www.joesandbox.com/api/v2'

    def __init__(self, key):
        self.key = key

    def _lookup(self, sha256):
        r = requests.post(f'{self.BASE}/analysis/search',
                          data={'apikey': self.key, 'q': sha256},
                          timeout=30)
        r.raise_for_status()
        d = r.json()
        if d.get('data'):
            a = d['data'][0]
            return {
                'source': 'joesandbox', 'known': True,
                'webid':     a.get('webid'),
                'detection': a.get('detection'),
                'score':     a.get('score'),
                'permalink': f'https://www.joesandbox.com/analysis/{a.get("webid")}/0/html',
            }
        return None

    def _submit(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/submission/new',
                data={'apikey': self.key, 'accept-tac': 1,
                      'comments': 'honeypot-xore', 'internet-access': 0},
                files={'sample': (path.name, fh)}, timeout=120)
        if r.status_code != 200:
            return _err(self.NAME, f'submit HTTP {r.status_code}: {r.text[:120]}')
        sid = r.json().get('data', {}).get('submission_id')
        return {
            'source': 'joesandbox', 'known': False,
            'submission_id': sid,
            'permalink': f'https://www.joesandbox.com/submission/{sid}',
        }

    def _scan(self, path, hashes, **_):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info(f'  JoeSandbox: known → detection={result.get("detection")}')
            return result
        log.info(f'  JoeSandbox: submitting {path.name}...')
        return self._submit(path)


# ── Scanner 6: MetaDefender (OPSWAT) ───────────────────────────────────────

class MetaDefenderScanner(BaseScanner):
    """
    MetaDefender Cloud — 37+ AV engines (OPSWAT).
    Free: unlimited hash lookups, 10 uploads/day.
    https://onlinehelp.opswat.com/mdcloud/
    """
    NAME = 'MetaDefender'
    BASE = 'https://api.metadefender.com/v4'

    def __init__(self, key):
        self.hdrs = {'apikey': key}

    def _lookup(self, sha256):
        r = requests.get(f'{self.BASE}/hash/{sha256}',
                         headers=self.hdrs, timeout=30)
        r.raise_for_status()
        d    = r.json()
        scan = d.get('scan_results', {})
        if scan.get('scan_all_result_i') is not None:
            return {
                'source': 'metadefender', 'known': True,
                'positives':   scan.get('total_detected_avs', 0),
                'total':       scan.get('total_avs', 0),
                'scan_result': scan.get('scan_all_result_a', ''),
                'file_info':   d.get('file_info', {}),
                'permalink':   f'https://metadefender.opswat.com/results/file/{sha256}/regular/overview',
            }
        return None

    def _upload(self, path):
        hdrs = {**self.hdrs, 'filename': path.name, 'samplesharing': '1'}
        with open(path, 'rb') as fh:
            r = requests.post(f'{self.BASE}/file',
                              headers=hdrs, data=fh, timeout=120)
        if r.status_code != 200:
            return _err(self.NAME, f'upload HTTP {r.status_code}: {r.text[:120]}')
        data_id = r.json().get('data_id')
        log.info(f'  MetaDefender: uploaded → data_id={data_id}')
        return {
            'source': 'metadefender', 'known': False,
            'data_id':   data_id,
            'permalink': f'https://metadefender.opswat.com/results/file/{data_id}/regular/overview',
        }

    def _poll(self, data_id, permalink):
        base = {'source': 'metadefender', 'known': False,
                'data_id': data_id, 'permalink': permalink}
        for attempt in range(20):
            time.sleep(15)
            r = requests.get(f'{self.BASE}/file/{data_id}',
                             headers=self.hdrs, timeout=30)
            if r.status_code != 200:
                return {**base, 'status': 'poll_error',
                        'error': f'poll HTTP {r.status_code}'}
            scan = r.json().get('scan_results', {})
            prog = scan.get('progress_percentage', 0)
            log.info(f'  MetaDefender: [{attempt+1}/20] {prog}%')
            if prog == 100:
                return {
                    **base, 'status': 'completed',
                    'positives':   scan.get('total_detected_avs', 0),
                    'total':       scan.get('total_avs', 0),
                    'scan_result': scan.get('scan_all_result_a', ''),
                }
        return {**base, 'status': 'timeout',
                'note': 'Check permalink for final results'}

    def _scan(self, path, hashes, wait=True):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info(f'  MetaDefender: known → {result["positives"]}/{result["total"]}')
            return result
        log.info(f'  MetaDefender: uploading {path.name}...')
        upload = self._upload(path)
        if upload.get('status') == 'failed':
            return upload
        if wait and upload.get('data_id'):
            return self._poll(upload['data_id'], upload['permalink'])
        return upload


# ── Scanner 7: CAPE Sandbox ───────────────────────────────────────────────────

class CAPESandboxScanner(BaseScanner):
    """
    CAPE Sandbox — Cuckoo fork, config extraction, memory dumps.
    Self-hosted or public: https://capesandbox.com
    """
    NAME = 'CAPE'

    def __init__(self, base_url, api_key=None):
        self.base = base_url.rstrip('/')
        self.hdrs = {'Authorization': f'Token {api_key}'} if api_key else {}

    def _lookup(self, sha256):
        r = requests.get(
            f'{self.base}/apiv2/tasks/search/sha256/{sha256}/',
            headers=self.hdrs, timeout=30)
        if r.status_code == 200 and r.json().get('data'):
            t = r.json()['data'][0]
            return {
                'source': 'cape', 'known': True,
                'task_id':  t.get('id'),
                'status':   t.get('status'),
                'malscore': t.get('malscore'),
                'permalink': f'{self.base}/analysis/{t.get("id")}/summary/',
            }
        return None

    def _submit(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.base}/apiv2/tasks/create/file/',
                headers=self.hdrs,
                files={'file': (path.name, fh)},
                data={'options': 'procmemdump=1,hollowshunter=1'},
                timeout=120)
        if r.status_code != 200:
            return _err(self.NAME, f'submit HTTP {r.status_code}: {r.text[:120]}')
        tid = r.json().get('data', {}).get('task_id')
        return {
            'source': 'cape', 'known': False,
            'task_id':  tid,
            'permalink': f'{self.base}/analysis/{tid}/summary/',
        }

    def _scan(self, path, hashes, **_):
        result = self._lookup(hashes['sha256'])
        if result:
            log.info(f'  CAPE: known → task={result.get("task_id")} score={result.get("malscore")}')
            return result
        log.info(f'  CAPE: submitting {path.name}...')
        return self._submit(path)


# ── Scanner 8: Any.run ────────────────────────────────────────────────────────

class AnyRunScanner(BaseScanner):
    """
    Any.run — interactive cloud sandbox.
    Paid API required. https://any.run/api-documentation/
    """
    NAME = 'AnyRun'
    BASE = 'https://api.any.run/v1'

    def __init__(self, key):
        self.auth = {'Authorization': f'API-Key {key}'}

    def _submit(self, path):
        with open(path, 'rb') as fh:
            r = requests.post(f'{self.BASE}/file',
                              headers=self.auth,
                              files={'file': (path.name, fh)}, timeout=120)
        if r.status_code not in (200, 201):
            return _err(self.NAME, f'file upload HTTP {r.status_code}: {r.text[:120]}')
        file_uuid = r.json().get('data', {}).get('fileUUID')
        r2 = requests.post(
            f'{self.BASE}/analysis',
            headers={**self.auth, 'Content-Type': 'application/json'},
            json={'env': {'OS': 'windows', 'Bitness': 64, 'Type': 'complete'},
                  'obj': {'type': 'file', 'fileUUID': file_uuid}},
            timeout=60)
        if r2.status_code not in (200, 201):
            return _err(self.NAME, f'analysis create HTTP {r2.status_code}: {r2.text[:120]}')
        tid = r2.json().get('data', {}).get('taskid')
        return {
            'source': 'anyrun', 'known': False,
            'task_id': tid,
            'permalink': f'https://app.any.run/tasks/{tid}',
        }

    def _scan(self, path, hashes, **_):
        log.info(f'  Any.run: submitting {path.name}...')
        return self._submit(path)


# ── IOC extraction ────────────────────────────────────────────────────────────

def extract_iocs(report: dict, ioc_dir: Path):
    sha256 = report['sha256']
    ioc_dir.mkdir(parents=True, exist_ok=True)

    hashes_file = ioc_dir / 'hashes.csv'
    if not hashes_file.exists():
        hashes_file.write_text('sha256,sha1,md5,filename,first_seen\n')
    if sha256 not in hashes_file.read_text():
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        with open(hashes_file, 'a') as f:
            f.write(f'{sha256},{report["sha1"]},{report["md5"]},'
                    f'{report["filename"]},{ts}\n')

    vt = report.get('results', {}).get('VirusTotalScanner', {})
    if vt.get('names'):
        families_file = ioc_dir / 'families.csv'
        if not families_file.exists():
            families_file.write_text('sha256,name\n')
        with open(families_file, 'a') as f:
            for name in vt['names']:
                f.write(f'{sha256},{name}\n')


# ── Core scan function ──────────────────────────────────────────────────────────

def scan_file(path: Path, scanners: list, output_dir: Path,
              ioc_dir: Path, wait: bool) -> dict:
    """
    FIX: report is initialised BEFORE scanners run and written in a
    finally block — so it is ALWAYS committed even if every scanner fails.
    """
    # Step 1: hash (can fail — treat as hard error for this file only)
    try:
        hashes = hash_file(path)
    except Exception as e:
        log.error(f'  Cannot hash {path}: {e}')
        return {}

    sha256 = hashes['sha256']
    log.info(f'\n{"─"*60}')
    log.info(f'Scanning : {path.name}')
    log.info(f'SHA256   : {sha256}')
    log.info(f'Size     : {hashes["size"]:,} bytes')

    # Initialise report immediately — written in finally regardless
    report = {
        'file':       str(path),
        'filename':   path.name,
        'sha256':     sha256,
        'sha1':       hashes['sha1'],
        'md5':        hashes['md5'],
        'size':       hashes['size'],
        'scanned_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'results':    {},
    }

    try:
        for scanner in scanners:
            cls = scanner.__class__.__name__
            log.info(f'  → {scanner.NAME}')
            # BaseScanner.scan() never raises — always returns a dict
            result = scanner.scan(path, hashes, wait=wait)
            report['results'][cls] = result
            # Flag whether this scanner succeeded
            report['results'][cls]['_ok'] = 'error' not in result
    finally:
        # ALWAYS write the report, even if the loop above crashed mid-way
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / f'{sha256}.json'
        out.write_text(json.dumps(report, indent=2))
        log.info(f'  Report  : {out}')
        try:
            if ioc_dir:
                extract_iocs(report, ioc_dir)
        except Exception as e:
            log.warning(f'  IOC extraction error: {e}')

    return report


# ── Scanner factory ─────────────────────────────────────────────────────────────

def build_scanners() -> list:
    scanners = []
    specs = [
        ('VT_API_KEY',            VirusTotalScanner,     'VirusTotal'),
        ('MALWAREBAZAAR_API_KEY',  MalwareBazaarScanner,  'MalwareBazaar'),
        ('HYBRID_ANALYSIS_KEY',   HybridAnalysisScanner, 'HybridAnalysis'),
        ('MALSHARE_API_KEY',      MalshareScanner,       'Malshare'),
        ('JOESANDBOX_API_KEY',    JoeSandboxScanner,     'JoeSandbox'),
        ('METADEFENDER_API_KEY',  MetaDefenderScanner,   'MetaDefender'),
        ('ANYRUN_API_KEY',        AnyRunScanner,         'Any.run'),
    ]
    for env_var, cls, name in specs:
        if k := os.environ.get(env_var):
            scanners.append(cls(k))
            log.info(f'[+] {name} enabled')

    if url := os.environ.get('CAPE_API_URL'):
        scanners.append(CAPESandboxScanner(url, os.environ.get('CAPE_API_KEY', '')))
        log.info(f'[+] CAPE enabled ({url})')

    if not scanners:
        # HARD FAIL: no API keys configured at all
        log.error('FATAL: No scanner API keys configured.')
        log.error('Set at least one of: VT_API_KEY, MALWAREBAZAAR_API_KEY, etc.')
        sys.exit(1)

    return scanners


# ── Main ──────────────────────────────────────────────────────────────────────

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
    scanners   = build_scanners()   # exits 1 if no keys
    tmpdir     = Path(tempfile.mkdtemp(prefix='honeypot_scan_'))

    try:
        file_list = Path(args.file_list)
        lines = [
            l.strip() for l in file_list.read_text().splitlines()
            if l.strip() and not l.startswith('#')
        ]
    except Exception as e:
        log.error(f'FATAL: Cannot read file list {args.file_list}: {e}')
        sys.exit(1)

    if not lines:
        log.info('No files to scan — nothing changed.')
        sys.exit(0)

    log.info(f'Files     : {len(lines)}')
    log.info(f'Passwords : {passwords}')
    log.info(f'Scanners  : {[s.NAME for s in scanners]}')
    log.info(f'Wait      : {args.wait_results}')

    all_reports   = []
    scanner_ok    = 0   # files where ≥1 scanner succeeded
    scanner_total = 0   # files attempted

    try:
        for line in lines:
            p = Path(line)
            if not p.exists():
                log.warning(f'Not found, skipping: {p}')
                continue
            to_scan = expand_file(p, passwords, tmpdir)
            if not to_scan:
                log.info(f'Skipping (not scannable): {p.name}')
                continue
            for f in to_scan:
                if f.stat().st_size == 0:
                    log.info(f'Skipping empty: {f.name}')
                    continue
                scanner_total += 1
                r = scan_file(f, scanners, output_dir, ioc_dir, args.wait_results)
                if r:
                    all_reports.append(r)
                    # Count as OK if at least one scanner result has no error
                    any_ok = any(
                        v.get('_ok') for v in r.get('results', {}).values()
                    )
                    if any_ok:
                        scanner_ok += 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────────
    log.info(f'\n{"="*60}')
    log.info(f'Scanned : {scanner_total} file(s)')
    for r in all_reports:
        vt      = r['results'].get('VirusTotalScanner', {})
        md      = r['results'].get('MetaDefenderScanner', {})
        vt_str  = f"{vt.get('positives','?')}/{vt.get('total','?')}" if vt.get('_ok') else 'error'
        md_str  = str(md.get('positives', '-')) if md.get('_ok') else 'error'
        log.info(f'  {r["sha256"][:16]}… {r["filename"]:30s}  VT:{vt_str}  MD:{md_str}')

    if scanner_total > 0 and scanner_ok == 0:
        # Every single scanner errored on every file — hard fail
        log.error('FATAL: All scanners failed on all files. Check API keys and network.')
        sys.exit(2)

    sys.exit(0)


if __name__ == '__main__':
    main()
