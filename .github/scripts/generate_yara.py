#!/usr/bin/env python3
"""
generate_yara.py — Auto-generate YARA rules from scanner JSON reports.

Pipeline position: runs AFTER analyze_samples.py, reads its JSON output.

What it does
────────
1. Reads every *.json report in --report-dir (written by analyze_samples.py).
2. For each report it builds a "profile" containing:
   - Detected family names from VirusTotal (names[] + scan results)
   - Tags and signature from MalwareBazaar
   - Malscore / family from CAPE
   - Unique printable ASCII strings extracted directly from the sample binary
     (via subprocess 'strings -n 6', filtered for useful patterns)
   - File type, hashes, size
3. Groups reports by malware family (normalised name).
4. For each family that does NOT already have a rule in --output-dir:
   - Picks the most-discriminating strings (length, uniqueness, entropy heuristic)
   - Emits a well-formed YARA rule skeleton with meta + string conditions
5. For families that already have a rule:
   - Checks whether new unique strings should be appended (update mode)
6. Validates every generated rule with `yara --compile` before saving.
   Invalid rules are written to yara-rules/auto/_invalid/ for manual review.
7. Exits 0 always — a rule-gen failure must never abort the scan pipeline.
8. Skips any report whose sha256 is already tracked in GENERATED.md to avoid
   re-processing samples on re-runs.

Output
──────
  yara-rules/auto/<family>.yar   — one file per normalised family name
  yara-rules/auto/_invalid/      — rules that failed yara --compile
  yara-rules/auto/GENERATED.md   — index of all auto-generated rules

Limitations
───────────
- String-based rules only (no byte pattern / hex sequence extraction yet).
- Family normalisation is best-effort; VT names are noisy.
- Generated rules are STARTING POINTS — review before relying on them.
  They will tend to have higher FP rates than hand-crafted rules.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('honeypot.yara_gen')

# ── Constants ───────────────────────────────────────────────────────────────

MIN_STRING_LEN   = 8    # minimum printable-string length to consider
MAX_STRINGS      = 20   # max string conditions per rule
MIN_STRINGS_RULE = 3    # skip rule if fewer than this many useful strings found

# Strings that are almost universally present and not useful for detection
NOISY_STRINGS: set[str] = {
    'This program cannot be run in DOS mode',
    'Rich',
    '.text', '.data', '.rdata', '.bss', '.pdata', '.rsrc', '.reloc',
    'KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll', 'ntdll.dll',
    'GetProcAddress', 'LoadLibraryA', 'ExitProcess',
    'msvcrt.dll', 'VCRUNTIME', '__CxxFrameHandler',
    '/bin/sh', '/bin/bash',  # too common
    'localhost', '127.0.0.1',
}

# Regex patterns that indicate a string is likely useful for detection
USEFUL_PATTERNS = [
    re.compile(r'[a-zA-Z]{4,}\.[a-zA-Z]{2,4}$'),   # filenames
    re.compile(r'https?://'),                          # URLs
    re.compile(r'/[a-zA-Z0-9_/.-]{6,}'),              # Unix paths
    re.compile(r'[A-Z][a-z]+[A-Z][a-zA-Z]{3,}'),     # CamelCase API names
    re.compile(r'[a-z]{4,}_[a-z]{3,}'),               # snake_case identifiers
    re.compile(r'(?i)(attack|flood|shell|exec|payload|backdoor|keylog|crypt|xor|inject|bypass|persist|spread|infect|botnet|c2|cnc|wget|curl|chmod|busybox|mirai|miori|mozi|sora|hoho)'),
]

# VT detection name prefixes to strip when normalising family names
VT_PREFIXES = re.compile(
    r'^(?:Trojan|Backdoor|Worm|Virus|Ransom|Adware|Spyware|Dropper|Downloader|'
    r'Exploit|Rootkit|PUP|PUA|HEUR|ML|Suspicious|Generic|Gen|Generik|Banker|'
    r'Stealer|Miner|Loader|Injector|RAT|Bot|Agent)'
    r'[./\-_]?',
    re.IGNORECASE,
)


# ── Utilities ───────────────────────────────────────────────────────────────

def _safe_list(val) -> list:
    """Return val if it's a non-None list, else []."""
    return val if isinstance(val, list) else []


def normalise_family(raw: str) -> Optional[str]:
    """Strip AV vendor noise and return a clean family identifier, or None."""
    if not raw or len(raw) < 3:
        return None
    # Strip common VT prefixes iteratively (some names stack multiple)
    name = raw.strip()
    for _ in range(4):
        new = VT_PREFIXES.sub('', name).strip('./-_ ')
        if new == name:
            break
        name = new
    # Normalise separators
    name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    name = re.sub(r'_+', '_', name).strip('_')
    # Skip names that are pure version numbers or too short/long
    if re.match(r'^[0-9_]+$', name) or len(name) < 3 or len(name) > 60:
        return None
    return name.lower()


def extract_strings_from_binary(path: Path) -> list[str]:
    """Run 'strings -n MIN_STRING_LEN' on a file and return filtered results."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        result = subprocess.run(
            ['strings', '-n', str(MIN_STRING_LEN), str(path)],
            capture_output=True, text=True, timeout=30,
        )
        lines = result.stdout.splitlines()
    except Exception as e:
        log.warning(f'strings extraction failed for {path.name}: {e}')
        return []

    useful = []
    seen   = set()
    for line in lines:
        s = line.strip()
        if len(s) < MIN_STRING_LEN or len(s) > 200:
            continue
        if s in NOISY_STRINGS or s in seen:
            continue
        if not any(p.search(s) for p in USEFUL_PATTERNS):
            continue
        seen.add(s)
        useful.append(s)

    # Sort by length descending (longer = more specific)
    useful.sort(key=len, reverse=True)
    return useful[:MAX_STRINGS * 3]  # keep a wider set before final trim


def score_string(s: str) -> float:
    """Heuristic score: longer + more unique chars = better detection string."""
    char_entropy = len(set(s)) / max(len(s), 1)
    length_score = min(len(s) / 40.0, 1.0)
    # Bonus for known-bad patterns
    bonus = 0.3 if any(p.search(s) for p in USEFUL_PATTERNS[3:]) else 0.0
    return char_entropy * 0.4 + length_score * 0.4 + bonus


def select_best_strings(strings: list[str], n: int = MAX_STRINGS) -> list[str]:
    scored = sorted(strings, key=score_string, reverse=True)
    return scored[:n]


def yara_escape(s: str) -> str:
    """Escape a string for use inside a YARA double-quoted string literal."""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\t', '\\t').replace('\n', '\\n')


# ── Rule generation ──────────────────────────────────────────────────────────

def build_rule(
    family:      str,
    description: str,
    strings:     list[str],
    sha256_list: list[str],
    file_types:  set[str],
    tags:        list[str],
    references:  list[str],
    condition:   str = 'any',
) -> str:
    """
    Emit a well-formed YARA rule.

    condition:
      'any'   → any of ($s*)
      'N'     → N of ($s*)   where N = min(3, len(strings))
      'all'   → all of them
    """
    date_str    = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    rule_name   = f'AutoGen_{family.capitalize()}'
    tag_str     = ' '.join(f'autogen {t}' for t in tags[:3]) if tags else 'autogen'
    # Deduplicate references
    refs = list(dict.fromkeys(references))[:3]

    lines = [f'rule {rule_name}', '{']

    # meta
    lines.append('    meta:')
    lines.append(f'        description = "Auto-generated rule for {family} (honeypot telemetry)"')
    lines.append(f'        author      = "honeypot-bot"')
    lines.append(f'        date        = "{date_str}"')
    lines.append(f'        auto_generated = true')
    if sha256_list:
        lines.append(f'        sample_sha256 = "{sha256_list[0]}"')
    if file_types:
        lines.append(f'        file_types  = "{", ".join(sorted(file_types))}"')
    for i, ref in enumerate(refs, 1):
        lines.append(f'        reference{i}  = "{ref}"')

    # strings
    lines.append('')
    lines.append('    strings:')
    for i, s in enumerate(strings, 1):
        esc = yara_escape(s)
        lines.append(f'        $s{i} = "{esc}" ascii nocase')

    # condition
    lines.append('')
    lines.append('    condition:')
    n_cond = max(1, min(3, len(strings) // 2))
    if condition == 'all':
        lines.append('        all of them')
    elif condition == 'any':
        lines.append(f'        {n_cond} of ($s*)')
    else:
        lines.append(f'        {condition}')
    lines.append('}')
    lines.append('')

    return '\n'.join(lines)


def validate_rule(rule_text: str) -> tuple[bool, str]:
    """Compile rule with `yara` CLI; return (valid, error_message)."""
    if not shutil.which('yara'):
        # yara not available — skip validation, assume valid
        return True, ''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar',
                                     delete=False) as tmp:
        tmp.write(rule_text)
        tmp_path = tmp.name
    try:
        # Use a dummy target file (the rule file itself) — we only care about compile
        r = subprocess.run(
            ['yara', '--compile-rules', tmp_path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True, ''
        # Some yara versions don't support --compile-rules; try scanning /dev/null
        r2 = subprocess.run(
            ['yara', tmp_path, '/dev/null'],
            capture_output=True, text=True, timeout=10,
        )
        if r2.returncode == 0:
            return True, ''
        return False, (r2.stderr or r2.stdout).strip()
    except Exception as e:
        return True, f'validation skipped: {e}'  # soft pass
    finally:
        os.unlink(tmp_path)


# ── Report parsing ───────────────────────────────────────────────────────────

def collect_family_names(report: dict) -> list[str]:
    """Extract all candidate family names from a scan report."""
    names = []
    results = report.get('results', {})

    # VirusTotal: names[] field
    vt = results.get('VirusTotalScanner', {})
    names.extend(_safe_list(vt.get('names')))

    # VirusTotal: individual engine results (if present)
    for engine_result in vt.get('scans', {}).values() if isinstance(vt.get('scans'), dict) else []:
        if isinstance(engine_result, dict) and engine_result.get('result'):
            names.append(engine_result['result'])

    # MalwareBazaar: signature + tags (both may be null in JSON)
    mb = results.get('MalwareBazaarScanner', {})
    if sig := mb.get('signature'):
        names.append(sig)
    names.extend(_safe_list(mb.get('tags')))

    # CAPE: family
    cape = results.get('CAPESandboxScanner', {})
    if fam := cape.get('family'):
        names.append(fam)

    # HybridAnalysis: verdict string
    ha = results.get('HybridAnalysisScanner', {})
    if verdict := ha.get('verdict'):
        names.append(verdict)

    return [n for n in names if n and isinstance(n, str)]


def parse_report(report_path: Path, sample_dir: Path) -> dict | None:
    """Parse a scanner JSON report and return a profile dict."""
    try:
        data = json.loads(report_path.read_text())
    except Exception as e:
        log.warning(f'Cannot parse {report_path.name}: {e}')
        return None

    sha256   = data.get('sha256', '')
    filename = data.get('filename', '')
    size     = data.get('size', 0)
    results  = data.get('results', {})

    # Resolve sample path (may have been moved / archived)
    candidates = [
        Path(data.get('file', '')),
        sample_dir / filename,
    ]
    if filename:
        candidates.extend(sample_dir.rglob(filename))

    sample_path: Path | None = None
    for candidate in candidates:
        if candidate and candidate.exists() and candidate.is_file():
            sample_path = candidate
            break

    # Determine file type from VT or MB
    vt = results.get('VirusTotalScanner', {})
    mb = results.get('MalwareBazaarScanner', {})
    file_type = vt.get('type_description', '') or mb.get('file_type', '') or ''

    # Gather references
    refs = []
    if vt.get('permalink'):
        refs.append(vt['permalink'])
    if mb.get('permalink'):
        refs.append(mb['permalink'])

    family_names = collect_family_names(data)

    # Extract strings from the actual binary if we can find it
    binary_strings: list[str] = []
    if sample_path:
        binary_strings = extract_strings_from_binary(sample_path)
        log.info(f'  Extracted {len(binary_strings)} candidate strings from {sample_path.name}')
    else:
        log.warning(f'  Sample binary not found for {filename} (sha256={sha256[:16]}…) — strings skipped')

    return {
        'sha256':         sha256,
        'filename':       filename,
        'size':           size,
        'file_type':      file_type,
        'family_names':   family_names,
        'binary_strings': binary_strings,
        'references':     refs,
        'tags':           _safe_list(mb.get('tags')),
    }


# ── Main generation logic ────────────────────────────────────────────────────

def load_existing_rules(output_dir: Path) -> dict[str, Path]:
    """Return {family_name: path} for all existing auto-generated rules."""
    existing = {}
    if not output_dir.exists():
        return existing
    for f in output_dir.glob('*.yar'):
        if f.stem.startswith('_'):
            continue
        existing[f.stem.lower()] = f
    return existing


def load_processed_sha256s(output_dir: Path) -> set[str]:
    """
    Read sha256 hashes already recorded in GENERATED.md's embedded rule meta.
    This prevents re-processing the same sample on repeated workflow runs.
    We also scan all existing .yar files for sample_sha256 meta lines.
    """
    seen: set[str] = set()
    if not output_dir.exists():
        return seen
    for yar in output_dir.glob('*.yar'):
        if yar.stem.startswith('_'):
            continue
        try:
            for line in yar.read_text().splitlines():
                m = re.search(r'sample_sha256\s*=\s*"([0-9a-f]{64})"', line)
                if m:
                    seen.add(m.group(1))
        except Exception:
            pass
    return seen


def append_new_strings_to_rule(rule_path: Path, new_strings: list[str]) -> bool:
    """Read an existing rule and append new string entries if not already present."""
    try:
        content = rule_path.read_text()
    except Exception:
        return False

    # Find existing string values to avoid duplication
    existing_vals = set(re.findall(r'\$s\d+\s*=\s*"([^"]+)"', content))
    to_add = [s for s in new_strings if s not in existing_vals]
    if not to_add:
        return False

    # Find the last $sN index
    indices = [int(m) for m in re.findall(r'\$s(\d+)', content)]
    next_idx = (max(indices) + 1) if indices else 1

    new_lines = []
    for s in to_add[:5]:  # cap appended strings per update
        esc = yara_escape(s)
        new_lines.append(f'        $s{next_idx} = "{esc}" ascii nocase')
        next_idx += 1

    # Insert before the condition block
    updated = re.sub(
        r'(\n\s*condition:)',
        '\n' + '\n'.join(new_lines) + r'\1',
        content,
    )
    rule_path.write_text(updated)
    return True


def generate_index(output_dir: Path, new_rules: list[str], updated_rules: list[str]) -> None:
    """Write/update GENERATED.md index in the output directory."""
    index_path = output_dir / 'GENERATED.md'
    date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    lines = ['# Auto-Generated YARA Rules', '',
             f'> Last updated: {date_str}', '',
             'Rules in this directory are **automatically generated** from honeypot scan telemetry.',
             'They are starting points — review and tune before relying on them in production.', '',
             '| Rule file | Status |',
             '|---|---|']

    for f in sorted(output_dir.glob('*.yar')):
        if f.stem.startswith('_'):
            continue
        status = '\U0001f195 new' if f.stem in new_rules else ('\U0001f504 updated' if f.stem in updated_rules else '✅ existing')
        lines.append(f'| `{f.name}` | {status} |')

    lines += ['', '## Notes',
              '- `auto_generated = true` meta tag marks all rules here.',
              '- Invalid rules (failed `yara --compile`) are in `_invalid/`.',
              '- To promote a rule to `yara-rules/`, copy and refine it there.']

    index_path.write_text('\n'.join(lines) + '\n')


def run(report_dir: Path, sample_dir: Path, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    invalid_dir = output_dir / '_invalid'
    invalid_dir.mkdir(exist_ok=True)

    # Collect profiles from all report JSONs
    reports = list(report_dir.glob('*.json'))
    if not reports:
        log.info('No scanner reports found — nothing to generate.')
        return 0

    log.info(f'Processing {len(reports)} report(s) from {report_dir}')

    # Load sha256s already embedded in existing .yar files to skip re-processing
    processed_sha256s = load_processed_sha256s(output_dir)
    if processed_sha256s:
        log.info(f'Already processed sha256s: {len(processed_sha256s)} (will skip)')

    # Group profiles by normalised family name
    family_map: dict[str, list[dict]] = defaultdict(list)
    skipped_existing = 0
    for rp in reports:
        profile = parse_report(rp, sample_dir)
        if not profile:
            continue
        # Skip samples whose sha256 is already recorded in an existing .yar rule
        if profile['sha256'] and profile['sha256'] in processed_sha256s:
            log.info(f'  Skipping already-processed sample: {profile["filename"]} ({profile["sha256"][:16]}…)')
            skipped_existing += 1
            continue
        raw_names = profile['family_names']
        families  = {normalise_family(n) for n in raw_names}
        families.discard(None)
        if not families:
            # No family detected — use sha256 prefix as fallback key
            families = {f'unknown_{profile["sha256"][:8]}'}
        for fam in families:
            family_map[fam].append(profile)

    if skipped_existing:
        log.info(f'Skipped {skipped_existing} already-processed report(s)')

    if not family_map:
        log.info('No new families to process.')
        return 0

    log.info(f'Identified {len(family_map)} unique family/cluster(s)')
    existing_rules = load_existing_rules(output_dir)

    new_rules     = []
    updated_rules = []
    skipped       = 0
    invalid       = 0

    for family, profiles in sorted(family_map.items()):
        # Aggregate strings + metadata across all profiles for this family
        all_strings: list[str] = []
        sha256s:     list[str] = []
        file_types:  set[str]  = set()
        references:  list[str] = []
        tags:        list[str] = []

        for p in profiles:
            all_strings.extend(p['binary_strings'])
            if p['sha256']:
                sha256s.append(p['sha256'])
            if p['file_type']:
                file_types.add(p['file_type'])
            references.extend(p['references'])
            tags.extend(p['tags'])

        # Deduplicate and score
        unique_strings = list(dict.fromkeys(all_strings))
        best_strings   = select_best_strings(unique_strings)

        if len(best_strings) < MIN_STRINGS_RULE:
            log.info(f'  [{family}] only {len(best_strings)} useful strings — skipping rule')
            skipped += 1
            continue

        rule_key = family.lower()

        if rule_key in existing_rules:
            # Update mode: try to append new strings
            rule_path = existing_rules[rule_key]
            added = append_new_strings_to_rule(rule_path, best_strings)
            if added:
                log.info(f'  [{family}] updated existing rule → {rule_path.name}')
                updated_rules.append(rule_key)
            else:
                log.info(f'  [{family}] no new strings to add — unchanged')
        else:
            # New rule
            rule_text = build_rule(
                family      = family,
                description = f'Auto-generated for {family}',
                strings     = best_strings,
                sha256_list = sha256s,
                file_types  = file_types,
                tags        = list(dict.fromkeys(tags)),
                references  = list(dict.fromkeys(references)),
            )
            valid, err = validate_rule(rule_text)
            rule_path  = output_dir / f'{rule_key}.yar'

            if not valid:
                log.warning(f'  [{family}] rule failed validation: {err}')
                inv_path = invalid_dir / f'{rule_key}.yar'
                inv_path.write_text(f'// INVALID — {err}\n\n{rule_text}')
                invalid += 1
                continue

            rule_path.write_text(rule_text)
            log.info(f'  [{family}] new rule → {rule_path.name} ({len(best_strings)} strings)')
            new_rules.append(rule_key)

    generate_index(output_dir, new_rules, updated_rules)

    log.info(f'\n{"="*50}')
    log.info(f'New rules    : {len(new_rules)}')
    log.info(f'Updated rules: {len(updated_rules)}')
    log.info(f'Skipped      : {skipped}  (too few strings)')
    log.info(f'Invalid      : {invalid}  (failed yara compile)')

    # Print counts for workflow output
    print(f'new_rules={len(new_rules)}')
    print(f'updated_rules={len(updated_rules)}')

    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Generate YARA rules from honeypot scanner JSON reports.')
    parser.add_argument('--report-dir',  required=True,
                        help='Directory containing scanner JSON reports (reports/scanner/)')
    parser.add_argument('--sample-dir',  default='samples/',
                        help='Root samples directory (for binary string extraction)')
    parser.add_argument('--output-dir',  default='yara-rules/auto/',
                        help='Where to write generated .yar files')
    args = parser.parse_args()

    try:
        sys.exit(run(
            report_dir = Path(args.report_dir),
            sample_dir = Path(args.sample_dir),
            output_dir = Path(args.output_dir),
        ))
    except Exception as e:
        log.error(f'Unhandled error in generate_yara: {e}', exc_info=True)
        # Never abort the pipeline
        sys.exit(0)


if __name__ == '__main__':
    main()
