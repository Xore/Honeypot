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
6. Validates every generated rule with `yara -w <rule> /dev/null` before saving.
   Invalid rules are written to yara-rules/auto/_invalid/ for manual review.
7. Exits 0 always — the workflow separately compiles the active corpus after
   generation, while preserving scanner reports when generator output is bad.
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
import math
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

# committed samples are password-protected archives (analyze_samples.py's own
# publish convention), not raw binaries -- reuse its extraction logic rather
# than duplicating it, so both passes agree on what "the sample" actually is.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_samples import ARCHIVE_EXTS, expand_file  # noqa: E402

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

# .NET compiler/runtime metadata and the stock VS manifest template: present
# in essentially every managed executable regardless of what it does, so they
# have zero discriminating power. Found via #109 — 15 of 18 auto-generated
# rules turned out to be byte-identical because every one of them was built
# entirely from this set.
NET_BOILERPLATE: set[str] = {
    '_CorExeMain', 'System.Runtime.CompilerServices',
    'System.Runtime.InteropServices', 'RuntimeCompatibilityAttribute',
    'CompilationRelaxationsAttribute', 'WrapNonExceptionThrows',
    'TargetFrameworkAttribute', 'FrameworkDisplayName',
    'AssemblyCompanyAttribute', 'AssemblyConfigurationAttribute',
    'AssemblyCopyrightAttribute', 'AssemblyDescriptionAttribute',
    'AssemblyFileVersionAttribute', 'AssemblyProductAttribute',
    'AssemblyTrademarkAttribute', 'AssemblyTitleAttribute',
    'AssemblyVersionAttribute', 'AssemblyCultureAttribute',
    'GetCommandLineArgs', 'GetLaunchExeFilename', 'FileSystemInfo',
    'DebuggableAttribute', 'STAThreadAttribute', 'GuidAttribute',
    'ComVisibleAttribute', 'System.Reflection', 'System.Diagnostics',
    'mscorlib', 'mscorlib.dll', 'System.Private.CoreLib',
}
NOISY_STRINGS |= NET_BOILERPLATE

# Regexes matching the stock VS AssemblyInfo/manifest XML template, strong-
# named assembly references, and Microsoft's own PKI infrastructure — all
# linker/toolchain-generated, present in any .NET binary that references the
# same framework assemblies, and not something a sample author wrote. Found
# while testing #109's fix: the URL bonus below was scoring
# crl.microsoft.com cert-revocation links as "discriminating" just because
# they're URLs.
BOILERPLATE_PATTERNS = [
    re.compile(r'<assemblyIdentity\b'),
    re.compile(r'<requestedExecutionLevel\b'),
    re.compile(r'^<\?xml\b'),
    re.compile(r'urn:schemas-microsoft-com'),
    re.compile(r'Culture=neutral,\s*PublicKeyToken='),   # strong-named assembly ref
    re.compile(r'(?i)://(?:crl|www)\.microsoft\.com/'),   # MS cert/CRL infrastructure
    re.compile(r'(?i)microsoft\.com/pkiops/'),
]

# A string that shows up in this many DISTINCT samples within a single run is
# boilerplate by definition, whether or not it's on the static list above —
# real detection content is specific to a family, not universal. This is the
# "large fraction of already-generated rules" heuristic from #109, applied
# across the current batch instead of requiring a pre-built list to keep up
# with every compiler's manifest template.
BOILERPLATE_SAMPLE_FRACTION = 0.34
BOILERPLATE_SAMPLE_MIN      = 2

# Regex patterns that indicate a string is likely useful for detection
USEFUL_PATTERNS = [
    re.compile(r'[a-zA-Z]{4,}\.[a-zA-Z]{2,4}$'),   # filenames
    re.compile(r'https?://'),                          # URLs
    re.compile(r'/[a-zA-Z0-9_/.-]{6,}'),              # Unix paths
    re.compile(r'[A-Z][a-z]+[A-Z][a-zA-Z]{3,}'),     # CamelCase API names
    re.compile(r'[a-z]{4,}_[a-z]{3,}'),               # snake_case identifiers
    re.compile(r'(?i)(attack|flood|shell|exec|payload|backdoor|keylog|crypt|xor|inject|bypass|persist|spread|infect|botnet|c2|cnc|wget|curl|chmod|busybox|mirai|miori|mozi|sora|hoho)'),
]

# Patterns that strongly indicate sample-specific, high-value content —
# C2 infrastructure, IPC artifacts, embedded paths — rather than generic
# framework identifiers. Distinct from USEFUL_PATTERNS: these get a large
# score bonus instead of just clearing the inclusion bar.
DISCRIMINATING_PATTERNS = [
    re.compile(r'https?://[^\s"\']+'),                       # full URLs
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),               # IPv4 literals
    re.compile(r'(?i)\\\\\.\\pipe\\'),                         # named pipes
    re.compile(r'(?i)\bglobal\\\\'),                           # named mutexes
    re.compile(r'[A-Za-z]:\\\\[^\\]+\\\\[^\\]+'),              # absolute Windows paths, 2+ segments
    re.compile(r'\b[0-9a-f]{32,64}\b'),                        # hashes/keys embedded as text
]

# Patterns that look like compiler/runtime/framework identifiers rather than
# anything the malware author wrote — CamelCase alone (USEFUL_PATTERNS[3])
# rewards these just as much as a real API-abuse string, which is exactly
# how .NET attribute names won the string-selection race in #109.
DEPRIORITIZED_PATTERNS = [
    re.compile(r'Attribute$'),
    re.compile(r'^(?:System|Microsoft|mscorlib)\.'),
    re.compile(r'(?i)^<\?xml|^<assembly|xmlns'),
    re.compile(r'(?i)\b(?:runtime|framework|compiler|manifest)\b'),
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
        if any(p.search(s) for p in BOILERPLATE_PATTERNS):
            continue
        if not any(p.search(s) for p in USEFUL_PATTERNS):
            continue
        seen.add(s)
        useful.append(s)

    # Sort by length descending (longer = more specific)
    useful.sort(key=len, reverse=True)
    return useful[:MAX_STRINGS * 3]  # keep a wider set before final trim


def extract_strings_from_sample(path: Path, passwords: list[str], tmpdir: Path) -> list[str]:
    """extract_strings_from_binary, but unpacks an archived sample first.

    Every committed sample is a password-protected archive
    (analyze_samples.py's publish convention), not a raw binary -- running
    `strings` directly against path scans the *compressed container bytes*,
    which for a real ZIP/7z/etc. essentially never contain the payload's own
    strings. Reuses analyze_samples.expand_file (same multi-password,
    multi-format, recursive-archive logic the scanner submission path
    already relies on) so both passes agree on what "the sample" actually
    is, rather than a second, divergent unpacking implementation here.

    Falls back to scanning path directly if it isn't a recognized archive
    extension, or if unpacking it yields nothing (wrong password list,
    corrupt archive) -- never silently returns zero strings when there was
    at least a chance of finding something.
    """
    if path.suffix.lower() in ARCHIVE_EXTS:
        members = expand_file(path, passwords, tmpdir)
        if members:
            strings: list[str] = []
            seen: set[str] = set()
            for member in members:
                for s in extract_strings_from_binary(member):
                    if s not in seen:
                        seen.add(s)
                        strings.append(s)
            return strings
        log.warning(f'  Could not unpack {path.name} with the configured passwords -- '
                    f'falling back to scanning the archive container itself')
    return extract_strings_from_binary(path)


def score_string(s: str) -> float:
    """Heuristic score: reward sample-specific content, punish framework noise."""
    char_entropy = len(set(s)) / max(len(s), 1)
    length_score = min(len(s) / 40.0, 1.0)
    # Bonus for known-bad patterns (attack/exec/c2 keywords etc.)
    bonus = 0.3 if any(p.search(s) for p in USEFUL_PATTERNS[3:]) else 0.0
    # Large bonus for genuinely discriminating content: C2 URLs/IPs, IPC
    # names, embedded paths — the things #109 found the old scoring never
    # favoured over compiler-generated identifiers.
    if any(p.search(s) for p in DISCRIMINATING_PATTERNS):
        bonus += 0.6
    # Penalty for strings that are CamelCase only because they're a runtime
    # or framework identifier, not because an author named them that way.
    if any(p.search(s) for p in DEPRIORITIZED_PATTERNS):
        bonus -= 0.5
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
    # #109: "3 of 20" fires on almost anything once N stops scaling with the
    # string count. Require ~40% of the strings to match instead of capping
    # at a flat 3, so a 20-string rule needs 8 hits, not 3.
    n_cond = required_string_matches(len(strings))
    if condition == 'all':
        lines.append('        all of them')
    elif condition == 'any':
        lines.append(f'        {n_cond} of ($s*)')
    else:
        lines.append(f'        {condition}')
    lines.append('}')
    lines.append('')

    return '\n'.join(lines)


def required_string_matches(string_count: int) -> int:
    """Return the minimum matches for a generated string rule."""
    return min(
        max(MIN_STRINGS_RULE, math.ceil(string_count * 0.4)),
        string_count,
    )


def build_hash_only_rule(
    family:      str,
    sha256_list: list[str],
    file_types:  set[str],
    references:  list[str],
) -> str:
    """
    Emit a hash-only rule when too few discriminating strings survive
    boilerplate filtering. #109: "no rule is better than one that matches
    every .NET binary" — a hash match is honest about only covering the
    exact samples seen, instead of a loose string rule that fires on
    anything sharing a compiler.
    """
    date_str  = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    rule_name = f'AutoGen_{family.capitalize()}_HashOnly'
    refs      = list(dict.fromkeys(references))[:3]
    hashes    = list(dict.fromkeys(sha256_list))[:10]

    lines = ['import "hash"', '', f'rule {rule_name}', '{']
    lines.append('    meta:')
    lines.append(
        f'        description = "Auto-generated hash-only rule for {family} '
        '(no discriminating strings survived boilerplate filtering)"'
    )
    lines.append('        author      = "honeypot-bot"')
    lines.append(f'        date        = "{date_str}"')
    lines.append('        auto_generated = true')
    lines.append('        hash_only   = true')
    if hashes:
        lines.append(f'        sample_sha256 = "{hashes[0]}"')
    if file_types:
        lines.append(f'        file_types  = "{", ".join(sorted(file_types))}"')
    for i, ref in enumerate(refs, 1):
        lines.append(f'        reference{i}  = "{ref}"')

    lines.append('')
    lines.append('    condition:')
    conds = [f'hash.sha256(0, filesize) == "{h}"' for h in hashes]
    lines.append('        ' + ' or\n        '.join(conds))
    lines.append('}')
    lines.append('')

    return '\n'.join(lines)


def string_set_signature(strings: list[str]) -> str:
    """Order-independent fingerprint of a rule's string set, for dedup."""
    return hashlib.sha256('\n'.join(sorted(strings)).encode()).hexdigest()


def existing_rule_signatures(output_dir: Path) -> dict[str, str]:
    """Map every existing rule file's string-set signature to its filename."""
    sigs: dict[str, str] = {}
    if not output_dir.exists():
        return sigs
    for f in output_dir.glob('*.yar'):
        if f.stem.startswith('_'):
            continue
        try:
            vals = re.findall(
                r'\$s\d+\s*=\s*"([^"]*)"', f.read_text(encoding='utf-8')
            )
        except Exception:
            continue
        if vals:
            sigs[string_set_signature(vals)] = f.name
    return sigs


def validate_rule(rule_text: str) -> tuple[bool, str]:
    """Compile rule with `yara` CLI; return (valid, error_message)."""
    if not shutil.which('yara'):
        return False, 'yara executable not found; refusing unvalidated output'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', encoding='utf-8',
                                     delete=False) as tmp:
        tmp.write(rule_text)
        tmp_path = tmp.name
    try:
        # Use a dummy target file (the rule file itself) — we only care about compile
        r = subprocess.run(
            ['yara', '-w', tmp_path, os.devnull],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True, ''
        return False, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, f'validation failed: {e}'
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


def parse_report(report_path: Path, sample_dir: Path,
                  passwords: list[str] | None = None, tmpdir: Path | None = None) -> dict | None:
    """Parse a scanner JSON report and return a profile dict."""
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
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

    # Extract strings from the actual binary if we can find it. Samples are
    # committed as password-protected archives (see extract_strings_from_sample's
    # own docstring), so unpack before scanning rather than reading the
    # archive container's own compressed bytes.
    binary_strings: list[str] = []
    if sample_path:
        if tmpdir is not None:
            binary_strings = extract_strings_from_sample(sample_path, passwords or [], tmpdir)
        else:
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
            for line in yar.read_text(encoding='utf-8').splitlines():
                m = re.search(r'sample_sha256\s*=\s*"([0-9a-f]{64})"', line)
                if m:
                    seen.add(m.group(1))
        except Exception:
            pass
    return seen


def append_new_strings_to_rule(
    rule_path: Path,
    new_strings: list[str],
) -> tuple[bool, str, str | None]:
    """Append strings, rescale the threshold, and validate before replacing."""
    try:
        content = rule_path.read_text(encoding='utf-8')
    except Exception as e:
        return False, f'cannot read existing rule: {e}', None

    if 'hash_only   = true' in content or 'strings:' not in content:
        return False, 'existing rule is hash-only', None

    # Find existing string values to avoid duplication
    existing_vals = set(re.findall(r'\$s\d+\s*=\s*"([^"]+)"', content))
    to_add = [s for s in new_strings if s not in existing_vals]
    if not to_add:
        return False, '', None

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

    total_strings = len(existing_vals) + len(new_lines)
    threshold = required_string_matches(total_strings)
    updated, replacements = re.subn(
        r'(?m)^(\s*)\d+\s+of\s+\(\$s\*\)\s*$',
        rf'\g<1>{threshold} of ($s*)',
        updated,
        count=1,
    )
    if replacements != 1:
        return False, 'generated rule has no scalable $s* threshold', updated

    valid, error = validate_rule(updated)
    if not valid:
        return False, error, updated

    rule_path.write_text(updated, encoding='utf-8')
    return True, '', updated


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
              '- Invalid rules (failed YARA compilation) are in `_invalid/`.',
              '- To promote a rule to `yara-rules/`, copy and refine it there.']

    index_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def run(report_dir: Path, sample_dir: Path, output_dir: Path,
        passwords: list[str] | None = None) -> int:
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

    # Group profiles by normalised family name. Extraction happens into a
    # scratch dir scoped to just this loop -- unpacked samples don't need to
    # survive past string extraction, and freeing that disk space before the
    # (potentially large) rule-writing phase below is worth the narrower scope.
    family_map: dict[str, list[dict]] = defaultdict(list)
    all_profiles: list[dict] = []
    skipped_existing = 0
    with tempfile.TemporaryDirectory(prefix='honeypot-yara-extract-') as extract_tmp:
        extract_dir = Path(extract_tmp)
        for rp in reports:
            profile = parse_report(rp, sample_dir, passwords, extract_dir)
            if not profile:
                continue
            # Skip samples whose sha256 is already recorded in an existing .yar rule
            if profile['sha256'] and profile['sha256'] in processed_sha256s:
                log.info(f'  Skipping already-processed sample: {profile["filename"]} ({profile["sha256"][:16]}…)')
                skipped_existing += 1
                continue
            all_profiles.append(profile)
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

    # #109: a string present across a large fraction of this run's DISTINCT
    # samples is boilerplate by definition, whatever it is — real detection
    # content is specific to one family, not shared by everything compiled
    # with the same toolchain. Computed dynamically so it also catches
    # boilerplate from compilers NET_BOILERPLATE doesn't know about yet.
    sample_count = len({p['sha256'] for p in all_profiles if p['sha256']}) or len(all_profiles)
    boilerplate_threshold = max(BOILERPLATE_SAMPLE_MIN,
                                 math.ceil(sample_count * BOILERPLATE_SAMPLE_FRACTION))
    string_sample_counts: dict[str, set[str]] = defaultdict(set)
    for p in all_profiles:
        key = p['sha256'] or p['filename']
        for s in p['binary_strings']:
            string_sample_counts[s].add(key)
    dynamic_boilerplate = {
        s for s, samples in string_sample_counts.items()
        if len(samples) >= boilerplate_threshold
    }
    if dynamic_boilerplate:
        log.info(f'Dynamic boilerplate filter: {len(dynamic_boilerplate)} string(s) '
                  f'seen in >= {boilerplate_threshold}/{sample_count} samples, excluded')

    log.info(f'Identified {len(family_map)} unique family/cluster(s)')
    existing_rules   = load_existing_rules(output_dir)
    written_sigs      = existing_rule_signatures(output_dir)

    new_rules     = []
    updated_rules = []
    skipped       = 0
    invalid       = 0
    hash_only     = 0
    deduped       = 0

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

        # Strip this run's dynamic boilerplate, then dedupe and score
        all_strings    = [s for s in all_strings if s not in dynamic_boilerplate]
        unique_strings = list(dict.fromkeys(all_strings))
        best_strings   = select_best_strings(unique_strings)

        rule_key = family.lower()

        if len(best_strings) < MIN_STRINGS_RULE:
            # #109: no discriminating strings survived — a loose string rule
            # here would just match every binary from the same toolchain.
            # Fall back to naming the exact samples seen instead of skipping
            # silently, as long as we actually have hashes to name.
            if sha256s:
                rule_text = build_hash_only_rule(
                    family      = family,
                    sha256_list = sha256s,
                    file_types  = file_types,
                    references  = list(dict.fromkeys(references)),
                )
                valid, err = validate_rule(rule_text)
                rule_path  = output_dir / f'{rule_key}.yar'
                if not valid:
                    log.warning(f'  [{family}] hash-only rule failed validation: {err}')
                    (invalid_dir / f'{rule_key}.yar').write_text(
                        f'// INVALID — {err}\n\n{rule_text}', encoding='utf-8'
                    )
                    invalid += 1
                    continue
                rule_path.write_text(rule_text, encoding='utf-8')
                log.info(f'  [{family}] {len(best_strings)} discriminating strings '
                         f'after boilerplate filtering — wrote hash-only rule '
                         f'({len(sha256s)} sample(s)) instead')
                new_rules.append(rule_key)
                hash_only += 1
            else:
                log.info(f'  [{family}] only {len(best_strings)} useful strings and no '
                         'sha256 to fall back on — skipping rule')
                skipped += 1
            continue

        # #109: 15 of 18 files ended up byte-identical. Refuse to write a
        # second rule with the same string set under a different family
        # name — one rule (or none) covers it.
        sig = string_set_signature(best_strings)
        if sig in written_sigs:
            log.info(f'  [{family}] string set is identical to existing rule '
                      f'{written_sigs[sig]} — skipping duplicate')
            deduped += 1
            continue

        if rule_key in existing_rules:
            rule_path = existing_rules[rule_key]
            existing_text = rule_path.read_text(encoding='utf-8')

            # A hash-only rule has no strings block to append to. Once later
            # telemetry provides enough discriminating strings, replace it
            # with a normal generated rule instead of producing invalid YARA.
            if 'hash_only   = true' in existing_text:
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
                if not valid:
                    log.warning(f'  [{family}] hash-only promotion failed validation: {err}')
                    (invalid_dir / f'{rule_key}.yar').write_text(
                        f'// INVALID — {err}\n\n{rule_text}', encoding='utf-8'
                    )
                    invalid += 1
                    continue
                rule_path.write_text(rule_text, encoding='utf-8')
                log.info(f'  [{family}] promoted hash-only rule to string rule')
                updated_rules.append(rule_key)
                written_sigs[sig] = rule_path.name
                continue

            added, err, candidate = append_new_strings_to_rule(rule_path, best_strings)
            if added:
                log.info(f'  [{family}] updated existing rule → {rule_path.name}')
                updated_rules.append(rule_key)
                written_sigs[sig] = rule_path.name
            elif err:
                log.warning(f'  [{family}] rule update failed validation: {err}')
                if candidate is not None:
                    (invalid_dir / f'{rule_key}.yar').write_text(
                        f'// INVALID — {err}\n\n{candidate}', encoding='utf-8'
                    )
                invalid += 1
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
                inv_path.write_text(
                    f'// INVALID — {err}\n\n{rule_text}', encoding='utf-8'
                )
                invalid += 1
                continue

            rule_path.write_text(rule_text, encoding='utf-8')
            log.info(f'  [{family}] new rule → {rule_path.name} ({len(best_strings)} strings)')
            new_rules.append(rule_key)
            written_sigs[sig] = rule_path.name

    generate_index(output_dir, new_rules, updated_rules)

    log.info(f'\n{"="*50}')
    log.info(f'New rules    : {len(new_rules)}')
    log.info(f'Updated rules: {len(updated_rules)}')
    log.info(f'Hash-only    : {hash_only}  (no discriminating strings survived)')
    log.info(f'Deduped      : {deduped}  (identical string set to an existing rule)')
    log.info(f'Skipped      : {skipped}  (too few strings, no hash fallback)')
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
    parser.add_argument('--archive-passwords', default='',
                        help='Comma-separated passwords to try when unpacking a committed '
                             'sample archive before string extraction (matches '
                             'analyze_samples.py\'s --archive-passwords)')
    args = parser.parse_args()
    passwords = [p.strip() for p in args.archive_passwords.split(',') if p.strip()]

    try:
        sys.exit(run(
            report_dir = Path(args.report_dir),
            sample_dir = Path(args.sample_dir),
            output_dir = Path(args.output_dir),
            passwords  = passwords,
        ))
    except Exception as e:
        log.error(f'Unhandled error in generate_yara: {e}', exc_info=True)
        # Never abort the pipeline
        sys.exit(0)


if __name__ == '__main__':
    main()
