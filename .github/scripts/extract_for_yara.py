#!/usr/bin/env python3
"""extract_for_yara.py — print the scannable file(s) inside a sample, after
unpacking it if it's an archive.

Committed samples are password-protected archives (analyze_samples.py's own
publish convention), not raw binaries. Running the `yara` CLI directly
against one scans the compressed container bytes, not the payload -- the
same bug generate_yara.py's extract_strings_from_sample fixes for rule
generation. This is the equivalent fix for analyze.yml's YARA local
pre-scan step, which is bash, not Python: reuses analyze_samples.expand_file
(same multi-password, multi-format, recursive-archive logic the scanner
submission path already relies on) so every pass through this pipeline
agrees on what "the sample" actually is, and prints one path per line for
the calling shell loop to scan.

Falls back to printing the original path unchanged if it isn't a recognized
archive extension, or if unpacking yields nothing (wrong password list,
corrupt archive) -- never silently prints nothing when there was at least a
chance of scanning something.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_samples import ARCHIVE_EXTS, expand_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path)
    parser.add_argument('--dest', required=True, type=Path,
                         help='Scratch directory to extract into')
    parser.add_argument('--passwords', default='',
                         help='Comma-separated archive passwords to try')
    args = parser.parse_args()

    if not args.sample.is_file():
        print(f'extract_for_yara: {args.sample} is not a file', file=sys.stderr)
        return 1

    args.dest.mkdir(parents=True, exist_ok=True)
    passwords = [p.strip() for p in args.passwords.split(',') if p.strip()]

    targets = expand_file(args.sample, passwords, args.dest)
    if not targets and args.sample.suffix.lower() in ARCHIVE_EXTS:
        print(f'extract_for_yara: could not unpack {args.sample.name} with the '
              f'configured passwords, falling back to the archive itself', file=sys.stderr)
        targets = [args.sample]

    for t in targets:
        print(t)
    return 0


if __name__ == '__main__':
    sys.exit(main())
