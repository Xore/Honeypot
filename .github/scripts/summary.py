#!/usr/bin/env python3
"""
summary.py - Print a Markdown table of scanner results to stdout.
Usage: python3 summary.py <reports_dir>
Output is appended to $GITHUB_STEP_SUMMARY by the workflow.
"""
import json
import sys
from pathlib import Path

reports_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('reports/scanner')

report_files = sorted(reports_dir.glob('*.json'))

if not report_files:
    print('No scanner reports found.')
    sys.exit(0)

print('## \U0001f52c Scanner Results')
print('')
print('| SHA256 | File | VT | MetaDefender | MalwareBazaar | Status |')
print('|--------|------|----|--------------|---------------|--------|')

for f in report_files:
    try:
        d    = json.loads(f.read_text())
        sha  = d.get('sha256', '?')[:16] + '...'
        name = d.get('filename', '?')
        r    = d.get('results', {})

        vt = r.get('VirusTotalScanner', {})
        md = r.get('MetaDefenderScanner', {})
        mb = r.get('MalwareBazaarScanner', {})

        vt_s = f"{vt.get('positives','?')}/{vt.get('total','?')}" if vt.get('_ok') else '\u274c error'
        md_s = str(md.get('positives', '0'))                       if md.get('_ok') else '\u274c error'

        # MB: show signature if known, '0' if submitted/not found, error otherwise
        if not mb.get('_ok'):
            mb_s = '\u274c error'
        elif mb.get('known') and mb.get('signature'):
            mb_s = mb['signature']
        else:
            mb_s = '0'

        any_ok = any(v.get('_ok') for v in r.values())
        status = '\u2705 ok' if any_ok else '\u274c all failed'

        # links where available
        vt_link  = vt.get('permalink', '')
        vt_cell  = f'[{vt_s}]({vt_link})' if vt_link and vt.get('_ok') else vt_s

        print(f'| `{sha}` | {name} | {vt_cell} | {md_s} | {mb_s} | {status} |')
    except Exception as e:
        print(f'| ? | error: {e} | | | | |')
