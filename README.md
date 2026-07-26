# Honeypot — Malware Sample Repository

![Malware Analysis Pipeline](https://github.com/Xore/Honeypot/actions/workflows/analyze.yml/badge.svg)

This repository stores malware samples, analysis reports, IOCs, and YARA rules captured by the [honeypot-stack](https://github.com/Xore/honeypot-stack). Every new sample pushed to `samples/` automatically triggers a full multi-scanner analysis pipeline via GitHub Actions.

> ⚠️ **WARNING**: This repository contains **real malware samples**. All binaries are stored in password-protected ZIP archives (password: `infected`). Never execute them outside of an isolated sandbox.

---

## Repository Layout

```
Honeypot/
├── samples/
│   ├── ELF/          # Linux/IoT ELF binaries (Mirai, Tsunami, miners)
│   ├── PE/           # Windows PE executables (droppers, RATs, stealers)
│   ├── Scripts/      # Shell / PowerShell / Python dropper scripts
│   ├── Docs/         # Malicious Office documents, PDF exploits
│   ├── Miori/        # Miori botnet family variants
│   ├── UNKNOWN/      # Unclassified / pending triage
│   └── UNKWN/        # Overflow from UNKNOWN
├── yara-rules/
│   ├── miori_mirai.yar     # Miori/Mirai botnet family
│   ├── elf_malware.yar     # Generic ELF/IoT malware
│   ├── pe_malware.yar      # PE droppers, RATs, stealers, ransomware
│   ├── scripts.yar         # Malicious shell/PS/Python/VBS scripts
│   ├── malicious_docs.yar  # Office macro droppers, PDF exploits
│   ├── generic.yar         # Cross-platform generic indicators
│   ├── README.md           # Rule authoring guide
│   └── auto/               # 🤖 Auto-generated rules (from scan telemetry)
│       ├── <family>.yar    # One file per detected family
│       ├── GENERATED.md    # Index of auto-generated rules
│       └── _invalid/       # Rules that failed yara --compile (for review)
├── reports/
│   ├── scanner/      # Per-sample JSON reports (named by SHA256)
│   ├── pdf/          # PDF scan reports (one per run date)
│   └── yara/         # YARA pre-scan hit logs
├── iocs/
│   ├── hashes.csv    # SHA256, SHA1, MD5, filename, first_seen
│   ├── families.csv  # SHA256 → detected family name mappings
│   └── CHANGELOG.md  # Per-run IOC and YARA generation log
├── docs/
├── quarantine/
└── .github/
    ├── workflows/
    │   └── analyze.yml           # Main pipeline
    └── scripts/
        ├── analyze_samples.py    # Multi-scanner submission
        ├── generate_yara.py      # Auto YARA rule generator
        ├── report.py             # PDF report generator
        └── summary.py            # GitHub step summary writer
```

---

## Pipeline Overview

The pipeline triggers on:
- **`push`** to `main` affecting `samples/**` — scans only newly Added/Renamed files
- **`pull_request`** to `main` affecting `samples/**` — dry-run (no commit)
- **`schedule`** — weekly full rescan every Sunday 02:00 UTC (refreshes VT scores)
- **`workflow_dispatch`** — manual trigger with optional path override

### Step-by-step

```
1. Detect new sample files  (--diff-filter=AR, fallback to full list)
        ↓
2. YARA pre-scan            (yara-rules/*.yar + yara-rules/auto/*.yar)
        ↓                   Offline detection before consuming API quota
3. Multi-scanner analysis   (analyze_samples.py)
        ↓                   Hash lookup → upload if unknown → wait for results
        ↓                   Writes reports/scanner/<sha256>.json
        ↓                   Appends iocs/hashes.csv, iocs/families.csv
4. Auto YARA generation     (generate_yara.py)
        ↓                   Reads scanner JSON reports
        ↓                   Runs `strings -n 8` on sample binaries
        ↓                   Normalises VT/MB/CAPE family names
        ↓                   Scores + selects best detection strings
        ↓                   Emits yara-rules/auto/<family>.yar
        ↓                   Validates with `yara --compile`
5. IOC changelog update     (iocs/CHANGELOG.md)
6. PDF report generation    (report.py → reports/pdf/)
7. Artifact upload          (PDF retained 90 days)
8. Commit everything        (reports/ + iocs/ + yara-rules/auto/) [skip ci]
```

---

## Scanners

| # | Scanner | Type | Secret |
|---|---------|------|--------|
| 1 | **VirusTotal** | 70+ AV engines | `VT_API_KEY` |
| 2 | **MalwareBazaar** | abuse.ch community DB | `MALWAREBAZAAR_API_KEY` |
| 3 | **Hybrid-Analysis** | Falcon Sandbox dynamic | `HYBRID_ANALYSIS_KEY` |
| 4 | **Malshare** | Community repo | `MALSHARE_API_KEY` |
| 5 | **JoeSandbox** | Deep dynamic analysis | `JOESANDBOX_API_KEY` |
| 6 | **MetaDefender** | 37+ AV engines (OPSWAT) | `METADEFENDER_API_KEY` |
| 7 | **CAPE Sandbox** | Cuckoo fork, config extraction | `CAPE_API_URL` + `CAPE_API_KEY` |
| 8 | **Any.run** | Interactive sandbox | `ANYRUN_API_KEY` |

At least **one** scanner secret must be configured. The pipeline degrades gracefully — a single scanner failure never aborts the job. Exit code `2` (all scanners failed) is the only hard failure.

---

## Secrets Required

| Secret | Required | Description |
|--------|----------|-------------|
| `GH_PAT` | ✅ Always | GitHub PAT with `repo` write scope (for bot commits) |
| `VT_API_KEY` | Recommended | VirusTotal API key |
| `MALWAREBAZAAR_API_KEY` | Optional | abuse.ch MalwareBazaar |
| `HYBRID_ANALYSIS_KEY` | Optional | Hybrid-Analysis / Falcon Sandbox |
| `MALSHARE_API_KEY` | Optional | Malshare community repo |
| `JOESANDBOX_API_KEY` | Optional | JoeSandbox Cloud |
| `METADEFENDER_API_KEY` | Optional | MetaDefender (OPSWAT) |
| `CAPE_API_URL` | Optional | Your CAPE instance URL |
| `CAPE_API_KEY` | Optional | CAPE authentication token |
| `ANYRUN_API_KEY` | Optional | Any.run paid API |

---

## YARA Rules

### Hand-crafted rules (`yara-rules/*.yar`)

Curated rules aligned to the sample families present in this repo:

| File | Covers |
|------|--------|
| `miori_mirai.yar` | Miori/Mirai credential tables, DDoS strings, C2 XOR, shell downloaders |
| `elf_malware.yar` | UPX ELF, reverse shells, XMRig miners, backdoors, rootkits, port scanners |
| `pe_malware.yar` | UPX PE, droppers, RATs, credential stealers, anti-VM, ransomware |
| `scripts.yar` | Shell downloaders, persistence, PowerShell obfuscation, Python/VBS backdoors |
| `malicious_docs.yar` | Office macros (AutoOpen/AutoExec), PDF JS, CVE-2017-11882, CVE-2022-30190 |
| `generic.yar` | Base64 shellcode blobs, IRC botnets, C2 HTTP patterns, anti-forensics |

### Auto-generated rules (`yara-rules/auto/`)

After every scan run, `generate_yara.py` automatically:
1. Reads `reports/scanner/*.json`
2. Extracts binary strings via `strings -n 8` from the sample
3. Normalises VT/MalwareBazaar/CAPE family names
4. Scores strings by length, character entropy, and keyword relevance
5. Emits `yara-rules/auto/<family>.yar` (or appends new strings to existing rules)
6. Validates with `yara --compile`; invalid rules go to `_invalid/` for review
7. Commits alongside scanner results

> Auto-generated rules are **starting points** — they carry `auto_generated = true` in meta. Review and promote to `yara-rules/` when confident in precision.

---

## Adding Samples

```bash
# Password-protect a sample before committing
zip --password infected samples/ELF/mybot.zip mybot
git add samples/ELF/mybot.zip
git commit -m "sample: add ELF dropper from SSH honeypot"
git push
# Pipeline triggers automatically
```

Supported archive formats: `.zip`, `.7z`, `.tar.gz`, `.bz2`, `.xz`, `.rar`  
Archive passwords tried automatically: `infected`, `malware`, `infected123`, `virus`

---

## Sample Families Tracked

| Family | Category | Notes |
|--------|----------|-------|
| Miori | ELF/Miori | Mirai fork targeting MIPS/ARM IoT via brute-force + PHP exploit |
| Mirai | ELF | Classic IRC C2 botnet, DDoS, SSH/Telnet scanner |
| XMRig | ELF/PE | Cryptominer, often dropped post-compromise |
| Generic ELF backdoors | ELF | Reverse shells, UPX-packed binaries |
| Shell droppers | Scripts | TFTP/wget/curl-based download-and-exec |
| Malicious Office | Docs | AutoOpen macros, CVE exploit documents |
| Unknown | UNKNOWN/UNKWN | Pending triage — scanned but not yet classified |
