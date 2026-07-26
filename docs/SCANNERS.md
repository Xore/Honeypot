# Scanner Integration Reference

| Scanner | Env Var | Free Tier | Notes |
|---|---|---|---|
| VirusTotal | `VT_API_KEY` | ✅ 4 req/min | 70+ AV engines, hash lookup + upload |
| MalwareBazaar | `MALWAREBAZAAR_API_KEY` | ✅ | Auth-Key header required on all requests |
| Hybrid-Analysis | `HYBRID_ANALYSIS_KEY` | ✅ | env_id=110 (Win7-64) on free tier; 160 requires paid |
| Malshare | `MALSHARE_API_KEY` | ✅ | Community malware repo |
| JoeSandbox | `JOESANDBOX_API_KEY` | ⚠️ community | Deep dynamic analysis |
| MetaDefender | `METADEFENDER_API_KEY` | ✅ | 37+ AV; permalink: metadefender.com/results/file/{id}/overview |
| CAPE Sandbox | `CAPE_API_URL` + `CAPE_API_KEY` | ✅ self-hosted | Cuckoo fork, config extraction |
| Any.run | `ANYRUN_API_KEY` | ❌ paid only | Interactive sandbox |

## Sample Folder Layout

```
samples/
  ELF/          # Linux/IoT ELF binaries
  PE/           # Windows PE executables
  Scripts/      # Dropper scripts (.sh, .ps1, .py, etc.)
  Docs/         # Malicious documents (.pdf, .docx, .xls)
  Miori/        # Miori botnet samples (by C2 IP)
  UNKWN/        # Unclassified / unknown family

reports/
  scanner/      # Per-file JSON scan results (auto-generated)
  pdf/          # PDF summary reports (auto-generated)

iocs/           # hashes.csv, families.csv (auto-generated)
quarantine/     # Suspicious files pending manual review
```

## Adding New Samples

Drop files into the appropriate `samples/` subfolder and push to `main`.
The GitHub Actions pipeline triggers automatically on any `samples/**` change
and submits to all configured scanners.

## Environment Variable Setup

Set secrets in **Settings → Secrets and variables → Actions**:

```
GH_PAT                  # Personal Access Token (repo + workflow scope)
VT_API_KEY
MALWAREBAZAAR_API_KEY
HYBRID_ANALYSIS_KEY
MALSHARE_API_KEY
METADEFENDER_API_KEY
JOESANDBOX_API_KEY      # optional
CAPE_API_URL            # optional, e.g. http://10.0.0.5:8000
CAPE_API_KEY            # optional
ANYRUN_API_KEY          # optional, paid
```
