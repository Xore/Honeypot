# Honeypot — Malware Sample Repository

This repository stores malware samples, analysis reports, and threat intelligence captured by the [honeypot-stack](https://github.com/Xore/honeypot-stack).

Samples are automatically submitted to VirusTotal and JoeSandbox via a GitHub Actions pipeline. PDF reports are generated and committed here.

> ⚠️ **WARNING**: This repository contains real malware samples. All binaries are stored in password-protected ZIP archives (password: `infected`). Never execute them outside of an isolated sandbox.

---

## Folder Structure

```
Honeypot/
├── samples/
│   ├── ELF/          # Linux ELF binaries (Mirai, Tsunami, etc.)
│   ├── PE/           # Windows PE executables
│   ├── Scripts/      # Shell scripts, Python, Perl droppers
│   ├── Miori/        # Miori botnet family variants
│   └── UNKNOWN/      # Unclassified / pending triage
├── reports/
│   ├── virustotal/   # VT JSON + PDF reports per sample (by SHA256)
│   ├── joesandbox/   # JoeSandbox PDF analysis reports
│   └── summary/      # Monthly aggregated threat reports
├── iocs/
│   ├── hashes.csv    # SHA256, MD5, SHA1, family, date
│   ├── ips.txt       # Attacker IPs observed
│   └── urls.txt      # C2 and dropper URLs
├── Scripts/          # Legacy scripts (kept for compatibility)
└── .github/
    └── workflows/
        └── analyze.yml  # Automated analysis pipeline
```

---

## Automated Pipeline

The analysis workflow triggers on every push to `samples/`. It:
1. Computes SHA256 hash and checks VT for existing reports
2. If unknown, uploads to **VirusTotal** and waits for results
3. Submits to **JoeSandbox** for dynamic analysis
4. Generates a **PDF report** using `weasyprint`
5. Commits reports + IOC updates back to this repository

See `.github/workflows/analyze.yml` and the pipeline source in [honeypot-stack/analysis/](https://github.com/Xore/honeypot-stack/tree/main/analysis).

---

## Secrets Required

| Secret | Description |
|--------|-------------|
| `VT_API_KEY` | VirusTotal API key (free or premium) |
| `JOESANDBOX_API_KEY` | JoeSandbox Cloud API key |
| `GH_PAT` | GitHub Personal Access Token (repo write scope) |

---

## Sample Families

| Family | Count | Notes |
|--------|-------|-------|
| Miori | - | Mirai variant targeting MIPS/ARM |
| Mirai | - | Classic ELF botnet |
| Unknown ELF | - | Pending classification |
| Shell droppers | - | TFTP/wget-based downloaders |
