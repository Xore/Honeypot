# Multi-Scanner Setup Guide
## Xore/Honeypot Repository

The analysis pipeline submits every captured executable to **8 scanner services**.
Archives (`.zip`, `.7z`, `.tar.gz`, `.rar`) are extracted first — the raw
executable is submitted, never the archive.

---

## Scanner APIs

| # | Scanner | Type | Cost | Limit | Secret |
|---|---------|------|------|-------|--------|
| 1 | **VirusTotal v3** | 70+ AV engines | Free | 4 req/min, 500 upload/day | `VT_API_KEY` |
| 2 | **MalwareBazaar** | Community DB, family tagging | Free | None | `MALWAREBAZAAR_API_KEY` |
| 3 | **Hybrid-Analysis** | Falcon Sandbox, dynamic | Free tier | Reasonable | `HYBRID_ANALYSIS_KEY` |
| 4 | **Malshare** | Community repo | Free | 2k req/day | `MALSHARE_API_KEY` |
| 5 | **JoeSandbox** | Deep dynamic, community | Free (public) / Paid | Limited free | `JOESANDBOX_API_KEY` |
| 6 | **MetaDefender** | 37+ AV engines (OPSWAT) | Free | 10 uploads/day, unlimited hash lookup | `METADEFENDER_API_KEY` |
| 7 | **CAPE Sandbox** | Cuckoo fork, config extraction | Self-hosted / public | Depends | `CAPE_API_URL` + `CAPE_API_KEY` |
| 8 | **Any.run** | Interactive cloud sandbox | Paid API | Per plan | `ANYRUN_API_KEY` |

---

## Getting API Keys

### 1. VirusTotal (required)
1. [virustotal.com](https://www.virustotal.com) → Sign up → Profile → **API key**
2. Free: 4 req/min, 500 uploads/day, 15,500/month
3. Add secret: `VT_API_KEY`

### 2. MalwareBazaar (strongly recommended — free)
1. [bazaar.abuse.ch](https://bazaar.abuse.ch) → Register → **Account → API Key**
2. Completely free, no rate limit
3. Gives: malware family name, tags, first-seen, reporter
4. Add secret: `MALWAREBAZAAR_API_KEY`

### 3. Hybrid-Analysis (strongly recommended — free)
1. [hybrid-analysis.com](https://www.hybrid-analysis.com) → Register → **Profile → API key**
2. Free tier includes file submissions with dynamic sandbox
3. Windows 10 64-bit environment (env_id=120)
4. Add secret: `HYBRID_ANALYSIS_KEY`

### 4. Malshare (optional — free)
1. [malshare.com/register.php](https://malshare.com/register.php)
2. API key shown on dashboard after registration
3. 2000 requests/day free
4. Add secret: `MALSHARE_API_KEY`

### 5. JoeSandbox (recommended)
1. [joesandbox.com](https://www.joesandbox.com) → Register
2. **Community plan** (free): public analyses, limited submissions
3. **Paid plans**: private analyses, higher limits
4. Go to **Account → API key**
5. Add secret: `JOESANDBOX_API_KEY`

### 6. MetaDefender Cloud — OPSWAT (recommended — free)
1. [metadefender.opswat.com](https://metadefender.opswat.com) → Register
2. Free: **unlimited hash lookups**, 10 file uploads/day
3. 37+ AV engines + CDR (content disarm)
4. Go to **API keys** in your account
5. Add secret: `METADEFENDER_API_KEY`

### 7. CAPE Sandbox (optional)
- **Self-hosted**: Use your own CAPE instance URL
- **Public**: [capesandbox.com](https://capesandbox.com) — register for API
- Add secrets: `CAPE_API_URL` (e.g. `https://capesandbox.com`) and `CAPE_API_KEY`

### 8. Any.run (optional — paid)
1. [any.run](https://any.run) → Register → Paid plan required for API
2. Add secret: `ANYRUN_API_KEY`

---

## Adding Secrets to This Repo

**Settings → Secrets and variables → Actions → New repository secret**

| Secret | Required | Notes |
|--------|----------|-------|
| `GH_PAT` | **Yes** | PAT with `repo` + `workflow` scope |
| `VT_API_KEY` | **Yes** | virustotal.com |
| `MALWAREBAZAAR_API_KEY` | Recommended | bazaar.abuse.ch (free) |
| `HYBRID_ANALYSIS_KEY` | Recommended | hybrid-analysis.com (free) |
| `METADEFENDER_API_KEY` | Recommended | metadefender.opswat.com (free, unlimited hash lookup) |
| `JOESANDBOX_API_KEY` | Recommended | joesandbox.com |
| `MALSHARE_API_KEY` | Optional | malshare.com (free) |
| `CAPE_API_URL` | Optional | Self-hosted or capesandbox.com |
| `CAPE_API_KEY` | Optional | With CAPE_API_URL |
| `ANYRUN_API_KEY` | Optional | Paid |

---

## Archive Handling

Samples stored as archives are extracted before scanning:

```
ELF/mirai.zip        (password: infected)
  └── mirai.x86     ← submitted to all scanners
  └── mirai.arm     ← submitted to all scanners
```

**Supported formats**: `.zip` (plain + AES-256), `.7z`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.rar`

**Passwords tried**: `infected` → `malware` → `infected123` → `virus`

---

## Hash-First Strategy

Before uploading any file, every scanner does a **hash lookup**.
If the SHA256 is already known, the existing report is returned immediately:
- No quota spent on upload
- Instant results for known malware
- Avoids duplicate MalwareBazaar submissions

Only truly new/unknown samples are uploaded.

---

## Report Output

Each sample: `reports/scanner/<sha256>.json`

```json
{
  "filename": "mirai.x86",
  "sha256": "abc123...",
  "scanned_at": "2026-07-26T14:00:00Z",
  "results": {
    "VirusTotalScanner":    { "positives": 54, "total": 72, "permalink": "..." },
    "MalwareBazaarScanner": { "signature": "Mirai", "tags": ["mirai", "botnet"] },
    "HybridAnalysisScanner":{ "verdict": "malicious", "threat_score": 100 },
    "MetaDefenderScanner":  { "positives": 31, "total": 37 },
    "JoeSandboxScanner":    { "detection": "malicious", "score": 90 }
  }
}
```

IOCs appended to:
- `iocs/hashes.csv` — SHA256, SHA1, MD5, filename, first-seen
- `iocs/families.csv` — SHA256 → malware family names (from VT)
