# YARA Rules

This directory contains YARA rules used for **offline pre-scanning** of samples
before submitting to external APIs (VirusTotal, MalwareBazaar, etc.).

The GitHub Actions workflow (`analyze.yml`) automatically runs all `*.yar` and
`*.yara` files in this directory against every new sample added to `samples/`.

## Rule Files

| File | Covers |
|---|---|
| `miori_mirai.yar` | Miori / Mirai botnet family (IoT DDoS) |
| `elf_malware.yar` | Generic ELF / IoT malware patterns |
| `pe_malware.yar` | PE droppers, loaders, RATs, packers |
| `scripts.yar` | Malicious shell / PowerShell / VBS droppers |
| `malicious_docs.yar` | Macro-enabled Office docs, PDF exploits |
| `generic.yar` | Cross-platform generic indicators |

## Adding New Rules

1. Place `.yar` or `.yara` files directly in this directory.
2. Follow the naming convention: `<family_or_category>.yar`
3. Every rule **must** have a `meta` block with at least:
   - `description`
   - `author`
   - `date` (YYYY-MM-DD)
   - `reference` (if available)
4. Every checked-in rule file must compile independently. The analysis workflow
   validates the complete curated and auto-generated corpus on rule changes:

   ```bash
   bash .github/scripts/validate_yara.sh
   ```

## Sources / Upstream

Rules are based on publicly known indicators from:
- [Mirai/Miori source leaks and analyses](https://github.com/jgamblin/Mirai-Source-Code)
- [JPCERT/CC YARA rules](https://github.com/JPCERTCC/jpcert-yara)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- Community research and honeypot telemetry
