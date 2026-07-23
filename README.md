# AI-Firmware-Security-Agent

> AI firmware security analyzer — Stage-1 happy path.
> Sixth project of the **longyuanai AI Security Agent suite**.

## What it does (PoC)

Parses a synthetic firmware (`.tar.gz` with `manifest.yml`), builds a
component inventory (SBOM), looks each component up against NVD with a
deterministic local fallback, and asks the LLM (via `shared-llm-core`) to write a
business-language risk narrative per vulnerable component.

```
firmware.tar.gz ──► Parser ──► Component[*] ──► CVE DB lookup
                                                    │
                                                    ▼
                                          ComponentMatch[*]
                                                    │
                                                    ▼
                                       Top-N ──► LLM Enricher
                                                      │
                                                      ▼
                                          ComponentNarrative[*]
                                                      │
                                                      ▼
                                      Markdown Firmware Report
```

## PoC shortcuts

- **Firmware format** is a tiny `tar.gz` containing `manifest.yml` plus a
  fake `rootfs/`. Real firmware parsing (binwalk → squashfs → package list)
  is out of scope for PoC; the parser interface is designed so a real
  Binwalk-backed parser can replace `_manifest_to_components()` without
  touching anything else.
- **CVE fallback** is a hard-coded `mock_lookup()` covering 7 known
  packages (busybox, openssl, openssh, xz, lighttpd, dropbear, kernel).
  NVD failures use this local data so scans remain available offline.

## Install

```bash
cd 006AI-Firmware-Security-Agent
poetry install
```

## Run the demo

```bash
# Local vLLM
docker compose -f ../000shared-llm-core/docker-compose.yml up -d vllm
export LLM_PROVIDERS=local
python -m ai_firmware_agent.cli scan --demo -o report.md

# Optional: higher NVD rate limits
python -m ai_firmware_agent.cli scan --demo --nvd-api-key "$NVD_API_KEY" -o report.md

# Optional: enrich CVEs with FIRST EPSS exploit probabilities
python -m ai_firmware_agent.cli scan --demo --use-epss -o report.md

# Optional: mark CVEs in the CISA Known Exploited Vulnerabilities catalog
python -m ai_firmware_agent.cli scan --demo --use-kev -o report.md
```

## Scan a firmware image

`.bin` inputs are extracted locally with Binwalk and `unsquashfs`; archives
containing `manifest.yml` remain supported.

```bash
python -m ai_firmware_agent.cli scan \
  --input samples/firmware_demo/demo-router.squashfs.bin \
  --output report.md
```

Install Binwalk and squashfs-tools on the analysis host. Extraction failures
return a concise CLI error and do not expose firmware contents externally.

## Test

```bash
poetry run pytest -v
```

All tests use a stubbed router; no live LLM is required.
