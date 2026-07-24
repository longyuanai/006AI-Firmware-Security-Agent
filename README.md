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

## Implementation notes

- **Firmware formats** include the original `tar.gz` fixture and real `.bin`
  images extracted with Binwalk/`unsquashfs`. The tracked OpenWrt sample is
  paired with its official target manifest so adapter tests remain
  deterministic on Windows hosts without native extraction tools.
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

### Scan the public OpenWrt sample

The repository includes a 5,043,932-byte OpenWrt 23.05.5 image and its
official target package manifest. Source URLs and SHA-256 values are recorded
in [`samples/README.md`](samples/README.md).

```powershell
$sample = (Resolve-Path `
  "samples/openwrt-23.05.5-ath79-tiny-engenius-eap350-v1-initramfs-kernel.bin").Path
$body = @{ firmware_path = $sample } | ConvertTo-Json -Compress
$env:PYTHONIOENCODING = "utf-8"
$OutputEncoding = New-Object Text.UTF8Encoding($false)

# Direct FirmwareAdapter-compatible envelope
$body | python -m ai_firmware_agent.cli scan --json
```

To exercise the shared IntegrationGateway on port `18080`, expose the sibling
sources and start Uvicorn:

```powershell
$env:PYTHONPATH = "../000shared-integration/src;../000shared-llm-core/src;src"
python -m uvicorn shared_integration.gateway:app --host 127.0.0.1 --port 18080
```

In another terminal:

```powershell
$sample = (Resolve-Path `
  "samples/openwrt-23.05.5-ath79-tiny-engenius-eap350-v1-initramfs-kernel.bin").Path
$body = @{ firmware_path = $sample } | ConvertTo-Json -Compress
$utf8Body = [Text.Encoding]::UTF8.GetBytes($body)

Invoke-RestMethod http://127.0.0.1:18080/v0.5/006/scan `
  -Method Post -ContentType "application/json; charset=utf-8" -Body $utf8Body
Invoke-RestMethod http://127.0.0.1:18080/v0.5/health
```

The frozen `FindingSource.FIRMWARE` value is `"006"`, so the contract route is
`POST /v0.5/006/scan`. The label `/v0.5/firmware/scan` is not a valid
`IntegrationGateway` source route.

## PRisk v0.1

Vulnerable components are ranked before LLM enrichment using:

`0.25 × (CVSS / 10) + 0.25 × EPSS + 0.20 × KEV + 0.15 × Exploit + 0.15 × Exposure`

All inputs are clamped to `0..1`. `Component.extra.exploit` and
`Component.extra.exposure` can provide explicit context; otherwise KEV supplies
known-exploitation evidence and a documented component-category mapping supplies
the exposure estimate.

## Report chart

When `--output report.md` is used, the CLI also writes
`report-vulnerability-distribution.png` using Matplotlib's headless Agg
renderer. The Markdown report links the image with a portable relative path.

## Docker

The build uses a named BuildKit context for the sibling `000shared-llm-core`
repository:

```bash
docker build \
  --build-context shared=../000shared-llm-core \
  -t ai-firmware-agent:0.1 .

docker run --rm ai-firmware-agent:0.1 --help
```

Docker Compose configures that context automatically:

```bash
docker compose build
docker compose run --rm firmware-agent scan \
  --input /firmware/firmware_demo/demo-router.squashfs.bin \
  --output /output/report.md \
  --top-n 0
```

Set `NVD_API_KEY` in the shell when higher NVD rate limits are needed. The
container runs as UID `10001`, mounts sample firmware read-only, and keeps
reports in `./output`.

## CI

`.github/workflows/ci.yml` runs Ruff, mypy, and pytest on both
`ubuntu-latest` and `windows-latest` with Python 3.11. The workflow checks out
`000shared-llm-core` and `000shared-integration` from the same GitHub owner as
sibling directories, matching the local integration layout. If either
repository is private, grant the workflow read access with `SHARED_CORE_TOKEN`
and (if needed) `SHARED_INTEGRATION_TOKEN`, both with read-only contents
permission.

Run the same quality gates locally:

```bash
poetry run ruff check src tests
poetry run mypy
poetry run pytest --basetemp=.pytest-tmp
```

## Test

```bash
poetry run pytest -v
```

All tests use a stubbed router; no live LLM is required.

## Firmware emulation

Build the isolated QEMU user-mode image:

```bash
docker build -f Dockerfile.emulator -t ai-firmware-emulator:0.5 .
```

`emulate_firmware(rootfs, architecture="mipsel")` invokes that image through
`docker run`. Firmware files are mounted read-only and the container has no
network, capabilities, root user, or writable root filesystem. The result
contains observed processes, listening TCP/UDP ports, and a v0.5 §9 firmware
Finding. Tests inject a Docker runner and never execute QEMU.

## 0-day candidate prediction

`predict_zero_days(components, patterns)` compares inventory versions with
version strings extracted from known CVE evidence. Exact known affected
versions are excluded; adjacent release lines become review candidates with a
bounded confidence, analogue CVEs, weakness signals, and an explanatory v0.5
§9 Finding. These results are hypotheses for manual analysis, not claims that
a new vulnerability or exploit exists.

## Multi-agent attack chain

`reconstruct_attack_chain(findings, orchestrator)` sends one defensive mission
to the v0.5 §7 roles `SCOUT`, `EXPLOITER`, and `REVIEWER`. It returns a
background/attack/consequences narrative and a related §9 Finding. The
EXPLOITER role is instructed to simulate the logical path only; it does not
execute firmware commands or produce deployable exploit code.

`reconstruct_attack_chain_with_router(...)` constructs the official
`shared_llm_core.MultiAgentOrchestrator`. Until the sibling shared core is
upgraded from 0.1 to 0.5, use the injected-orchestrator form for tests and
offline integration.

## IntegrationGateway adapter

The firmware CLI accepts the shared-integration JSON subprocess contract:

```bash
echo '{"firmware_path":"C:\\absolute\\path\\firmware.tar.gz"}' \
  | python -m ai_firmware_agent.cli scan --json
```

`FirmwareAdapter` also invokes the equivalent command without the explicit
`scan` token; both forms return `{"findings": [...], "errors": [...]}`.
Adapter scans are offline and deterministic: component parsing, the bundled
CVE fallback, and PRisk run locally without an NVD or LLM request.
