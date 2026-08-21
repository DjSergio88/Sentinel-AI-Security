# SentinelAI

**Your personal AI security technician.**

SentinelAI is a defensive cybersecurity and privacy platform for everyday users.  
Repository: [DjSergio88/Sentinel-AI-Security](https://github.com/DjSergio88/Sentinel-AI-Security)

> **Honesty policy:** SentinelAI never pretends a feature works when it is not configured.  
> Milestone 1 provides **local Windows security posture analysis only**.  
> VPN, cloud AI, and external threat intelligence are **not** active until configured.

Current version: **0.1.1**  
Current milestone: **1 — Windows security engine** (verified)

> **Protected status meaning:** When the agent shows Protected, it means local posture checks found no elevated issues. It is **not** a malware-free guarantee and not a substitute for Windows Security full scans.

---

## What works today (Milestone 1)

| Capability | Status |
|---|---|
| Windows `SentinelAgent` CLI | ✅ Implemented |
| Quick / Smart / Full posture scans | ✅ Local heuristics |
| Process & startup inventory | ✅ |
| Downloads inventory + SHA-256 (Smart/Full) | ✅ |
| Windows Defender / Firewall checks | ✅ Best-effort local |
| Browser extension inventory | ✅ Chromium-based |
| Explainable risk scoring | ✅ |
| External threat intel | ❌ Not configured → *Local analysis only* |
| VPN | ❌ Not configured → *VPN infrastructure not configured* |
| Cloud auth / dashboards | ❌ Not implemented |
| AI cloud assistant | ❌ Not configured |
| Desktop UI / tray app | ❌ Milestone 2–3 |
| Android / macOS / iOS / Linux apps | ❌ Later milestones |

---

## Repository layout

```text
SentinelAI
├── apps/windows/sentinel-agent/   # SentinelAgent.exe
├── core/
│   ├── common/                    # Shared types
│   ├── security-engine/           # Collectors + scan orchestration
│   └── threat-analysis/           # Explainable risk scoring
├── docs/                          # Architecture & guides
├── .github/workflows/             # CI
└── Cargo.toml                     # Rust workspace
```

Placeholders for future modules (not yet implemented) are described in `docs/architecture.md`.

---

## Prerequisites (Windows)

1. [Rust](https://rustup.rs/) (stable, MSVC toolchain)
2. [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **Desktop development with C++** workload
3. Git

---

## Build

```powershell
cd Sentinel-AI-Security
cargo build -p sentinel-agent --release
```

Binary output:

```text
target\release\SentinelAgent.exe
```

---

## Usage

```powershell
# Capability disclosure (always truthful)
.\target\release\SentinelAgent.exe info

# Quick posture scan (human-readable)
.\target\release\SentinelAgent.exe scan --kind quick

# Smart scan with JSON report
.\target\release\SentinelAgent.exe scan --kind smart --json --output .\reports\scan.json

# Compact status (Quick Scan)
.\target\release\SentinelAgent.exe status
```

Scans run with the privileges of the current user. SentinelAI does **not** require SYSTEM for Milestone 1 collectors.

---

## Tests

```powershell
cargo test --workspace
```

Tests use harmless fixtures only. **Never** use real malware samples.

---

## Documentation

| Doc | Purpose |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System architecture & milestones |
| [docs/security-model.md](docs/security-model.md) | Security & privacy model |
| [docs/development.md](docs/development.md) | Local development |
| [docs/audit-2026-08-21.md](docs/audit-2026-08-21.md) | Initial repository audit |
| [docs/milestone-1-verification.md](docs/milestone-1-verification.md) | Milestone 1 capability verification |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution workflow |

---

## License

**No open-source license has been selected yet.**  
The project may become proprietary/commercial. Do not assume OSS rights until an explicit `LICENSE` is added by the owner (**DjSergio88**).

---

## Priority order

Security → correctness → privacy → reliability → maintainability → performance → features.
