# Architecture

## Product vision

SentinelAI is a consumer managed cybersecurity platform with an **AI security assistant** as the differentiator.  
Windows is the first production target.

## Current state (v0.1.1 / Milestone 1)

Verified on Windows: collectors perform real OS reads (registry, `sc`, `sysinfo`, filesystem, `netstat`).  
See `docs/milestone-1-verification.md`.

```text
┌─────────────────────────────────────────┐
│           SentinelAgent.exe             │
│  (CLI — info / scan / status)           │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│         sentinel-security-engine        │
│  collectors → findings → ScanReport     │
└──────────────────┬──────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌─────────────────┐  ┌────────────────────┐
│ threat-analysis │  │ sentinel-common    │
│ RiskScorer      │  │ types / posture    │
└─────────────────┘  └────────────────────┘
```

Analysis mode today: **Local analysis only**.  
**Protected** means no elevated local findings with complete core checks — not a malware-free claim.

## Target modular layout

```text
SentinelAI
├── apps/          # windows, macos, linux, android, ios
├── core/          # security-engine, threat-analysis, phishing, vpn, …
├── cloud/         # API, auth, devices, billing, AI gateway
├── dashboard/     # customer + admin
├── infrastructure/# docker, db, vpn gateways
├── tests/
└── docs/
```

Only `apps/windows/sentinel-agent` and `core/{common,security-engine,threat-analysis}` are implemented in Milestone 1.

## Scan pipeline

```text
Scan request (Quick|Smart|Full)
        ↓
Collectors (process, startup, config, network, browser, downloads, paths)
        ↓
Heuristic signals → RiskScorer (explainable)
        ↓
Findings + SecurityScore + truthful notes
        ↓
JSON / human report
```

### Action policy (future autonomous mode)

| Level | Behavior |
|---|---|
| 0 | Inform user |
| 1 | Recommend action |
| 2 | Ask confirmation |
| 3 | Auto safe reversible actions only |

Destructive actions are never automatic.

## Technology choices

| Layer | Choice | Rationale |
|---|---|---|
| Shared security core | **Rust** | Memory safety, performance, cross-compile path |
| Windows agent | Rust + Win32/registry/`sc`/`netstat` | Native APIs, least privilege |
| Future UI | TBD (Milestone 2) — likely Tauri or native | Premium consumer UX |
| Future cloud API | TBD (Milestone 4) — prefer Rust or Go + PostgreSQL | Security-first backend |
| VPN | WireGuard only (Milestone 8) | Established cryptography |

## Milestone roadmap

1. Windows security engine ✅ (this release)
2. Windows desktop UI
3. Windows background agent / tray
4. Cloud auth + device registration
5. AI security assistant gateway
6. Phishing / scam engine
7. Update system
8. VPN architecture + real infra
9. Customer dashboard
10. Android
11. macOS
12. iOS
13. Linux

## Truthfulness requirements

- No “VPN Connected” unless a real tunnel is up
- No external TI claims unless a provider is configured
- No “malware detected” without verified indicators
- Local heuristics use confidence vocabulary: Known malicious → Trusted
