# Changelog

All notable changes to SentinelAI are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-08-21

### Changed

- Honesty hardening: never claim **Protected** when Defender/Firewall signals are incomplete.
- Defender/Firewall component status uses live registry/`sc` snapshot; unknown stays `null` (not default `true`).
- “Enabled” Info finding only when all core OS protection signals are positively confirmed.
- Protected summary text clarifies local posture ≠ full antivirus clearance.
- Softened AppData\\Roaming process heuristic to reduce false positives for normal vendor apps.

### Added

- Integration tests in `core/security-engine/tests/milestone1_capabilities.rs`.
- Unit coverage for process enumeration, startup registry reads, download SHA-256 hashing, JSON report serialization, incomplete-assessment scoring.
- `docs/milestone-1-verification.md` capability matrix.

### Security

- Confirmed read-only Defender/Firewall checks (no disable/stop/reconfigure paths).
- Agent notes state SentinelAI does not disable or reconfigure Windows security controls.

## [0.1.0] — 2026-08-21

### Added

- Initial Rust workspace for SentinelAI.
- `sentinel-common` — shared scan, finding, confidence, and posture types.
- `sentinel-threat-analysis` — explainable risk scoring (never labels unknown software as malware by local heuristics alone).
- `sentinel-security-engine` — Windows collectors for:
  - process inventory & heuristics
  - startup persistence (Run keys + Startup folder)
  - downloads inventory with optional SHA-256
  - Windows Defender / Firewall posture (registry + `sc query`)
  - network listening-port indicators
  - Chromium browser extension inventory
  - suspicious filesystem location checks
- `SentinelAgent` Windows CLI (`apps/windows/sentinel-agent`):
  - `info`, `scan`, `status` commands
  - truthful capability disclosure (local analysis only; VPN not configured)
- GitHub Actions: `test.yml`, `build-windows.yml`, `security.yml`
- Documentation: architecture, security model, development, initial audit
- `.env.example` for future AI/TI providers (no secrets committed)

### Notes

- Repository was empty at audit time; this is the first implementable baseline.
- Full AV filesystem scanning, VPN, cloud, UI, and mobile targets are **not** included.
