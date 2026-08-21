# Milestone 1 Verification Report — 2026-08-21

Branch: `feat/milestone-1-windows-security-engine`  
Version: `0.1.0`  
Scope: Windows security engine / `SentinelAgent` only (Milestone 2 not started)

## Capability verification

| Capability | Result | Evidence |
|---|---|---|
| Windows Defender status | **Functional (best-effort)** | Real registry read of Real-Time Protection + `sc query WinDefend` |
| Windows Firewall status | **Functional (best-effort)** | Real registry reads of Domain/Standard/Public firewall profiles |
| Process enumeration | **Functional** | Live `sysinfo` inventory; unit test asserts non-empty PIDs |
| Startup enumeration | **Functional** | Real HKLM/HKCU Run keys + Startup folder |
| Suspicious-process heuristics | **Functional** | Temp-path / unusual-location / PowerShell pattern signals → explainable score |
| Downloads + SHA-256 | **Functional** | Inventory + hashing; tempfile unit test matches known SHA-256 |
| Risk scoring | **Functional** | `RiskScorer` with reasons; never emits KnownMalicious from local heuristics alone |
| JSON report generation | **Functional** | `--json` / `--output`; serde round-trip tests |
| Permission errors | **Functional** | Missing dirs / registry failures → warnings, no panic |
| Windows-only isolation | **Functional** | `#[cfg(windows)]` for Defender/Firewall/startup registry; non-Windows returns warnings |

## Honesty fixes applied during verification

- Removed optimistic “Windows security basics look enabled” unless **all** core signals are positively confirmed.
- Incomplete Defender/Firewall reads → Low/Unknown finding; score cannot be **Protected**.
- Firewall/Defender component status no longer defaults `enabled: true` when unknown.
- “Protected” summary clarifies: local posture only — **not** a malware-free guarantee.
- Agent notes explicitly: does not disable/reconfigure Defender or Firewall.

## Test / build results

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **32 passed** (includes `tests/milestone1_capabilities.rs`)
- `cargo build -p sentinel-agent --release` — success

## Secrets

- No `.env`, keys, PEM, or WireGuard private material tracked.
- `.env.example` only; `.gitignore` blocks secrets and `reports/`.

## What is simulated / approximate

- Defender “realtime” uses registry disable flags (approximate), not full WSC COM API.
- Full Scan does **not** perform exhaustive AV filesystem scanning (documented warning).
- Heuristics are local signals, not malware verdicts.
- Browser extension check is inventory/count, not deep extension malware analysis.
- Network check is local uncommon listening ports via `netstat`, not TI reputation.
