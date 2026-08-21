# Development Guide

## Setup (Windows)

```powershell
# Rust
winget install Rustlang.Rustup

# C++ build tools (MSVC)
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# Refresh PATH / open a new terminal, then:
rustup default stable-x86_64-pc-windows-msvc
```

## Common commands

```powershell
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
cargo build -p sentinel-agent --release
.\target\release\SentinelAgent.exe info
.\target\release\SentinelAgent.exe scan --kind quick
```

## Branching

Use Conventional Commits and feature branches. Never force-push `main`.

## Manual setup still required

| Item | Why |
|---|---|
| MSVC Build Tools | Link `SentinelAgent.exe` |
| GitHub Actions secrets (later) | Code signing, cloud keys |
| VPN infra | Not deployed — product must say so |
| AI provider keys | Optional; unset ⇒ local analysis messaging |

## Adding a collector

1. Create module under `core/security-engine/src/collectors/`
2. Return `CollectorOutput` with findings/warnings
3. Wire into `ScanEngine::run`
4. Add unit tests with harmless fixtures
5. Document in CHANGELOG
