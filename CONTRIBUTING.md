# Contributing to SentinelAI

Thank you for helping build a trustworthy security product.

## Workflow

1. Inspect the current branch and pull latest changes.
2. Create a feature branch: `feat/…`, `fix/…`, `security/…`, `docs/…`, `test/…`, `ci/…`
3. Implement incrementally; keep the project buildable.
4. Add/adjust tests with **harmless** fixtures only.
5. Update `README.md` / `CHANGELOG.md` / `docs/` when behavior changes.
6. Commit with Conventional Commits (`feat:`, `fix:`, `security:`, …).
7. Open a pull request against `main`.

## Rules

- Do **not** commit secrets, `.env` files, VPN private keys, or signing keys.
- Do **not** rewrite working code without a migration plan.
- Do **not** claim features that are not implemented/configured.
- Do **not** add offensive/malware capabilities.
- License: ask **DjSergio88** before adding any `LICENSE` file.

## Local checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p sentinel-agent --release
```
