# Security & Privacy Model

## Principles

1. **Security > correctness > privacy > reliability > maintainability > performance > features**
2. Defensive functionality only; user authorization required
3. Least privilege — Milestone 1 runs as the interactive user
4. Minimal telemetry by default (telemetry pipeline not implemented yet)
5. Honest capability reporting

## What SentinelAI must never do

- Disable Windows Defender, Firewall, or other OS protections
- Steal credentials, keylog, spy, or stealth-persist
- Bypass security controls or provide exploitation guidance
- Commit secrets, VPN private keys, or signing keys
- Upload passwords, private keys, photos, documents, messages, or browser history without explicit informed consent

## Local data

Milestone 1 scan reports are written only when the user passes `--output`.  
No background cloud upload is implemented.

## Cryptography

- File hashing: SHA-256
- Future VPN: WireGuard only (no proprietary crypto protocols)
- Future auth: short-lived access tokens + refresh tokens (Milestone 4)

## Confidence labels

| Label | Meaning |
|---|---|
| Known malicious | Verified indicator only |
| High risk | Strong local heuristics |
| Suspicious | Concerning signals |
| Potentially unwanted | Possibly unwanted software patterns |
| Unknown | Insufficient evidence |
| Low risk | Mild or informational |
| Trusted | Strong mitigating signals |

Unknown software is **never** auto-labeled malware.
