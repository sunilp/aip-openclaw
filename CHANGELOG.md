# Changelog

## 0.1.0 (2026-04-25)

Initial release of the AIP OpenClaw security plugin.

### Features
- Skill signing with merkle tree and Ed25519 envelope
- Skill verification with tamper detection, expiry, and trust list
- Capability manifest parser (TOML) with runtime enforcement
- Runtime guard with tool, network, file, shell, and budget enforcement
- Audit logging (JSON lines)
- CLI: sign, verify, init, keygen, guard commands
- OpenClaw SKILL.md wrapper for ClawHub distribution
- Progressive security model (4 levels)
