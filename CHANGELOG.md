# Changelog

## Unreleased

- Refuse to overwrite or uninstall same-name foreign scheduled tasks, services, or NRPT rules.
- Roll back both active profile files, after a stopped-controller acknowledgement, if a tray import fails.
- Preserve recovery backups across failed or repeated profile-import attempts.
- Reject duplicate WireGuard sections/required fields, invalid keys, and invalid endpoint ports.
- Preserve raw ETW performance-counter timestamps and flush actionable DNS failure diagnostics.
- Serialize installs and remove exact-owned profile staging left by interrupted runs.

## 0.1.0 - 2026-09-02

- Initial source release.
- Per-executable IPv4 TCP/UDP routing through a WireGuard adapter.
- Per-executable ordinary Windows DNS dispatch to tunnel or physical DNS.
- Tray controls, profile import, startup recovery, installer, and uninstaller.
- Automatic tunnel-service startup without a fixed post-readiness soak.
