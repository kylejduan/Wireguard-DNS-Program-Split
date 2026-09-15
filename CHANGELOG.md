# Changelog

## Unreleased

- Add the experimental Linux include mode: a BPF LSM classifier marks new IPv4 sockets of enrolled executable paths, kernel policy routing and nftables send them and their ordinary DNS through WireGuard, and unlisted programs keep host routing and DNS. See [docs/linux.md](docs/linux.md).
- Record the reference-host end-to-end check: enrolled copies exit through the provider with provider DNS, unlisted programs keep the router path, and total included latency is set by the provider endpoint distance and DNS cache bypass, not by the classifier.
- Replace the delayed startup controller task with an automatic, restartable Windows service.
- Wait for physical-route readiness without repair backoff and tolerate a tunnel-service `StartPending` race.
- Refuse to overwrite or uninstall same-name foreign scheduled tasks, services, or NRPT rules.
- Roll back both active profile files, after a stopped-controller acknowledgement, if a tray import fails.
- Preserve recovery backups across failed or repeated profile-import attempts.
- Reject duplicate WireGuard sections/required fields, invalid keys, and invalid endpoint ports.
- Preserve raw ETW performance-counter timestamps and flush actionable DNS failure diagnostics.
- Serialize installs and remove exact-owned profile staging left by interrupted runs.
- Serialize the dispatcher readiness message, detect late IPv6 defaults, and remove only exact-owned endpoint routes.

## 0.1.0 - 2026-09-02

- Initial source release.
- Per-executable IPv4 TCP/UDP routing through a WireGuard adapter.
- Per-executable ordinary Windows DNS dispatch to tunnel or physical DNS.
- Tray controls, profile import, startup recovery, installer, and uninstaller.
- Automatic tunnel-service startup without a fixed post-readiness soak.
