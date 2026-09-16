# Changelog

## Unreleased

- Add the experimental Linux include mode: a BPF LSM classifier marks new IPv4 sockets of enrolled executable paths, kernel policy routing and nftables send them and their ordinary DNS through WireGuard, and unlisted programs keep host routing and DNS. See [docs/linux.md](docs/linux.md). Updating from policy ABI 2 requires an explicit disable/uninstall with the old CLI before installing ABI 3 artifacts.
- Add a Linux CI job for the unprivileged suite, a manual privileged disposable-VM job, and the guarded native overhead measurement harness.
- Fix Linux guard semantics: label Unix streams again on first use after a generation change instead of re-resolving every message and refusing an included process's unrelated streams; classify tasks in private user namespaces normally; refuse only enrolled unlinked images so unlisted processes keep socket creation after a package upgrade replaces their binary; identify filesystems by the kernel's superblock device (btrfs subvolume roots) and verify the classification context at load time; match `nscd` cache parents and 63-byte slot names exactly.
- Harden the Linux loader and controller: guard loading tolerates cgroups that vanish mid-walk, verifies the BPF object inventory before pinning, publishes pins by atomic rename from a staging directory, never fails on user-writable runtime-directory content, and lets libbpf own the verifier log; the controller recovers pending edits from its health loop, survives transient errors, retries the DNS probe, observes the daemon's activation before competing for the lock, reports lock timeouts as such, resolves named routing tables, refuses opaque iptables-nft mark and conntrack extensions, delivers included traffic to all local host addresses, and completes an explicit disable after a foreign ruleset flush.
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
