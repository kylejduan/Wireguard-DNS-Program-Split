# Changelog

## Unreleased

- Windows controller: a local split-DNS probe failure now holds the stack when the physical resolver itself is not answering, instead of failing the startup gate and retrying in a loop. The dispatcher answers unlisted names by forwarding them to that resolver, so when a LAN resolver stops responding the probe cannot pass however healthy this stack is; the previous behaviour aborted `Start-Stack` before the payload filters started and cycled, at one point leaving the NRPT rule pointing at a dispatcher that had been stopped, which fails every lookup on the host. The same condition is now also a hold reason in the periodic health path, and `Get-ProgramSplitPhysicalResolver` reports the forwarding resolver for both checks. A dead resolver observed in the field took the whole LAN's DNS down for about ten minutes and cost several restart cycles, each one a fail-open window for the selected applications.

- Windows controller: a periodic health failure while the host has no physical default route, source address or pre-dispatch resolver now holds the stack and retries instead of restarting it. Losing the uplink used to remove the payload filters and the NRPT rule, so selected applications could leave through the physical path while the tunnel could not work anyway; a gateway reboot produced seven such cycles over four and a half minutes. Validation still restarts the stack once the uplink returns with a different route, address or resolver.

## 0.2.0 - 2026-09-17

### Linux (new, experimental)

- Add the experimental Linux include mode: a BPF LSM classifier marks new IPv4 sockets of enrolled executable paths, kernel policy routing and nftables send them and their ordinary DNS through WireGuard, and unlisted programs keep host routing and DNS. See [docs/linux.md](docs/linux.md).
- Resolver guard file path: a regular file proved to have no resolver role is remembered in a bounded 65,536-entry cache keyed by inode identity and stamped with the guard configuration epoch, so ordinary opens and reads skip pathname matching; only single-link files whose names no built-in rule inspects are cached, a rename into a protected slot still labels the file first, and a second link or an enrollment change forces a recheck. Field reads on that path are direct instead of probe helpers, and name comparisons are branch-free. Policy ABI 4 adds the cache map: disable and uninstall with the old CLI before installing.
- Fix Linux guard semantics: label Unix streams again on first use after a generation change instead of re-resolving every message and refusing an included process's unrelated streams; classify tasks in private user namespaces normally; refuse only enrolled unlinked images so unlisted processes keep socket creation after a package upgrade replaces their binary; identify filesystems by the kernel's superblock device (btrfs subvolume roots) and verify the classification context at load time; match `nscd` cache parents and 63-byte slot names exactly.
- Harden the Linux loader and controller: guard loading tolerates cgroups that vanish mid-walk, verifies the BPF object inventory before pinning, publishes pins by atomic rename from a staging directory, never fails on user-writable runtime-directory content, and lets libbpf own the verifier log; the controller recovers pending edits from its health loop, survives transient errors, retries the DNS probe, observes the daemon's activation before competing for the lock, reports lock timeouts as such, resolves named routing tables, inventories iptables-nft mark and conntrack rules through their textual dumps, delivers included traffic to all local host addresses, and completes an explicit disable after a foreign ruleset flush.
- Record the reference-host end-to-end check: enrolled copies exit through the provider with provider DNS, unlisted programs keep the router path, and total included latency is set by the provider endpoint distance and DNS cache bypass, not by the classifier.

### Windows

- Windows health checks no longer restart the whole stack over one lost packet. `dns-probe.exe` takes an attempt count, retransmits the same query, uses a random query id and requires the reply to echo the question, ignores datagrams and ICMP resets that are not a reply to it, pauses before retrying a refusal or socket error, and reports `No DNS response after N attempts`, `DNS response rejected` and `DNS probe failed` separately (a timeout used to be reported as `Invalid DNS response`). The periodic tunnel probe, the startup local split-DNS probe and dispatcher validation use three attempts, as the Linux controller already did; the startup tunnel gate stays single-shot because its own loop retries. A restart leaves the included applications on the direct route until the stack is back, so an avoidable one is a privacy cost, not only an interruption.
- The Windows controller snapshots the component logs into `logs\health-failures\<time>` (the ten most recent are kept) before the restart that overwrites them, including logs a running component still holds open; a long-running log is kept as its last 2 MB.
- The Windows controller service also accepts pre-shutdown, which arrives before Windows starts ending processes, answers interrogate, and appends one line to `controller-service.log` saying which path ended it, written before it reports stopped.
- The tunnel start path clears a stuck stop within five seconds so that, when the service and adapter then come up promptly, reset plus the readiness wait stays inside the controller's 45-second component limit.
- Windows controller: keep supervising when an interactive disable cannot complete cleanup (record the failure in `last-error.txt` best-effort and retry with bounded backoff), retry service-stop cleanup for up to 150 seconds before reporting failure, log why a health check restarts the stack, and log a component's output even when it fails. The tunnel component issues non-blocking start and stop controls, reports a fast start failure at once, never terminates a young starting host (a slow start is adopted by the next attempt, including when stop runs as failure cleanup), and resets a host that has been starting for more than 90 seconds or a stop that exceeds 20 seconds by terminating only the owned, handle-pinned `tunnel-host.exe`. A stuck tunnel previously made the controller exit with code 1 on every disable, leaving SCM restarting it in a loop.
- Windows controller service: accept the shutdown notification and report a controller ended by system shutdown as a clean stop. Every restart and shutdown previously logged the service as failed with service-specific error 1 ("Incorrect function").
- Windows dispatcher: reuse the route of a name and type answered within the previous three seconds when a repeated query carries no new DNS Client attribution event, instead of answering `SERVFAIL`. Retransmissions and TCP fallback by the Windows DNS Client no longer fail; never-attributed queries still do.
- Replace the delayed startup controller task with an automatic, restartable Windows service.
- Wait for physical-route readiness without repair backoff and tolerate a tunnel-service `StartPending` race.
- Refuse to overwrite or uninstall same-name foreign scheduled tasks, services, or NRPT rules.
- Roll back both active profile files, after a stopped-controller acknowledgement, if a tray import fails.
- Preserve recovery backups across failed or repeated profile-import attempts.
- Reject duplicate WireGuard sections/required fields, invalid keys, and invalid endpoint ports.
- Preserve raw ETW performance-counter timestamps and flush actionable DNS failure diagnostics.
- Serialize installs and remove exact-owned profile staging left by interrupted runs.
- Serialize the dispatcher readiness message, detect late IPv6 defaults, and remove only exact-owned endpoint routes.

### Tests and CI

- Tests: tunnel recovery and controller health tests live in their own files, and `./tests/run.sh --live` runs the recovery functions against the real Service Control Manager using a throwaway service that hangs on purpose (elevation prompt; the installed tunnel is never touched).
- Add a Linux CI job for the unprivileged suite, a manual privileged disposable-VM job, and the guarded native overhead measurement harness.
- The Windows CI job also runs the tunnel recovery and controller health tests.

## 0.1.0 - 2026-09-02

- Initial source release.
- Per-executable IPv4 TCP/UDP routing through a WireGuard adapter.
- Per-executable ordinary Windows DNS dispatch to tunnel or physical DNS.
- Tray controls, profile import, startup recovery, installer, and uninstaller.
- Automatic tunnel-service startup without a fixed post-readiness soak.
