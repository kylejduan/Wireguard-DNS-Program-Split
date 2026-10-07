# Reliability verification

As of October 7, 2026, the repository has been audited for lifecycle recovery, adapter ownership, bounded resource use, DNS attribution, and routing failure behavior. This is bounded verification, not a claim of bug-free operation or a months-long soak.

## Repairs

- Windows controller, dispatcher, and service-output logs rotate automatically. Failure snapshots copy a finite tail even while the source grows.
- Controller scheduling uses monotonic time so daylight-saving transitions and clock corrections do not defer health checks or cleanup.
- Idle ETW flushing uses a one-second cadence; waiting queries trigger immediate flushing and retain 10 ms retries.
- DNS attribution expires on event ingestion as well as lookup and has a hard capacity. Overflow fails closed until the attribution lifetime has elapsed.
- TCP connect and partial transfers have total deadlines. Client connections have bounded request counts, sockets close on exceptions, and DNS workers finish before shared state is destroyed.
- ETW names are read within their returned buffer, property allocation is bounded, callback exceptions cannot unwind through the Windows callback ABI, and partial trace startup is cleaned up.
- WFP component operations now use a mutex, matching the DNS component's serialized lifecycle. Component termination waits are bounded; executable-list arguments support spaces.
- Profile import resolves filesystem provider paths correctly, including UNC input files. Installation still requires a filesystem supporting Windows ACLs.
- The documented tunnel startup mode now matches implementation: Automatic controller, Manual tunnel, with orphan preflight before creation and idempotent adoption of a running tunnel.

## Verification

| Surface | Evidence |
| --- | --- |
| Windows native code | Warning-clean optimized builds; parser/attribution tests; actual loopback UDP/TCP forwarding; trickle-read deadline and shutdown interruption; log rotation, failed-rotation recovery, and pipe output tests |
| Windows orchestration | PowerShell ownership, repair, preflight, and bounded log/snapshot tests; CI additionally runs installation ACL checks, real SCM tunnel/controller lifecycle tests, and actual Windows DNS Client/ETW queries against selected and direct loopback resolvers |
| Linux unit/native code | 292 unit tests plus classifier, resolver IPC, policy capacity, boot-probe and preemption checks |
| Linux kernel/network | Fresh disposable Ubuntu 26.04/kernel 7.0 VM: actual selected/unlisted DNS and payload separation, persistent transfers and TCP fallback, resolver IPC boundaries, enrollment changes, crash recovery, underlay loss/recovery, disable and uninstall |
| Linux boot | Two actual VM reboots: first selected socket blocked before the dependent service; failed early guard prevented dependent service startup; cleanup restored the semantic baseline |
| Repository | Public-artifact guard, diff checks, Windows/Linux CI; work files and private evidence remain ignored under `local/` |

The Linux test VM used a new overlay of the existing disposable image. It did not change the production Linux installation. Its processes and SSH forwarding listener are stopped after verification. Windows test fixtures run from the checkout; local WSL storage cannot implement the Windows ACL tests, so those checks run in Windows CI. Real controller service tests refuse any host where the project controller already exists.

## Remaining boundaries

Windows dynamic WFP filters still disappear when their host exits: payload recovery is fail-open. Explicit disable restores ordinary direct access. Persistent fail-closed enforcement would change this lifecycle contract and needs its own implementation and traffic proof, including boot, uninstall, IPv6, existing flows and filter ownership. The current Windows deployment remains IPv4-only; use the supported no-IPv6-default-route configuration.

Windows DNS packets and ETW events lack a shared transaction identifier. Concurrent or delayed same-name/type lookups therefore remain ambiguous. Bounded storage, zeroed TTLs, missing-hint refusal, and overload quarantine do not turn the shared Windows resolver into a formal per-process security boundary.

Tests and short resource checks cannot prove uptime over weeks or months, absence of every race, or compatibility with future Windows, kernel, driver, VPN-provider, and router changes. Keep these boundaries explicit when reporting deployment health. Repository verification does not establish that an installed copy has received a new build.
