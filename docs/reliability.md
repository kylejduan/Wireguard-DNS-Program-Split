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
- Windows payload filters are persistent WFP objects under a fixed project provider, replaced in one transaction and removed only by explicit disable, service stop or uninstallation. Hard blocks in the same set refuse selected applications' IPv4 off the tunnel address and their IPv6, independent of the PIA driver.
- Profile import resolves filesystem provider paths correctly, including UNC input files. Installation still requires a filesystem supporting Windows ACLs.
- The documented tunnel startup mode now matches implementation: Automatic controller, Manual tunnel, with orphan preflight before creation and idempotent adoption of a running tunnel.

## Verification

| Surface | Evidence |
| --- | --- |
| Windows native code | Warning-clean optimized builds; parser/attribution tests; actual loopback UDP/TCP forwarding; trickle-read deadline and shutdown interruption; log rotation, failed-rotation recovery, and pipe output tests |
| Windows orchestration | PowerShell ownership, repair, preflight, and bounded log/snapshot tests, including filter-preserving repairs and reloads; CI additionally runs installation ACL checks, real SCM tunnel/controller lifecycle tests, actual Windows DNS Client/ETW queries against selected and direct loopback resolvers, and persistent filter install, verification, atomic replacement under a concurrent reader, killed installs and removal against the real filter engine |
| Linux unit/native code | 292 unit tests plus classifier, resolver IPC, policy capacity, boot-probe and preemption checks |
| Linux kernel/network | Fresh disposable Ubuntu 26.04/kernel 7.0 VM: actual selected/unlisted DNS and payload separation, persistent transfers and TCP fallback, resolver IPC boundaries, enrollment changes, crash recovery, underlay loss/recovery, disable and uninstall |
| Linux boot | Two actual VM reboots: first selected socket blocked before the dependent service; failed early guard prevented dependent service startup; cleanup restored the semantic baseline |
| Repository | Public-artifact guard, diff checks, Windows/Linux CI; work files and private evidence remain ignored under `local/` |

The Linux test VM used a new overlay of the existing disposable image. It did not change the production Linux installation. Its processes and SSH forwarding listener are stopped after verification. Windows test fixtures run from the checkout; local WSL storage cannot implement the Windows ACL tests, so those checks run in Windows CI. Real controller service tests refuse any host where the project controller already exists.

## Remaining boundaries

Windows payload filters are persistent and fail closed through crashes, BFE restarts, repairs and reboots; explicit disable restores ordinary direct access. CI has no PIA driver, which is the driver-unregistered state: its live test shows a listed copy's TCP connect and IPv6 refused with `WSAEACCES` and its UDP datagram blocked in the filter engine's audit record, while an unlisted copy and the listed copy's IPv6 loopback work. It also shows that the unregistered redirect callouts alone let traffic through, which the blocks close. Traffic through a working redirect needs proof on the deployed workstation: a selected application must reach the VPN exit, fail with the tunnel stopped, after a BFE restart and at boot, and must not reach IPv6 destinations. Existing flows keep their route until closed. Boot-time copies of the blocks are installed and verified in CI, and the deployed workstation's set was present from boot after a reboot; their enforcement before BFE starts was not observed, because Filtering Platform auditing is off on that host. Repairs and reloads never stop the dispatcher. A dispatcher that ends is replaced by the supervisor in `controller-service.exe` about a second later; CI measures unlisted DNS answering again within about two seconds of a kill at random moments during reloads, repairs and health checks, with selected DNS never taking the direct lane. If no dispatcher is ready for 15 seconds the owned rule is suspended, sending selected applications' ordinary DNS to the physical resolver, and restored once one is.

Windows DNS packets and ETW events lack a shared transaction identifier. Concurrent or delayed same-name/type lookups therefore remain ambiguous. Bounded storage, zeroed TTLs, missing-hint refusal, and overload quarantine do not turn the shared Windows resolver into a formal per-process security boundary.

Tests and short resource checks cannot prove uptime over weeks or months, absence of every race, or compatibility with future Windows, kernel, driver, VPN-provider, and router changes. Keep these boundaries explicit when reporting deployment health. Repository verification does not establish that an installed copy has received a new build.
