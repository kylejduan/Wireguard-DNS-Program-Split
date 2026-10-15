# Windows and Linux performance audit

## October 10, 2026

Baseline: `b1312cb`. This audit measured the deployed Windows workstation and
native Ubuntu 26.04/kernel 7.0 Linux host, then tested and deployed two scoped
control-plane optimizations. Payload forwarding, DNS attribution, health-check
intervals, profiles and executable inclusion policy are unchanged.

### Paired measurements

| Operation | Before | After | CPU reduction |
| --- | ---: | ---: | ---: |
| Windows complete active-state check | 14.77 ms CPU / 17.37 ms elapsed | 4.53 ms CPU / 6.70 ms elapsed | 69% |
| Linux nftables mark/zone inventory scan | 5.17 ms CPU | 2.11 ms CPU | 59% |

Windows used ten alternating rounds of twenty checks per version, in one
PowerShell process against the same running stack. The table reports mean
per-check CPU and elapsed time. Process CPU accounting has finite timer
resolution; these are aggregate estimates, not individual-call precision.

Linux used twenty alternating rounds of twenty scans per version, on the
native host against one captured 315-entry live nftables snapshot. The table
reports median round CPU per scan. Old and new implementations produced the
same mark/zone inventory. The production health check scans before and after
its DNS readiness probe; both observations remain fresh.

### Changes

Windows previously enumerated process modules to obtain each DNS/WFP host's
executable path on every two-second supervision pass. The controller now uses
`QueryFullProcessImageName` with a short-lived, pinned process handle. It still
checks the actual executable path each time, rejects inaccessible/exited
processes, and never caches ownership by PID. The small interop helper is
compiled once per controller process, on its first identity check.

Linux previously allocated temporary dictionaries, sets and return pairs at
every level of its recursive firewall JSON traversal. It now accumulates into
one mask and set per scan. Every expression is still visited; a fully occupied
mark mask does not bypass rejection of a later unknown expression. There is
no cross-check cache of firewall or ownership state.

### Live resource samples

CPU percentages below refer to **one core**, not the whole machine. Samples
cover 90 seconds of the existing desktop/server workload, without an artificial
saturation workload. They are indicative operational readings, not matched
whole-host A/B experiments.

| Sample scope | CPU before | CPU after | Memory before | Memory after |
| --- | ---: | ---: | ---: | ---: |
| Windows persistent processes | 1.74% | 1.15% | 230.4 MiB private | 227.6 MiB private |
| Linux controller cgroup | 3.63% | 3.44% | 21.7 MiB | 17.6 MiB |

Services restarted between samples. Memory differences can reflect restart and
warm-up effects and are not attributed to the code changes.

The Windows sample includes the persistent controller host, PowerShell
controller and tray, DNS dispatcher, WFP host and tunnel host. It excludes
short-lived validation children, Windows service/provider work, and kernel or
driver CPU. Linux service-cgroup accounting includes the controller's child
processes but excludes kernel packet processing. The two scopes are therefore
not directly comparable.

Separately, 30 seconds of kernel BPF accounting on the busy Linux host measured
4.31% of one core across the project's hooks. The most active were file-open
(57,709 calls/s), receive (70,012/s), send (31,069/s), and file-permission
(18,677/s) hooks. Socket classification averaged 2.68 microseconds inside the
hook, once per new socket. These figures include accounting instrumentation
and concurrent host work; they exclude hook-entry overhead, nftables,
conntrack, routing and WireGuard encryption. Accounting was enabled with a
scoped BPF statistics descriptor and verified stopped after closing it.

### DNS and packet path

All timings are milliseconds. Percentiles describe successful responses; the
Linux after column is the completed recheck described below.

| Resolver path | p50 before | p50 after | Tail before | Tail after |
| --- | ---: | ---: | ---: | ---: |
| Windows physical, raw UDP | 6.41 | 7.53 | p99 8.27 | p99 8.98 |
| Windows system DNS | 10.43 | 11.33 | p99 14.84 | p99 14.95 |
| Windows tunnel, raw UDP | 146.49 | 146.82 | p95 151.31 | p95 147.98 |
| Linux host resolver | 0.28 | 0.37 | p95 6.99 | p95 2.62 |
| Linux tunnel resolver | 145.83 | 146.14 | p95 147.59 | p95 148.77 |

The median paired Windows system-minus-raw difference was 4.15 ms before and
3.78 ms after. This is an operational observation, not an attributed DNS-path
improvement: neither optimization changes DNS forwarding.

All recorded Windows requests and the eighty baseline Linux requests succeeded.
The first post-deployment Linux attempt hit one three-second timeout before the
harness wrote its buffered results; the failing lane was not recorded. The
harness was changed to retain each result immediately, and the next eighty
requests completed without errors. Linux remained ready, with protection
verified and no automatic service restarts. The timeout's cause is unresolved;
the successful recheck does not erase it.

Windows alternated 200 ordinary Windows DNS Client requests with 200 raw UDP
requests to the physical resolver, using four common names. Timings come from
the existing native probe functions in one process, excluding process launch.
Windows cache bypass was requested; upstream resolvers could still be warm.
The tunnel row uses twenty raw UDP requests to the profile resolver.

Linux alternated forty unmarked host-resolver requests with forty temporarily
marked UDP sockets through the existing tunnel. No executable enrollment or
routing changes were needed. This measures the resolver path, not an additional
proof of executable classification. The host resolver can cache answers.

The approximately 146 ms tunnel DNS round trip dominates these paths; the
control-plane optimizations do not remove provider/WAN distance. A different
provider endpoint may reduce application latency, but changing the user's
profile was outside this optimization. DNS cache isolation and attribution
waits were retained.

Both implementations leave payload forwarding in the kernel. The Windows WFP
host slept without measurable process CPU in the baseline window. No new
throughput-saturation or full packet-path A/B experiment was performed on the
production machines. Earlier controlled Linux packet and stream results remain
in [Linux overhead measurements](linux-performance.md); they are historical,
not new results from this audit.

### Verification and boundaries

- 297 Linux unit tests and the native parsing, policy, boot and preemption
  checks passed.
- Windows optimized native self-tests and all nine PowerShell test scripts
  passed, including live/foreign/exited process identity cases. The WSL-backed
  installer ACL fixture was rerun using Windows-native temporary storage.
- Firewall tests cover combined masks/zones, changed live input, large rulesets,
  invalid zones and unknown expressions after all mark bits are already used.
- Deployment verified source/artifact hashes, preserved configuration and
  permissions, Windows service/DNS health, and Linux readiness with unchanged
  pinned enforcement, allocation, generation and inclusion policy.
- Public-tree and whitespace checks passed. Private measurements and rollback
  artifacts stay outside the published tree.

This establishes lower measured overhead for the changed operations. It does
not prove a theoretical minimum, worst-case latency, maximum throughput or
long-term stability. Further broad reductions would require changing the
PowerShell/Python supervision architecture or verification cadence; neither
was weakened to improve a benchmark. Existing [platform limitations](limitations.md)
and [Linux operating limits](linux.md) still apply.

Raw samples, benchmark sources and deployment checks are retained locally under
`local/performance/20261010/`. The local evidence manifest has SHA-256
`9ed831effab89742d09e74496f7e99f6011e1489e2d7942cd3aea338d46084e3`.

## October 11, 2026: broader audit and implementation

Baseline: `0259e76`. The follow-up examined supervision, native helpers, kernel
hooks and maps, network inventory, DNS allocation/framing/logging/attribution,
UI memory, build options and host tuning. The changes below preserve the same
health intervals and routing policy.

### Implemented changes and measurements

- Windows reuses a private PowerShell validation worker for periodic NRPT and
  dispatcher checks. Each request invokes the existing script in a fresh script
  scope, reloads configuration and observes live state. Anonymous pipes allow
  only the two validators. The 45-second deadline remains; failure discards the
  worker, and a kill-on-close job contains its probe descendants. Stack stop
  and controller shutdown dispose the worker. Startup/recovery mutations still
  use separate component processes. Owned validation/component process handles
  are now disposed explicitly.
- Linux daemon observations reuse a native helper over private anonymous pipes.
  Only twelve immutable kernel BTF function IDs survive between requests; the
  parsed BTF is freed. Every request opens a fresh pin-directory lock and repeats
  map, link, program, configuration and policy checks. The helper keeps no live
  object descriptors while idle. Artifact replacement invalidates the worker;
  timeout, crash, malformed or excessive output fails the check and discards it.
  CLI operations remain single-use. The kernel programs, map layouts and ABI
  are unchanged.
- Linux hashes the owned nft table once per fresh network snapshot. The two
  independent network observations around DNS probing remain intact.
- Linux command capture enforces 32 MiB stdout and 1 MiB stderr limits while
  reading. It multiplexes input/output, rejects incomplete results, redacts
  command diagnostics and kills/reaps its fixed helper on timeout or overflow.
  This bounds peak buffering; it is not presented as a normal-load CPU saving.
- Windows UDP ingress uses one 65,535-byte receive buffer and copies only the
  received bytes into each request. A 128-byte query therefore no longer retains
  a 65,535-byte vector while waiting for attribution/upstream. At 256 outstanding
  queries of that size, request-buffer capacity falls by approximately 15.9 MiB,
  less the single shared receive buffer. This excludes response buffers, socket
  storage and thread stacks. Maximum-sized UDP/TCP exchanges remain supported.
- TCP DNS sends prefix and body together using scatter/gather in both directions,
  retaining partial-write handling and absolute deadlines. An ordinary complete
  write needs one send call instead of two. A 600-request loopback comparison
  passed; observed latency differences were small/noisy, so no WAN latency
  improvement is claimed. Tray text changes only when its displayed value changes.

Five alternating Windows rounds, after warmup, measured the two validators at
1,715.625 ms CPU/pass in fresh processes versus 106.25 ms in the contained worker
(93.8% lower); elapsed time was 2,596.7 versus 882.3 ms. All validations passed.
These figures cover validator process CPU, excluding the parent's small pipe
handling cost, native probe grandchildren and Windows providers. A previous
paired run gave 1,884.375 versus 112.5 ms. The warm worker used about **162 MiB
private memory** in the isolated benchmark: this deliberately trades persistent
memory for far less repeated startup CPU. It is not a minimum-memory design.

Ten alternating Linux rounds of snapshot, DNS probe, snapshot measured combined
caller/helper CPU at 43.60 versus 2.60 ms (94.0% lower), and elapsed time at
189.2 versus 148.5 ms. All forty snapshots matched the installed enforcement
identities and policy. The helper used about 5.1 MiB RSS. CPU combines caller
process time with reaped-child accounting for the baseline and scheduler runtime
for the resident helper; RSS is process memory, not kernel map memory.

Eight complete healthy checks per version measured 140.21 versus 101.39 ms CPU
(27.7% lower), including children and the resident helper. Elapsed time was
283.8 versus 244.4 ms. These full-check batches were sequential, not alternating,
and include concurrent host work. They support the direction of the more tightly
paired helper result, not a precise whole-host CPU prediction.

### Disposition of the remaining opportunities

| Area | Decision and evidence needed before another implementation |
| --- | --- |
| Native Windows tray | Promising: the PowerShell tray previously used 83 MiB private memory. Requires equivalent menus, profile import/rollback, permissions and UI validation. No measured native replacement yet. |
| Native Windows controller | Could eliminate interpreter memory, including the new worker tradeoff. Recovery/ownership/hold behavior makes this a separate substantial port. |
| Batched native Linux network inventory | 33 commands per baseline check; the worker removes three launches. Replacing the remaining command parsers with netlink/nft/WireGuard APIs needs fresh-state and foreign-rule parity tests. Parallel launches alone do not establish lower CPU. |
| Sparse long-path BPF map | About 4.13 MiB reserved while empty. `BPF_F_NO_PREALLOC` needs map migration, allocation-failure/rollback and disposable-kernel testing. Keep the existing map ABI. |
| Negative-role BPF cache | About 6 MiB; file-open hooks consumed about 3% of one core under the sampled workload. Need hit/miss and contention measurements before trading memory for extra lookup work. |
| Guard epoch lookups and nft chain traversal | Potential per-operation savings, but concurrent updates, hook priorities, conntrack zones and foreign rules are correctness boundaries. Require controlled packet/kernel tests. |
| Socket classifier representation | Only about 0.019% of one core in the sample. Existing short-path tier and once-per-new-socket classification make this lower priority than file guards. |
| Upstream UDP response buffers | Still reserve up to 65,535 bytes after a reply becomes readable. Sizing from queued bytes introduces another socket query; no measured net gain yet. |
| DNS logging and ETW event-ID/metadata filtering | Potential burst-load improvements. Need event-loss, schema-version and diagnostic-retention tests; do not remove failure evidence or narrow attribution coverage speculatively. |
| IOCP/async DNS instead of threads | Requires bounded queues, fairness, cancellation and saturation/tail-latency comparison. Current low query volume does not justify claiming an improvement from a rewrite. |
| Upstream socket/connection pooling | Must retain source binding and isolate transaction IDs, peers, questions, late replies, resets and configuration generations. No verified workload benefit yet. |
| Private route-partitioned DNS cache/coalescing | Could save WAN work, but changes behavior. Requires attribution before cache lookup, TTL/EDNS/DNSSEC handling and strict direct/tunnel isolation. Never enable a shared cross-route cache. |
| Attribution wakeups and process-cache eviction | Per-key wakeups and incremental eviction could help bursts/churn. Current sampled classification p99 was 2 ms; benchmark contention before adding structures. Preserve PID creation-time identity. |
| Notifications replacing supervisor polling | Could reduce idle wakeups. Must preserve detection intervals and recover from lost notifications; only redundant tray updates were removed now. |
| Incremental Windows application-list updates | Reduces management disruption, not idle CPU. Needs coordinated WFP/DNS policy generations and rollback. |
| LTO/PGO/toolchain settings | Already optimized builds. Require representative A/B CPU and size measurements; no blanket compiler upgrade or `-O3` change. |
| MTU, offloads, NIC queues/IRQ affinity | Hardware/workload-dependent throughput/latency tradeoffs. No blind production tuning. |
| Provider endpoint and application connection reuse | Could dominate end-user latency (prior tunnel DNS around 146 ms), but changes the profile/application rather than split overhead. No changes made. |

The resource-bound tests cover output overflow before a newline, stderr floods,
large simultaneous input/output, hangs, crashes, malformed output and child
reaping. Worker tests cover fresh inputs, failed checks, artifact replacement,
process reuse and shutdown. Native ownership tests inject replaced maps, links
and programs after metadata reuse and require rejection. Windows tests include
maximum UDP/TCP frames and real socket deadlines; disposable Windows CI also
checks nested worker cleanup under SCM and the DNS Client/ETW path.

The WSL-backed installer ACL fixture still cannot set Windows ACLs on the Linux
filesystem. The equivalent PowerShell suites run with Windows-native temporary
storage, and the throwaway real-SCM recovery test runs from NTFS. The disposable
native-kernel suite is not run on production: no BPF policy, map or nft rule
changes are included here. These checks do not establish maximum DNS QPS,
line-rate throughput or a weeks-long soak.

Private measurements and scripts are retained under `local/performance/20261011/`.

### Deployment verification

The implementation and console-encoding fix were published as `5a5a2e3` and
`c317d49`. [CI for the deployed source](https://github.com/kylejduan/Wireguard-DNS-Program-Split/actions/runs/38138767821)
passed Linux unit/native checks and Windows native, PowerShell, real SCM and
DNS Client/ETW checks. Locally, 313 Linux unit tests, the native Linux checks,
ten Windows PowerShell suites, native Windows self-tests and the throwaway
real-SCM recovery test passed. The first Windows CI attempt exposed a UTF-8
stdin-preamble difference; it was reproduced locally, fixed in the pipe
protocol, and retained as a regression test alongside Unicode output coverage.

Both live installations were updated with rollback copies retained. Linux
artifact hashes were verified, and configuration, BPF object, pinned map/link
identities, policy, allocation and generation were preserved. A 60-second sample
of the deployed controller cgroup, including its children, averaged 2.79% of one
core and about 20.3 MiB of cgroup memory. It stayed ready with protection verified,
stable processes and zero automatic restarts. The temporary candidate staging
was removed; the root-private rollback copy remains.

Windows installed hashes match the verified sources/build. Only the four
expected existing files changed and the validation worker was added; existing
ACLs, configuration, profiles, drivers and other binaries were preserved.
System and tunnel DNS passed after deployment. During a 90-second sample the
controller, worker, tray and native processes kept the same PIDs, and two
periodic dispatcher validation passes completed. The worker used 136.8 MiB
private memory in this live sample. The sum of the seven persistent process CPU
rates was about 2.14% of one core; this excludes transient probes and external
Windows providers and is not a whole-system measurement. The tray task was
running, the stack was active, the installation remained under Program Files,
and the legacy ProgramData directory was absent.

These are short deployment checks, not a long-term stability or saturation proof.

## October 14, 2026: fail-closed release deployment

The fail-closed changes were published as `c5c84ba`.
[CI for the deployed source](https://github.com/kylejduan/Wireguard-DNS-Program-Split/actions/runs/38596681911)
passed the Linux unit and native checks and the Windows native, PowerShell,
real SCM, DNS Client/ETW, persistent WFP and dispatcher supervision checks.
Locally, 336 Linux unit tests, the native Linux checks, 112 privileged checks in
a disposable VM, the Windows native self-tests and the PowerShell suites passed.

The Windows workstation was upgraded in place without stopping enforcement:
the earlier release's controller was ended without teardown, the files were
replaced with hash and ACL checks, and the persistent filter set was committed
before the earlier filter host ended. The first attempt stopped on an
over-strict identity check in the deployment script (WMI reports a renamed
running image under its original path) and rolled itself back, verified, in
13 seconds; the corrected attempt succeeded. After deployment:

- `wfp-probe.exe status` reported 20 filters (10 per listed application,
  8 boot-time), and every component validation passed. The dispatcher reported
  `etw-filter=query-event`.
- A listed browser's 14 external connections all used the tunnel address and
  none the physical address; unlisted egress kept the ISP address. A listed
  application's DNS went through the tunnel and an unlisted lookup went direct.
- With the tunnel stopped for 45 seconds, the listed browser was active but had
  no external connection, while unlisted egress worked; the tunnel recovered
  33.5 seconds after it was released.
- A killed dispatcher was replaced and answering in 0.26 seconds. With the
  controller killed, all 20 filters stayed in place, and the service recovered
  in 10.8 seconds.
- Configuration, profiles, drivers, the WireGuard runtime and service settings
  were unchanged. BFE restart, reboot and uninstall were not exercised on the
  live host, and CI does not exercise them end to end either; see
  [reliability](reliability.md) for what remains to be observed.

On the Linux reference host the CLI, loader and BPF object were replaced with
the running guard adopted unchanged. A 60-second sample of the controller
cgroup averaged 2.43% of one core and 17.0 MiB, ready with protection verified
and no restarts. The new guard programs, 1,024-entry maps and the settle drain
take effect at the host's next boot. A rehearsal of the same swap in the
disposable VM marked every one of about 8.3 million sockets created during it.

These are short deployment checks, not a long-term stability or saturation proof.

## October 14, 2026: supervision hardening release deployment

A whole-codebase performance and reliability review of 0.3.0 led to the
changes published as `394a145`.
[CI for the deployed source](https://github.com/kylejduan/Wireguard-DNS-Program-Split/actions/runs/38679614288)
passed. Locally, 344 Linux unit tests, the native Linux checks, 118 privileged
checks in a disposable VM, the Windows native self-tests and the PowerShell
suites passed.

On the Linux reference host the controller, loader, BPF object and controller
unit were replaced in place with the running guard kept, and the installation
record was rewritten to match. A 60-second sample of the controller cgroup
averaged 0.99% of one core and 16.6 MiB, down from 2.43% and 17.0 MiB for 0.3.0,
mainly because unchanged ruleset listings are no longer re-read and re-analysed
on every check.

The Windows workstation was upgraded in place with the persistent filters,
NRPT rule and tunnel kept. The first attempt stopped on a wrong expectation in
the deployment script: the supervisor started a fresh dispatcher from the new
image instead of adopting the renamed running one. The script rolled back, and
the corrected attempt succeeded. After deployment:

- The supervisor's new dispatcher answered 1.28 seconds after the controller
  started. All component validations passed, including with the component and
  probe logs held open for reading only.
- The fail-closed checks of the 0.3.0 deployment passed again: a listed
  browser used only the tunnel address, had no external connection while the
  tunnel was stopped, and kept all 20 filters through a controller kill.
- Unlisted lookups through the dispatcher took 16.7 ms at the median, against
  16.6 ms before, and the dispatcher's own classification 0.09 ms against
  0.07 ms. Only the configured router resolver is present on this host, so the
  resolver failover was exercised in CI rather than live.
- Settled over 180 seconds, the controller service, controller, validation
  worker, dispatcher and tunnel host used 1.28% of one core, against 1.16% for
  the same processes on 0.3.0, excluding the short-lived bounded runs. The
  validation worker's handle count cycled between about 760 and 1,020 with
  garbage collection over five minutes, without growth.
- Earlier backups inside the installation directory, a migration backup and a
  42 MB log from before rotation existed were removed.

These are short deployment checks, not a long-term stability or saturation proof.
