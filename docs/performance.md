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
