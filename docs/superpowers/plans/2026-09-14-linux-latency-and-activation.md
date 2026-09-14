# Linux latency optimization and native-host activation

> Execute with `superpowers:subagent-driven-development`; the user authorized
> optimization, native-host activation and measurement with a separate test app.

**Goal:** Reduce measured local latency and compute while preserving automatic
executable-path selection, then activate and verify the native reference host.

**Architecture:** Keep kernel WireGuard, synchronous executable classification,
kernel DNS translation and exact ownership. Evaluate shorter exact-path keys,
cheaper health inventory and simpler repeated packet predicates independently.

**Spec:** [Existing Linux contract](../specs/2026-09-12-linux-include-mode-design.md)
and [performance baseline](../../linux-performance.md).

## Constraints and acceptance

- Preserve 4095-byte pathname support, 1024 total entries, raw filesystem bytes,
  canonical identity, rename/replacement behavior and independent helper paths.
- Preserve the explicit preemption exclusion and file-reference lifetime.
- Preserve selected DNS/IP separation, unlisted host behavior, failure blocking,
  five-second health checks, ownership verification and private config handling.
- Current branch; exact scoped commits and pushes. At most five files per phase.
  Mechanical source splits precede intentional changes when needed.
- Existing disposable-VM tests continue refusing the production host. A native
  measurement harness has its own explicit ownership and restoration contract.
- Test artifacts are optimized native binaries. Keep profiling windows separate
  from primary latency measurements, retain failures and all timing samples.
- Treat sub-millisecond added p99 as a target, not a guaranteed worst-case bound.
- Refresh host identity, protection/catalog state, services, boot parameters,
  management routes and resolver state before host changes. Preserve data and
  unrelated units. The user authorized the previously described BPF boot and
  old-VPN migration necessary for activation; prepare exact rollback first.

## Task 1: Short exact-path tier

Owned source: `src/linux/bpf/policy.bpf.h`,
`src/linux/native/bpf-loader.cpp`; tests: `tests/linux/test_policy_bulk.py`
and, when required, `tests/linux/test_classifier.sh`. A private native helper
header may be introduced in a separate mechanical phase if needed.

- [x] Add behavior coverage around 255/256 filesystem-byte boundaries, mixed
  short/long bulk loading, raw bytes, maximum paths, combined capacity, duplicate
  entries, exact-key deletion and malformed bulk input.
- [x] Add a 256-byte exact-key map for path strings of at most 255 bytes. Retain
  full-size resolution; longer strings use the existing 4096-byte exact-key map.
  Zero/copy only the selected key width. No digest-only identity or path cache.
- [x] Version the changed pin/map ABI; loader ownership checks require the exact
  layout. Enumeration, replacement, add/remove and capacity span both maps.
- [x] Build and run native tests, then the VM classifier, preemption, resolver,
  bulk policy and installed lifecycle gates. Compare against unchanged baseline.

## Task 2: Reference-host preparation and measurement design

Root owns all native-host access and mutations. A separate review task may design
the measurement interface without changing the host or shared fixtures.

- [x] Capture fresh host inventory and exact rollback copies in private local
  evidence. Confirm actual service boot/restart behavior and storage mounts.
- [x] Stage an independently validated boot entry preserving all current kernel
  parameters and LSM order, adding BPF. Retain the original boot entry.
- [x] Reboot through the approved maintenance boundary, verify BPF loading and
  original service health, and retain the observed SSH interruption interval
  without presenting it as an exact collector outage.
- [x] Retire only the old VPN owner's tunnel responsibility, preserving its
  other management duties and old profile for rollback.
- [x] Prove the unlisted router path and prepare a supported profile and empty
  include list. Use a separate native test app; no unfinished bot is required.

## Task 3: Measure and select further changes

Use `tests/linux/overhead_probe.c` and `overhead_stats.py` as the workload and
analysis foundation. Read `test_overhead.py` before defining a native-host
harness; do not weaken the existing VM admission checks to run it on production.

- [x] Measure fresh TCP/UDP sockets, ordinary TCP/UDP DNS, persistent payloads,
  unlisted file/Unix IPC and controller CPU under a balanced comparison schedule.
  Include scheduling lateness/deadline evidence, not just successful RTTs.
- [x] Attempt separate BPF profiling after primary measurements and record
  unavailable capability explicitly. Retain the missing BPF/packet-rule cost
  attribution as a limit; do not infer that cost from socket timings.
- [x] Pursue native/in-process inventory only if controller cost warrants it;
  retain both pre/post-probe full ownership observations and foreign checks.
- [x] Pursue predicate factoring only if packet profiling warrants it; preserve
  raw/NAT/filter priorities, DNS conntrack zones and inbound interface checks.
- [x] Accept candidates only after functional parity and measured benefit; retain
  rejected experiments and state uncertainty where differences are inconclusive.

## Task 4: Activate and close

- [x] Install the accepted build with empty initial policy, then enroll the
  independent native test executables through the ordinary management CLI.
- [x] Prove included VPN exit and profile-DNS traffic separately from unlisted
  router exit/DNS, with management/LAN/Tailscale and existing services healthy.
- [x] Verify loss/recovery and durable service ordering with scoped test clients;
  avoid destructive whole-host failure injection.
- [x] Remove owned test clients/listeners/network resources and leave only the
  user-requested production service active. Keep bot enrollment self-service.
- [x] Publish measured results, operating/migration updates and all verified code.
  Final report states tested scope, uncertainty, active state and any remaining gap.

## Completion record — September 14, 2026

- Exact-path tier: `3ead242`; guarded native harness: `b1411cb`. Source/ABI tests,
  full privileged VM suite, stable-kernel positive/negative boot proofs, 201 local
  tests/native gates and Linux/Windows CI passed.
- The native 18-window comparison passed 1,944,000 operations with zero errors.
  Largest estimated added paired p99: 95.6 us; largest individual approximate
  interval upper endpoint: 460.2 us. Socket creation improved about 7.8 us versus
  baseline. See the performance report for all results and scheduling backlog.
- Whole-host CPU counters failed consistency checks and remain invalid. The
  separate distro BPF profiler is unavailable despite its advertised command.
  Those investigations are complete with explicit missing-evidence limits;
  packet-rule/native-inventory rewrites were not justified and were not added.
- Native link-loss/recovery and controller restart passed. Provider activation,
  selected/unlisted first-socket marks, libc lookup, distinct HTTPS exits and
  separately captured ordinary DNS paths passed using independent test utilities.
  Router upstream Cloudflare DoH was not independently verified.
- Production guard/controller remain active/enabled with empty inclusion for
  agents. The old full-tunnel owner is disabled; management and existing services
  remain active. Test clients, fixture networking and the disposable VM are gone.
  Private rollback and failed/partial evidence were retained.
- Native BPF boot was verified before installation; boot startup/failure gating
  was proved in the matching VM. Native production was not rebooted a second time.
  Bot implementation/deadlines and an absolute minimum/zero-overhead guarantee
  are outside the completed standalone-application acceptance.
