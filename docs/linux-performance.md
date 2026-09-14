# Linux overhead measurements

The target is minimal added local latency, ideally below 1 ms at p99, with low
CPU cost. This is separate from total VPN or Internet round-trip time. A VM
measurement cannot establish a worst-case bound or the actual bot's behavior on
TV. See [Linux operation](linux.md) for the supported traffic and host context.

## Native reference-host results — September 14, 2026

The physical reference host (Ubuntu 26.04, kernel 7.0.0-31-generic, i9-11900,
16 logical CPUs) passed **1,944,000 operations** over six balanced rounds and
18 primary windows with its existing services running. Baseline `00b3efd` was
compared with `3ead242`, whose compact exact-path tier preserves 4095-byte paths,
1024 combined entries and the same preemption protection. All 15 production
source hashes and both builds' artifact hashes were verified before execution.

The largest estimated added p99 shift was **95.6 us**; the largest upper endpoint
of the individual approximate 95% intervals was **460.2 us**. These observations
meet the sub-millisecond added-local-overhead target for this experiment. They
are paired round-quantile estimates, not per-request or worst-case bounds.

Included UDP/TCP socket creation added approximately **7.2/7.1 us** at p99,
respectively, versus plain WireGuard. Both improved by approximately **7.8 us**
versus the previous implementation, with individual intervals excluding zero.
Unlisted UDP/TCP socket creation improved by **6.1/6.5 us**. Full-path resolution
remains synchronous; common paths now clear/hash a 256-byte exact key instead
of a 4096-byte key. There is no cross-socket identity cache.

| Workload | Candidate p99 (us) | Paired added p99 (us) | Approximate 95% interval (us) |
|---|---:|---:|---:|
| Included UDP socket | 22.4 | +7.2 | [+1.5, +11.7] |
| Included TCP socket | 22.7 | +7.1 | [+2.6, +10.8] |
| Included UDP DNS | 3087.7 | +95.6 | [-215.5, +460.2] |
| Included TCP DNS | 4229.7 | -176.1 | [-703.8, +349.6] |
| Included persistent UDP | 3911.5 | +65.8 | [-290.1, +382.8] |
| Included persistent TCP | 3411.6 | -8.3 | [-167.0, +208.2] |
| Unlisted UDP socket | 20.5 | +5.6 | [-0.0, +9.8] |
| Unlisted TCP socket | 21.4 | +6.2 | [+1.6, +9.8] |
| Unlisted UDP DNS | 499.4 | +30.8 | [-80.7, +148.0] |
| Unlisted TCP DNS | 620.0 | -34.6 | [-188.4, +144.0] |
| Unlisted persistent UDP | 284.5 | -70.9 | [-205.0, +55.8] |
| Unlisted persistent TCP | 405.9 | -47.6 | [-179.5, +108.2] |
| Unlisted file read | 28.3 | +3.7 | [-2.8, +9.5] |
| Unlisted mmap | 56.5 | +4.8 | [-6.2, +16.3] |
| Unlisted fresh Unix IPC | 17.2 | +2.3 | [-2.0, +5.9] |
| Unlisted pre-attachment Unix IPC | 23.4 | +8.7 | [+3.0, +13.6] |

**Scheduling and total latency:** the sequential included-UDP workload at 1000/s
accumulated backlog. Its candidate p99 completion measured from scheduled start
was **211.6 ms**, versus **647.3 ms** with plain WireGuard and **195.8 ms** with
the previous implementation. All offered operations completed without errors,
but this workload does not establish a sub-millisecond deadline guarantee.
The other candidate workloads' scheduled-completion p99 ranged from 245.6 us to
4.36 ms. Total DNS and WireGuard echo p99 can exceed 1 ms even when the estimated
added selection overhead is much smaller. No failed samples or outliers were
removed. Actual bot deadline acceptance awaits that application's implementation.

| Resource observation | Previous implementation | Compact exact-path tier |
|---|---:|---:|
| Controller CPU, percent of one core | 2.356% | 2.322% |
| Controller CPU seconds over observed spans | 1.548 | 1.516 |
| Observed spans, including output drain (seconds) | 65.709 | 65.281 |
| Largest sampled controller memory (MiB) | 22.27 | 21.54 |
| All measured client processes, CPU seconds | 22.572 | 19.643 |

Client-process CPU fell **13.0%** in this run; these totals include fixture work
and kernel work charged to those clients. Plain-WireGuard/direct clients used
18.449 CPU-seconds. The controller comparison does not establish a material
change: its five-second checks and ownership observations remain intact.

Whole-host CPU accounting failed its declared tick-growth consistency checks
on all 18 windows and is explicitly **invalid** for total-CPU conclusions.
Controller cgroup identity/accounting and client CPU observations remain separate;
they do not quantify all kernel workers or unrelated host activity. The host
profiler also returned an unsupported-build JSON error despite exit status zero;
that diagnostic is recorded as unavailable. No global profiling sysctl changed.
Further native inventory or packet-rule rewrites were not justified by these
observations; the measured exact-key optimization is retained.

The native runner removed every owned test process, namespace, link, route,
installation and private fixture input, with empty ownership/intents and unchanged
host invariants. Separate native link-loss/recovery and controller-restart checks
passed. The complete privileged VM suite and stable-kernel positive/negative
boot proofs passed. An earlier rehearsal's optional cached `table=local` annotation
was resolved using the unchanged host-scope local FIB evidence; the original
failure and corrected interpretation are both retained. Earlier VM upgrade and
IPv6 router-advertisement interference records are retained separately.

Native evidence identifier: `overhead-73fa80c5fc`. Summary SHA-256:
`db0ec614bac5b694d362152cd9289bd72a8456fd172c56660b61c9ef7f7a63b9`.
See [native validation](linux-native-validation.md) for the exact manifest,
workloads, admission, accounting and recovery procedure. These native observations
supersede VM-only performance assumptions for the reference host; the September 13
experiment below remains a separate historical comparison.

## Measured results — September 13, 2026

The complete corrected comparison passed all **1,944,000 operations** across
18 windows on a native Ubuntu 26.04 VM, kernel 7.0.0-30-generic, with four vCPUs.
Source hashes match the declared production revisions and exact baseline patch.
All traffic checks passed; original routes, resolver state, BPF attachments and
listeners were restored after cleanup.

The largest positive estimate of the added p99 shift was **20.3 us**. The largest
upper endpoint of the individual approximate 95% intervals was **336.0 us**.
These observations are consistent with the sub-millisecond local-overhead target
for this experiment. Every interval includes zero, so negative estimates do not
establish a speedup. They do not establish a worst-case or TV workload guarantee.

Candidate p99 is the aggregate measured operation latency. The shift and interval
compare paired round p99 values against the condition without project hooks:
plain WireGuard for included network traffic, direct host behavior for unlisted
workloads. They are different statistics; subtracting aggregate p99 values will
not reproduce the paired shift. Intervals apply individually to each workload.

| Workload | Candidate p99 (us) | Paired p99 shift (us) | Approximate 95% interval (us) |
|---|---:|---:|---:|
| Included UDP socket | 81.3 | +13.3 | [-12.5, +32.7] |
| Included TCP socket | 81.2 | +13.6 | [-19.0, +37.8] |
| Included UDP DNS | 1067.5 | -143.2 | [-886.7, +336.0] |
| Included TCP DNS | 1390.0 | -205.0 | [-1131.5, +290.7] |
| Included persistent UDP | 761.2 | -125.9 | [-544.7, +121.7] |
| Included persistent TCP | 1041.5 | -287.3 | [-1068.0, +146.4] |
| Unlisted UDP socket | 78.8 | +9.1 | [-16.7, +28.2] |
| Unlisted TCP socket | 79.1 | +13.9 | [-11.3, +33.0] |
| Unlisted UDP DNS | 656.9 | -64.4 | [-337.7, +178.2] |
| Unlisted TCP DNS | 809.7 | -219.5 | [-634.5, +94.6] |
| Unlisted persistent UDP | 349.8 | -78.8 | [-299.7, +56.1] |
| Unlisted persistent TCP | 554.1 | -159.8 | [-552.1, +104.8] |
| Unlisted file read | 84.9 | -28.4 | [-75.3, +2.0] |
| Unlisted mmap | 125.0 | -25.6 | [-81.0, +12.4] |
| Unlisted fresh Unix IPC | 61.5 | -0.8 | [-28.6, +19.5] |
| Unlisted pre-attachment Unix IPC | 79.8 | +20.3 | [-3.3, +38.7] |

Total DNS or TCP round-trip p99 can exceed 1 ms even when the estimated added
local overhead is below 1 ms.

| Resource observation | Corrected baseline | Optimized build |
|---|---:|---:|
| Controller CPU, percent of one core | 1.874% | 1.130% |
| Controller CPU over the measured 60 seconds | 1.124 s | 0.678 s |
| Largest sampled controller memory | 15.2 MiB | 15.0 MiB |
| All measured client processes, CPU seconds | 13.063 s | 12.166 s |
| Separate explicit health check, mean CPU | 87.908 ms | 51.409 ms |
| Commands per explicit health check | 43 | 29 |

Controller CPU fell **39.7%** in the running-service comparison. The separate
five-check diagnostic showed **41.5%** lower CPU per check; it ran outside the
primary timing windows and includes profiler cost. Health checks still run every
five seconds with real DNS/handshake and ownership verification.

Client CPU includes fixture work and kernel work charged to those processes;
it excludes other kernel workers. Without project hooks, the same client
workloads used 11.966 CPU-seconds. The guest-wide CPU series is internally
inconsistent with the summed process observations and is retained without using
it for total-CPU conclusions. This run therefore supplies no reliable estimate
of total guest/kernel-worker CPU overhead. Controller memory samples also exclude
the early guard cgroup and pinned kernel allocations.

Separate one-second persistent-payload observations produced zero classification
and resolver-path-lookup counter increments in both product conditions, with the
controller active. Those observations are not added to the latency sample set.

Local evidence is retained as `overhead-5f0ad806b8`; its summary SHA-256 is
`9d533dadf483a6be4edf6c99e20abdb6e2c201010b8fa1aa8541790971ad0a5e`.
The detailed comparison method and reproduction command follow.

## Correctness prerequisite

The first full comparison was rejected when the old implementation produced two
socket denials and one wrong socket mark. Its per-CPU pathname scratch buffer
could be overwritten by another task preempting an LSM invocation on the same
CPU. CPU pinning alone does not prevent that interleaving. Commit `75e9b6c`
disables preemption only during scratch lookup, pathname resolution and policy
lookup, then restores it before releasing the executable reference.

The dedicated `test_preemption.py` fixture pins two processes to one CPU and
reverses their selected/unlisted roles while periodic FIFO wakeups force
preemption. Across two ten-second rounds, the old object produced 16,241 wrong
marks and 29,817 resolver-cache access errors. The corrected object passed 1,310,528 socket
creations with zero socket, mark, cache or Unix-IPC errors. This is a correctness
stress test, not a latency comparison. Its evidence and the rejected timing run
are retained separately; failed samples are never used as successful timings.

The final performance baseline contains exactly the same correctness fix, with
no controller or resolver fast-path optimizations backported. This keeps the
optimization comparison meaningful. Included network traffic is compared with
plain WireGuard; unlisted workloads are compared with the direct host path.
The [kernel's LSM entry](https://github.com/torvalds/linux/blob/v7.0/kernel/bpf/trampoline.c)
and [RCU implementation](https://github.com/torvalds/linux/blob/v7.0/include/linux/rcupdate.h)
explain why a short explicit preemption guard is necessary.

## Comparison method

The native disposable VM compares three conditions against the same controlled
WireGuard peer, destination, DNS responder and MTU 1420:

- Plain WireGuard, with no project hooks or controller.
- The previous implementation at `240b140`, with the `75e9b6c` correctness fix.
- The optimized production implementation at `75e9b6c`.

The controller stays running in both implementation conditions. Before clients
start, each controller must finish its own fresh health check. Six rounds use
all six order permutations once, in a seeded random order. Each condition runs
for ten measured seconds per round, totaling 60 seconds per condition.

Sixteen paced workloads run concurrently: included/unlisted UDP and TCP socket
creation (1,000/s each), UDP and TCP DNS (100/s each), persistent UDP echoes
(1,000/s with 1,200 payload bytes), persistent TCP echoes (200/s with 16,384
payload bytes), plus unlisted file reads, mmap and fresh/pre-attachment Unix IPC
(1,000/s each). Both native TCP endpoints use `TCP_NODELAY`. The same native
client bytes run from distinct included and unlisted paths.
Included DNS addresses the peer directly in the plain-WireGuard condition and
the host loopback stub in both product conditions; kernel translation reaches
the same controlled responder. That translation cost is part of the comparison.

Every operation retains latency, scheduled lateness, error and payload-byte
counts. No timing outliers or noisy counter windows are discarded or retried.
Peer checks validate actual source addresses, DNS answers and payloads. Controller
PID/start time, service state and cgroup identity must remain stable. An error or
incomplete window fails the experiment and retains its evidence.

Reported latency differences compare the mean of paired round p99 values. Their
approximate 95% intervals bootstrap whole paired rounds (4,000 resamples). They
do not estimate the p99 of an unknowable per-request counterfactual difference,
establish equivalence, or bound worst-case delay. Aggregate p50/p95/p99, CPU per
operation, scheduling lateness, offered-load goodput and whole-controller-cgroup
CPU/memory are retained separately. Peer and guest CPU are separate observations;
controller cgroup CPU alone does not include all kernel work.
Memory maxima are the largest once-per-second `memory.current` samples, not
continuous peak measurements.

## Reproduce

Use only the explicitly provisioned disposable native VM described in
[development verification](linux.md#development-verification). Prepare separate
source directories from the named commits. Before building the baseline, apply
only the two production-file changes from `75e9b6c` (`policy.bpf.h` and
`bpf-loader.cpp`); leave its controller and resolver guard unchanged. The exact
patch is available with `git show --format= 75e9b6c -- src/linux/bpf/policy.bpf.h src/linux/native/bpf-loader.cpp`.
Run `scripts/build-linux.sh` in each source directory. The current checkout
supplies the benchmark and installed-test helpers;
the benchmark verifies each production package matches its source and records
source/artifact hashes before and after the experiment.

```sh
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 python3 tests/linux/test_overhead.py --vm \
  --baseline-root /path/to/baseline --candidate-root /path/to/candidate \
  --baseline-revision '240b140 + 75e9b6c correctness backport' \
  --candidate-revision 75e9b6c
```

Results are written under ignored `local/validation/overhead-*`. Keep raw records,
metadata, resource samples and failures together. The optional controller
profiler runs outside the primary timing windows; it is not needed to run the
comparison. Fixtures remove their own installed runtime, networking and processes
and verify the original host state afterward.
