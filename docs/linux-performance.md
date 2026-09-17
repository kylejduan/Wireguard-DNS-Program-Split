# Linux overhead measurements

The target is minimal added local latency, ideally below 1 ms at p99, with low
CPU cost. This is separate from total VPN or Internet round-trip time. A VM
measurement cannot establish a worst-case bound or the actual bot's behavior on
TV. See [Linux operation](linux.md) for the supported traffic and host context.

## Resolver guard file-path cache — September 17, 2026

The reference host (same kernel, build `1eab0ac`, policy ABI 4) was measured
before and after the guard learned to remember regular files that have no
resolver role. Each window enabled `kernel.bpf_stats_enabled`, ran one pinned
workload, and restored it to 0; the kernel's per-program accounting gives the
in-hook cost per call. Calls from other host processes during a window are
included, so figures are for the host as it ran, not a synthetic minimum.

| Hook cost per call, workload | Before | After |
|---|---:|---:|
| `file_permission`, `pread` of a cached 512-byte range (500,000 calls) | 235 ns | 52 ns |
| `file_open`, open, read and close loop (500,000 cycles) | 265 ns | 66 ns |
| `file_permission`, same loop | 258 ns | 63 ns |
| `socket_sendmsg` / `socket_recvmsg` / `file_permission`, Unix stream socketpair echo | 63–71 ns | 38–46 ns |
| `socket_post_create` classification, per new socket | 1.5 us | 0.8–2.7 us |

Before the change every open and read of a regular file recomputed its role from
the pathname with about eight probe helpers and an 80-byte hash lookup. It now
reads the inode's cached "no role" entry, a single-link check and the guard
epoch. The `pread` system call as a whole fell from 975 ns to 546 ns, and the
open, read and close cycle from 4.20 us to 2.65 us; part of that second change is
host variation between the two runs. The classifier's per-socket cost did not
change; its spread reflects how few sockets other processes created in each
window. The cache is bounded at 65,536 entries.

The same session repeated the isolated per-packet benchmark from September 15.
The host was busier (an 11.7 us base loopback round trip against 6.8 us), and the
paired differences did not resolve a change: rules present added +3.8 us
[+2.6, +4.9] to an unlisted round trip and +2.2 us [+0.4, +3.7] to an included
one, and the mark-dependent part came out negative. Unlisted packets traverse
the same rule sequence as before, so the September 15 figures below remain the
clean per-packet measurement. Evidence is retained under ignored
`local/validation/linux-guard-cache-20260917`; after-change summary SHA-256
`55497e53856cdac9a92f1708428d09666c169d1d695fdfcf3fd856b747e86387`.

## Reference-host end-to-end check — September 15, 2026

This check re-verified the activated reference host with the accepted build
and no source change. Root-owned copies of `curl` and `dig` in a private
directory were enrolled, compared with the unlisted originals, then removed
together with the directory; the include list is empty again. Each enrollment
returned `ready` in under one second and the controller stayed `ready`
throughout, with no restart.

| Observation | Included copy | Unlisted original |
|---|---|---|
| IPv4 exit reported by a public echo service | Provider exit address | Home ISP address |
| Resolver egress reported by `whoami.akamai.net` | Provider resolver egress | Router upstream (Cloudflare) |
| TXT query sent directly to `ns1.google.com` | Provider exit address | Home ISP address |
| `dig +tcp` resolver egress | Provider resolver egress | Router upstream (Cloudflare) |
| `curl -6` | Refused: `socket()` returns `EPERM` | Existing host behavior |

Total included latency on this host is set by the provider path, not by the
classifier or firewall rules. The tunnel endpoint's direct ICMP round trip was
147 ms (five samples, 0.25 ms spread). Five fresh HTTPS connections to a
remote HTTPS API host took about 0.89 s each when included and about 0.18 s when
unlisted:

| Phase (`curl -w`, mean of five) | Included (ms) | Unlisted (ms) |
|---|---:|---:|
| Name lookup | 147 | 0.9 |
| TCP connect | 295 | 8.8 |
| TLS handshake complete | 567 | 24 |
| Total | 862 | 189 |

Every included round trip crosses the endpoint, and every ordinary included
DNS query is a full tunnel round trip to the profile resolver because included
queries are translated before the host stub resolver and never use its cache;
`dig` reported 146 ms for a name that the unlisted host cache answered in 0 ms.
Twenty sequential included `dig -4` runs took 3.17 s against 0.25 s unlisted.
These are provider distance and cache-bypass costs, and they do not change the
microsecond-scale added-overhead estimates below. They are the numbers an
application deadline sees. Choose the nearest permitted provider server for the
application's destinations, keep connections persistent, and cache resolved
names inside the application.

### Isolated per-packet and per-hook cost

A second measurement on the same host, boot and build isolated what the
implementation itself adds to each packet, without WireGuard or any WAN path. A
64-byte UDP echo client and server, pinned to two idle CPUs, ran 10 rounds of
100,000 serial round trips under five interleaved conditions: a private network
namespace with no rules; the same namespace after loading the production
nftables table, fwmark rule and owned table exactly as rendered by the
installed allocation, first with an unmarked and then with a marked socket
(`SO_MARK` set to the included mark by root); and the live host namespace,
unmarked and marked. Each condition delivered all 1,000,000 echoes without
error. Paired per-round differences, with approximate 95% bootstrap intervals
on the mean:

| Added per round trip (two packets) | Mean (us) | p50 (us) | p99 (us) |
|---|---:|---:|---:|
| Product rules present, unlisted socket | +1.37 [+1.23, +1.53] | +1.16 | +1.30 |
| Product rules present, included socket | +1.54 [+1.38, +1.69] | +1.36 | +1.33 |
| Mark-dependent part alone | +0.16 [-0.06, +0.39] | +0.19 | +0.03 |
| Live host, marked versus unmarked | +0.21 [+0.09, +0.34] | +0.21 | +0.81 |

The base namespace round trip was 6.8 us at p50 and 8.3 us at p99. The rules
therefore add about 0.7 us per packet direction, about 0.1 us of which depends
on the mark; the rest is chain traversal and conntrack that every host packet
pays once the table exists. The live host's own stack (other firewall and
policy rules) accounts for the further 0.8 us between the namespace and host
unmarked conditions and is not part of this implementation.

During a separate 3.1-second window, `kernel.bpf_stats_enabled` was set to 1
and then restored to 0 while 400,000 marked echoes ran. The kernel's own
per-program accounting gave the exact in-hook cost, excluding trampoline entry:

| Hook | Calls/s observed | ns per call |
|---|---:|---:|
| `guard_send` (`socket_sendmsg`) | 259,797 | 14.9 |
| `guard_recv` (`socket_recvmsg`) | 260,089 | 14.8 |
| `guard_read` (`file_permission`) | 4,069 | 55.4 |
| `guard_open` (`file_open`) | 1,383 | 110.8 |
| `guard_mmap` (`mmap_file`) | 58 | 131.4 |
| `guard_datagram` (`unix_may_send`) | 146 | 652.8 |
| `classify` (`socket_post_create`) | 43 | 1,451.9 |

All product hooks together used 0.0083 CPU during that window. The earlier
census figures of 650–1,200 cycles per send/receive call included the
profiler's own instrumentation; the kernel accounting shows the IP fast path
of those hooks at about 15 ns. Socket classification itself costs about 1.5 us
inside the hook, once per socket, consistent with the 4–11 us added p99 that
the whole-syscall comparisons measured. Evidence is retained under ignored
`local/validation/linux-loopback-20260915`; summary SHA-256
`f7cfa4b3e1d2954b87bdb5ca3e2a958309b89b94a9525979c6b84ebe2d0cc512`.

## Production CPU and backlog follow-up — September 15, 2026

This follow-up adds read-only production measurements and a scoped hook census
on the same reference host, boot and kernel as the final results below. The
accepted `d0a40ff` build was running with an empty include list and no test
workload. It changes no earlier number. Here CPU means CPU-seconds per second,
the share of one core. Result SHA-256: E1 rates and controller
`20e5cab823cf942e35645ef8896ba0943b3fd830798ed0a8f8b5f3c85e990273`; E2 guard
census `9f89491e3b9673c02eabe5537443c1bf00b94b3a4e62eaa41d15979056aa31f3`.

**Controller.** The earlier 2.3–2.5% per-window controller figures are quantized
observations: each window of about 11 seconds contained two or three discrete
health checks. A 600-second passive sample at 2 Hz measured 109 checks averaging
110.3 ms of controller-cgroup CPU each (SD 17.1 ms), 74.6% of it in the child
processes a check starts, for 0.0204 CPU. The build was unchanged, so the value
being lower than in the benchmark windows is host-state variation, not a source
change.

**Hook work charged to other processes.** BPF hook time runs in the calling
process, outside the controller cgroup. Over 624 seconds, the product's own
counters recorded 25.0 unlisted socket creations/s through the classifier
(about 0.00009 CPU, at most 0.00012 with the in-situ per-call cost) and 115.8
unknown-stream fallbacks/s. A `bpftool prog profile` census of all 11 guard LSM
programs, one at a time for 2–5 seconds each (37 seconds attached, no workload),
measured exact production call rates, which include those fallbacks. The socket
receive and send hooks ran about 68,000 and 42,000 calls/s and the
file-permission hook about 20,000/s, at roughly 650–1,200 cycles per call. In
total the guard hooks used about 116 million cycles/s, or 0.0315–0.0386 CPU at
the highest observed and the mean CPU frequency. The counts include the
profiler's own fentry/fexit instrumentation, so they are conservative per call;
assuming every call ran at the 0.8 GHz minimum frequency gives a hard 0.142 CPU.
The Unix-stream connect, socketpair and file-receive hooks recorded no calls in
their windows, which is an absence of samples, not zero cost.

**Estimate and limits.** Controller, classifier and guard hooks together come to
about **0.052–0.059 CPU** (about 5–6% of one core). This excludes nftables chain
passes, the fwmark rule, routing and WireGuard packet work, which the census
cannot count. The only packet evidence is 52,902 interface packets/s (5,229/s
excluding loopback) times the benchmark's per-unit cost of at most about 1.4 us,
which gives at most about 0.074 CPU. That proxy is not a chain-pass count,
overlaps the send and receive hook work already measured, and is crude. No
total feature upper bound, zero-overhead claim or whole-host A/B resolution
follows: at this host's 1.1–1.6 CPU between-round spread, a whole-host
comparison cannot resolve differences of this size.

**Serial 1,000/s backlog.** Re-analysis of the final serial and stream raw
samples classifies the serial backlog as capacity accumulation. A
single-outstanding loop keeps up only while its mean service time, the round
trip plus about 4 us of loop overhead, stays below the 1 ms period. The three
published backlog maxima come from the most contended round, whose windows had a
per-window utilization of 1.07–1.42, and host run-queue contention explained
most of the variation in mean round trip. After adjusting for contention, no
product effect on the included round trip was resolved, and plain WireGuard and
the previous implementation backlog the same way. This is an application
concurrency and capacity limit, not a measured classifier defect, and no product
change is justified. An incomplete supporting diagnostic ran the unchanged probe
over loopback in a private network namespace without WireGuard; its three
completed serial runs (6 of 8 total planned 10-second runs completed) held the
schedule, with send-lateness p99 100.6 us. It is not a like-for-like benchmark.

Applications that need 1,000 requests/s through the tunnel should send
independently paced requests with a bounded in-flight window of at least
2 × rate × round-trip p99.9. With the local fixture's per-window p99.9 of
4.2–10.0 ms, that is at least 20 at 1,000/s. Account for scheduled completion,
the reply time minus the intended send time, and shed or coalesce requests older
than their deadline instead of bursting to catch up. In the final stream
experiment this pattern delivered 1,000 requests/s with zero loss and at most 20
in flight. The serial workload remains the unchanged reference. These local
fixture figures do not describe WAN or provider latency, and p99 shifts
elsewhere in this document are paired estimates, not worst-case bounds.

## Final native serial results — September 14, 2026

This section reports the final **serial** experiment. It runs the original
single-outstanding UDP request/reply timing loop, unmodified, with the final
harness. It is not the earlier native serial run below, whose whole-host CPU
accounting is invalid, and it is not compared with the stream experiment in the
next section. The final profiler diagnostic follows the stream section.

The same physical reference host, boot and kernel as the stream run (`TV`,
7.0.0-31-generic, 16 online CPUs, no virtualization) compared plain WireGuard or
the direct host path, baseline `b843960` and candidate `d0a40ff`. It used six
balanced rounds of 16 concurrent paced workloads, 10 seconds per condition, with
the same frozen harness (`3351c2a03d2b61dd8682bf63d7ec18e30e837dbcfe20fb5a77cc154c02fd2722`),
probe and builds. Evidence identifier: `overhead-3a9e380183`. Summary SHA-256:
`58a4680c85b105921c59c071a7b4b3cadc7657fecda49d2330c26cc8541d6ca2`.

All **1,944,000** offered operations completed across 18 of 18 windows without
errors. All 54 CPU accounts passed with zero steal. Separate analysis and
reconciliation entrypoints recounted the raw records and re-executed the frozen
statistics and CPU-accounting modules, reproducing every latency statistic and
every CPU account. All 90 route proofs, fixture-membership checks, peer counts
and the cleanup/invariant readback passed, and all 36 peer socket records showed
zero receive drops.

The operator's recorded outcome is again **restored-with-findings**. After
restoration, exactly one of 313 nftables rows differed: the owned
`inet wg_program_split` table's attempt UUID comment and kernel handle. Each
comment matched its own `wgps0` alias, and readiness and provider acceptance
passed. Root's independent review of the full nftables snapshots, raw outcome and
provider acceptance closed it as the expected lifecycle identity change, and the
original restored-with-findings status is preserved. The profiler's original
provenance capture reported the same finding as an error. That record is kept,
and the final profiler diagnostic used a separately reviewed descriptor.

### Serial latency

Candidate p99 and the paired shifts have the same meaning as in the stream
section below.

| Workload | Candidate p99 (us) | Added p99 vs plain/direct (us) [95%] | vs previous (us) [95%] |
|---|---:|---:|---:|
| Included UDP socket | 26.2 | +11.3 [+7.5, +15.5] | -5.5 [-9.9, -1.5] |
| Included TCP socket | 26.8 | +11.3 [+7.2, +15.4] | -7.1 [-14.1, -0.9] |
| Included UDP DNS | 3116.6 | -219.6 [-586.8, +123.3] | -301.9 [-538.8, -0.4] |
| Included TCP DNS | 4402.1 | -206.8 [-487.1, +118.0] | -90.7 [-540.4, +333.6] |
| Included persistent UDP | 3917.4 | -319.8 [-541.1, -109.7] | -210.6 [-580.2, +237.7] |
| Included persistent TCP | 3389.3 | -165.1 [-380.1, +39.2] | -42.6 [-242.7, +147.1] |
| Unlisted UDP socket | 24.6 | +9.4 [+5.8, +13.1] | -5.4 [-9.3, -1.2] |
| Unlisted TCP socket | 24.8 | +9.2 [+5.3, +13.0] | -5.7 [-10.3, -0.8] |
| Unlisted UDP DNS | 479.5 | -138.2 [-416.0, +95.8] | -140.6 [-320.4, -7.5] |
| Unlisted TCP DNS | 706.6 | -37.1 [-384.6, +339.9] | -53.8 [-282.0, +192.8] |
| Unlisted persistent UDP | 258.0 | -16.7 [-107.1, +59.7] | -104.1 [-206.6, -14.9] |
| Unlisted persistent TCP | 485.6 | -51.4 [-226.3, +98.5] | -193.0 [-359.5, -47.0] |
| Unlisted file read | 32.5 | +7.8 [+2.9, +12.8] | +1.7 [-3.0, +6.5] |
| Unlisted mmap | 61.4 | +6.1 [-3.1, +14.7] | -2.6 [-13.1, +4.5] |
| Unlisted fresh Unix IPC | 19.8 | +5.8 [+2.9, +8.7] | +2.4 [+0.1, +5.1] |
| Unlisted pre-attachment Unix IPC | 26.8 | +12.8 [+9.4, +16.3] | -15.9 [-24.9, -9.0] |

Against plain WireGuard or the direct path, socket creation added **9.2–11.3 us**
and local file and IPC operations added 5.8–12.8 us, with intervals excluding
zero. The largest estimated added p99 was **+12.8 us**, and the largest upper
endpoint of the individual intervals was **+339.9 us** (unlisted TCP DNS). These
estimates meet the sub-millisecond added-local-overhead target for this
experiment. Against the previous implementation, socket creation was 5.4–7.1 us
faster, with intervals excluding zero.

The same socket workload added 4.0–6.5 us in the stream experiment. That spread
between two separate experiments is run-to-run variation beyond either run's
intervals. Several network comparisons have intervals wholly below zero, most
notably included persistent UDP against plain WireGuard. With the serial backlog
described below and only six rounds, these are observed differences, not
speedups. Endpoints within about 0.5 us of zero, such as fresh IPC and included
UDP DNS against the previous implementation, are weak evidence that is not
practically resolved; no regression or zero-cost conclusion follows.

### Serial scheduling and backlog

The included persistent UDP client waits for each reply before sending its next
1,200-byte request, at 1,000 requests/s through the WireGuard fixture. With a
round trip near the 1 ms period, it falls behind in every condition.

| Included persistent UDP (serial) | Plain WireGuard | Previous | Candidate |
|---|---:|---:|---:|
| Round trip p50 / p99 (us) | 441.1 / 4014.7 | 445.0 / 4034.8 | 435.8 / 3917.4 |
| Send lateness p99 / p99.9 / max (ms) | 1928.6 / 2190.9 / 2216.2 | 3582.5 / 4086.2 / 4175.3 | 596.6 / 720.9 / 743.6 |
| Scheduled completion p99 / p99.9 / max (ms) | 1929.9 / 2192.5 / 2220.6 | 3586.2 / 4087.3 / 4177.2 | 597.6 / 722.6 / 744.5 |
| Lowest per-window effective rate (requests/s) | 818.4 | 705.4 | 930.9 |

All 60,000 requests per condition completed, but late. Where each window entered
backlog varies, and six rounds cannot separate that from routing cost, so the
ordering between conditions is not an improvement claim. This workload provides
no sub-millisecond deadline. The direct-path unlisted persistent UDP client did
not backlog: its scheduled-completion p99 was 581.8 us and its maximum 5.14 ms.
Across the other candidate workloads, send-lateness p99 was 253.7–479.7 us
(maximum 4.69 ms). Scheduled-completion p99 ranged from 269.1 us to 4.57 ms,
with a maximum of 8.92 ms.

### Serial CPU

| Resource observation (six windows each) | Plain/direct | Previous | Candidate |
|---|---:|---:|---:|
| Observed span, including output drain (s) | 68.744 | 69.365 | 66.316 |
| Whole-host busy CPU-seconds (± modeled allowance) | 557.630 (±0.129) | 589.188 (±0.129) | 537.001 (±0.129) |
| Mean busy CPUs (share of 16) | 8.11 (50.7%) | 8.49 (53.1%) | 8.10 (50.6%) |
| Controller cgroup CPU-seconds (percent of one core) | — | 1.728 (2.492%) | 1.557 (2.347%) |
| Fixture cgroup CPU-seconds (clients, peers, sampler) | 23.210 | 27.760 | 26.560 |
| Client loop CPU inside the fixture (lower bound) | 17.249 | 21.339 | 20.252 |
| Sampler CPU inside the fixture | 0.880 | 0.988 | 0.947 |
| Other host CPU, including kernel work (± modeled allowance) | 534.420 (±0.604) | 559.699 (±0.571) | 508.885 (±0.618) |
| Largest sampled controller memory (MiB) | — | 17.29 | 21.46 |

| Paired planned-window difference (CPU-seconds per second) | Mean | Approximate 95% interval | Between-round SD |
|---|---:|---:|---:|
| Host busy, candidate − plain/direct | +0.048 | [-1.062, +1.064] | 1.479 |
| Host busy, candidate − previous | -0.231 | [-1.014, +0.561] | 1.113 |
| Fixture, candidate − plain/direct | +0.058 | [+0.040, +0.075] | 0.024 |
| Fixture, candidate − previous | -0.017 | [-0.029, -0.006] | 0.016 |
| Controller, candidate − previous | -0.0007 | [-0.0032, +0.0018] | 0.0032 |

Plain/direct planned-window busy time averaged 8.13 CPUs but ranged from 5.74 to
10.45 across rounds, so whole-host feature cost is not resolved. The controller
used about 2.3–2.5% of one core, and its difference from the previous
implementation is not resolved. Serial backlog lengthened some output drains, so
full spans differ between conditions. The fixture differences are measured scope
differences with attribution uncertainty, and the ± values are modeled
allowances rather than hard bounds; both carry the limits described in the
stream section below.

## Final native stream results — September 14, 2026

This section reports the final **stream** experiment. It sends UDP requests
independently of replies, a different application pattern from the serial
workload in the previous section; it is not a speedup of serial requests and the
two are not compared. The final profiler diagnostic follows this section; the
dated sections after it remain the original historical records.

The physical reference host (`TV`, kernel 7.0.0-31-generic, 16 online CPUs, no
virtualization) compared plain WireGuard or the direct host path, baseline
`b843960` and candidate `d0a40ff` in six balanced rounds of 16 concurrent paced
workloads, 10 seconds per condition. The harness (combined SHA-256
`3351c2a03d2b61dd8682bf63d7ec18e30e837dbcfe20fb5a77cc154c02fd2722`), probe binary
and both builds matched their approved staging hashes. Evidence identifier:
`overhead-91f6debe3c`. Summary SHA-256:
`aea70e12c9132dda91a16ba903993c9e4cac521f1be14eef519caad2c85feaa3`.

All **1,944,000** offered operations completed across 18 of 18 windows without
errors. All 54 CPU accounts (full span, planned window and drain for each window)
passed with zero steal. Separate analysis and reconciliation entrypoints recounted
the raw records and re-executed the frozen statistics and CPU-accounting modules,
reproducing every latency statistic and every CPU account. This is an exact-module
cross-check, not an independent implementation. All 90 route proofs,
fixture-membership checks, peer counts and the cleanup/invariant readback passed.
All 72 stream client and peer socket records showed zero receive drops with
2 MiB effective receive buffers.

The operator's recorded outcome is **restored-with-findings**, not an unqualified
pass. After accepted production was restored, the owned `inet wg_program_split`
nftables table carried a new attempt UUID comment and kernel handle. Root's
separate review found every nftables expression and foreign entry identical, with
each comment matching its `wgps0` interface alias; readiness and provider
acceptance passed. The finding concerns post-run restoration identity and does
not affect the measured windows.

### Stream latency

Candidate p99 is the aggregate measured operation latency. The shift columns are
the mean of six paired round p99 differences with approximate 95% bootstrap
intervals, which apply individually. They are not per-request, absolute or
worst-case bounds.

| Workload | Candidate p99 (us) | Added p99 vs plain/direct (us) [95%] | vs previous (us) [95%] |
|---|---:|---:|---:|
| Included UDP socket | 23.1 | +6.5 [+4.2, +8.6] | -8.2 [-10.5, -5.8] |
| Included TCP socket | 23.4 | +6.2 [+3.9, +8.7] | -8.2 [-9.7, -6.8] |
| Included UDP DNS | 3052.2 | +51.1 [-388.0, +464.5] | +111.9 [-227.8, +456.9] |
| Included TCP DNS | 4481.6 | -183.9 [-735.5, +383.4] | +237.4 [-237.2, +711.9] |
| Included UDP stream | 3537.1 | +37.1 [-258.2, +288.7] | +77.1 [-38.6, +195.9] |
| Included persistent TCP | 3558.1 | +166.4 [-188.1, +521.4] | +171.6 [-120.9, +481.1] |
| Unlisted UDP socket | 21.3 | +4.8 [+1.8, +7.1] | -6.5 [-8.7, -4.2] |
| Unlisted TCP socket | 21.7 | +4.0 [+2.0, +5.9] | -7.4 [-9.6, -4.9] |
| Unlisted UDP DNS | 544.5 | +21.5 [-234.6, +212.1] | +106.2 [-4.7, +203.7] |
| Unlisted TCP DNS | 648.4 | -95.5 [-338.0, +154.4] | +31.8 [-86.8, +158.6] |
| Unlisted UDP stream | 292.8 | +35.9 [-118.0, +179.9] | +46.6 [-61.8, +154.9] |
| Unlisted persistent TCP | 497.2 | +16.6 [-242.9, +197.7] | +76.9 [-15.3, +165.9] |
| Unlisted file read | 29.9 | +2.5 [-1.6, +6.0] | +1.9 [+0.0, +4.1] |
| Unlisted mmap | 62.2 | +2.0 [-10.8, +14.2] | +4.7 [-1.4, +11.7] |
| Unlisted fresh Unix IPC | 15.8 | +0.3 [-2.0, +2.4] | +0.3 [-1.5, +2.2] |
| Unlisted pre-attachment Unix IPC | 23.5 | +7.9 [+4.8, +10.6] | -15.6 [-17.8, -13.4] |

Socket creation added **4.0–6.5 us** at p99 versus plain WireGuard or the direct
path and was **6.5–8.2 us** faster than the previous implementation; all eight
of those intervals exclude zero. Against plain WireGuard or the direct path, the
largest estimated added p99 was **+166.4 us** (included persistent TCP), and the
largest upper endpoint of the individual intervals was **+521.4 us** for the same
workload. These estimates meet the sub-millisecond added-local-overhead target
for this experiment.

Against the previous implementation, which is a different reference, network
echo and DNS estimates ranged from +31.8 to +237.4 us. The largest is included TCP
DNS, with an upper endpoint of +711.9 us, and every such interval includes zero,
so six rounds do not resolve them. The file-read comparison with the previous
implementation has a computed lower endpoint of +1.166 ns, shown as +0.0 us. From
six rounds that is weak evidence, not practically resolved at that precision,
and no regression, zero-cost or no-regression conclusion follows.

### Stream scheduling

Each stream client offered 1,000 requests/s of 1,200 bytes; all 60,000 per
condition were delivered, at pooled rates of 999.8–1000.1 requests/s. The
in-flight high-water mark was 8 included and 4 unlisted for the candidate, and at
most 20 in any condition, of the bounded 256 window.

| Candidate stream (us) | Included | Unlisted |
|---|---:|---:|
| Round trip p50 / p99 | 538.0 / 3537.1 | 47.6 / 292.8 |
| Send lateness p99 / max | 351.6 / 3559.6 | 392.0 / 3412.1 |
| Scheduled completion p99 / p99.9 / max | 3611.7 / 4688.5 / 7652.3 | 644.2 / 1760.8 / 3761.0 |
| Added round-trip p99 vs plain/direct [95%] | +37.1 [-258.2, +288.7] | +35.9 [-118.0, +179.9] |

Round trip is reply time minus actual send; send lateness is actual minus
scheduled send; scheduled completion is reply time minus scheduled send, which is
what an application deadline sees. The included round-trip p99 through the local
WireGuard fixture was about 3.4–3.5 ms in every condition, so a sub-millisecond
**added** estimate does not make that total deadline sub-millisecond. Plain
WireGuard's included scheduled-completion maximum was 19.8 ms. Across all 16
candidate workloads, send-lateness p99 was 255.6–515.4 us (maximum 9.55 ms) and
scheduled-completion p99 ranged from 269.1 us to 4.64 ms.

### Stream CPU

Whole-host CPU accounting was valid in this run. Busy time is elapsed CPU capacity
minus timed idle and iowait, with verified high-resolution NO_HZ on all 16 CPUs,
verified kernel HZ 1000, zero steal and consistent repeated `/proc/stat` reads.
The earlier September 14 serial record's whole-host CPU remains invalid; this run
does not change that record.

| Resource observation (six windows each) | Plain/direct | Previous | Candidate |
|---|---:|---:|---:|
| Observed span, including output drain (s) | 66.100 | 66.109 | 66.096 |
| Whole-host busy CPU-seconds (± modeled allowance) | 516.621 (±0.129) | 496.566 (±0.130) | 534.238 (±0.130) |
| Mean busy CPUs (share of 16) | 7.82 (48.8%) | 7.51 (46.9%) | 8.08 (50.5%) |
| Controller cgroup CPU-seconds (percent of one core) | — | 1.457 (2.204%) | 1.647 (2.492%) |
| Fixture cgroup CPU-seconds (clients, peers, sampler) | 23.710 | 27.021 | 25.763 |
| Client loop CPU inside the fixture (lower bound) | 17.877 | 21.081 | 19.674 |
| Sampler CPU inside the fixture | 0.845 | 0.900 | 0.927 |
| Other host CPU, including kernel work (± modeled allowance) | 492.911 (±0.551) | 468.088 (±0.622) | 506.828 (±0.592) |
| Largest sampled controller memory (MiB) | — | 22.22 | 22.82 |

The ± values are modeled accounting and source-read allowances. They come from
read brackets, USER_HZ rounding and cgroup publication lag under the kernel's
accounting assumptions, and are not hard bounds on true CPU. Consecutive
`/proc/stat` reads detect large inconsistent idle/iowait splits, but smaller or
consistently biased interleavings, and changes between membership samples, can
remain undetected. Passing the account gates does not remove these limits; see
[native validation](linux-native-validation.md#run-and-evidence).

| Paired planned-window difference (CPU-seconds per second) | Mean | Approximate 95% interval | Between-round SD |
|---|---:|---:|---:|
| Host busy, candidate − plain/direct | +0.335 | [-0.847, +1.488] | 1.632 |
| Host busy, candidate − previous | +0.686 | [-0.140, +1.584] | 1.193 |
| Fixture, candidate − plain/direct | +0.034 | [+0.013, +0.057] | 0.031 |
| Fixture, candidate − previous | -0.021 | [-0.037, -0.003] | 0.024 |
| Controller, candidate − previous | +0.0032 | [+0.0020, +0.0046] | 0.0017 |

Unrelated services kept the host busy. Without project hooks, planned-window busy
time averaged 7.87 CPUs, ranging from 7.08 to 8.72 across rounds. Paired host
differences varied by 1.1–1.6 CPUs between rounds, so this experiment does not
resolve whole-host feature cost; those intervals include zero. The modeled
allowances are small beside that spread.

The narrower scope differences have intervals that exclude zero. The controller
cgroup used 0.0032 CPU (0.32% of one core) more than the previous implementation,
about 2.5% of one core in total, including its five-second health checks. The
fixture cgroup covers the clients, peers, sampler and kernel work performed in
their context. It used 0.034 CPU more than plain WireGuard or the direct path,
and 0.021 CPU less than the previous implementation.

These are measured scope differences with attribution uncertainty, not guaranteed
upper or lower bounds on true feature cost. The kernel does not enable IRQ time
accounting, so unrelated interrupt work is charged to whichever task it
interrupts, and observer differences and scheduling variability also contribute.
Client loop CPU is part of the fixture and is not added again. Sampler CPU
differed by about 0.001 CPU between conditions.

The local peer runs on the same host, so these results exclude Internet, WAN
and total-VPN latency. They give no absolute, worst-case, hardware or kernel
guarantee. Six paired rounds give weak tail precision, and sampled memory maxima
are not continuous peaks.

## Final native profiler diagnostic — September 14, 2026

This diagnostic is separate from the primary timing and CPU results above. It
attached one 5-second `bpftool prog profile` window, counting hardware cycles and
instructions, to `guard_connect` (program 5181) on the running production
controller. `guard_connect` is the product's Unix-stream resolver IPC LSM hook,
not the IPv4 socket classifier. No selected test workload ran and the include
list was empty, so any counts would have mixed the profiler's own
instrumentation with ordinary live activity.

The hook made no calls in the window. Both counters read `run_cnt 0`, `value 0`,
`enabled 0` and `running 0`, and the profiler's quality verdict is
**inconclusive**. That is an absence of samples, not a zero cost. No hook
latency, total packet-path CPU or broader kernel CPU conclusion follows from this
diagnostic.

The non-attaching pre-check passed. After the window, every profiler program,
link, map and BTF object was gone, including in an independent readback 3 seconds
later. Product BPF objects, the controller (same PID, ready, protection
verified, empty include list), protected services, and the
`kernel.bpf_stats_enabled` and `kernel.sched_schedstats` settings (both 0) were
unchanged. The raw readings are `profile-guard_connect-final/profile.stdout`,
SHA-256 `d0d8aa9d55f8612e03aacc622d9218e68fd83932e3595dab827fc5995c710082`; the
result record is SHA-256
`a4cb3f5fbb4da77edeac71055a1f1fa40fcf8a3dd99d5f586f36598cd91b9f8c`.

### Targeted follow-up diagnostic

The idle window above remains inconclusive. A separate 5-second profile ran with
its own synthetic workload: one short-lived local process made fresh, ordinary
unlisted `AF_UNIX`/`SOCK_STREAM` connections at 500/s to a Unix socket that it
created and owned, which exercises `guard_connect`'s ordinary fast path. It used
the same program 5181, link 486 and reviewed descriptor
(`480619d7ccc97b5b471c24e3120d906d4ba668effe0fc975caeb74593fff0f8e`).

| Targeted window | Result |
|---|---|
| Hook calls recorded (both metrics) | 2,500 |
| Cycles / instructions | 37,309,272 / 22,652,359 |
| Counter multiplexing | None (enabled equals running for both) |
| Profiler quality | Complete, no reasons |
| Connections offered / connected / accepted | 2,814 / 2,814 / 2,814, 0 errors |
| Workload client span; process CPU | 5.628 s; 0.31 s |

The profiler's BPF objects and the workload's process, socket and directory were
removed, and the operator's independent readback 3 seconds later found none
present. Product objects, the controller (same PID, no restarts), protected
services, global settings and the TCP and Unix listener sets were unchanged. The
raw readings are `profile-guard_connect-targeted/profile.stdout`, SHA-256
`d4bed68dc10fc8ebc9a5e80d11ab329958f1dd4cfa1c4043c1b5c486fea4f779`; the result
record is SHA-256
`278c4459b035b249d90f6c5ff7b61e51467d69b8cfb579e82e3c42fff402ffeb`.

This workload is outside every primary measurement and does not replace or
improve any earlier timing. It confirms that the profiler works, and it
characterizes only this ordinary Unix-connect guard fast path under
instrumentation. The counts include the profiler's own instrumentation. They are
not standalone hook latency, IPv4 socket-classifier cost, selected-resolver
denial cost, whole-kernel or nftables packet CPU, or evidence of zero overhead,
and they are not converted to time. The workload helper's 8-second limit bounded
that one run; it is not a real-time guarantee. The actual client span was 5.63 s
under ordinary operating-system scheduling.

## Native reference-host results — September 14, 2026

The physical reference host (Ubuntu 26.04, kernel 7.0.0-31-generic, i9-11900,
16 logical CPUs) passed **1,944,000 operations** over six balanced rounds and
18 primary windows with its existing services running. Baseline `b843960` was
compared with `d0a40ff`, whose compact exact-path tier preserves 4095-byte paths,
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
CPU. CPU pinning alone does not prevent that interleaving. Commit `72cbf0c`
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
- The previous implementation at `7297931`, with the `72cbf0c` correctness fix.
- The optimized production implementation at `72cbf0c`.

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
only the two production-file changes from `72cbf0c` (`policy.bpf.h` and
`bpf-loader.cpp`); leave its controller and resolver guard unchanged. The exact
patch is available with `git show --format= 72cbf0c -- src/linux/bpf/policy.bpf.h src/linux/native/bpf-loader.cpp`.
Run `scripts/build-linux.sh` in each source directory. The current checkout
supplies the benchmark and installed-test helpers;
the benchmark verifies each production package matches its source and records
source/artifact hashes before and after the experiment.

```sh
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 python3 tests/linux/test_overhead.py --vm \
  --baseline-root /path/to/baseline --candidate-root /path/to/candidate \
  --baseline-revision '7297931 + 72cbf0c correctness backport' \
  --candidate-revision 72cbf0c
```

Results are written under ignored `local/validation/overhead-*`. Keep raw records,
metadata, resource samples and failures together. The optional controller
profiler runs outside the primary timing windows; it is not needed to run the
comparison. Fixtures remove their own installed runtime, networking and processes
and verify the original host state afterward.
