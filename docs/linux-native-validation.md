# Guarded native Linux validation

`tests/linux/test_native_overhead.py` compares absent/plain WireGuard, validated
baseline `00b3efd`, and candidate `3ead242` against an owned local peer. It uses
the real installed singleton controller and kernel hooks. This procedure contains
no measured results; see [performance interpretation](linux-performance.md).

## Preparation and admission

Root completes host, protected-service and networking review before execution.
The runner does not reboot, migrate an old VPN owner, overwrite an existing
installation, activate a provider profile, or alter host resolver/NSS files.
Existing product paths, units/overrides, `wgps0` or product nft ownership cause
refusal. Complete any authorized migration separately before the comparison;
provider activation and exit/DNS acceptance follow separately afterward.

Native admission requires root, hostname `TV`, `systemd-detect-virt=none`, a
non-WSL kernel, and exact manifest boot/machine identities. Rehearsal requires
an actual non-TV VM and `/var/lib/wgps-vm-provisioned`. Existing disposable-VM
guards remain unchanged and refuse TV. Never spoof a hostname, create a fake
provisioning marker, or use the disposable-VM environment flag for native access.

Stage the runner, `native_overhead_{owner,runtime,cpu}.py`, `overhead_stats.py`,
and independently built artifacts from both declared revisions. Compile the
standalone C workload once and hash its exact bytes:

```sh
cc -O2 -std=c11 -Wall -Wextra -Werror tests/linux/overhead_probe.c \
  -o /var/lib/wgps-validation/overhead-probe
sha256sum /var/lib/wgps-validation/overhead-probe
```

Artifact and probe copies, and every directory above them, must be root-owned
without group/other write. Admission refuses anything else and never re-owns a
source; the runner copies the probe from the same read that verified its hash.

For each revision, record SHA-256 for exactly the five build files shown below.
Revision labels do not establish provenance: stage verified builds from those
revisions and use their actual hashes. Admission enforces baseline `00b3efd` and
checks all listed artifact/probe hashes; it does not enforce a candidate label.

## Manifest

Write JSON to a singly linked, non-symlink, root-owned **0600** file whose resolved
parent is root-owned **0700**. The runner exclusively locks the manifest and
checks its identity. Use a fresh UUID for every run; derive names from its first
ten hexadecimal digits as `nu<digits>`, `nr<digits>`, `nn<digits>`.

The following is a schema example; replace every placeholder. Addresses, ports,
service names and paths must come from refreshed, sanitized root inventory.

```json
{
  "schema": 1,
  "mode": "native-tv",
  "run_id": "<fresh-UUID>",
  "names": {
    "underlay": "nu<first10hex>",
    "remote": "nr<first10hex>",
    "namespace": "nn<first10hex>"
  },
  "boot_id": "<actual-boot-ID>",
  "machine_id": "<actual-machine-ID>",
  "evidence": "/var/lib/wgps-validation/<new-run-directory>",
  "root_preflight_complete": true,
  "protected_services_reviewed": ["<reviewed-service>.service"],
  "management_ips": ["<management-IP>", "<LAN-IP>", "<Tailscale-IP>"],
  "reserved_networks": ["<provider-or-other-reserved-CIDR>"],
  "underlay": "<unused-IPv4-network/30>",
  "host_tunnel": "<unused-IPv4-address>",
  "peer_tunnel": "<different-unused-IPv4-address>",
  "host_port": 55101,
  "peer_port": 55102,
  "payload_port": 57053,
  "probe": "/var/lib/wgps-validation/overhead-probe",
  "probe_sha256": "<exact-probe-SHA256>",
  "builds": {
    "baseline": {
      "directory": "/var/lib/wgps-validation/baseline/build/linux",
      "revision": "00b3efd",
      "sha256": {
        "wg-program-split.pyz": "<exact-baseline-SHA256>",
        "bpf-loader": "<exact-baseline-SHA256>",
        "classifier.bpf.o": "<exact-baseline-SHA256>",
        "wg-program-split-guard.service": "<exact-baseline-SHA256>",
        "wg-program-split.service": "<exact-baseline-SHA256>"
      }
    },
    "candidate": {
      "directory": "/var/lib/wgps-validation/candidate/build/linux",
      "revision": "3ead242",
      "sha256": {
        "wg-program-split.pyz": "<exact-candidate-SHA256>",
        "bpf-loader": "<exact-candidate-SHA256>",
        "classifier.bpf.o": "<exact-candidate-SHA256>",
        "wg-program-split-guard.service": "<exact-candidate-SHA256>",
        "wg-program-split.service": "<exact-candidate-SHA256>"
      }
    }
  }
}
```

Evidence must be new, persistent, absolute and resolved, outside `/tmp`; all its
parents must be root-owned and not group/other writable. Paths below `/home/tv`
also require `native_account_verified: "tv@TV"` and still face those directory
checks. Prefer a prepared `/var/lib` parent. Ports must be integers 1024–65535.
The /30 and two /32 addresses must not overlap one another, current addresses,
non-default routes in any table, or declared reserved/provider networks. Names
and host UDP port must be unused, including wildcard listener collisions.

## Run and evidence

First rehearse using a separate manifest with `mode: "vm-rehearsal"`, the VM's
real identities, a fresh UUID and new evidence directory. Start each runner in a
fresh root-owned transient systemd service named `wgps-overhead-<first10hex>`
using that manifest's UUID. Before any host access, the runner requires its own
cgroup to be exactly `/system.slice/wgps-overhead-<first10hex>.service`,
containing only itself, plus valid live NO_HZ readback and a verified kernel HZ
(see below); otherwise it stops with no inventory, evidence or fixture. Clients, peers
and the sampler then share this fixture cgroup; product units remain in their own
cgroups. Cgroup v2 always reports `cpu.stat` usage, so no accounting property is
set; current systemd ignores the deprecated `CPUAccounting=`. On the respective
target:

```sh
sudo systemd-run --unit=wgps-overhead-<first10hex> --wait --pipe --collect \
  --property=KillMode=mixed --property=TimeoutStopSec=600 \
  --property=WorkingDirectory=<absolute-repository> \
  /usr/bin/python3 <absolute-repository>/tests/linux/test_native_overhead.py --vm-rehearsal \
  --manifest /root/wgps-validation/rehearsal.json --rounds 6 --seconds 10 --seed 20260914
sudo systemd-run --unit=wgps-overhead-<first10hex> --wait --pipe --collect \
  --property=KillMode=mixed --property=TimeoutStopSec=600 \
  --property=WorkingDirectory=<absolute-repository> \
  /usr/bin/python3 <absolute-repository>/tests/linux/test_native_overhead.py --native-tv \
  --manifest /root/wgps-validation/native.json --rounds 6 --seconds 10 --seed 20260914 --profile
```

With `KillMode=mixed`, stopping the unit sends SIGTERM only to the runner. The
runner turns SIGTERM or SIGHUP into normal unwinding and ignores further stop
signals: it retires clients, the product and the fixture while its cleanup
commands keep running. Processes left after `TimeoutStopSec` are killed. A stop
during an installer or CLI command can leave an unresolved intent or a retained
product; then use `--recover` as described below.

Rounds must be multiples of six, 6–60; arms last 10–30 seconds. Each block uses
all six condition permutations. Fresh independent keys/profile serve an owned
namespace/veth peer at MTU 1420; provider keys/identity are never reused. Native
peers bind DNS/payload listeners inside that namespace. The absent arm adds one
owned /32 route; product arms use normal installation, selection and routing.

Identical optimized ELF bytes at selected/unlisted paths exercise 16 paced
socket, synthetic TCP/UDP DNS, persistent payload, file, mmap and Unix IPC cases,
including pre-attachment IPC. Product arms retain normal health checks and need
fresh daemon readiness. Just before the first CPU sample and GO, every arm repeats
the kernel route-get proof (`route_proof_before_go`), outside every measured span.
Failures and partial output remain; there is no selective retry. A failed
experiment requires a new manifest/run for another comparison.

`--udp-mode serial` preserves the original single-outstanding UDP request/reply
workload. `--udp-mode stream` sends independently of replies on the same persistent
socket, at the same 1000 requests/s and 1200-byte payload. Only those two case
names change to `included_udp_stream` and `unlisted_udp_stream`; all other cases
and offered rates stay identical. Run the modes as separate experiments and keep
their results distinct. A bounded 256-request window accepts reordered replies;
loss, duplicates, corruption, send failure or window exhaustion fails the run.
`fixture_receive` records effective receive buffers and drop counters for both
peers and the stream clients. Any drop fails the arm as a fixture socket drop,
distinct from path loss. Stream mode also fails the arm when a buffer or counter
is unavailable, instead of treating it as zero. Serial clients report null
buffers and counters, and serial arms record, but do not require, peer counters;
that legacy mode cannot attribute loss when a counter is missing.
Every offered sample remains, including failures, with actual scheduling lateness
and `inflight_max` in the client report. This models an application able to have
multiple requests pending; it does not speed up a sequential application.

`metadata.json`, `before.json`/`after.json`, `ownership.jsonl`, per-arm raw JSON,
startup/resource records and `summary.json` retain identity, timing and accounting
evidence. `failure.json` and `cleanup.json` distinguish execution, including a
rejected measurement, from cleanup.
Private fixture inputs are mode 0600; share only reviewed, sanitized evidence.

CPU samples bracket GO and continue through full client output drain/exit.
The planned account runs from a sample at GO to the planned end; the drain
account continues to the final exit. Full-span scoped CPU is the fixture cgroup,
including client output writing, plus the product unit cgroups keyed by exact
unit name. The product inventory must be exactly its two units, and each cgroup
inode must match the service record at the first sample. Client loop CPU stays a per-operation measurement; for the full
span it is only a lower bound on fixture CPU and is never added again. Harness and
peer process records are identity and membership observations, not added CPU.
Before GO and after drain, every fixture member must descend from the runner,
owned peers and clients must be members, and no child cgroup may exist; otherwise
the arm fails. Every precise CPU sample must also record fixture membership; a
missing or violating record invalidates the CPU accounts. `fixture_lifecycle` separately records whole-arm
fixture CPU from before the first client launch through retirement, including
runner-invoked product commands; it is never added to a primary-window account.
`observer_cpu_seconds` is the sampler's own thread CPU. It runs inside the fixture
and costs more on product arms, which also read the product cgroups and daemon,
so it limits the resolution of absent-versus-product fixture differences. Each
account also reports the CPU module's `sampler_cpu_seconds`, which excludes the
daemon sample. Sampling stays at 200 ms intervals until measured observer cost
from real runs justifies a change.

Whole-host CPU uses **elapsed CPU capacity minus timed idle + iowait** from the
aggregate `cpu` row, then subtracts separately reported steal time. Per-CPU rows
truncate separately, so they are capacity checks only. Live `/proc/timer_list` must prove
high-resolution NO_HZ on every online CPU before GO and after drain in each arm
(`nonidle_source_before`/`_after`). The later readback is attached to the final
sample, so any change invalidates the full-span and drain totals. This
avoids mixing tick-sampled busy time with timed idle, as the kernel's
[CPU accounting guide](https://docs.kernel.org/admin-guide/cpu-load.html) and
[NO_HZ implementation](https://github.com/torvalds/linux/blob/v7.0/kernel/time/tick-sched.c)
explain. Allowances derive from the `/proc/stat` read bracket and two USER_HZ
units per difference. Scope and residual checks add the whole sample bracket and
one kernel tick per online CPU for cgroup publication lag. Kernel HZ counts as
verified only when the kernel config gives `CONFIG_HZ`, a jiffies readback about
0.5 s long agrees with it, and no `nohz_full` CPUs are configured. Admission
requires this before creating any state, and every account rechecks it. The
one-tick lag is an accounting-model assumption under normal scheduling, not a
hard real-time bound. The readback runs outside measured spans. There is no
percentage tolerance or forced equality between busy ticks and elapsed time.

Idle and iowait are checked together because their classification can change.
The kernel reads them separately, so each precise sample reads `/proc/stat` at
least twice, at most `cpu.STAT_READS` times, and keeps every raw read, bracket and
check in `stat_consistency`. A read is accepted only when the next read agrees
within rounding and elapsed capacity; if no pair agrees, the sample is invalid.
This detects split-read jumps larger than rounding; smaller interleavings stay
inside the stated allowance. Only the source read is repeated, never a workload
window, and no sample is dropped. The idle complement remains an estimate: timed
idle omits idle-loop overhead and interrupt time on idle CPUs, and the
allowances are bounds, not exact attribution.

Every adjacent sample checks capacity, clock agreement, hotplug, counter and scope
identities, and fixture membership. Raw busy ticks and their deficit remain diagnostic. Scheduler v17
task-residence time is an independent diagnostic: it excludes idle-task work and
has unfinished-slice uncertainty, so it is not substituted for total CPU.
Workload completion and measurement acceptance are separate. Every completed
window and all its samples stay in `rows.json` and `resources.json`; no window
is retried or dropped. After all windows, `summary.json` `acceptance` lists each
invalid full-span, planned or drain account and, for `--native-tv`, any nonzero
steal. Any entry sets `accepted: false`: the runner writes `failure.json`, skips
`--profile`, cleans up normally and exits nonzero. A rejected run forbids any
total-CPU conclusion even when timings exist. VM steal is recorded, not gated;
VM CPU results validate plumbing only. Residual includes unrelated activity, kernel
workers and, with `CONFIG_IRQ_TIME_ACCOUNTING`, interrupt time that hit fixture
tasks; it is neither unrelated-only nor feature-only CPU. Paired host-busy
differences between arms, not the residual, estimate feature cost. The NO_HZ
source records these kernel options, `nohz_full` and timing boot parameters.
Historical samples lacking NO_HZ proof retain their original strict tick checks
and invalid results. No global profiling or scheduling settings change.
Sampled memory maxima are not continuous peaks.

`--profile` runs separate exact-program-ID, one-second BPF cycles/instructions
diagnostics only after an accepted primary measurement, using socket UDP and the experiment's UDP
payload case. `profile-*/profile.json` records unsupported
capability, including JSON errors returned with exit zero; unsupported profiling
is missing diagnostic evidence. It changes no global profiling sysctl and does
not measure total packet-path CPU or nft rule cost.

## Recovery and limits

Ownership intents/receipts are fsynced. Cleanup verifies PID/start identities,
link ifindex/alias, namespace identity and file identities before deletion;
product teardown uses verified production uninstall logic. It preserves unrelated
services, resolver/NSS and networking, with final invariant/collision readback.
No broad flush, process kill sweep or whole-host snapshot restoration is used.

```sh
sudo python3 tests/linux/test_native_overhead.py --native-tv \
  --manifest /root/wgps-validation/native.json --recover
```

Recovery requires the same boot/machine and manifest, and refuses a still-live
original owner. It takes no measurements, so it does not need the transient unit.
It repeats the final readback: a fresh snapshot is compared with `before.json`
and, once nothing is retained, preflight runs again. `recovery.json` lists
cleanup and invariant errors separately. Use `--vm-rehearsal` for VM recovery. Durable uninstall phases
permit resuming captured partial removal, including a removed installed CLI via
the identity-verified staged package. Unresolved acquisition intents, changed
identities or unexpected files block automatic cleanup: retain the exact objects
and inspect `ownership.jsonl`, `cleanup.json` and any `recovery.json`; do not guess
ownership or delete receipts to force recovery.

Automatic recovery ends at a reboot or power loss. Boot binding is intentional:
stale PIDs, interface indices and runtime state cannot be adopted safely. Root
must then inspect `ownership.jsonl` and remove any retained benchmark product
and fixture objects by hand. Never restore production over a retained benchmark
installation.

Latency intervals estimate mean paired-round quantile shifts, with weak tail
precision at six rounds. Report scheduling lateness, scheduled completion and
offered/delivered load alongside RTT; fixed-rate goodput is not saturation
throughput. Shared-host local peers do not establish Internet latency, worst-case
delay, equivalence or unfinished-bot performance. Ordinary libc/NSS, local
loss/recovery, controller restart, provider exit/DNS and durable boot acceptance
remain separate records; the runner does not automate those checks.
