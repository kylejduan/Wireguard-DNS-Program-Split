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
real identities, a fresh UUID and new evidence directory. Run on each target:

```sh
sudo python3 tests/linux/test_native_overhead.py --vm-rehearsal \
  --manifest /root/wgps-validation/rehearsal.json --rounds 6 --seconds 10 --seed 20260914
sudo python3 tests/linux/test_native_overhead.py --native-tv \
  --manifest /root/wgps-validation/native.json --rounds 6 --seconds 10 --seed 20260914 --profile
```

Rounds must be multiples of six, 6–60; arms last 10–30 seconds. Each block uses
all six condition permutations. Fresh independent keys/profile serve an owned
namespace/veth peer at MTU 1420; provider keys/identity are never reused. Native
peers bind DNS/payload listeners inside that namespace. The absent arm adds one
owned /32 route; product arms use normal installation, selection and routing.

Identical optimized ELF bytes at selected/unlisted paths exercise 16 paced
socket, synthetic TCP/UDP DNS, persistent payload, file, mmap and Unix IPC cases,
including pre-attachment IPC. Product arms retain normal health checks and need
fresh daemon readiness. Failures and partial output remain; there is no selective
retry. A failed experiment requires a new manifest/run for another comparison.

`--udp-mode serial` preserves the original single-outstanding UDP request/reply
workload. `--udp-mode stream` sends independently of replies on the same persistent
socket, at the same 1000 requests/s and 1200-byte payload. Only those two case
names change to `included_udp_stream` and `unlisted_udp_stream`; all other cases
and offered rates stay identical. Run the modes as separate experiments and keep
their results distinct. A bounded 256-request window accepts reordered replies;
loss, duplicates, corruption, send failure or window exhaustion fails the run.
Every offered sample remains, including failures, with actual scheduling lateness
and `inflight_max` in the client report. This models an application able to have
multiple requests pending; it does not speed up a sequential application.

`metadata.json`, `before.json`/`after.json`, `ownership.jsonl`, per-arm raw JSON,
startup/resource records and `summary.json` retain identity, timing and accounting
evidence. `failure.json` and `cleanup.json` distinguish execution from cleanup.
Private fixture inputs are mode 0600; share only reviewed, sanitized evidence.

CPU samples bracket GO and continue through full client output drain/exit.
Planned-window and drain accounts are separate; full-span accounting includes
client primary CPU, peers, harness and disjoint controller/early-guard cgroups.
Raw aggregate/per-CPU ticks, pressure, context switches, read skew and identities
support validity checks across every adjacent sample. `cpu_valid=false` forbids
a total-CPU conclusion even when timing records exist. Residual includes unrelated
work, kernel workers and client serialization; guest ticks are not added and
iowait is not execution. Sampled memory maxima are not continuous peaks.

`--profile` runs separate exact-program-ID, one-second BPF cycles/instructions
diagnostics after all primary windows. `profile-*/profile.json` records unsupported
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
original owner. Use `--vm-rehearsal` for VM recovery. Durable uninstall phases
permit resuming captured partial removal, including a removed installed CLI via
the identity-verified staged package. Unresolved acquisition intents, changed
identities or unexpected files block automatic cleanup: retain the exact objects
and inspect `ownership.jsonl`, `cleanup.json` and any `recovery.json`; do not guess
ownership or delete receipts to force recovery.

Latency intervals estimate mean paired-round quantile shifts, with weak tail
precision at six rounds. Report scheduling lateness, scheduled completion and
offered/delivered load alongside RTT; fixed-rate goodput is not saturation
throughput. Shared-host local peers do not establish Internet latency, worst-case
delay, equivalence or unfinished-bot performance. Ordinary libc/NSS, local
loss/recovery, controller restart, provider exit/DNS and durable boot acceptance
remain separate records; the runner does not automate those checks.
