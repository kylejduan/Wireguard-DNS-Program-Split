# Automatic Linux Include Mode Implementation Plan

**Status, September 13, 2026:** The seven repository implementation phases are
complete. Native disposable-VM acceptance, installed-service lifecycle tests,
and separate positive/failing-guard reboot tests passed. After the scratch
preemption correction in `75e9b6c`, the full native VM suite, including installed
lifecycle gates, and the Linux unit/native checks passed again. Existing Windows
checks also passed. This closes the implementation plan, not the separate TV deployment or target-workload latency
gates below. Independent scoped reviews drove regression fixes.

**Goal:** Automatically select included executables' new IPv4 TCP/UDP sockets
and ordinary DNS for WireGuard, independently of their normal launch method,
while preserving unlisted applications' host networking.

**Implemented architecture:** Synchronous BPF LSM executable-path classification
and socket marking, owned WireGuard routing/nftables policy, resolver IPC/cache
guards, a native libbpf loader and a Python/systemd controller. The transport
comparison selected direct kernel DNS translation. The private forwarder is
retained only as a test comparator, not a runtime dependency.

Read the [design and original alternatives](../specs/2026-09-12-linux-include-mode-design.md),
[current operating behavior](../../linux.md),
[overhead measurements and correctness prerequisite](../../linux-performance.md),
[application enrollment guide](../../linux-agents.md) and
[host migration procedure](../../linux-migration.md).

## Completed implementation and gate matrix

This matrix replaces the original unchecked task lists. “Passed” describes the
named tests on the supported disposable VM or local model; it does not extend
the result to every application, kernel, crash instruction or live host.
Paths below are relative to the repository root.

| Original phase | Implemented result and passing evidence | Boundary or superseded work |
|---|---|---|
| 1. Classification before socket use | `classifier.bpf.c`, shared policy code and the native loader attach the exact `lsm_cgroup/socket_post_create` hook. `test_classifier.sh` proves first-socket marks/denials, cgroup composition checks, unrelated mark preservation, immediate TCP/UDP traffic, concurrency, rename/replacement/alias semantics, static/dynamic ELF and independent helper enrollment. System/user service and host-root private-mount fixtures pass. `test_preemption.py` reproduces the old shared-scratch race and verifies the corrected selected/unlisted socket and resolver behavior under forced same-CPU preemption. | The proposed two-hook handoff was unnecessary and was not implemented. No asynchronous watcher substitutes for classification. Normal loader exit preserves pins; SIGKILL between every native pin publication is not proved. |
| 2. DNS and resolver isolation | `firewall.py`, `resolver_guard.bpf.c`, `test_dns_paths.py` and `test_resolver_ipc.py` prove automatic selected DNS, original response peers, identical-tuple conntrack separation, tunnel-loss blocking, IPC/cache aliases and inherited descriptor/splice restrictions. `test_resolver_integration.py` exercises actual distro nscd, Avahi and supported NSS fallback. Large EDNS/UDP and TCP fallback are covered by `test_packet_paths.py`. | Direct kernel DNS supersedes the proposed production dnsmasq UID, listener, unit and upstream-only mark. Existing mapped caches cannot be revoked; fresh exec succeeds, while old mapped state requires restart. Unsupported NSS/IPC integrations remain excluded. |
| 3. Configuration and ownership | Strict profile/settings/stored-key parsing, bounded native bulk policy loading, collision-aware allocation and exact resource receipts are implemented in `config.py`, `network.py`, `ownership.py` and the native boundary. Configuration/network/ownership/bulk tests cover malformed input, capacity, secret handling and foreign-resource preservation. Actual network acquisition, readback, repair and cleanup pass in `test_network_vm.py`. | `test_acquisition_failures.py` covers 52 modeled before/after boundaries: ten mutating prepare commands and sixteen receipt publications. Ambiguous outcomes retain resources; only proved receipts authorize rollback. This is not every native instruction or every possible process-crash interleaving. |
| 4. Guard, controller and recovery | `controller.py`, `preflight.py` and both systemd units load blocked policy first, require real marked DNS plus handshake readiness, verify owned state on recovery and retain enforcement on normal stop/controller death. Lifecycle tests cover pending edits, tampering, bounded locking and healthy restart without reblocking. Installed tests exercise real SIGKILL/restart, stop, underlay loss and recovery. | Restart uncertainty remains sticky when old application state was observed; PID snapshots cannot prove a whole fork lineage has ended. Application service dependencies are explicit; installation does not edit arbitrary bot units. |
| 5. Install and CLI | Isolated root-owned packaging, inactive installation, read-only planning/configured include listing, serialized include edits and exact disable/uninstall are implemented. `test_install_cli.py` and `test_acceptance.py` cover installed import isolation, units, real first-socket/DNS/IP behavior, retained private profiles and changed/foreign-file preservation. Healthy idempotent edits retain readiness after full validation. | `include list` reports configured keys, not live enforcement. Actual policy edits still guard/reverify. Explicit disable releases protection and never kills arbitrary application processes. |
| 6. Acceptance and CI | `tests/run-linux.sh` runs the unit/native checks and an explicitly marked disposable-VM suite; Windows checks remain in `tests/run.sh`. CI has unprivileged Linux/Windows jobs and an opt-in privileged VM job. Persistent TCP/UDP byte integrity, source identity and absence of per-packet executable lookup pass. `test_boot.py` separately passed two actual reboots with exact cleanup and baseline restoration. | A dependent early probe was denied before receiving its first socket; a deliberately failed guard prevented that dependent service from starting. This proves explicit guard ordering, not admission control over every possible boot process. Performance and compatibility qualifications below still apply. |
| 7. Documentation and publication | Linux operating/migration documentation, common-runtime enrollment guidance, strict examples, source/private-artifact checks and platform instructions are present. Implementation was published in scoped commits; this document records the final disposition of the original tasks. | Private profiles, live paths, keys, runtime receipts and validation logs remain outside Git. External review and TV deployment are not claimed. |

## Supported application and control contract

The tested platform is native Ubuntu 26.04/kernel 7.0 with systemd, cgroup v2,
BTF and effective BPF LSM. Required hooks must actually load; a version or
compiled kernel option alone is insufficient.

Common native applications and Python, Node, Java, .NET and shell workloads use
the same executable identity mechanism. Enroll the native runtime that creates
the socket and each independent network helper. A shared interpreter selects
all applications using that interpreter. A script/JAR/DLL pathname alone is
not an executable enrollment. Containers, changed roots, unsupported namespaces
and sandbox integrations are outside this scope; the native mechanism is not a
universal application-compatibility claim.

Bot agents can enroll their own paths later through the shared CLI; there is no
required repository-specific bot path or launcher. Preserve other agents'
entries and use the [enrollment guide](../../linux-agents.md) for runtime choice,
updates, restart boundaries and optional application-owned service ordering.

```text
wg-program-split validate --profile PATH --settings PATH
wg-program-split plan --profile PATH --settings PATH
wg-program-split install --profile PATH --settings PATH
wg-program-split activate
wg-program-split include list
wg-program-split include add ABSOLUTE_EXECUTABLE
wg-program-split include remove EXACT_STORED_KEY
wg-program-split status
wg-program-split check
wg-program-split disable
wg-program-split uninstall
```

Configured paths survive a temporarily missing/replaced file through exact
stored-key loading/removal. Symlinks are resolved on enrollment; linked renames
change subsequent socket selection, and atomic replacement preserves selection
for newly launched images. Existing sockets retain their marks. Old unlinked
images and uncertain path lookups fail explicitly rather than becoming direct.
Included IPv6/raw/packet sockets are refused; unlisted host IPv6 remains usable.
The shared per-CPU pathname buffer is protected by a short preemption-disabled
region through policy lookup; the executable reference is released afterward.
This preserves fresh per-operation resolution without a classification cache.

## Verification entry points and evidence limits

From the repository root:

```sh
./tests/run-linux.sh
./tests/run.sh
./tests/check-public-tree.sh
git diff --check
```

Only inside the explicitly provisioned disposable native VM, invoked by a
non-root account with a working systemd user manager:

```sh
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 ./tests/run-linux.sh --vm
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 ./tests/run-linux.sh --performance
python3 tests/linux/test_boot.py --help
```

The boot harness is a separate staged operation requiring host-side manifest
hash retention, two actual reboots and exact owned cleanup; `--help` does not
run it. VM fixtures require their marker and refuse TV/WSL. They preserve
pre-existing BPF attachments, routing/resolver state and unrelated resources.
Ignored `local/validation/` holds dated detailed evidence rather than private
live values in these documents.

Remaining verification qualifications:

- Native loader SIGKILL at each instruction between pin publications is not
  proved by normal loader exit, controller SIGKILL or the modeled acquisition
  failures. Those results must remain separate.
- Static/dynamic ELF, launch mechanisms and independent helpers are verified;
  every language library, desktop application and networking API is not.
  Application-owned encrypted DNS follows selected payload routing, but a
  dedicated DoH/DoT/DoQ client compatibility matrix was not completed.
- Source-bound/loopback DNS and large responses are verified. Arbitrary
  `SO_BINDTODEVICE`, reverse-path-filter settings and MTU combinations are not
  a completed compatibility matrix.
- [Linux overhead measurements](../../linux-performance.md) records the rejected
  run, correctness regression and fair-comparison method/results. The comparison
  baseline includes the same scratch correctness fix as the candidate; faulty
  classification cannot count as faster successful work. Only completed,
  error-free measurements support numerical claims. The user's target is ideally less
  than 1 ms of added **local p99** latency with minimal CPU/memory cost; this is
  neither zero overhead nor a total VPN/Internet round-trip guarantee. Target
  application deadline tails and compute under representative load remain
  deployment gates, not conclusions from VM microbenchmarks.

## Separate TV deployment gates — not completed

Repository acceptance did not change TV. Before any live cutover:

- [ ] Refresh the actual VPN/repair-daemon, DNS, LSM, systemd, Tailscale,
  protected-capture and local-service inventory; prepare exact rollback.
- [ ] Coordinate the BPF-LSM boot change, preserve existing security-module
  order and verify effective hooks after reboot. Do not infer enabled BPF LSM
  from a compiled option or the disposable VM's result.
- [ ] Retire only the confirmed old VPN ownership and repair responsibility,
  preserving LAN/Tailscale duties and protected captures. Never overlap tunnels
  using the same provider identity.
- [ ] Verify harmless included/unlisted TCP/UDP and DNS paths, failure behavior,
  router/default-route restoration and intended Tailscale DNS. Router upstream
  DoH needs separate router evidence.
- [ ] Verify service continuity and guard boot ordering on TV. Application
  agents subsequently enroll their own runtimes/helpers and verify their real
  workloads; there is no mandatory specific bot enrollment for this reusable
  implementation.
- [ ] Measure added local latency, throughput and compute on target hardware
  under representative application load; retain dated evidence and any
  unresolved regressions. VM correctness is not TV performance acceptance.
