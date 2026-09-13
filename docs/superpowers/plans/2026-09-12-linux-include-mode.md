# Automatic Linux Include Mode Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` task by task.
> Read the linked design first, preserve the current branch and verify
> every phase. A completed peer assessment is pending.

**Goal:** Automatically route included executable paths' new connections
and ordinary DNS through WireGuard, regardless of their launch method.

**Architecture:** Synchronous kernel executable-path classification and
socket marking select an owned VPN routing table. Included DNS is
translated to a private tunnel-only forwarder before the host resolver.

**Tech Stack:** C eBPF, native C++/libbpf loader, Python standard library,
WireGuard/iproute2/nftables, private dnsmasq-base instance, systemd.

**Spec:** [Automatic executable-path design](../specs/2026-09-12-linux-include-mode-design.md).

**Status:** Proposed plan awaiting completed peer review. Kernel and DNS
proof gates precede productization. No runtime proof, implementation or
joint review acceptance is claimed at this stage.

## Global constraints

- First validation target: native Ubuntu 26.04, kernel 7.0, cgroup v2,
  kernel BTF and BPF LSM enabled. Verify exact helper/attachment support.
- Include full native executable paths automatically. No wrapper/UID/name
  substitution and no asynchronous first-packet classification claim.
- Initial payload: IPv4 TCP/UDP. Block included IPv6; leave host IPv6 alone.
- Helpers need their own paths. Reject script-only and unsupported
  container/namespace enrollment. Already-running selected programs need
  restart after activation/enrollment, including retained resolver state.
- Keep unlisted host routing and resolver configuration effective.
- Own specific interfaces, routing rules, nftables tables, BPF links,
  services and listeners. Never flush/replace unrelated networking.
- Keep profiles, keys, actual paths/users, private audits and logs out of Git.
- Target 500 lines per source/test file; phases touch at most five files.
- All source paths, interfaces and commands below describe planned work.
  They are not available commands or passing tests in the current repo.

## Phase 1: Prove full-path classification before first socket use

**Create:**

- `src/linux/bpf/classifier.bpf.c`: provisional LSM path/mark program.
- `src/linux/native/bpf-loader.cpp`: libbpf loading, map update and attachment.
- `scripts/build-linux.sh`: reproducible BPF/native build under `build/linux/`.
- `tests/linux/probe_socket.c`: immediate TCP/UDP and identity fixtures.
- `tests/linux/test_classifier.sh`: disposable-VM classification gate.

Build only in a disposable VM with matching kernel and security settings.
Record verifier output and active hooks. A successful compile is not a
successful attachment, and an attached program is not traffic proof.

- [ ] Build a minimal `lsm_cgroup/socket_post_create` program using the
  actual executable-file/path kfuncs and `bpf_setsockopt(SO_MARK)`. Use a
  configured pathname map and release acquired file references on every
  return path. Do not write directly into arbitrary kernel socket fields.
- [ ] Prove it loads and marks the first socket before userspace receives
  it. Check cgroup-LSM allow/deny return semantics, competing attachments
  and preservation of unrelated mark bits. Start in a test-owned cgroup,
  then verify root-cgroup descendant coverage on the disposable VM.
- [ ] If that combined hook is rejected, test the design's synchronous
  LSM-create to cgroup-socket-create handoff. Do not add a userspace exec
  watcher as an undeclared replacement. If neither works, stop this plan
  and revise the design with the reviewer.
- [ ] Run identical probe bytes under two different absolute paths;
  include only one. Launch through shell, system and user services and
  cron-compatible direct exec. Immediate first TCP/UDP traffic must have
  the right class every time, including concurrent short-lived processes.
- [ ] Include a service with `PrivateTmp=yes` that retains the host root.
  Reject unsupported filesystem-root/network-namespace contexts rather
  than matching an unrelated container's identical pathname. Inject
  pathname lookup errors/truncation and require explicit socket errors,
  never direct fallback; check ordinary unlisted sockets remain healthy.
- [ ] Replace the included binary atomically at its configured path:
  newly launched copies remain included without updating an inode map;
  new sockets from the old unlinked image must error until restart.
  Deleted/synthetic paths never become known-unlisted through a map miss.
  Test actual file/dentry state and genuine filenames ending in
  ` (deleted)`; do not strip a textual suffix and assume identity.
- [ ] Assert that a still-linked rename changes the canonical path used
  for subsequent sockets. Enrolling the destination before the move keeps
  inclusion; moving to an unlisted destination makes new sockets direct.
  Existing socket marks retain their class. Test symlink canonicalization,
  distinct hard links, multiple threads, helpers and policy changes.
  Reject unsupported script/namespace cases with an explicit reason.
- [ ] Inspect loader-crash behavior and pin/link ownership. Record kernel,
  effective LSMs, helper/attach results and packet/classification evidence
  under ignored `local/validation/`. Commit only source/tests after the
  gate passes; never claim the full feature is implemented at this phase.

Representative fixture behavior, implemented by `probe_socket.c`:

```text
probe_socket tcp HOST PORT       # connect as its first network operation
probe_socket udp HOST PORT       # send without a preceding UDP connect
probe_socket udp-connected HOST PORT
probe_socket identity           # executable, UID, namespaces and socket mark
```

The fixture reports observed socket marks/peer tuples and uses bounded
I/O. Test keys and addresses belong to the disposable fixture, not TV.

## Phase 2: Prove DNS translation and IPC isolation

**Create:**

- `src/linux/bpf/resolver_guard.bpf.c`: selected-process resolver IPC/cache guards.
- `src/linux/wg_program_split/dns.py`: private dnsmasq configuration renderer.
- `src/linux/wg_program_split/firewall.py`: owned mark/DNS rules renderer.
- `tests/linux/test_dns_paths.py`: controlled responders and lookup clients.
- `tests/linux/test_resolver_ipc.py`: cache, Varlink, D-Bus and alias fixtures.

Consume the classifier ABI from phase 1. The policy distinguishes direct,
included-application and internal DNS-forwarder sockets. The internal
class uses the dedicated service UID and executable identity together;
other instances of the same dnsmasq executable remain direct.

- [ ] Start a private dnsmasq listener on an unused loopback port with one
  numeric VPN DNS upstream and no default config/resolv/hosts files.
  Syntax-check with `dnsmasq --test` against the generated config.
- [ ] Translate marked application UDP/TCP destination port 53 in the
  output NAT path before host resolver delivery. Exclude the internal
  upstream mark. Preserve original peer tuples through conntrack.
- [ ] Prove queries addressed to both the loopback stub and a nonloopback
  DNS address work, including connected UDP, TCP, truncation/fallback,
  EDNS and large responses. Verify source addresses, reverse translation
  and packet counters; never enable global `route_localnet` to conceal
  an unproven design problem.
- [ ] Enforce DNS-forwarder egress only to profile DNS through `wgps0`,
  including worker children and its first upstream socket. Removing the
  tunnel or killing dnsmasq must not send a query to the host resolver.
- [ ] Add LSM restrictions for selected applications' resolved/nscd/Avahi
  IPC, system/user buses and shared hosts-cache files. Test aliases,
  alternate path references and sockets created after guard activation.
  Preserve prior LSM denies and unlisted applications' access.
- [ ] Test the reference `hosts: files mdns4_minimal [NOTFOUND=return] dns`
  arrangement and `files dns`. Unsupported NSS backends fail preflight.
  Do not claim `nss-resolve` compatibility unless a test demonstrates
  successful included DNS and zero host-daemon lookup activity.
- [ ] Warm host caches, then start fresh included/unlisted fixtures and
  query the same unique and repeated names concurrently. Give the two DNS
  responders different answers and require their per-query ledgers to
  show exact origin separation. Capture network destinations as well.
- [ ] Separately enroll an already-running fixture that mapped the shared
  hosts cache before policy activation. New access guards cannot revoke
  its mapping: require an explicit restart-needed result, then verify DNS
  separation after restart. Include inherited mappings in descendants;
  zero open network sockets must not imply per-application DNS readiness.
- [ ] Stop if DNS or IPC protection is not demonstrable; do not continue
  by redirecting all host DNS or weakening origin classification.
  Review the evidence and commit the scoped phase after it passes.

## Phase 3: Validate profiles, configuration and routing ownership

**Create:**

- `src/linux/wg_program_split/__init__.py`: package marker with private internals.
- `src/linux/wg_program_split/config.py`: strict JSON and WireGuard validation.
- `src/linux/wg_program_split/network.py`: explicit route/WireGuard operations.
- `src/linux/wg_program_split/ownership.py`: serialized acquisition/rollback.
- `tests/linux/test_config_network.py`: validation and injected failures.

Private interfaces: `parse_profile(text: str) -> Profile`,
`parse_settings(text: str) -> Settings`,
`network_plan(profile: Profile, allocation: Allocation) -> list[Operation]`.
`Operation` keeps secret stdin/file-descriptor input separate from its
argument vector. No privileged command uses a shell.

Proposed settings shape:

```json
{
  "schema_version": 1,
  "included_executables": [],
  "dns_listen_port": 53053
}
```

Runtime allocation records the owned mark mask/classes, routing table,
rule priorities, firewall table, listener, service UID and BPF object IDs.
These are selected after collision checks; do not repurpose Tailscale or
another VPN's marks, priorities or tables.

- [ ] Reject duplicate/unknown profile or JSON fields, invalid key sizes,
  unsafe resolver addresses, IPv6, endpoint hostnames, multiple peers,
  partial AllowedIPs, `Table`, `FwMark`, hooks and `SaveConfig`.
  Test errors and repr for secret redaction. Generate fake keys in tests.
- [ ] Canonicalize included paths and validate native ELF input without
  executing it. Report helper/script and namespace limitations. Match
  source-address/MTU/profile changes to required restart behavior.
- [ ] Generate only owned route additions: marked traffic table with a
  terminal unreachable/blackhole fallback and the WG preferred route;
  separate encrypted transport behavior. Keep the host local/default
  rules effective. Decide any necessary mark-scoped source NAT only from
  the passing phase-2 packet evidence.
- [ ] Record acquisitions incrementally with boot ID, interface identity,
  rule/table specification, BPF link/map IDs, file hashes and process
  ownership. Lock mutations and reject foreign or ambiguous resources.
- [ ] Inject failure after each resource acquisition. Roll back only
  resources proved to belong to the current attempt. A same-name object
  after a crash is not sufficient evidence for deletion.
- [ ] Run `PYTHONPATH=src/linux python3 -m unittest discover -s tests/linux -p 'test_config_network.py' -v`.
  Confirm failures originate from missing/new behavior, implement the
  minimum satisfying code, then rerun and commit the verified phase.

## Phase 4: Early guard, controller and recovery

**Create:**

- `src/linux/wg_program_split/controller.py`: activation/recovery state machine.
- `src/linux/systemd/wg-program-split-guard.service`: early pinned protection.
- `src/linux/systemd/wg-program-split.service`: networking controller.
- `src/linux/systemd/wg-program-split-dns.service`: private DNS instance.
- `tests/linux/test_lifecycle.py`: staged and real systemd lifecycle cases.

The state machine has `blocked`, `preparing`, `ready` and `degraded`
protection states. Missing policy is not equivalent to direct authorization.
Atomically publish a complete policy generation; pin the active objects.

- [ ] Order guard loading ahead of ordinary host network/app startup,
  without creating systemd dependency cycles or disabling the host's
  security services. Generate and validate complete units using
  `systemd-analyze verify` on the supported VM.
- [ ] Load included-path protection in blocking state first. Install
  routing/firewall state, configure WG and launch the restricted DNS
  forwarder, then probe both tunnel and forwarded DNS before readiness.
- [ ] Keep pinned links/maps and fail-closed rules across controller exit,
  management-service stop and network failure. Recovery verifies real
  owned state before reuse. Distinguish connectivity failure from lost
  protection and never advertise one as the other.
- [ ] Preserve unlisted DNS, routes and existing cgroup BPF programs while
  faulting every startup/recovery phase. Test early-boot immediate-connect
  fixtures, interface deletion, existing sockets and retained resolver
  state at activation. Track affected processes independently of socket
  inventories and keep restart requirements across controller recovery.
- [ ] Identify the actual deployment bot's ordering needs so it cannot
  start before the guard. Runtime automatic inclusion must still work
  from all normal launch methods; do not require a wrapper to hide a
  missing classifier. No bot-unit edits occur during reusable install.
- [ ] Verify complete cleanup of fixture services/cgroups and listeners,
  review observed boot/stop/restart behavior and commit.

## Phase 5: Install, control CLI and reversible removal

**Create:**

- `src/linux/wg_program_split/cli.py`: command dispatcher.
- `src/linux/wg_program_split/install.py`: trusted install/update/removal.
- `scripts/wg-program-split`: installed isolated Python entrypoint.
- `config/linux-settings.example.json`: generic settings example.
- `tests/linux/test_install_cli.py`: staging-root install and exact ownership.

Proposed CLI, all commands still unavailable in the current source:

```text
wg-program-split validate --profile PATH --settings PATH
wg-program-split plan --profile PATH --settings PATH
wg-program-split install --profile PATH --settings PATH
wg-program-split include add ABSOLUTE_EXECUTABLE
wg-program-split include remove ABSOLUTE_EXECUTABLE
wg-program-split status
wg-program-split check
wg-program-split disable
wg-program-split uninstall
```

There is deliberately no required `run` command: programs start normally.
`disable` explicitly releases routing protection and reports affected
applications/connections. `uninstall` retains private profiles and modified
files by default. Neither operation kills arbitrary matching processes.

- [ ] Package Python in a root-owned zipapp and invoke it with
  `/usr/bin/python3 -I`. Test caller-directory/PYTHONPATH injection.
  Load BPF only through the installed native loader and exact owned pins.
- [ ] Install private config under `/etc/wg-program-split/`, transient
  state under `/run/wg-program-split/`, and the BPF pins under an owned
  bpffs subtree. Validate parent permissions and symlink handling.
- [ ] Install the private service account and units without activating
  another VPN, changing kernel boot options or converting applications.
  Refuse unsupported effective BPF-LSM state with a precise preflight
  result, not a promise based on `CONFIG_BPF_LSM=y` alone.
- [ ] Ensure `plan` does not mutate network state. Never print private
  keys, raw profiles, credentials or secret-bearing subprocess arguments.
- [ ] Stage include-list changes atomically; preserve policy generation
  and pinned protection on errors. Report already-running selected
  programs needing restart for connections or retained resolver state.
- [ ] Remove only exact owned rules/pins/interfaces/units/files. Retain
  foreign or locally edited resources and report any remaining listeners.
  Run staging-root tests, full unit tests and the kernel/DNS gates; commit.

## Phase 6: End-to-end acceptance and CI

**Create:** `tests/run-linux.sh`, `tests/linux/test_acceptance.py`,
`tests/linux/fixtures.py`. **Modify:** `.github/workflows/ci.yml`,
`tests/check-public-tree.sh`.

- [ ] Build a controlled WireGuard peer, direct and VPN DNS responders,
  TCP/UDP endpoints and warm-cache/IPC fixtures inside a disposable VM.
  Use ephemeral keys and test-owned `/run` storage, not production data.
- [ ] Exercise every normal launch method, same-name/different-path
  executables, replacements, helpers, children, static/dynamic binaries,
  first-packet concurrency and explicitly unsupported cases.
- [ ] Verify TCP/UDP exits and DNS UDP/TCP destinations independently;
  include application-owned DoH as VPN payload, IPv6 attempts, MTU,
  VPN/DNS failure, loader death, rollback and real reboot ordering.
- [ ] Measure unlisted new-connection latency and sustained throughput.
  Require kernel forwarding for established payload; document measured
  overhead and any regression rather than assuming it is zero.
- [ ] Assert pre/post host resolver/default route invariants and inventory
  owned additions separately from pre-existing firewall/BPF objects.
  Drain only test-owned processes, ports, mounts, links and artifacts.
- [ ] Add unprivileged and explicitly privileged Linux jobs; retain Windows
  CI. A missing kernel/LSM capability is a reported failure for the
  privileged acceptance job, not a silently skipped pass.
- [ ] Extend source/private-artifact checks to Linux/Python/BPF files.
  Run both platform suites and `git diff --check`, then commit.

## Phase 7: User documentation and publication

**Modify:** `README.md`, `CONTRIBUTING.md`, `.gitignore`.
**Create:** `docs/linux.md`, `docs/linux-migration.md`.

- [ ] Document tested kernel requirements, BPF LSM enablement, automatic
  path semantics including rename/replacement behavior, helpers/scripts,
  DNS APIs, connection and resolver-state restart boundaries,
  pinned fail-closed behavior, localhost/LAN behavior and removal.
- [ ] Explain that kernel enablement and retirement of an old full tunnel
  are separate operator-specific migration operations. Give an audit and
  rollback sequence; never ship machine-specific boot settings/endpoints.
- [ ] Keep examples aligned with the parser and code. Ignore build/Python
  caches, profiles, captures and runtime receipts. Keep Windows scope and
  limitations accurate while linking the tested Linux implementation.
- [ ] Run `./tests/run.sh`, `./tests/run-linux.sh`, the documented disposable
  VM acceptance command, `./tests/check-public-tree.sh` and
  `git diff --check`. Record exact pass/fail/blocker evidence.
- [ ] Inspect status and staged diff, commit and push only scoped work on
  the current branch. Do not force-push or overwrite concurrent work.

## TV deployment acceptance after implementation

This phase changes a live host and remains separate from repository work.

- [ ] Verify the effective active VPN, DNS, BPF/LSM, systemd, Tailscale,
  protected captures, bot path/launch and local metrics dependencies.
- [ ] Prepare/review a concrete BPF-LSM boot change preserving the existing
  security-module order. Reboot only in a coordinated maintenance window;
  verify actual hooks afterward before claiming compatibility.
- [ ] Prepare rollback for the old VPN and its repair daemon. Disable only
  the daemon's VPN management, keep its LAN/Tailscale duties, and retire
  the old tunnel through its confirmed owner. Preserve credentials.
- [ ] Never overlap old/new tunnels using the same provider identity.
  Do not stop protected captures or inspect their outcomes for this task.
- [ ] Verify direct DNS/IP use the router and intended Tailscale DNS still
  works. Independently verify router upstream DoH if that claim is made.
- [ ] Run harmless included/unlisted probes first; prove no direct fallback
  and no DNS crossovers. Enroll the real bot only after these pass.
- [ ] Verify effective bot behavior, existing service continuity, LAN and
  Tailscale access, and boot persistence. Preserve dated local evidence
  and report any verification not actually performed.
