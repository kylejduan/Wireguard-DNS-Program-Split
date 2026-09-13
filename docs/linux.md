# Linux executable include mode

This implementation automatically routes selected executable paths through kernel
WireGuard. It is experimental: the native VM proofs cover the mechanisms below;
TV installation, its boot configuration and bot latency require separate acceptance.
The Windows implementation and its installation commands remain separate.

| Traffic from a supported executable | Included path | Unlisted path |
|---|---|---|
| New IPv4 TCP/UDP sockets | WireGuard | Existing host route |
| Ordinary UDP/TCP DNS on port 53 | Profile DNS through WireGuard | Existing resolver path |
| Application-owned DoH/DoT/DoQ | Application's provider, over WireGuard | Application's existing behavior |
| IPv6 and raw/packet sockets | Refused | Existing host behavior |
| Ordinary IPv4 localhost traffic | Localhost | Localhost |

The program does not configure the router or verify its upstream Cloudflare DoH.
Leaving host DNS unchanged preserves whatever router/resolver configuration is
already effective. There is no exclude mode or automatic LAN/Tailscale exception
for included remote traffic.

## Mechanism and cost

A BPF LSM program resolves the current executable's complete canonical path when
the kernel creates a socket. It sets the selected socket's routing mark before
userspace receives the socket. Exact path matching is synchronous; there is no
process polling window, wrapper, process-name match, UID substitution or cached
classification shared between sockets.
The temporary per-CPU pathname buffer is protected against task preemption
through resolution and lookup; executable references are released afterward.
The [forced-preemption regression](linux-performance.md#correctness-prerequisite)
records the early implementation defect and verifies the correction.

An owned routing table and nftables rules steer selected traffic through
WireGuard. Port-53 DNS uses kernel destination/source translation, preserving the
original peer tuple. A separate conntrack zone prevents included and unlisted
queries with identical tuples from sharing a NAT decision. The implementation
enables `route_localnet` only on its own WireGuard interface and limits incoming
loopback-addressed replies. Established payload forwarding stays in the kernel;
there is no userspace packet queue or DNS forwarder service.

Resolver guards prevent included processes from using supported host resolver
IPC and shared nscd hosts-cache files. These guards also cover inherited/received
file descriptors, Unix stream `splice`, endpoint aliases and late standard
endpoints. Ordinary IP sends and ordinary file operations do not repeat the
guard's executable-path lookup. The controller checks health every five seconds;
successful health checks do not briefly block new sockets.

The optimized controller shares a coherent guard snapshot and reads the owned
WireGuard interface once per network observation. Ordinary-file and IP resolver
guard paths reject irrelevant objects with fewer helper calls. Path identity,
ownership verification, real DNS probes and the five-second health interval are
retained.

The target is added local p99 overhead below 1 ms where practical, with minimal
CPU cost. See the [performance comparison](linux-performance.md) for the controlled
three-condition experiment, uncertainty and reproduction command. It measures
the running controller alongside concurrent included and unlisted workloads.
There is no zero-overhead, worst-case delay or Internet RTT guarantee. TV
release-build bot measurements remain necessary before deployment.

## Supported host and applications

The initial native target is Ubuntu 26.04 with kernel 7.0, unified cgroup v2,
kernel BTF and **active** BPF LSM. A build configuration containing
`CONFIG_BPF_LSM=y` alone is insufficient. The loader verifies the actual helpers,
attachments, initial namespaces and pinned objects. WSL, containers and changed
filesystem roots are outside the supported host enrollment context. A private
mount namespace retaining the host root, such as `PrivateTmp=yes`, is covered.

Enroll a native ELF executable, using its absolute path. Symlinks are resolved
when enrolled. Scripts run under their interpreter: enrolling Python includes
other programs using that same interpreter path. A distinct interpreter copy or
native application is needed for finer separation. Helper executables need their
own entries. There is no promise of compatibility with every application, NSS
module, sandbox, privileged networking API or externally supplied socket.

Replacing an executable atomically at the enrolled path preserves inclusion for
new copies. New sockets from the old unlinked image are refused until restart.
Renaming a still-linked image changes the path used for subsequent sockets;
enroll the destination before moving it if inclusion must continue. Existing
socket marks do not change. Unresolvable, synthetic or unlinked executable
identities are refused rather than guessed to be unlisted.

Host resolver IPC restrictions can affect applications that require the system
or user bus for other features. Selected custom endpoints named `bus` at a tmpfs
filesystem root are also restricted. Unsupported NSS arrangements fail host
preflight. Actual `files dns` and `files mdns4_minimal [NOTFOUND=return] dns`
fallbacks have been tested with the distro's nscd and Avahi implementations.
Application-owned encrypted DNS keeps the application's chosen
provider; this implementation does not rewrite encrypted DNS content.

## Build and install

Build on the supported native kernel or a matching disposable VM. Dependencies
include a C/C++ compiler, Clang with the BPF target, `bpftool`, `pkg-config`,
libbpf/libelf development files, Python 3, `wg`, `ip`, `nft`, `conntrack`,
legacy iptables inventory tools and systemd. The x86-64 proof VM used Clang 21 and
libbpf 1.6.3. No third-party binaries or provider credentials are distributed.

```sh
./scripts/build-linux.sh
./tests/run-linux.sh
```

Use a WireGuard profile with one IPv4 `Address`, one numeric IPv4 `DNS`, and one
peer with `AllowedIPs = 0.0.0.0/0` and a numeric IPv4 endpoint. Optional fields are
MTU, preshared key and persistent keepalive. Hooks, commands, multiple peers,
IPv6 routes, duplicate fields and arbitrary wg-quick settings are rejected.
Defaults are MTU 1420 and keepalive 0 (disabled). Activation requires MTU no larger
than the observed underlay/path MTU minus 80 bytes; lower it for smaller links.
Profiles are limited to 65,536 UTF-8 bytes. Policy supports up to 1,024 paths,
each at most 4,095 filesystem bytes; bulk loading uses bounded binary stdin.
Existing foreign full-tunnel routing must first be retired by its owner.

Start with the empty list in `config/linux-settings.example.json`. `validate`
and `plan` read inputs without changing live networking:

```sh
python3 -I build/linux/wg-program-split.pyz validate --profile /path/to/provider.conf --settings config/linux-settings.example.json
python3 -I build/linux/wg-program-split.pyz plan --profile /path/to/provider.conf --settings config/linux-settings.example.json
sudo python3 -I build/linux/wg-program-split.pyz install --artifacts build/linux --profile /path/to/provider.conf --settings config/linux-settings.example.json
```

Installation copies a root-owned isolated Python application, native loader,
BPF object and two service units. Private configuration lives in
`/etc/wg-program-split` with mode 0700 and files with mode 0600. Installation does
not activate the VPN, alter kernel boot options or convert application services.
It refuses to overwrite existing installation files. The current update path is
explicit disable/uninstall followed by installation; retained configuration must
match the supplied input.

## Operate

Stop an application and its children before enrolling it for the first time,
then start it normally after activation. The executable is automatically included
regardless of its normal launcher or system/user service.

```sh
sudo wg-program-split include add /absolute/path/to/native-program
sudo wg-program-split include list
sudo wg-program-split activate
sudo wg-program-split status
sudo wg-program-split check
sudo wg-program-split include remove /exact/stored/canonical/path
```

`activate` enables and starts the early guard and controller units. Kernel guards
are attached in blocking state before networking is prepared. A real marked DNS
query and a recent observed WireGuard handshake are required before ready state.
Profile changes require explicit disable/reactivation. Include edits use a
durable pending operation and exact-key readback; deleting an entry still works
after its file disappears or becomes a symlink. There is no bulk live reload.

`include list` reads configured canonical paths without activating protection;
use `check` for actual readiness. Repeating an already-effective inclusion or
removing an absent key checks health without deliberately blocking healthy new
sockets. Healthy controller restart likewise verifies and retains ready state.
New enrollments and uncertain recovery still establish blocking protection first.
See the [bot-agent workflow](linux-agents.md) for common language runtimes,
helper enrollment, concurrent agents and application service dependencies.

Already-open sockets and pre-existing mapped resolver caches cannot be revoked
by enrollment. Status lists up to 1,024 observed processes needing restart (with an 8-MiB
diagnostic bound) and records an
unresolved restart boundary for the boot lifetime: a missed fork can retain old
state after the observed parent exits. An empty later PID list does not prove
that boundary is closed. `enforcement_state=ready` describes new covered traffic;
`protection_verified=false` remains explicit for unresolved application state.
For a clean result, establish the guard before the affected application tree
starts. The program never kills arbitrary matching processes.

Normal controller exit, service stop and controller restart retain pinned guards,
firewall and terminal fallback routing. Tunnel/underlay failure does not authorize
direct fallback. Checks can repair a missing owned preferred route or deleted
WireGuard interface while their exact firewall/fallback/rule/zone anchors remain
intact. Foreign replacements, missing safety anchors and ambiguous interrupted
acquisitions remain blocked/degraded for inspection.

The early unit orders guard loading before ordinary system startup. **Ordering
does not make a failed guard load stop host boot.** Active supported hooks are a
prerequisite. A deployment bot should additionally require and follow the guard
unit so a guard startup failure prevents that bot from starting. This service
dependency gates startup; it does not perform executable classification. A root
administrator or another network manager removing/replacing enforcement is
outside the ordinary tunnel/controller-loss guarantee.

```sh
sudo wg-program-split disable
sudo wg-program-split uninstall
```

Explicit disable stops/disables verified owned services and releases owned
networking before removing BPF pins. Removal preserves private profile/settings.
If an installed artifact was changed or replaced, uninstall defers artifact
deletion and retains a runnable command for a later retry. It reports the retained
paths; it does not overwrite or delete the replacement. Unproved runtime ownership
also stops cleanup. Read the error and inspect effective state before retrying.

## Development verification

`./tests/run-linux.sh` runs unprivileged configuration, ownership, lifecycle,
installer, native path/JSON and fixture checks. It does not attach BPF or change
host routing. `./tests/run.sh` remains the Windows suite. The Linux CI job uses
the supported Ubuntu 26.04 userspace and kernel UAPI headers.

Privileged tests are intentionally restricted to a separately provisioned native
disposable VM with active BPF LSM, the supported dependencies, root and the marker
`/var/lib/wgps-vm-provisioned`. They refuse TV and WSL. Never create the marker on
a production machine to bypass this boundary. Invoke through `sudo` from a
non-root account with an active systemd user manager and `/run/user/<uid>`; the
suite proves inclusion through that account's real user service. CI runners need
the same account/session setup. These prerequisites are checked before fixtures
change networking.

The resolver acceptance tests additionally require the distribution's `nscd`,
`libnss-mdns`, `avahi-daemon` and `strace`; the DNS comparison requires
`dnsmasq-base`. These are test dependencies, not added runtime services.

```sh
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 ./tests/run-linux.sh --vm
sudo env WG_CLASSIFIER_DISPOSABLE_VM=1 ./tests/run-linux.sh --performance
```

The combined native suite covers real DNS origins, resolver caches, persistent
TCP/UDP, large EDNS/TCP fallback, tunnel/daemon failure, repair and installed
removal. A separate two-reboot proof verifies first-socket blocking and failure
of a dependent application to start when the guard fails. Reboots are deliberately
excluded from the ordinary CI command. On the same disposable VM, run
`python3 tests/linux/test_boot.py --help` for the staged protocol: an external
host records each checkpoint hash, requests each reboot and verifies the new
boot ID before continuing. The harness never reboots a machine itself.

The manual privileged CI job requires an operator-provisioned disposable runner
labelled `wgps-disposable-vm`; it is not run on untrusted pull requests. Missing
capabilities fail the requested privileged suite. Ignored `local/validation`
contains the local evidence, while test keys/configuration remain private.
