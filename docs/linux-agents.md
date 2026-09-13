# Enrolling applications on Linux

Bot agents can add their own applications to the shared include list. The host
operator installs and activates the VPN once; each agent manages only its own
executable paths through the CLI. Do not replace the entire settings file or
disable the shared VPN when one bot stops.

## Choose the executable that makes the connection

Selection follows the kernel's current native executable, independently of its
normal launch method. These common host application types use the same mechanism:

| Application | Path to enroll |
|---|---|
| Rust, Go, C or C++, static or dynamically linked | The built application executable |
| Python script or module | Its Python interpreter executable |
| Node.js JavaScript or TypeScript | Its Node executable, plus any separate network helpers |
| Java or Kotlin JAR/classes | The Java executable in its runtime installation |
| .NET | Its native apphost, or the `dotnet` executable when launched with `dotnet app.dll` |
| Other interpreters and language VMs | Their native ELF runtime executable, identified through `/proc/PID/exe` |
| Shell script | Each native command that performs networking; the shell too if it creates sockets itself |
| Application with subprocesses | Every distinct executable that needs VPN access |

Language source files, JARs and managed DLLs are not native executable identities.
Passing a script to `include add` is rejected instead of silently selecting the
system interpreter. A process's `/proc/PID/exe` link identifies the runtime to
enroll; inspect it during development, then stop that process tree before initial
enrollment. Do not use a process name, arguments, a PID or a service name as the
persistent selection key.

An interpreter shared by several applications selects **all of those applications**.
Use a dedicated runtime when only one bot should be included. For Python, create
the virtual environment with `python3 -m venv --copies /opt/bots/example/venv` and
verify its resolved interpreter is inside that environment. A normal symlinked
virtual environment can resolve to system Python. For other runtimes, use a
separate installation with its required libraries; copying only a Java or .NET
launcher may break its library lookup.

A child that forks without executing another image keeps the same executable
identity. After `exec`, the child's new executable is selected independently.
Enrolling a shell or parent application does not automatically include every
helper it launches. Inherited, already-open sockets keep their original marks.

## Agent workflow

1. Build/install the application and its dedicated runtime, if needed. Resolve
   their absolute paths. Stop this application's entire tree before its first
   enrollment, including any process retaining old sockets or resolver mappings.
2. Add each path using the privileged management CLI. Operations are serialized;
   concurrent agents retain one another's entries. Repeating an existing entry
   retains healthy readiness. Actual policy changes temporarily block new
   selected sockets while verification completes, so make them during deployment;
   established marked payload traffic continues.

   ```sh
   sudo wg-program-split include add /opt/bots/example/bin/order-bot
   sudo wg-program-split include add /opt/bots/example/bin/network-helper
   sudo wg-program-split include list
   sudo wg-program-split check
   ```

3. Inspect the JSON. `include list` reports the configured canonical keys;
   `check` verifies the actual guard, owned network, VPN DNS probe and handshake.
   Require `enforcement_state` to be `ready` before starting the application.
   Exit status zero by itself is insufficient: a completed check can report a
   degraded state. `protection_verified=false` or
   `restart_boundary_unresolved=true` requires attention before claiming full
   application protection.
4. Start the application normally. Verify its real IPv4 exit and ordinary DNS
   origin separately, and check required helper processes. Verify an unlisted
   application still uses the host's existing router IP and DNS. The CLI's
   readiness probe does not prove a particular application uses the expected
   runtime or DNS API.

Agents need their existing administrative authorization to manage enrollment;
the application itself does not need root or special capabilities. There is no
packet proxy or launcher to keep running. Do not add enrollment to every request
or connection: enroll during deployment, then let the kernel classify sockets.

For a system service, merge the following into an application-specific drop-in:

```ini
[Unit]
Requires=wg-program-split-guard.service
After=wg-program-split-guard.service
```

This prevents startup when the early guard fails. The guard can be blocking while
VPN connectivity is established; retain the application's normal connection
retry behavior. The dependency does not select the executable or prove network
readiness. Add the path before starting the service.

## Updates, removal and boundaries

Atomic replacement at the same canonical path keeps new instances included.
Restart old instances: an unlinked old executable cannot open new covered
sockets. For versioned release directories, add the new real path before launch
and remove the old stored key after its processes have stopped. Symlinks are
resolved when added; changing a `current` symlink does not enroll its new target.

```sh
sudo wg-program-split include remove /opt/bots/example/releases/old/order-bot
```

Removal uses the exact stored key even if the old file is gone. Removing one
application leaves other agents' entries intact. Existing sockets are not
reclassified by an add/remove operation. If enrollment encountered running
applications, an empty later restart list alone cannot clear the boot-lifetime
uncertainty; do not delete the journal to hide it.

The supported context is a native host with the initial network/user/PID
namespaces and filesystem root. Common language runtimes are covered through
their native executables; this is not a compatibility promise for every library
or application. Containers, changed roots and sandboxed networking require a
separate integration. Included traffic currently supports IPv4 TCP/UDP; IPv6
and raw/packet sockets are refused. Ordinary port-53 DNS uses the VPN profile's
resolver; application-owned encrypted DNS keeps its chosen provider over the
VPN. See the [operating limits](linux.md) and [host migration](linux-migration.md).
