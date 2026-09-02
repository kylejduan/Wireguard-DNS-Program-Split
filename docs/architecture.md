# Architecture

## Data flow

```text
selected executable ── WFP bind redirect ── WireGuard adapter ── Internet
        │                                        │
        └─ Windows DNS ─ local dispatcher ─ profile DNS

unlisted executable ────────────────────── physical adapter ── Internet
        │                                        │
        └─ Windows DNS ─ local dispatcher ─ adapter/router DNS
```

## Components

- `tunnel-host.exe` exposes a compatible WireGuard tunnel DLL as a Windows service.
- `wfp-probe.exe` installs dynamic WFP filters for the exact executable paths in `included-apps.txt`. It supplies the tunnel IPv4 address to the signed PIA WFP callout.
- `dns-dispatcher.exe` listens on loopback port 53. It consumes Microsoft-Windows-DNS-Client ETW query events, resolves each event's process path, and binds the upstream query to either the physical or tunnel source address.
- A narrowly owned NRPT `.` rule sends ordinary Windows resolver queries to the dispatcher.
- `Controller.ps1`, running as SYSTEM, owns startup, recovery, and 30-second tunnel-DNS health checks.
- `Tray.ps1`, running as the interactive user, changes the desired state, executable list, and profile.

## Route invariant

The physical default route must remain Windows' preferred default. The WireGuard adapter receives a deliberately losing default route with metric `9999`; the WFP bind redirect causes selected sockets to use the tunnel source address and therefore its route. The WireGuard endpoint receives an explicit physical `/32` route.

Because unlisted payload does not traverse a universal TUN or user-mode packet engine, direct-path throughput is limited by the normal Windows network stack rather than this project's classifier.

## DNS attribution

Windows commonly performs application DNS through the shared DNS Client service. The dispatcher therefore cannot classify the loopback packet's owner. It pairs the query with the DNS Client ETW event, whose process ID identifies the originating executable.

Attribution waits up to 500 ms. A selected hint chooses tunnel DNS; an attributed unlisted query chooses physical DNS. Missing or inaccessible attribution is blocked with `SERVFAIL`. Responses have TTLs zeroed, and the controller temporarily caps the Windows positive cache at one second, reducing cross-process cache reuse.

Selected attribution takes precedence whenever it arrives before forwarding begins. DNS packets and ETW events do not share a transaction identifier, so delayed or simultaneous events for the same name and record type cannot always be paired uniquely. See [Limitations](limitations.md).

## Startup

The WireGuard tunnel service uses `Automatic` start so Service Control Manager can bring the adapter up early. The startup task then adopts that service, performs one successful tunnel-DNS gate, and enables the dispatcher, NRPT, and dynamic WFP filters. There is no fixed post-success soak. Every 30 seconds the controller also verifies that the physical interface, source address, and DNS resolver still match the dispatcher's startup snapshot; a change restarts the stack with fresh values.
