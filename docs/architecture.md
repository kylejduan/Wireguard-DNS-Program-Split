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
- `dns-dispatcher.exe` listens on loopback port 53. It owns a unique per-launch Microsoft-Windows-DNS-Client ETW session, resolves each event's process path, and binds the upstream query to either the physical or tunnel source address.
- A narrowly owned NRPT `.` rule sends ordinary Windows resolver queries to the dispatcher.
- `controller-service.exe` starts `Controller.ps1` as an automatic SYSTEM service, cooperates with ordered service stop, reports a controller ended by system shutdown as a clean stop, and lets Service Control Manager restart a failed controller.
- `Controller.ps1` owns startup, recovery, and 30-second tunnel plus end-to-end split-DNS health checks.
- `Tray.ps1`, running as the interactive user, changes the desired state, executable list, and profile.

## Route invariant

The physical default route must remain Windows' preferred default. The WireGuard adapter receives a deliberately losing default route with metric `9999`; the WFP bind redirect causes selected sockets to use the tunnel source address and therefore its route. The WireGuard endpoint receives an explicit physical `/32` route.

Because unlisted payload does not traverse a universal TUN or user-mode packet engine, direct-path throughput is limited by the normal Windows network stack rather than this project's classifier.

## DNS attribution

Windows commonly performs application DNS through the shared DNS Client service. The dispatcher therefore cannot classify the loopback packet's owner. It pairs the query with the DNS Client ETW event, whose process ID identifies the originating executable.

Attribution waits up to 500 ms. A selected hint chooses tunnel DNS; an attributed unlisted query chooses physical DNS. A query that repeats a name and type answered within the previous three seconds, with no newer attribution event, reuses that answer's route: this covers the Windows DNS Client's own retransmissions and TCP fallback, which raise no new event. Any other missing or inaccessible attribution is blocked with `SERVFAIL`. Responses have TTLs zeroed, and the controller temporarily caps the Windows positive cache at one second, reducing cross-process cache reuse.

Selected attribution takes precedence whenever it arrives before forwarding begins. DNS packets and ETW events do not share a transaction identifier, so delayed or simultaneous events for the same name and record type cannot always be paired uniquely. See [Limitations](limitations.md).

## Startup

The WireGuard tunnel and controller services use `Automatic` start. The controller waits for a physical IPv4 default route, adopts an early-started tunnel when available, and polls tunnel DNS until the first successful answer instead of sleeping for a fixed delay. It then enables and validates the dispatcher and NRPT path before starting dynamic WFP filters. Every 30 seconds the controller rechecks NRPT conflicts, executable and port ownership, ETW-backed loopback DNS, tunnel DNS, and the physical interface snapshot; repeated failure restarts the stack with fresh values.

The controller service reports running as soon as supervision starts, so Service Control Manager is not held pending on network readiness. On service stop it gives ordered cleanup up to four minutes to remove WFP filters before NRPT and the remaining stack, retrying incomplete cleanup for up to 150 seconds; a forced or failed stop is reported as a service failure. An interactive disable whose cleanup cannot complete is recorded in `last-error.txt` and retried with bounded backoff while the controller keeps supervising, because exiting would only make SCM restart it into the same failure. A tunnel service that stays in `StartPending` or `StopPending` cannot accept a stop control. A slow start is left running for the next repair attempt to adopt, but a host that has been starting for more than 90 seconds, or a stop that does not finish within 20 seconds, is reset by terminating only the owned `tunnel-host.exe`; the next repair then starts from a stopped service. System shutdown sends no stop control and leaves the stack in place for boot-time adoption; the host accepts the shutdown notification only so the controller's termination is not reported as a failure. On an unexpected controller exit, SCM restarts supervision while the last-known-good dispatcher and WFP hosts remain available for validation or repair.
