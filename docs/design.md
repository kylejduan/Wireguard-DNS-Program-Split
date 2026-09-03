# WireGuard Program Split design

## Goal

On Windows 11, route all IPv4 TCP and UDP sockets created by an explicit list of executable paths through one WireGuard tunnel. Route ordinary Windows DNS for those executables to the DNS resolver supplied by that WireGuard profile. Leave every unlisted application's payload on the native Windows route and resolve its ordinary DNS through the DNS server configured on the active physical adapter.

## Architecture

- A standard WireGuard profile is imported into a DNS-free, `Table = off` working profile. Its IPv4 interface address and IPv4 DNS address are retained in local settings.
- A WireGuard tunnel service creates the adapter. A deliberately high-metric tunnel default route exists only as the route selected by per-process WFP binding; the physical default remains preferred globally.
- A signed PIA WFP callout driver and a small dynamic user-mode WFP session bind listed executables to the tunnel address. Unlisted payload never crosses a universal TUN or user-mode packet proxy.
- An NRPT catch-all sends ordinary Windows DNS to a loopback dispatcher. Windows DNS Client ETW events attribute requests to executable paths; the dispatcher forwards selected requests from the tunnel address to tunnel DNS and other requests from the physical address to the physical adapter's current DNS server.
- A SYSTEM controller owns recovery and health checks. An interactive tray owns the enable switch, profile import, and executable list.

## Fast startup

The WireGuard tunnel and controller services start automatically through the Windows Service Control Manager. The controller waits for a physical IPv4 default route without entering failure backoff, adopts a healthy early-started tunnel, polls a short tunnel-DNS probe until its first success instead of imposing a fixed delay, then enables and validates the dispatcher and NRPT path before dynamic WFP filters. Ongoing 30-second checks retry transient failures and verify the absence of an IPv6 default route, the real Windows DNS Client, ETW attribution, loopback dispatcher, physical resolver snapshot, NRPT ownership, and tunnel DNS.

The small native controller host exists because measured Task Scheduler startup added roughly 24 seconds on the reference machine. It adds no routing logic: it supplies SCM lifecycle, cooperative shutdown, and restart-on-failure around the existing PowerShell controller.

## Trust and security boundaries

- WireGuard private keys and machine-specific settings are local-only and must never enter Git history.
- Deployed runtime files live beneath a locked `C:\ProgramData\WireGuardProgramSplit` tree writable only by SYSTEM and Administrators.
- The public project does not redistribute WireGuard or PIA binaries. Installation requires separately obtained compatible WireGuard runtime DLLs and a signed PIA WFP callout package; signatures are checked before installation.
- WFP objects are dynamic and disappear if their host exits. The controller restores them, but a controller or host failure is fail-open for payload unless optional persistent firewall guards are added.
- Application-owned DoH, DoT, and DoQ bypass ordinary Windows DNS and are outside the DNS split. Browser secure-DNS policy can be disabled explicitly.
- The initial release is IPv4-only. Profiles containing IPv6 are rejected rather than partially routed.

## Public and local separation

- The GitHub repository contains source, tests, generic examples using documentation-only address ranges, and dependency instructions.
- `local/`, profiles, binaries, driver packages, logs, state, and generated settings are ignored.
- The configured operator copy may live in OneDrive, but boot-time execution never depends on OneDrive availability. Installation deploys a protected runtime copy to ProgramData.

## Acceptance

- Native binaries compile warning-free and their self-tests pass.
- PowerShell parses cleanly and profile import rejects missing required fields, non-IPv4 address/DNS values, and IPv6 profiles.
- Repository secret and identity scans are clean before every push.
- A selected browser reports the WireGuard exit and tunnel DNS; an unselected browser reports the physical ISP exit and router-provided DNS.
- Unselected multi-gigabit traffic remains on the physical path without a universal TUN penalty.
- Cold-boot logs measure boot-to-active time and prove the fixed 20-second soak is absent.
- Installer rollback and uninstaller restore NRPT, DNS-cache policy, the owned tray task, routes, services, and local processes they own.
