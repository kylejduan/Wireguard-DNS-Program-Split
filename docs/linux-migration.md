# Native Linux migration

Repository implementation and disposable-VM tests do not migrate TV. No live
TV networking, router settings, boot configuration or application services are
changed by this source release. Perform migration in a coordinated maintenance
window with a working management connection and a prepared rollback.

1. Read the current native host state: OS/kernel, effective LSMs, BTF/cgroup
   support, active VPN owner, routes/rules, nftables, DNS/NSS, Tailscale and the
   actual bot executable and service. Preserve protected captures and current
   credentials. A previous status file or public-IP check is not sufficient.
2. If BPF LSM is not active, prepare the host-specific boot change preserving the
   complete existing security-module order. Do not replace the LSM list with
   `bpf` alone. Keep a rollback boot entry; verify the effective LSM stack and
   actual hook loading after the coordinated reboot. Installation never edits
   the bootloader or reboots the host.
3. Identify any old full-tunnel service and repair daemon. Retire its VPN
   management through its confirmed owner while preserving unrelated LAN and
   Tailscale duties. Do not overlap two tunnels using the same provider identity.
   Keep the old profile/service configuration available for rollback.
4. Verify unlisted host IP routing and DNS now use the intended router. Verify
   the router's upstream DoH independently if Cloudflare DoH is a requirement.
   Host resolver state alone does not establish the router's upstream transport.
5. Build and validate the Linux artifacts and profile, then install with an
   empty include list. Activate and inspect effective resources. Enroll harmless
   native test programs first and prove included/unlisted IP exits and DNS
   origins separately, including tunnel loss and controller restart.
6. Stop the bot's full application tree before first enrollment. Enroll its
   native executable and required helpers. Add an application service dependency
   on `wg-program-split-guard.service` for startup-failure gating, then start the
   application normally. No VPN launcher is required. Check its local metrics,
   DNS APIs, remote connections, helper processes and restart-boundary status.
7. Measure release-build bot behavior on TV: connection/DNS tails, CPU, sustained
   payload throughput and actual deadline misses against the accepted baseline.
   VM microbenchmarks do not settle this gate. Verify real reboot ordering and
   guard-failure behavior before relying on unattended startup.

If acceptance fails, stop the affected application tree, explicitly disable the
new implementation, verify its exact owned resources are gone, and restore the
old VPN through its owner. Restore only changes made during this migration.
Do not flush host firewall/routing tables, remove foreign BPF attachments or
disable unrelated security services. Confirm the application's effective IP,
DNS and management connectivity after rollback.
