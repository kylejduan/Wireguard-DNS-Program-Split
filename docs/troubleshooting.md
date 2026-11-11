# Troubleshooting

## Start with state and logs

The tray's **Open logs** command opens `C:\Program Files\WireGuardProgramSplit\logs`. `controller.log` shows component order; `last-error.txt` records the latest activation failure.

Useful checks from elevated PowerShell:

```powershell
Get-Service 'WireGuardProgramSplitController', 'WireGuardTunnel$WireGuardSplit', 'PiaWFPCallout'
Get-ScheduledTask 'WireGuard Program Split Tray'
Get-DnsClientNrptPolicy -Effective
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'
```

## Browser says the proxy refused connections

This project does not configure an HTTP proxy. Clear any manual proxy setting left by an earlier tool, then restart the browser:

```powershell
netsh winhttp show proxy
```

Firefox also has its own proxy control under Settings → Network Settings; use **No proxy** or **Use system proxy settings** unless you intentionally operate another proxy.

## Selected application has the normal public IP

- Confirm its exact executable path appears in the tray list.
- Add helper or child executables separately.
- Fully terminate and relaunch the application; existing sockets are not migrated.
- Run `src\Invoke-WfpFilters.ps1 -Action Validate` from elevated PowerShell; it fails unless the persistent filters match the list and the PIA driver has registered its callouts. Check `controller.log` for a healthy stack.
- Confirm no other VPN is connected and no foreign catch-all NRPT policy exists.

## Selected applications cannot connect

While the project is enabled, selected applications are blocked whenever the tunnel or the stack is down: the payload filters persist through repairs, crashes and reboots by design. A refused connection reports an access-denied socket error (`WSAEACCES`, 10013). Check `controller.log` and `last-error.txt` for why the stack is not active; the tray's Disable restores direct access.

If the controller is gone or the installation is broken, inspect and remove the filters from elevated PowerShell:

```powershell
& 'C:\Program Files\WireGuardProgramSplit\bin\wfp-probe.exe' status
& 'C:\Program Files\WireGuardProgramSplit\bin\wfp-probe.exe' remove
```

`status` lists the objects the project provider owns, including boot-time copies; `remove` deletes all of them and is safe to repeat. Stop the controller service first: an enabled controller reinstalls missing filters at its next 30-second check. Removal reads neither the settings nor the application list, so it also works when they are missing or damaged. `Uninstall.ps1` does the same as part of its cleanup and keeps the installation in place if it cannot. If the installation directory was deleted by hand, run `remove` with a `wfp-probe.exe` from a fresh build. The Private Internet Access desktop client cannot add its own callout objects while these filters exist.

## DNS fails

- After changing Ethernet ports or switching between Ethernet and Wi-Fi, compare
  the active adapter address with the direct source in
  state/dns-dispatcher-loaded-inputs.txt. Only connected physical IPv4
  interfaces are eligible; a disconnected adapter's retained lower-metric
  default must not win. Among connected candidates, the route and interface
  metrics are added. The controller reloads changed DNS inputs in place without
  restarting the dispatcher or tunnel. If no connected physical default exists,
  repair is held and the dispatcher retains its last loaded inputs; DNS may
  fail until a usable uplink returns. The heartbeat fallback detects a missing
  dispatcher, not an unreachable upstream resolver.
- Existing installations must restart the controller to activate a changed
  Common.ps1 in its resident PowerShell process. Schedule a normal reboot or
  an approved service maintenance window; stopping the controller removes the
  filters, NRPT rule, and tunnel. Copying source alone does not activate it.
- Dispatcher maintenance must be able to signal its SYSTEM-owned reload event.
  Run that action as SYSTEM through trusted maintenance tooling. Administrator
  elevation alone can be insufficient. Access denial is reported before
  replacing a running dispatcher's inputs; do not loosen event permissions.
- Disable application-owned Secure DNS/DoH during testing.
- Confirm the profile had exactly one reachable IPv4 DNS address.
- Inspect `dns-dispatcher.log` for `TUNNEL`, `DIRECT`, `BLOCKED`, or `FAILED`.
- `(tunnel lane full)` means 128 tunnel upstream exchanges are already outstanding. The query fails closed; it does not fall back to direct DNS. Check tunnel-resolver connectivity if this persists.
- Lane refusals have at most one detailed line per second; `TUNNEL LANE REFUSED count=N` summarizes them. `WORKERS EXHAUSTED count=N` reports global admission refusals.
- HINT fields `identity=pending` and `resolve=...us` identify a lookup that exceeded the bounded image-resolution wait or could not get a resolver slot. `identity=none` means the image could not be identified. Both preserve the unknown-name quarantine; late resolution does not erase it.
- `LOG QUEUE DROPPED N` means diagnostic messages were lost because the bounded logging queue was full, received an oversized message or its writer was unavailable. This does not discard attribution state. Do not infer that every query was logged across such a gap.
- `(resolver 2)` on a `DIRECT` line means the first physical resolver did not answer and a later one did.
- `RELOADED generation=N` records an in-place reload, and `RELOAD REJECTED` a rejected one, after which the loaded inputs stay in use. `state\dns-dispatcher-status.txt` names the process and generation that published `state\dns-dispatcher-loaded-*` copies. `controller-service.log` records each dispatcher start and end, and an NRPT suspension or restoration; `state\nrpt-suspended` exists while the rule is suspended.
- `BLOCKED (no process hint)` means the dispatcher deliberately returned `SERVFAIL` because it could not safely attribute the query. A preceding `BARRIER INCOMPLETE` line means the ordering barrier did not complete within 500 ms, and `ETW FLUSH FAILED` that the session could not be flushed; both refuse rather than guess.
- `type`, `event-qpc`, `query-qpc`, and `qpc-frequency` fields support ordering diagnostics; do not treat them as a unique transaction ID.
- Ensure no other service owns `127.0.0.1:53`.

## Direct traffic is slower

Unlisted payload should not traverse the tunnel. Confirm the physical default route wins and the tunnel route remains metric `9999`. Compare the same server, browser, protocol, and time window; multi-gigabit browser tests are sensitive to CPU, server capacity, extensions, and HTTP implementation.

Also distinguish configured receive offloads from their operational state. From an
elevated Windows PowerShell session, the read-only diagnostic below reports the
process sample and RSC state without changing the installation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\WireGuardProgramSplit\src\Get-PerformanceState.ps1' -SampleSeconds 60
```

Wait about a minute after activation and check `ValidationWorkerPresentAtStart`;
a failed validation can dispose that worker. The process sample includes each
process's own kernel time, but does not measure system-wide driver/DPC/interrupt
work, work in other processes, or transient helpers. If `Get-NetAdapterRsc`
reports `WFPCompatibility`, RSC can be configured
enabled while remaining non-operational. Incompatible WFP callouts can suppress
receive coalescing and add TCP receive work even when traffic uses the physical
route. Other security/VPN providers may contribute; that state alone does not
identify the responsible driver or quantify the throughput impact. See
[Microsoft's RSC driver guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/programming-considerations-for-rsc-drivers).

To measure the active user-mode stack and owned filters, take paired samples of new
connections to fixed addresses, stop the split, repeat, and start it again. This
is not a complete kernel-driver bypass: stopping the controller leaves shared
drivers loaded. Record RSC's operational state in both phases and account for
other WFP providers before attributing a receive-performance difference.

- Windows: `Stop-Service WireGuardProgramSplitController` removes the persistent payload filters, the NRPT rule and `dns-dispatcher.exe`, and stops the tunnel service; `Start-Service` restores them. Confirm `bin\wfp-probe.exe status` reports `ABSENT` and that `dns-dispatcher`, the NRPT rule and the tunnel address are absent during the window.
- Linux: `wg-program-split disable` removes `wgps0`, the `wg_program_split` nftables table, the routing rule and the BPF pins; `wg-program-split activate` restores them. Unlisted traffic is untouched either way, so the only cost of the window is that enrolled programs lose the tunnel.

Selected applications can leave through the physical path while the split is
stopped. Close them or establish verified temporary outbound blocks before the
test, then remove those blocks only after the protected stack is restored.
Keep an elevated local console open with
`Start-Service WireGuardProgramSplitController` ready before stopping it, and do
not use service-off as a workaround.

A paired run on both reference hosts on September 17, 2026 measured TCP handshake latency to three fixed public addresses, about 130 to 190 samples per phase:

| Phase | Median | p90 | Max | Samples at or above 100 ms |
|---|---:|---:|---:|---:|
| Linux host, split active | 7 ms | 138 ms | 1026 ms | 16.3% |
| Linux host, split disabled | 7 ms | 280 ms | 442 ms | 24.8% |
| Windows host, split active | 8 ms | 269 ms | 455 ms | 20.1% |
| Windows host, split disabled | 8 ms | 295 ms | 510 ms | 18.5% |

Removing the split did not remove the stalls on either operating system, and a Linux probe that overlapped the Windows disabled window spiked in the same ten-second buckets on both hosts (14 of 14 buckets agreed). That run supports a shared-path explanation for that particular stall pattern. It does not quantify Windows kernel-driver receive overhead, certify RSC operation, or exclude other local bottlenecks. Compare a local destination and record the offload state before attributing a new slowdown.

## Extra WireGuard network adapter

One active `WireGuardSplit` adapter is expected. Other VPNs may legitimately have their own adapters; the display name or a `#2` suffix alone does not establish an orphan.

Windows servicing can create stray `ROOT\WIREGUARD` devices from older driver-installation records. WireGuard documents this in its [upstream cleanup fix](https://github.com/WireGuard/wireguard-nt/commit/b0d305a1865c9b23fa677d9ddeb564a60d315973). Working Windows 11 tunnels use the `SWD\WireGuard` namespace. This project checks before creating a tunnel adapter and also after activation and every five minutes while enabled, so an older, compatible runtime pair can remain in use.

Background maintenance reports candidates without removing them. Startup preflight requires the owned tunnel service to be stopped and no adapter named `WireGuardSplit` to exist. A global start mutex serializes creation attempts, and any remaining enumerated root WireGuard device blocks creation. Inactivity alone does not prove a root adapter belongs to this project. After identifying its owner and confirming removal is appropriate, an administrator can run `Invoke-AdapterMaintenance.ps1 -Action Repair -InstanceId 'ROOT\WIREGUARD\0007'`, substituting the exact inspected instance. The service must be stopped or its software-enumerated tunnel healthy. Removal still requires WireGuard hardware/service/provider identity, disconnected status, zero traffic, automatic local addresses and local routes, then an immediate identity/activity recheck. Other instances, software-enumerated devices, shared driver packages and registry-only remnants are preserved. No reboot is requested.

From elevated PowerShell, inspect or run maintenance immediately:

```powershell
& 'C:\Program Files\WireGuardProgramSplit\src\Invoke-AdapterMaintenance.ps1' -Action Status
& 'C:\Program Files\WireGuardProgramSplit\src\Invoke-AdapterMaintenance.ps1' -Action Repair
```

`Status` does not change devices. The controller records outcomes in `controller.log`; `adapter-removal-before.json` and `adapter-removal-{output,error}.log` retain the latest attempted removal. An incomplete inspection/removal is logged and retried on the next interval without restarting the VPN. A device that has traffic, configuration, or uncertain ownership needs manual investigation instead of wider automatic deletion.

For an existing installation, deploy `AdapterMaintenance.ps1`, `Invoke-AdapterMaintenance.ps1`, `Invoke-Tunnel.ps1`, and the updated `Controller.ps1` together into the protected `src` directory, and set the owned tunnel service to Manual (leave the controller Automatic). Changing the startup type does not stop a running service. The preflight runs on the next stopped-tunnel start through `Invoke-Tunnel.ps1`; direct `Start-Service`/`sc start` of the tunnel bypasses the controller and is not the supported activation path. The running controller reads its script at launch: the periodic check becomes active on its next service start. The manual command works immediately and does not require restarting the tunnel. A fresh install includes the scripts automatically.

## Tunnel does not start after an update

Runtime DLLs are a matched dependency pair. Restore the pair that previously worked or obtain a compatible current pair, reinstall, and rerun the acceptance checks. Never replace only one DLL.

## Controller restarts or the tunnel service stays pending

The usual cause is the tunnel service stuck in `StartPending` or `StopPending`: Windows refuses a stop control in those states, and the WireGuard adapter was never created or removed. A slow start is left alone and adopted by the next repair attempt; a host that has been starting for more than 90 seconds, or a stop that does not finish within 20 seconds, is reset by terminating the project's own `tunnel-host.exe`. `controller.log` then shows `Tunnel service stuck in ...; terminating owned host process`. A disable that cannot finish cleanup keeps retrying: look for `Disable cleanup incomplete` in `controller.log` and the detail in `last-error.txt`. `controller-service.log` records `Stack cleanup failed` only when a service stop could not clean up within its window. If the reset itself fails, the network stack is wedged below the service (the same session usually cannot create other virtual adapters either) and a reboot is required. Health-check restarts are logged as `Stack health check failed` with the reason, and the component logs from that moment are kept under `logs\health-failures\<time>` (the restart overwrites the live copies). A probe reports `No DNS response after 3 attempts` when nothing came back, `DNS response rejected` when the server answered with an error, and `DNS probe failed` for a socket error; `controller-service.log` ends each run with the path that stopped the service.

## Startup is slow

`WireGuardProgramSplitController` should report `Automatic`; `WireGuardTunnel$WireGuardSplit` should report `Manual`. The controller starts the tunnel after adapter preflight, so the installation still activates automatically at boot. Compare the boot timestamp to the first `Stack active after tunnel readiness check` line. The controller has no fixed post-success delay; remaining time is physical-network readiness, adapter creation, endpoint handshake, and the first successful DNS probe. Inspect `controller-service.log` if the controller service itself repeatedly restarts.

## Repeated health-check failures

DNS ownership and NRPT failures repair only their own component. Full rebuilds and
failed starts share a durable budget of three attempts per fifteen-minute window.
At the limit the controller keeps traffic protection in place, continues health
checks, and defers another rebuild. A complete successful health check or an
explicit disable clears the budget. Corrupt or future-dated budget state defers
repairs and requires inspection. The first snapshot for a repeated failure reason
is retained; subsequent occurrences update its last-seen time. Up to ten distinct
reasons are kept, with thirty-day expiration checked when capturing evidence.

See [physical network recovery](network-recovery.md) for the separate, explicitly
enrolled Ethernet/Wi-Fi recovery limits. Windows Server CI does not reproduce all
Windows 11 driver and network-management behavior; test on representative Windows
11 hardware before broad deployment.
