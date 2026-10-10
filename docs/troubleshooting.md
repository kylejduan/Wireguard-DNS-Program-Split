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
- Check `wfp-filters.log` for its path and `controller.log` for a healthy stack.
- Confirm no other VPN is connected and no foreign catch-all NRPT policy exists.

## DNS fails

- Disable application-owned Secure DNS/DoH during testing.
- Confirm the profile had exactly one reachable IPv4 DNS address.
- Inspect `dns-dispatcher.log` for `TUNNEL`, `DIRECT`, `BLOCKED`, or `FAILED`.
- `BLOCKED (no process hint)` means the dispatcher deliberately returned `SERVFAIL` because it could not safely attribute the query.
- `type`, `event-qpc`, `query-qpc`, and `qpc-frequency` fields support ordering diagnostics; do not treat them as a unique transaction ID.
- Ensure no other service owns `127.0.0.1:53`.

## Direct traffic is slower

Unlisted payload should not traverse the tunnel. Confirm the physical default route wins and the tunnel route remains metric `9999`. Compare the same server, browser, protocol, and time window; multi-gigabit browser tests are sensitive to CPU, server capacity, extensions, and HTTP implementation.

To decide whether the stack is involved at all, measure the same workload with it removed. Take a paired sample of new connections to fixed addresses, stop the split, repeat the sample, and start it again:

- Windows: `Stop-Service WireGuardProgramSplitController` removes the NRPT rule, ends `dns-dispatcher.exe`, destroys the dynamic WFP session with all payload filters, and stops the tunnel service; `Start-Service` restores them. Confirm `wfp-probe`, `dns-dispatcher`, the NRPT rule and the tunnel address are absent during the window.
- Linux: `wg-program-split disable` removes `wgps0`, the `wg_program_split` nftables table, the routing rule and the BPF pins; `wg-program-split activate` restores them. Unlisted traffic is untouched either way, so the only cost of the window is that enrolled programs lose the tunnel.

Selected applications leave through the physical path while the split is stopped, so keep the window short and do not use it as a workaround.

A paired run on both reference hosts on September 17, 2026 measured TCP handshake latency to three fixed public addresses, about 130 to 190 samples per phase:

| Phase | Median | p90 | Max | Samples at or above 100 ms |
|---|---:|---:|---:|---:|
| Linux host, split active | 7 ms | 138 ms | 1026 ms | 16.3% |
| Linux host, split disabled | 7 ms | 280 ms | 442 ms | 24.8% |
| Windows host, split active | 8 ms | 269 ms | 455 ms | 20.1% |
| Windows host, split disabled | 8 ms | 295 ms | 510 ms | 18.5% |

Removing the split did not remove the stalls on either operating system, and a Linux probe that overlapped the Windows disabled window spiked in the same ten-second buckets on both hosts (14 of 14 buckets agreed). Connection setup delays of this size are upstream of the host; the measured local cost is microseconds per packet and per socket, and connections that terminate on the local network traverse the same hooks without spiking. Compare a local destination before suspecting the stack.

## Extra WireGuard network adapter

One active `WireGuardSplit` adapter is expected. Other VPNs may legitimately have their own adapters; the display name or a `#2` suffix alone does not establish an orphan.

Windows servicing can create stray `ROOT\WIREGUARD` devices from older driver-installation records. WireGuard documents this in its [upstream cleanup fix](https://github.com/WireGuard/wireguard-nt/commit/b0d305a1865c9b23fa677d9ddeb564a60d315973). Working Windows 11 tunnels use the `SWD\WireGuard` namespace. This project checks before creating a tunnel adapter and also after activation and every five minutes while enabled, so an older, compatible runtime pair can remain in use.

Background repair requires the owned software-enumerated tunnel to be up and its service to be running. Startup preflight instead requires the owned service to be stopped and no adapter named `WireGuardSplit` to exist. A global start mutex serializes creation attempts. Running or starting owned services are reused; the controller does not create a second tunnel. The tunnel service uses Manual startup so SCM cannot bypass this sequence at boot. It only removes a root-enumerated network device with WireGuard hardware/service/provider identity, disconnected status, zero sent/received bytes, no manually configured or routable address, and no routes beyond automatic local/multicast routes. It reinspects identity and activity immediately before invoking `pnputil /remove-device` for that exact instance. At most one removal is attempted per pass. Software-enumerated devices, ambiguous/inaccessible devices, registry-only remnants, and shared driver packages are left alone. Before creation, any remaining enumerated root WireGuard device blocks startup, including a device that could not be safely removed. A later retry can clean the next eligible device; uncertain devices require investigation. Registry-only remnants are not enumerated adapters and do not block startup. No service restart, driver removal, or reboot is requested.

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
