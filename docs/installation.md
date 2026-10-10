# Installation

## 1. Obtain a WireGuard profile

Export or generate an IPv4 WireGuard profile from your VPN provider. It must contain:

```ini
[Interface]
PrivateKey = ...
Address = one IPv4 CIDR
DNS = one IPv4 address

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0
Endpoint = hostname-or-IPv4:port
```

For Proton VPN, create and download the profile from the account website using Proton's [official WireGuard configuration guide](https://protonvpn.com/support/wireguard-configurations/). The Windows Proton client is not used to export profiles.

Keep the `.conf` private: it contains a WireGuard private key.

## 2. Supply local runtime dependencies

Create two local directories outside this repository:

- WireGuard runtime: `tunnel.dll` and `wireguard.dll` from compatible, legitimately obtained x64 Windows software.
- PIA driver package: `PiaWFPCallout.inf`, `PiaWfpCallout.sys`, and `piawfpcallout.cat` from an official Private Internet Access Windows distribution.

The installer verifies Authenticode signatures before deployment. This project neither downloads nor redistributes these files. Runtime DLL compatibility is not standardized across every vendor build; preserve the exact pair that passed validation together.

Disconnect any provider desktop VPN before installation. Once the profile and compatible runtime files have been preserved, that desktop client is not required by this project and may remain uninstalled. No PIA VPN connection is used; only its signed WFP callout driver is installed.

## 3. Build

In WSL/Ubuntu:

```bash
sudo apt update
sudo apt install g++-mingw-w64-x86-64
./tests/run.sh
```

The executables are written to `build/`, which is ignored by Git.

## 4. Inspect the plan

From Windows PowerShell, `-PlanOnly` validates all paths and transforms the profile without requiring elevation or changing Windows:

```powershell
./Install.ps1 `
  -Profile 'C:\private\provider.conf' `
  -Applications @('C:\Apps\One.exe', 'C:\Apps\Two.exe') `
  -WireGuardRuntimeDirectory 'C:\private\wireguard-runtime' `
  -PiaDriverDirectory 'C:\private\pia-driver' `
  -PlanOnly
```

## 5. Install

Repeat the command in an elevated Windows PowerShell session without `-PlanOnly`. Add `-DisableBrowserSecureDns` if selected browsers must use the WireGuard profile's DNS rather than browser-owned DoH.

The installation is machine-wide. Runtime files are ACL-locked beneath `C:\Program Files\WireGuardProgramSplit`; only SYSTEM and Administrators retain access. The tray appears after interactive logon.

The controller starts automatically; the tunnel service is Manual so it starts only after adapter preflight. Before starting a stopped tunnel, the controller serializes creation, removes eligible root-enumerated orphans, and refuses creation if any enumerated root WireGuard devices remain or a split adapter already exists. Running/starting owned tunnels are reused. The controller also checks after activation and every five minutes while enabled. These can be recreated by Windows servicing with older WireGuard runtimes. Cleanup requires verified WireGuard identity, disconnected status, zero traffic, and only automatic link-local addresses/local routes; it rechecks the device before removal. Other tunnels and the shared driver package are preserved. Uncertain devices remain for manual inspection, and maintenance errors do not restart the stack. See [adapter maintenance](troubleshooting.md#extra-wireguard-network-adapter).

Use the tray menu to add every executable involved in an application. Launchers, helpers, crash handlers, and updater executables are separate processes and are not included automatically. Restart an application after changing the list so existing sockets do not retain their old route.

## 6. Verify

Use two different browser executables with browser Secure DNS disabled:

1. Add one browser through the tray and leave the other unlisted.
2. Fully exit and reopen both.
3. Confirm the selected browser reports the VPN exit; the unlisted browser reports the normal ISP exit.
4. Confirm DNS logs contain `TUNNEL` for selected queries and `DIRECT` for unlisted queries.
5. Confirm unlisted high-throughput traffic remains near its normal no-VPN baseline.

Also verify the host has no usable IPv6 default route. IPv6 is not redirected in this release:

```powershell
Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue
```

## Move an existing ProgramData installation

From an elevated 64-bit Windows PowerShell session in the updated repository:

```powershell
./Migrate-Installation.ps1 -PlanOnly
./Migrate-Installation.ps1
```

The migration moves the existing protected tree to `%ProgramFiles%\WireGuardProgramSplit`, updates both service commands and the tray task, and installs the three scripts needed for paths with spaces. Configuration, profiles, included applications, logs, binaries, and permissions are preserved. Mutable state remains inside the protected installation tree. Both roots must be on the same volume; the destination must not exist. The installation must be enabled and running with an Automatic controller and Manual tunnel.

This briefly stops the split tunnel and DNS dispatcher; pause sensitive included-app traffic during the move. The migration validates startup and restores the old location and service commands if activation fails. Original scripts remain under `state\migration-backup-<id>` for inspection. It does not uninstall or reinstall shared drivers.

For a legacy installation that has not been moved, pass `-DestinationRoot "$env:ProgramData\WireGuardProgramSplit"` to `Uninstall.ps1`. Custom installation paths also require an explicit `-DestinationRoot`.

## Uninstall

Run elevated:

```powershell
./Uninstall.ps1
```

The uninstaller disables controller recovery, requests ordered stack cleanup, and removes the controller and tunnel services, tray task, dynamic filters, dispatcher, owned NRPT rule, deployed files, and restored DNS/browser policies. It intentionally leaves the signed PIA driver installed because another application may share it.
