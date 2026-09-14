# WireGuard DNS Program Split

Windows 11 tooling that sends selected executables' IPv4 TCP, UDP, and ordinary Windows DNS through a WireGuard profile while leaving every unlisted application's payload and DNS on the normal Windows/router path.

> **Experimental:** this is a source release for advanced Windows users. It installs privileged networking components, currently supports IPv4 only, and has explicit fail-open cases. Read [Limitations](docs/limitations.md) before using it.

## What is different

| Traffic | Selected executable | Unlisted executable |
|---|---|---|
| IPv4 TCP/UDP | WireGuard tunnel | Native Windows route |
| Windows DNS API | Profile DNS through WireGuard | Active physical-adapter DNS |
| Application-owned DoH/DoT/DoQ | Application decides | Application decides |

There is no universal TUN in the direct data path. A high-metric WireGuard route and Windows Filtering Platform (WFP) binding redirect only listed executable paths. This avoids imposing user-mode packet-proxy overhead on unlisted multi-gigabit traffic.

## Requirements

- Windows 11 x64 and an administrator account.
- One IPv4 WireGuard `.conf` containing exactly one interface `Address`, one `DNS`, and one peer. Proton users generate this from the Proton account website; the desktop client does not export it.
- Compatible x64 `tunnel.dll` and `wireguard.dll` files obtained from software you are licensed to use.
- The signed `PiaWFPCallout` driver package obtained from an official Private Internet Access desktop distribution.
- WSL with MinGW-w64 for the current build path.

Third-party binaries, profiles, keys, machine settings, and build output are intentionally not distributed here.
The provider desktop app is not a runtime dependency after its profile and compatible runtime files have been supplied. This project does not connect to PIA; it uses only the signed local callout driver.

## Quick start

From WSL:

```bash
sudo apt install g++-mingw-w64-x86-64
git clone https://github.com/kylejduan/Wireguard-DNS-Program-Split.git
cd Wireguard-DNS-Program-Split
./tests/run.sh
```

Then run an elevated Windows PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./Install.ps1 `
  -Profile 'C:\path\to\provider.conf' `
  -Applications 'C:\Program Files\Example\example.exe' `
  -WireGuardRuntimeDirectory 'C:\path\to\wireguard-runtime' `
  -PiaDriverDirectory 'C:\path\to\pia-driver' `
  -DisableBrowserSecureDns
```

The installer validates inputs and signatures, deploys to `C:\ProgramData\WireGuardProgramSplit`, starts an automatic SYSTEM controller service, and adds a current-user tray icon. Use the tray to enable/disable routing, add or remove executables, import another profile, and open logs.

See [Installation](docs/installation.md), [Architecture](docs/architecture.md), and [Troubleshooting](docs/troubleshooting.md).

## Safety model

- The imported profile is copied locally with locked ACLs and never printed by the scripts.
- The physical default route remains globally preferred.
- DNS without a process-attribution event returns `SERVFAIL`; it is not guessed onto either resolver.
- Dynamic WFP filters vanish if their host exits. The controller repairs them, but this release is not a persistent per-application kill switch.
- Existing connections must be closed and reopened after changing the included-app list.

## Development

`./tests/run.sh` cross-compiles with warnings as errors, runs native self-tests, parses every PowerShell script, tests profile transformation and rollback, verifies resource-ownership checks, and tests the non-mutating installation plan.

## Linux include mode

The experimental [Linux implementation](docs/linux.md) automatically selects native executable paths at socket creation. Included IPv4 TCP/UDP uses kernel WireGuard, ordinary included DNS uses the profile resolver through that tunnel, and unlisted programs retain host routing and DNS. No launcher or packet proxy is required. Linux supports include mode only.

The tested kernel target is native Ubuntu 26.04 with Linux 7.0 and active BPF LSM. Read the [Linux operating limits](docs/linux.md) and [migration procedure](docs/linux-migration.md), especially existing sockets/cache mappings, early boot, helpers and application-owned encrypted DNS. The native reference host is activated and verified with independent applications. Its [measured added overhead](docs/linux-performance.md#native-reference-host-results--september-14-2026) met the sub-millisecond target in the controlled comparison; actual bot deadlines remain application-specific.

Bot agents can manage their own entries using the [application enrollment workflow](docs/linux-agents.md). It covers native programs, Python, Node, Java, .NET and shell applications through their actual runtime/helper executables, with guidance for dedicated runtimes and shared interpreters.

Contributions are welcome under [GPL-3.0-or-later](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

This project is independent and is not affiliated with or endorsed by WireGuard, Proton AG, or Private Internet Access.
