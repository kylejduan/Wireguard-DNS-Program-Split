# Physical network recovery on Windows

Physical recovery is optional and disabled on a new installation. It handles two
narrow failure signatures observed on Windows. It cannot establish why a driver
entered that state or guarantee that a vendor defect will not recur.

First install appropriate signed NIC drivers from the computer or adapter vendor.
Compare the failing physical path with another device on the same LAN. A working
phone tether does not prove the router is healthy. Keep driver versions, Windows
updates, event timestamps and packet-drop evidence separate from hypotheses about
the trigger. In particular, a successful adapter restart proves a useful recovery,
not the original cause.

## Enable explicitly

Run the installed script from elevated Windows PowerShell, naming only adapters
you want it to manage. For example, adjust these names to match your machine:

```powershell
& "$env:ProgramFiles\WireGuardProgramSplit\src\Invoke-NetworkRecovery.ps1" `
    -Action Enable -InterfaceAlias 'Ethernet', 'Wi-Fi' -WifiProfile 'My saved home network'
```

The Wi-Fi profile must already exist for all users so the SYSTEM controller can
use it. Enrollment stores its name and the physical adapters' GUIDs, not passwords.
Renaming an interface does not change its enrollment; replacing the hardware
requires enrollment again. Only physical Ethernet and Wi-Fi adapters are accepted.
There is no automatic enrollment, wildcard selection, or virtual-adapter reset.

Use `-Action Status` to inspect enrollment and native adapter observations. Use
`-Action Disable` to turn off physical recovery. Disabling retains the attempt
budget; toggling the feature cannot bypass its cooldown. These commands do not
alter the application's normal VPN enable/disable setting.

## What it does

The enabled controller observes enrolled interfaces at most every 30 seconds.
It waits at least 90 seconds after its first observation and after an observation
gap longer than 45 seconds, including sleep, hibernate and Fast Startup transitions.

* **Ethernet:** `GetIfEntry2` must report a hardware interface with link up,
  administrative state up, no low-power flag, and the native paused bit on three
  successive valid observations, with no transmit progress. Only then may that
  exact GUID be restarted. Low-power or disconnected observations and observation
  gaps break the sequence. Cable removal, a failed DNS lookup, no DHCP,
  packet loss, or a dead router do not satisfy this rule.
* **Wi-Fi:** a disconnected, powered-on radio needs a WLAN AutoConfig failure
  within the last two minutes for the enrolled profile, with reason 163851
  (network unavailable). A newer connection request, success or disconnect
  supersedes it. Recovery first scans and retries the saved profile if it is
  visible. If another
  matching failure follows that attempt within two minutes, and the requested
  network is visible and connectable with at least 25 percent signal quality,
  it may restart that exact adapter and retry. Authentication failures, a working
  connection, radio-off state and another requested profile are left alone.

Every reset requires the split controller to be enabled and running and its
persistent WFP payload filters to validate. Recovery never removes those filters,
changes the profile, restarts WLAN AutoConfig, or changes another uplink. It takes
an exclusive lock in the protected state directory, rechecks live evidence just before acting, and reserves an attempt
on disk before requesting a reset. A failed, cancelled or interrupted request
still consumes its reservation or reconnect cooldown. A Wi-Fi reset cannot follow
a cancelled scan attempt: it requires a reconnect that was actually issued.
The reset uses Windows' `pnputil /restart-device` for one verified hardware device
instance. It never issues separate disable and enable commands or requests a reboot.

Resets have a ten-minute cooldown and a maximum of two per one-hour window per
adapter. A scan/reconnect sequence also backs off for ten minutes. Budgets persist
across service restarts, using atomic, write-through file replacement. An unreadable
or missing budget, or backward clock change, defers recovery. Enrollment creates
the initial ledger. A valid administrator can inspect the private state to resolve corruption.
Do not delete it automatically to force retries.

## Evidence and limits

`config\network-recovery.json` holds enrollment, and
`state\network-recovery-budget.json` holds retry accounting. Up to ten records in
`logs\network-recovery` preserve before/after native observations, the triggering
Wi-Fi event, recent bounded driver/power system-event metadata (time, provider,
ID and level, without unrelated device-message text), reserved budget and
requested/canceled/failed outcome. These local
records contain adapter identifiers and saved network names; redact them before
sharing. A requested reset is not a claim that Internet service recovered.

The native paused bit is intentionally a stricter trigger than a connectivity
probe. Some vendor stalls may not expose it and therefore need manual diagnosis.
Wi-Fi recovery also depends on the WLAN event log and native scan/profile APIs
being available to SYSTEM. No available evidence means no automatic reset.

Tests simulate faults and action races without disabling the developer's real
network. Hardware-specific fault injection, sleep/resume cycles and router/MLO
interoperability still need representative hardware testing. Recovery supplements
vendor fixes; it does not make an experimental split-tunnel implementation a
guaranteed anonymity product.
