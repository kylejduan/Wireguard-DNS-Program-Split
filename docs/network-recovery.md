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

Enrollment enables observation and conservative Wi-Fi scan/reconnect attempts.
**It does not authorize a hardware restart.** An older enrollment without the
`AllowAdapterRestart` Boolean also leaves hardware restarts off. To opt into the
advanced hardware recovery behavior, repeat the enrollment command with
`-AllowAdapterRestart`. Running enrollment again without that switch turns
hardware restarts off and retains the existing retry ledger. Manual-only hardware
recovery is the recommended setting when protecting a working connection matters
more than unattended recovery of a stalled secondary adapter.

Use `-Action Status` to inspect enrollment and native adapter observations. Use
`-Action Disable` to turn off physical recovery. Disabling retains the attempt
budget; toggling the feature cannot bypass its cooldown. These commands do not
alter the application's normal VPN enable/disable setting.

## What it does

The enabled controller observes enrolled interfaces at most every 30 seconds.
It waits at least 90 seconds after its first observation and after an observation
gap longer than 45 seconds, including sleep, hibernate and Fast Startup transitions.

* **Ethernet, only with hardware restarts allowed:** `GetIfEntry2` must report a hardware interface with link up,
  administrative state up, no low-power flag, and the native paused bit on three
  or more successive valid observations spanning at least five minutes, with no
  transmit or receive progress. The executor independently checks the first
  observation's monotonic timestamp. Only then may that exact GUID be restarted,
  and only if it is already the preferred physical default route. A working
  alternative uplink or an unknown route defers the reset. Low-power or disconnected observations and observation
  gaps break the sequence. Cable removal, a failed DNS lookup, no DHCP,
  packet loss, or a dead router do not satisfy this rule.
* **Wi-Fi:** a disconnected, powered-on radio needs a WLAN AutoConfig failure
  within the last two minutes for the enrolled profile, with reason 163851
  (network unavailable). A newer connection request, success or disconnect
  supersedes it. Windows gets at least a minute to recover: both the continuous
  disconnected observation and the latest failed request must be at least a
  minute old. Recovery then scans and retries the saved profile if it is visible.
  Only with hardware restarts separately allowed, after at least five minutes of
  continuous failure, another matching failure following an issued retry within
  ten minutes can qualify for a reset. The latest failure must still be between
  one and two minutes old, and the requested
  network must be visible and connectable with at least 25 percent signal quality,
  with no other preferred physical route. A disconnected Wi-Fi adapter can qualify
  when the route inventory confirms no physical default route. Authentication failures, a working
  connection, radio-off state and another requested profile are left alone.

A Wi-Fi reconnect also defers while another preferred physical route exists,
so an automatic retry cannot deliberately displace an existing uplink. Unknown
route inventory defers every action. The route and enrollment are checked again
after slow inventory and after an asynchronous Wi-Fi scan.

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

VPN health recovery also distinguishes a failed probe from a dead connection.
A running tunnel needs at least three spaced failed observations spanning a minute
before a tunnel-only restart, plus a fresh failed DNS probe and no receive-counter
progress. A successful probe, incoming traffic, an unknown traffic observation,
a long sampling gap, or a missing physical resolver cancels the accumulated
evidence. A genuinely stopped tunnel service is started promptly. DNS transport
failures repair DNS inputs in place; a missing NRPT rule repairs only that rule. The native supervisor alone restores
a rule it suspended; the controller does not compete with that fallback.
Unclassified diagnosis errors and repair-ledger cleanup errors defer and log.
Tunnel restarts share the existing persistent three-attempt budget per fifteen
minutes. Unapplied settings wait for an explicit reload; failed settings reads keep the
last running configuration. A positively missing service is recreated, while an
uncertain service query defers. A live DNS worker gets ten seconds of failed local heartbeats to recover;
an exited worker still restarts promptly. A worker that never publishes gets its
ten-second startup allowance before heartbeat-failure confirmation begins. Failure
history resets on adoption, replacement and disabling supervision. Dispatcher
Start reloads inputs and cannot kill a worker on a transient inventory error. After fifteen seconds without a ready
worker, the documented NRPT fallback can temporarily use system DNS. This does
not request a tunnel teardown.

At boot, the controller waits for a physical default route before running the
dispatcher preflight or recording a tunnel restart. Startup adoption remains
pending until readiness succeeds. A disappearing route clears accumulated
failure observations so an uplink that just returned gets a fresh observation
window. A link-down adapter with a driver-reported hardware failure does not
meet the linked-and-paused Ethernet recovery criteria; investigate that failure
instead of repeatedly resetting it.

The native heartbeat checks the UDP receive loop. A partial TCP or ETW fault that
still answers that heartbeat can require manual component recovery; an input
reload is not a guarantee that every internal worker fault is repaired. Automatic
repair favors preserving an answering worker over killing one on uncertain
inventory data.

Preserving a tunnel that still receives traffic can leave selected applications
waiting for their provider's DNS to recover. Automatic hardware resets, when
explicitly allowed, can still fail or disrupt an interface; the program cannot
guarantee a vendor driver's recovery. These thresholds reduce avoidable restarts
and do not prove that all future faults are harmless.

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
