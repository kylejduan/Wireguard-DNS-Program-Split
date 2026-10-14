# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only: controller-service.exe's dispatcher supervisor against a fixture installation
# running the real dns-dispatcher.exe. The dispatcher is killed at random moments, including during
# reloads, repairs and health checks: unlisted DNS must answer again within about two seconds and selected
# DNS must never take the direct lane. Reloads under load must drop no query. Finally an owned catch-all
# rule is suspended after 15 seconds without a ready dispatcher and restored once one is ready again.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The dispatcher supervisor integration test requires an elevated session.'
}
$ownedName = 'WireGuard Program Split local dispatcher'
if ((Get-Service -Name WireGuardProgramSplitController -ErrorAction SilentlyContinue) -or
    (Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -like '127.0.0.*' }) -or
    (Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Namespace -contains '.' })) {
    throw 'The dispatcher supervisor integration test requires a disposable host without the project, loopback DNS or a catch-all NRPT rule.'
}
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $RepositoryRoot "local\test-temp\supervisor $id"
$zone = "wgps-$id.invalid"
foreach ($directory in @('bin', 'src', 'config', 'state', 'logs')) {
    [IO.Directory]::CreateDirectory((Join-Path $root $directory)) | Out-Null
}
foreach ($name in @('dns-dispatcher.exe', 'dns-probe.exe')) {
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot "build\$name") -Destination (Join-Path $root 'bin')
}
foreach ($name in @('Common.ps1', 'Invoke-LocalNrpt.ps1', 'Invoke-DnsDispatcher.ps1')) {
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot "src\powershell\$name") -Destination (Join-Path $root 'src')
}
[IO.File]::WriteAllText((Join-Path $root 'config\settings.json'), '{ "TunnelAddress": "127.0.0.3", "TunnelDns": "127.0.0.3" }')
$selected = Join-Path $root 'selected.exe'
$direct = Join-Path $root 'direct.exe'
Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination $selected
Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination $direct
$state = Join-Path $root 'state'
$identities = Join-Path $state 'resolved-identities.tsv'
$inputs = Join-Path $state 'dns-dispatcher-inputs.txt'
$dispatcherExe = Join-Path $root 'bin\dns-dispatcher.exe'
$children = [Collections.Generic.List[object]]::new()
$probes = [Collections.Generic.List[object]]::new()
$zoneRule = $null

function Write-Atomic([string] $Path, [string] $Text) {
    $temporary = "$Path.test.tmp"
    [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
    foreach ($attempt in 1..20) {
        try { Move-Item -LiteralPath $temporary -Destination $Path -Force; return }
        catch { if ($attempt -eq 20) { throw } else { Start-Sleep -Milliseconds 50 } }
    }
}
# Two identity records that both select selected.exe, so every reload changes the bytes but not the lanes.
function Write-Identities([int] $Variant) {
    $text = "# wgps-identities 1`n$selected`t$selected`t00`n"
    if ($Variant % 2) { $text += "C:\absent\other.exe`tC:\absent\other.exe`t01`n" }
    Write-Atomic $identities $text
}
function Write-LoopbackInputs([int] $Variant) {
    Write-Atomic $inputs ("# wgps-dispatcher-inputs 1`r`n# variant $Variant`r`ndirect-source=127.0.0.2`r`n" +
        "direct-dns=127.0.0.2`r`ntunnel-source=127.0.0.3`r`ntunnel-dns=127.0.0.3`r`n")
}
function Request-Reload {
    $event = [Threading.EventWaitHandle]::OpenExisting('Global\WireGuardProgramSplitDispatcherReload')
    try { $null = $event.Set() } finally { $event.Dispose() }
}
function Read-Shared([string] $Path) {
    try { $stream = [IO.FileStream]::new($Path, 'Open', 'Read', 'ReadWrite, Delete') } catch { return '' }
    try { $reader = [IO.StreamReader]::new($stream); try { $reader.ReadToEnd() } finally { $reader.Dispose() } }
    finally { $stream.Dispose() }
}
function Get-Generation {
    if ((Read-Shared (Join-Path $state 'dns-dispatcher-status.txt')) -match '(?m)^generation=(\d+)') { [int]$Matches[1] } else { 0 }
}
# The supervised dispatcher once it has published its inputs under its own process ID.
function Wait-Dispatcher([int] $NotId = 0, [int] $Seconds = 15) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $Seconds) {
        $text = Read-Shared (Join-Path $state 'dns-dispatcher.pid')
        $managedPid = 0
        if ([int]::TryParse($text, [ref]$managedPid) -and $managedPid -ne $NotId -and
            (Read-Shared (Join-Path $state 'dns-dispatcher-status.txt')) -match "(?m)^pid=$managedPid\r?$") {
            $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
            if ($process -and [string]$process.Path -eq $dispatcherExe) { return $process }
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'No supervised DNS dispatcher became ready.'
}
function Launch([string] $Exe, [string[]] $Arguments, [string] $Label) {
    $process = Start-Process -FilePath $Exe -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $root "logs\$Label.out") -RedirectStandardError (Join-Path $root "logs\$Label.err")
    $null = $process.Handle
    $children.Add($process)
    $process
}
function Start-Probe([string] $Exe, [string] $Name, [int] $Attempts) {
    $info = [Diagnostics.ProcessStartInfo]::new($Exe, "--system $Name $Attempts")
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    $probes.Add($process)
    [pscustomobject]@{ Process = $process; Exe = $Exe; Name = $Name }
}
function Complete-Probes($List, [int] $Seconds = 20) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    foreach ($probe in $List) {
        $left = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $probe.Process.WaitForExit($left)) { $probe.Process.Kill(); $null = $probe.Process.WaitForExit(5000) }
    }
}
function Start-Script([string] $Script, [string] $Action, [string] $Label) {
    Launch 'powershell.exe' @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        ('"{0}"' -f (Join-Path $root "src\$Script")), '-Action', $Action) $Label
}
function Complete-Script($Process, [string] $Label, [int] $Seconds = 60) {
    Assert-True ($Process.WaitForExit($Seconds * 1000)) "$Label finishes"
    $Process.WaitForExit()
    "$(Read-Shared (Join-Path $root "logs\$Label.out")) $(Read-Shared (Join-Path $root "logs\$Label.err"))".Trim()
}
# Kills the dispatcher, keeps launching unlisted and selected probes, and returns the seconds until the
# first unlisted lookup started after the kill was answered.
function Measure-Recovery($Dispatcher, [string] $DirectName, [string] $SelectedName, [string] $Tag) {
    $Dispatcher.Kill()
    $killedAt = [DateTime]::Now
    $round = @()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $answered = $null
    for ($n = 0; $timer.Elapsed.TotalSeconds -lt 10 -and -not $answered; $n++) {
        $round += Start-Probe $direct ($DirectName -f "$Tag-$n") 1
        $round += Start-Probe $selected ($SelectedName -f "$Tag-$n") 1
        Start-Sleep -Milliseconds 150
        $answered = @($round | Where-Object { $_.Exe -eq $direct -and $_.Process.HasExited -and $_.Process.ExitCode -eq 0 }) |
            Select-Object -First 1
    }
    Complete-Probes $round
    $times = @($round | Where-Object { $_.Exe -eq $direct -and $_.Process.ExitCode -eq 0 } | ForEach-Object {
        ($_.Process.ExitTime - $killedAt).TotalSeconds })
    Assert-True ($times.Count -gt 0) "unlisted DNS answered again after kill $Tag"
    [pscustomobject]@{ Seconds = ($times | Measure-Object -Minimum).Minimum; Round = $round }
}

$failed = $false
try {
    $responder = Launch (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') @('--fixture', 900) 'responder'
    Write-Identities 0
    Write-LoopbackInputs 0
    [IO.File]::WriteAllText((Join-Path $state 'dns-dispatcher.supervised'), 'test')
    $supervisor = Launch (Join-Path $RepositoryRoot 'build\controller-service.exe') @('--supervise-dispatcher', ('"{0}"' -f $root)) 'supervisor'
    $dispatcher = Wait-Dispatcher
    $zoneRule = Add-DnsClientNrptRule -Namespace ".$zone" -NameServers '127.0.0.1' -DisplayName "WgpsTest-$id" -PassThru

    # Killed at random moments, half of them while a reload is in flight.
    $recoveries = [Collections.Generic.List[double]]::new()
    foreach ($iteration in 1..8) {
        Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 1500)
        if ($iteration % 2) {
            Write-Identities $iteration
            Request-Reload
            Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 40)
        }
        $previous = $dispatcher.Id
        $result = Measure-Recovery $dispatcher "direct-{0}.$zone" "selected-{0}.$zone" "kill$iteration"
        $recoveries.Add($result.Seconds)
        $dispatcher = Wait-Dispatcher -NotId $previous
    }
    Write-Output "OBSERVED: unlisted DNS answered again $(($recoveries | ForEach-Object { $_.ToString('0.00') }) -join ', ') s after each kill."
    Assert-True (($recoveries | Measure-Object -Maximum).Maximum -le 3) 'unlisted DNS answers within about two seconds of every kill'

    # Reloads under load: every lookup is answered in its own lane and the dispatcher is never replaced.
    $before = Get-Generation
    $reloads = 0
    $load = @()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    for ($n = 0; $timer.Elapsed.TotalSeconds -lt 12; $n++) {
        $load += Start-Probe $selected "selected-load-$n.$zone" 3
        $load += Start-Probe $direct "direct-load-$n.$zone" 3
        Write-Identities $n
        Write-LoopbackInputs $n
        Request-Reload
        $reloads++
        Start-Sleep -Milliseconds 250
    }
    Complete-Probes $load
    $dropped = @($load | Where-Object { $_.Process.ExitCode -ne 0 })
    $after = Get-Generation
    Assert-True ($dropped.Count -eq 0) "no lookup fails during reloads: $(($dropped | ForEach-Object { $_.Name }) -join ', ')"
    Assert-True ($after - $before -ge [Math]::Floor($reloads / 2) -and (Wait-Dispatcher).Id -eq $dispatcher.Id) `
        "reloads replace the inputs in place ($before to $after for $reloads requests)"
    Write-Output "OBSERVED: $($load.Count) lookups answered during $reloads reload requests (generation $before to $after)."

    # An invalid record is rejected and the loaded inputs stay in use.
    Write-Atomic $identities "not an identity record`n"
    $before = Get-Generation
    Request-Reload
    Start-Sleep -Milliseconds 1000
    $pair = @((Start-Probe $selected "selected-rejected.$zone" 3), (Start-Probe $direct "direct-rejected.$zone" 3))
    Complete-Probes $pair
    Assert-True ((Get-Generation) -eq $before -and (Read-Shared (Join-Path $root 'logs\dns-dispatcher.log')) -match 'RELOAD REJECTED' -and
        @($pair | Where-Object { $_.Process.ExitCode -ne 0 }).Count -eq 0) 'an invalid reload keeps the loaded inputs'
    Write-Identities 0
    Request-Reload

    $observed = Read-Shared (Join-Path $root 'logs\responder.out')
    Assert-True ($observed -match "TUNNEL selected-" -and $observed -match "DIRECT direct-" -and
        $observed -notmatch 'DIRECT selected-' -and $observed -notmatch 'TUNNEL direct-' -and
        (Read-Shared (Join-Path $root 'logs\dns-dispatcher.log')) -notmatch 'DNS selected-\S+ type=\d+ -> DIRECT') `
        'selected DNS never took the direct lane and unlisted DNS never the tunnel lane'
    Remove-DnsClientNrptRule -Name $zoneRule.Name -Force
    $zoneRule = $null

    # The owned catch-all rule with the runner's real resolver as the direct lane, through the real
    # component scripts: Start reloads the running dispatcher, Validate is the controller's health check.
    $start = Start-Script 'Invoke-DnsDispatcher.ps1' 'Start' 'start0'
    $text = Complete-Script $start 'start0'
    Assert-True ($start.ExitCode -eq 0 -and $text -match 'ready with the current inputs') "Start reloads the running dispatcher: $text"
    $enable = Start-Script 'Invoke-LocalNrpt.ps1' 'Enable' 'enable'
    $text = Complete-Script $enable 'enable'
    Assert-True ($enable.ExitCode -eq 0) "the owned catch-all rule is enabled: $text"
    $validate = Start-Script 'Invoke-DnsDispatcher.ps1' 'Validate' 'validate0'
    $text = Complete-Script $validate 'validate0'
    Assert-True ($validate.ExitCode -eq 0) "the supervised dispatcher passes the health check: $text"
    $dispatcher = Wait-Dispatcher
    # Selected lookups use names only the tunnel lane's resolver answers; the direct lane is the real resolver.
    $selectedAnswered = [Collections.Generic.List[string]]::new()
    $recoveries.Clear()
    foreach ($iteration in 1..4) {
        $action = if ($iteration % 2) { 'Start' } else { 'Validate' }
        if ($action -eq 'Start') { Write-Identities $iteration }
        $component = Start-Script 'Invoke-DnsDispatcher.ps1' $action "component$iteration"
        Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 2000)
        $previous = $dispatcher.Id
        $result = Measure-Recovery $dispatcher 'example.com' "selected-{0}.$zone" "owned$iteration"
        $recoveries.Add($result.Seconds)
        $result.Round | Where-Object { $_.Exe -eq $selected -and $_.Process.ExitCode -eq 0 } | ForEach-Object { $selectedAnswered.Add($_.Name) }
        $text = Complete-Script $component "component$iteration"
        if ($action -eq 'Start') { Assert-True ($component.ExitCode -eq 0) "a reload survives a dispatcher kill: $text" }
        $dispatcher = Wait-Dispatcher -NotId $previous
    }
    Write-Output "OBSERVED: with the owned rule, host DNS answered again $(($recoveries | ForEach-Object { $_.ToString('0.00') }) -join ', ') s after each kill."
    Assert-True (($recoveries | Measure-Object -Maximum).Maximum -le 3) 'host DNS answers within about two seconds of every kill'
    $settled = Start-Probe $selected "selected-settled.$zone" 3
    Complete-Probes @($settled)
    Assert-True ($settled.Process.ExitCode -eq 0) 'the selected lane answers through the last replacement'
    $selectedAnswered.Add($settled.Name)
    $observed = Read-Shared (Join-Path $root 'logs\responder.out')
    $missing = @($selectedAnswered | Where-Object { $observed -notmatch "TUNNEL $([regex]::Escape($_))" })
    Assert-True ($missing.Count -eq 0 -and
        (Read-Shared (Join-Path $root 'logs\dns-dispatcher.log')) -notmatch 'DNS selected-\S+ type=\d+ -> DIRECT') `
        "every selected lookup answered during the kills came from the tunnel lane ($($selectedAnswered.Count) answered; not in it: $($missing -join ', '))"

    # A lost pid record is republished by the supervisor, which holds the verified process.
    Remove-Item -LiteralPath (Join-Path $state 'dns-dispatcher.pid') -Force
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Read-Shared (Join-Path $state 'dns-dispatcher.pid')) -ne [string]$dispatcher.Id -and $timer.Elapsed.TotalSeconds -lt 5) {
        Start-Sleep -Milliseconds 100
    }
    Assert-True ($timer.Elapsed.TotalSeconds -le 2) 'the supervisor republishes a lost pid record'

    # A dispatcher that exists but does not answer, suspended here as a hung one would be, is replaced.
    Add-Type -Namespace WgpsTest -Name Native -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr process);
// Suspends the first process with this name other than exclude as soon as it appears, or returns 0.
public static int SuspendNew(string name, int exclude, int timeoutMilliseconds) {
    var timer = System.Diagnostics.Stopwatch.StartNew();
    while (timer.ElapsedMilliseconds < timeoutMilliseconds) {
        foreach (var process in System.Diagnostics.Process.GetProcessesByName(name)) {
            if (process.Id == exclude) continue;
            NtSuspendProcess(process.Handle);
            return process.Id;
        }
    }
    return 0;
}
'@
    $previous = $dispatcher.Id
    Assert-True ([WgpsTest.Native]::NtSuspendProcess($dispatcher.Handle) -eq 0) 'the dispatcher is suspended'
    $timer.Restart()
    $dispatcher = Wait-Dispatcher -NotId $previous -Seconds 20
    $replaced = $timer.Elapsed.TotalSeconds
    $hostLookup = Start-Probe $direct 'example.com' 3
    Complete-Probes @($hostLookup)
    Write-Output "OBSERVED: a suspended dispatcher was replaced by a ready one in $($replaced.ToString('0.0')) s."
    Assert-True ($replaced -le 8 -and -not (Get-Process -Id $previous -ErrorAction SilentlyContinue) -and
        $hostLookup.Process.ExitCode -eq 0 -and (Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName })) `
        'a dispatcher that stops answering is replaced, and host DNS works again with the rule in place'

    # A dispatcher adopted by a restarted supervisor, which then hangs, is replaced as well.
    $supervisor.Kill()
    $null = $supervisor.WaitForExit(5000)
    $supervisor = Launch (Join-Path $RepositoryRoot 'build\controller-service.exe') @('--supervise-dispatcher', ('"{0}"' -f $root)) 'supervisor adopting'
    $timer.Restart()
    while ((Read-Shared (Join-Path $root 'logs\controller-service.log')) -notmatch "Supervising running DNS dispatcher $($dispatcher.Id)\.") {
        Assert-True ($timer.Elapsed.TotalSeconds -lt 10) 'the restarted supervisor adopts the running dispatcher'
        Start-Sleep -Milliseconds 100
    }
    $previous = $dispatcher.Id
    Assert-True ([WgpsTest.Native]::NtSuspendProcess($dispatcher.Handle) -eq 0) 'the adopted dispatcher is suspended'
    $timer.Restart()
    $dispatcher = Wait-Dispatcher -NotId $previous -Seconds 20
    Write-Output "OBSERVED: an adopted dispatcher that hung was replaced by a ready one in $($timer.Elapsed.TotalSeconds.ToString('0.0')) s."
    Assert-True ($timer.Elapsed.TotalSeconds -le 8 -and -not (Get-Process -Id $previous -ErrorAction SilentlyContinue)) `
        'an adopted dispatcher that stops answering is ended and replaced'

    # A dispatcher that hangs before publishing its inputs is replaced after the startup deadline.
    $hung = 0
    foreach ($attempt in 1..5) {
        $previous = $dispatcher.Id
        $dispatcher.Kill()
        $hung = [WgpsTest.Native]::SuspendNew('dns-dispatcher', $previous, 10000)
        Assert-True ($hung -ne 0) 'a replacement dispatcher starts'
        if ((Read-Shared (Join-Path $state 'dns-dispatcher-status.txt')) -notmatch "(?m)^pid=$hung\r?$") { break }
        # It published before it was suspended; end it and try again.
        Stop-Process -Id $hung -Force
        $hung = 0
        $dispatcher = Wait-Dispatcher -NotId $previous
    }
    Assert-True ($hung -ne 0) 'a dispatcher was suspended before it published its inputs'
    $timer.Restart()
    $dispatcher = Wait-Dispatcher -NotId $hung -Seconds 30
    Write-Output "OBSERVED: a dispatcher suspended before publishing its inputs was replaced by a ready one after $($timer.Elapsed.TotalSeconds.ToString('0.0')) s."
    Assert-True ($timer.Elapsed.TotalSeconds -le 14 -and -not (Get-Process -Id $hung -ErrorAction SilentlyContinue)) `
        'a dispatcher that never publishes is ended and replaced after the startup deadline'

    # An NRPT helper blocked for as long as the test holds the NRPT lock does not delay a restart.
    $nrptLock = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitNrptComponent')
    Assert-True ($nrptLock.WaitOne(5000)) 'the test holds the NRPT lock'
    try {
        [IO.File]::WriteAllText((Join-Path $state 'nrpt-suspended'), 'test')
        Start-Sleep -Milliseconds 1500
        $previous = $dispatcher.Id
        $dispatcher.Kill()
        $timer.Restart()
        $dispatcher = Wait-Dispatcher -NotId $previous -Seconds 10
        $restart = $timer.Elapsed.TotalSeconds
    } finally { $nrptLock.ReleaseMutex() }
    Write-Output "OBSERVED: with an NRPT helper blocked, a killed dispatcher was replaced and ready in $($restart.ToString('0.00')) s."
    Assert-True ($restart -le 3) 'a blocked NRPT helper does not hold up dispatcher supervision'
    $timer.Restart()
    while ((Test-Path -LiteralPath (Join-Path $state 'nrpt-suspended')) -and $timer.Elapsed.TotalSeconds -lt 15) { Start-Sleep -Milliseconds 250 }
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $state 'nrpt-suspended')) -and
        (Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName })) 'the released helper completes and the rule stays'

    # With the owned catch-all rule every lookup on the host was attributed: how many came from a process that
    # could not be identified, which makes the name unsafe for direct routing for ten seconds.
    $hostLog = Read-Shared (Join-Path $root 'logs\dns-dispatcher.log')
    Write-Output ("OBSERVED: host-wide, $([regex]::Matches($hostLog, '(?m)^HINT [^\r\n]* path=\r?$').Count) of " +
        "$([regex]::Matches($hostLog, '(?m)^HINT ').Count) query events had an unidentified process; " +
        "$([regex]::Matches($hostLog, '(?m)^DNS [^\r\n]*BLOCKED').Count) queries were refused.")

    # A dispatcher that cannot start: the rule is suspended after 15 seconds and restored once one is ready.
    Move-Item -LiteralPath $identities -Destination "$identities.away" -Force
    $dispatcher.Kill()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName }) -and $timer.Elapsed.TotalSeconds -lt 40) {
        Start-Sleep -Milliseconds 250
    }
    $suspendedAfter = $timer.Elapsed.TotalSeconds
    Write-Output "OBSERVED: owned NRPT rule suspended $($suspendedAfter.ToString('0.0')) s after the dispatcher ended."
    Assert-True ($suspendedAfter -ge 14 -and $suspendedAfter -le 22 -and (Test-Path -LiteralPath (Join-Path $state 'nrpt-suspended'))) `
        'the supervisor suspends the owned rule about 15 seconds after the dispatcher ends'
    $hostLookup = Start-Probe $direct 'example.com' 3
    Complete-Probes @($hostLookup)
    Assert-True ($hostLookup.Process.ExitCode -eq 0) 'host DNS works while the rule is suspended'
    # Enable does not bring the rule back while no dispatcher is ready ...
    $enable = Start-Script 'Invoke-LocalNrpt.ps1' 'Enable' 'enable-suspended'
    $text = Complete-Script $enable 'enable-suspended'
    Assert-True ($enable.ExitCode -ne 0 -and -not (Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName }) -and
        (Test-Path -LiteralPath (Join-Path $state 'nrpt-suspended'))) "Enable leaves the rule suspended without a ready dispatcher: $text"
    # ... and a rule that appears anyway is suspended again: the supervisor reconciles, it does not latch.
    $null = Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $ownedName `
        -Comment 'Owned by WireGuardProgramSplit; safe to remove on recovery.'
    $timer.Restart()
    while ((Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName }) -and $timer.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 250
    }
    Write-Output "OBSERVED: an owned rule added during the outage was suspended again after $($timer.Elapsed.TotalSeconds.ToString('0.0')) s."
    Assert-True ($timer.Elapsed.TotalSeconds -le 8) 'the supervisor suspends a rule that reappears during the outage'
    Move-Item -LiteralPath "$identities.away" -Destination $identities -Force
    $timer.Restart()
    while (-not (Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName }) -and $timer.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 250
    }
    Write-Output "OBSERVED: owned NRPT rule restored $($timer.Elapsed.TotalSeconds.ToString('0.0')) s after the dispatcher could start."
    Assert-True ($timer.Elapsed.TotalSeconds -le 6 -and -not (Test-Path -LiteralPath (Join-Path $state 'nrpt-suspended'))) `
        'the supervisor restores the rule once a dispatcher is ready again'
    $dispatcher = Wait-Dispatcher

    # Stop ends supervision: the rule goes first, and no dispatcher is started again.
    $stop = Start-Script 'Invoke-DnsDispatcher.ps1' 'Stop' 'stop'
    $text = Complete-Script $stop 'stop'
    Assert-True ($stop.ExitCode -eq 0) "Stop succeeds: $text"
    Start-Sleep -Milliseconds 2500
    Assert-True (-not (Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName }) -and
        -not @(Get-Process -Name 'dns-dispatcher' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Path -eq $dispatcherExe }).Count) `
        'Stop removes the rule and ends supervision'
    Write-Output 'PASS: the supervisor restarts a killed dispatcher at once, reloads drop no query, and a lasting outage suspends only the owned rule.'
} catch {
    $failed = $true
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $root 'logs') -File -ErrorAction SilentlyContinue)) {
        Write-Output "Diagnostic $($file.Name):"
        (Read-Shared $file.FullName) -split "`n" | Select-Object -Last 40
    }
    throw
} finally {
    $failures = [Collections.Generic.List[string]]::new()
    Remove-Item -LiteralPath (Join-Path $state 'dns-dispatcher.supervised') -Force -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        try { if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force } } catch { $failures.Add([string]$_) }
    }
    foreach ($probe in $probes) { try { if (-not $probe.HasExited) { $probe.Kill() } } catch { } }
    foreach ($process in @(Get-Process -Name 'dns-dispatcher' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Path -eq $dispatcherExe })) {
        try { Stop-Process -Id $process.Id -Force } catch { $failures.Add([string]$_) }
    }
    try {
        if ($zoneRule) { Remove-DnsClientNrptRule -Name $zoneRule.Name -Force }
        Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $ownedName } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
        & ipconfig.exe /flushdns | Out-Null
    } catch { $failures.Add([string]$_) }
    $session = (Read-Shared (Join-Path $state 'dns-etw-session.txt')).Trim()
    if ($session) { & logman.exe stop $session -ets 2>$null | Out-Null }
    if ($failures.Count -and -not $failed) { throw "Supervisor fixture cleanup failed: $($failures -join ' | ')" }
}
