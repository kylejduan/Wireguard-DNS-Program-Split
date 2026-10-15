# SPDX-License-Identifier: GPL-3.0-or-later
param([switch] $SelfTest, [long] $StopEventHandle)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'ValidationWorker.ps1')
Assert-ProgramSplit64BitPowerShell
$configuration = Get-ProgramSplitConfiguration -Root $root
$state = Join-Path $root 'state'
$logs = Join-Path $root 'logs'
$enabledFile = Join-Path $state 'enabled'
$activeFile = Join-Path $state 'active'
$stackStoppedFile = Join-Path $state 'stack-stopped'
$reloadFile = Join-Path $state 'reload.request'
$errorFile = Join-Path $state 'last-error.txt'
$logFile = Join-Path $logs 'controller.log'
$includeFile = Join-Path $state 'included-apps.txt'
# Present whenever persistent payload filters may exist; Invoke-WfpFilters.ps1 owns it.
$filtersInstalledFile = Join-Path $state 'wfp-filters.installed'
# The tray's profile import asks to keep the filters through the disable that swaps the profile.
$keepFiltersFile = Join-Path $state 'keep-filters.request'
# When this controller, or an earlier one, first saw the current import request, on the monotonic clock.
$keepFiltersSeenFile = Join-Path $state 'keep-filters.seen.json'
$keepFiltersSeen = $null
# Process identity and monotonic first sighting of a pending tunnel host, as the tunnel component reported it.
$tunnelPendingSeen = $null
# Every component is up but tunnel DNS did not answer during startup; the tunnel-only restart takes over.
$tunnelRetryFile = Join-Path $state 'tunnel-retry'
# While present, controller-service.exe keeps the dispatcher running; see dispatcher-supervisor.h.
$dispatcherSupervisedFile = Join-Path $state 'dns-dispatcher.supervised'
# Adapter maintenance inspects only devices under this key; see AdapterMaintenance.ps1.
$rootAdapterKey = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\WIREGUARD'

function Get-ControllerElapsed {
    # Monotonic scheduling survives daylight-saving changes and wall-clock corrections.
    [TimeSpan]::FromSeconds([Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency)
}

function Write-ControllerLog([string] $message) {
    # A log write failure must not become a routing failure or crash loop.
    try {
        [IO.Directory]::CreateDirectory($logs) | Out-Null
        $line = "$(Get-Date -Format o) $message"
        if ($line.Length -gt 16384) { $line = $line.Substring(0, 16384) + ' [truncated]' }
        if ((Test-Path -LiteralPath $logFile) -and (Get-Item -LiteralPath $logFile).Length -gt (8MB - 64KB)) {
            foreach ($index in 3..1) {
                $source = if ($index -eq 1) { $logFile } else { "$logFile.$($index - 1)" }
                if (Test-Path -LiteralPath $source) { Move-Item -LiteralPath $source -Destination "$logFile.$index" -Force }
            }
        }
        Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
    } catch { }
}

function Start-Component([string] $name, [string] $action, [string[]] $switches = @()) {
    $script = Join-Path $PSScriptRoot $name
    $key = [IO.Path]::GetFileNameWithoutExtension($name)
    $stdout = Join-Path $logs "$key-output.log"
    $stderr = Join-Path $logs "$key-error.log"
    # Output comes back through pipes; the log files are a best-effort copy, so a reader holding one open
    # cannot fail the component and turn into a repair. The 45-second deadline is the runner's, from now,
    # so the order in which a parallel start collects results has no effect on any component's timeout.
    # The tunnel component is told when this controller first saw its current pending host, so its stuck-host
    # clock survives even when its state file cannot be written.
    if ($name -eq 'Invoke-Tunnel.ps1' -and $script:tunnelPendingSeen) { $switches = @($switches) + @('-PendingSeen', $script:tunnelPendingSeen) }
    $started = Start-ProgramSplitProcess -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList (
        @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Action', $action) + $switches) `
        -TimeoutMilliseconds 45000 -Encoding Oem
    [pscustomobject]@{
        Name = $name; Action = $action; Started = $started
        Stdout = $stdout; Stderr = $stderr
    }
}

function Complete-Component($component) {
    $name = $component.Name
    $action = $component.Action
    $result = Complete-ProgramSplitProcess -Started $component.Started -OutputLog $component.Stdout -ErrorLog $component.Stderr
    $output = $result.Output
    $errors = $result.Error
    if ($name -eq 'Invoke-Tunnel.ps1') {
        $pending = @($output | Where-Object { $_ -like 'TUNNEL-PENDING *' }) | Select-Object -Last 1
        if ($pending) { $script:tunnelPendingSeen = $pending.Substring('TUNNEL-PENDING '.Length) }
    }
    # Log what the component reported before judging its exit: a failed run's output records actions it
    # already took, such as resetting a stuck tunnel host, and the next run overwrites the file.
    if ($output) { Write-ControllerLog ($output -join ' ') }
    if ($result.TimedOut) { throw "$name $action timed out." }
    if ($result.ExitCode -ne 0) { throw "$name $action exited with code $($result.ExitCode): $($errors -join ' ')" }
    if ($errors) { throw "$name $action failed: $($errors -join ' ')" }
    Write-ControllerLog "$name $action completed in $($result.Milliseconds) ms."
}

function Invoke-Component([string] $name, [string] $action, [string[]] $switches = @()) {
    Complete-Component (Start-Component -name $name -action $action -switches $switches)
}

function Invoke-AdapterMaintenance {
    if ((Get-ControllerElapsed) -lt $script:nextAdapterMaintenance) { return }
    $script:nextAdapterMaintenance = (Get-ControllerElapsed) + [TimeSpan]::FromMinutes(5)
    # Without root WireGuard devices the component has nothing to inspect; skip its PowerShell start,
    # service query and adapter enumeration. An unreadable key still runs the component, which reports it.
    try { if (-not (Test-Path -LiteralPath $rootAdapterKey -ErrorAction Stop)) { return } } catch { }
    try { Invoke-Component 'Invoke-AdapterMaintenance.ps1' 'Repair' }
    catch {
        try { Write-ControllerLog "Adapter maintenance incomplete; keeping the stack active: $($_.Exception.Message)" }
        catch { } # Even a logging failure must not turn housekeeping into a VPN restart.
    }
}

function Test-ManagedProcess([string] $pidName, [string] $expectedPath) {
    $path = Join-Path $state $pidName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $managedPid = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($path), [ref]$managedPid)) { return $false }
    return Test-ProgramSplitProcessPath -ProcessId $managedPid -ExpectedPath $expectedPath
}

function Get-ExpectedProcesses([string] $processName, [string] $expectedPath) {
    @(Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $expectedPath
    })
}

function Test-OwnedNrptRulePresent {
    # An unreadable policy key counts as a missing rule, as the CIM query it replaced did.
    try {
        return [bool](Get-ProgramSplitLocalNrptRules |
            Where-Object { Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName })
    } catch { return $false }
}

function Get-StackState {
    # Runs on every loop pass, so the state files and owned processes are checked before the service
    # query and the NRPT rule's registry key. The rule stays in this check: once it is gone, selected
    # applications resolve through the physical resolver until the stack is repaired. The persistent
    # payload filters survive process, BFE and host restarts, so this pass reads only their install marker;
    # the 30-second validation verifies the objects themselves.
    # TunnelDown means every per-application component is in place and only the tunnel host is not running.
    # The dispatcher process is the supervisor's, which replaces one that ends within about a second, so a
    # dispatcher between processes is not a reason to repair the stack; the health check validates it.
    $tunnelRetry = Test-Path -LiteralPath $tunnelRetryFile -PathType Leaf
    if (-not ($tunnelRetry -or (Test-Path -LiteralPath $activeFile -PathType Leaf)) -or
        -not (Test-Path -LiteralPath $filtersInstalledFile -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $state 'dns-etw-session.txt') -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dispatcherSupervisedFile -PathType Leaf)) { return 'Inactive' }
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return 'Inactive' }
    if (-not (Test-OwnedNrptRulePresent)) { return 'Inactive' }
    if ($service.Status -eq 'Running' -and -not $tunnelRetry) { return 'Active' }
    return 'TunnelDown'
}

function Test-StackActive { (Get-StackState) -eq 'Active' }

function Test-StackPresent([switch] $Import) {
    # A profile import swaps only the tunnel: the payload filters, the dispatcher, the NRPT rule and the
    # cache policy stay, so selected applications' DNS keeps failing closed, and only the tunnel counts.
    if (Test-Path -LiteralPath $activeFile -PathType Leaf) { return $true }
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { return $true }
    if (Test-Path -LiteralPath (Join-Path $state 'endpoint-route.txt') -PathType Leaf) { return $true }
    if ($Import) { return $false }
    if (Test-Path -LiteralPath $filtersInstalledFile -PathType Leaf) { return $true }
    if (Test-Path -LiteralPath (Join-Path $state 'dns-etw-session.txt') -PathType Leaf) { return $true }
    if (Test-Path -LiteralPath $dispatcherSupervisedFile -PathType Leaf) { return $true }
    if (Test-OwnedNrptRulePresent) { return $true }
    if (Get-ExpectedProcesses 'dns-dispatcher' (Join-Path $root 'bin\dns-dispatcher.exe')) { return $true }
    # A dynamic-session filter host left running by an earlier release.
    return [bool](Get-ExpectedProcesses 'wfp-probe' (Join-Path $root 'bin\wfp-probe.exe'))
}

function Test-FilterHoldRequested {
    # Honored for five minutes, so a tray that exits during an import cannot leave a disabled stack's
    # filters in place indefinitely; the next disabled pass after that removes them. The five minutes run
    # on the monotonic clock from the first sighting of this request (its content, which the tray stamps),
    # kept in state across controller restarts, so a wall-clock step neither extends nor ends the hold.
    if (-not (Test-Path -LiteralPath $keepFiltersFile -PathType Leaf)) {
        $script:keepFiltersSeen = $null
        if (Test-Path -LiteralPath $keepFiltersSeenFile) { Remove-Item -LiteralPath $keepFiltersSeenFile -Force -ErrorAction SilentlyContinue }
        return $false
    }
    try {
        $identity = [IO.File]::ReadAllText($keepFiltersFile)
        $now = (Get-ControllerElapsed).TotalSeconds
        $seen = $script:keepFiltersSeen
        if (-not $seen) {
            try { $seen = [IO.File]::ReadAllText($keepFiltersSeenFile) | ConvertFrom-Json } catch { $seen = $null }
        }
        # A record from before a reboot, when the monotonic clock restarted, is a new sighting.
        if (-not $seen -or [string]$seen.Identity -cne $identity -or [double]$seen.FirstSeen -gt $now) {
            $seen = [pscustomobject]@{ Identity = $identity; FirstSeen = $now }
            $temporary = "$keepFiltersSeenFile.$PID.tmp"
            try {
                [IO.File]::WriteAllText($temporary, ($seen | ConvertTo-Json -Compress))
                Move-Item -LiteralPath $temporary -Destination $keepFiltersSeenFile -Force
            } catch { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        }
        $script:keepFiltersSeen = $seen
        return ($now - [double]$seen.FirstSeen) -lt 300
    } catch { return $false }
}

function Stop-Stack([switch] $RestoreCache, [switch] $ThrowOnFailure, [switch] $KeepTunnel, [switch] $RemoveFilters,
        [switch] $StopDns) {
    # Repairs and reloads stop only the tunnel, if that: the persistent payload filters, the owned NRPT rule
    # and the dispatcher stay, and the dispatcher takes new inputs in place. Disable, service stop and
    # uninstall also stop DNS (the rule first, then the dispatcher and its supervision) and, unless a profile
    # import holds them, remove the filters before anything else.
    Stop-ValidationWorker
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    if ($RemoveFilters) {
        try { Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    }
    if ($StopDns) {
        # The rule must not outlive the dispatcher it names, or every lookup on the host fails.
        try { Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
        try { Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Stop' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    }
    # An included-app reload changes only the dispatcher's inputs and the filters. Keeping the tunnel lets
    # the restart adopt it instead of waiting for a new handshake; a restart that fails still stops it.
    if (-not $KeepTunnel) {
        try { Invoke-Component 'Invoke-Tunnel.ps1' 'Stop' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    }
    if ($RestoreCache) {
        # The stack can be gone while the cache cap remains; the disable path retries until this clears.
        try {
            Invoke-Component 'Invoke-DnsCachePolicy.ps1' 'Disable'
            $script:cacheRestorePending = $false
        } catch {
            $script:cacheRestorePending = $true
            $cleanupErrors.Add([string]$_); Write-ControllerLog $_
        }
    }
    Remove-Item -LiteralPath $activeFile, $tunnelRetryFile -Force -ErrorAction SilentlyContinue
    if ($ThrowOnFailure -and $cleanupErrors.Count) {
        throw "Stack cleanup failed: $($cleanupErrors -join ' | ')"
    }
}

function Save-HealthFailureEvidence([string] $Reason) {
    # The restart that follows a failed health check rewrites every component log, which destroys the
    # only record of why the check failed. Snapshot them first. Best effort: this must never throw.
    try {
        $evidenceRoot = Join-Path $logs 'health-failures'
        $folder = Join-Path $evidenceRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
        [IO.Directory]::CreateDirectory($folder) | Out-Null
        $reasonFile = Join-Path $folder 'reason.txt'
        [IO.File]::WriteAllText($reasonFile, "$(Get-Date -Format o) $Reason")
        $tailBytes = 2MB
        foreach ($file in Get-ChildItem -LiteralPath $logs -File -Filter '*.log') {
            # Supervisor logs rotate independently; everything else is what a restart overwrites.
            if ($file.Name -in 'controller.log', 'controller-service.log') { continue }
            try {
                # Running components hold their logs open for writing; share that access instead of failing.
                $source = [IO.FileStream]::new($file.FullName, 'Open', 'Read', 'ReadWrite, Delete')
                try {
                    # Take the size from the open stream, since a directory listing can lag a file that is
                    # still being written, and keep only the tail of a long-running log: the newest lines
                    # are the evidence, and an unbounded copy would delay the restart it precedes.
                    $snapshotLength = $source.Length
                    if ($snapshotLength -gt $tailBytes) {
                        $null = $source.Seek($snapshotLength - $tailBytes, [IO.SeekOrigin]::Begin)
                        [IO.File]::AppendAllText($reasonFile, "`r`n$($file.Name) truncated to its last $tailBytes bytes")
                    }
                    $target = [IO.File]::Create((Join-Path $folder $file.Name))
                    try {
                        $remaining = [Math]::Min($snapshotLength, $tailBytes)
                        $buffer = [byte[]]::new(65536)
                        while ($remaining -gt 0) {
                            $read = $source.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length))
                            if ($read -eq 0) { break }
                            $target.Write($buffer, 0, $read)
                            $remaining -= $read
                        }
                    } finally { $target.Dispose() }
                } finally { $source.Dispose() }
            } catch { }
        }
        foreach ($old in @(Get-ChildItem -LiteralPath $evidenceRoot -Directory | Sort-Object Name -Descending | Select-Object -Skip 10)) {
            try { Remove-ProgramSplitTree -Path $old.FullName } catch { }
        }
        Write-ControllerLog "Health-failure evidence saved to $folder."
    } catch { }
}

function Test-TunnelDns([int] $TimeoutMilliseconds = 5000, [int] $Attempts = 1) {
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $stdout = Join-Path $logs 'dns-health.log'
    $stderr = Join-Path $logs 'dns-health-error.log'
    # The probe retransmits within one run: a lost datagram is not a dead tunnel, and restarting the
    # stack over it would leave the included applications on the direct route for the whole restart.
    $result = Invoke-ProgramSplitProcess -FilePath $probe -ArgumentList @(
        $configuration.TunnelDns, 'example.com', $TimeoutMilliseconds, $Attempts
    ) -TimeoutMilliseconds ($TimeoutMilliseconds * $Attempts + 3000) -OutputLog $stdout -ErrorLog $stderr
    if ($result.TimedOut) { throw 'Tunnel DNS health probe timed out.' }
    $output = $result.Output
    $errors = $result.Error
    if (-not ($output -match '^PASS:')) {
        $output += $errors
        throw "Tunnel DNS health probe failed: $($output -join ' ')"
    }
    Write-ControllerLog 'Tunnel DNS health probe passed.'
}

function Test-PhysicalResolverAnswers {
    # The dispatcher answers unlisted names by forwarding them to the physical resolvers, passing over one
    # that stops answering, so only when none answers does the local probe fail however healthy this
    # stack is. Restarting cannot fix that, and each restart stops the tunnel, so the caller holds
    # instead. Returns $false when no resolver is known or none answers.
    $resolvers = @(Get-ProgramSplitPhysicalResolvers -AdapterName $configuration.AdapterName `
        -TunnelDns $configuration.TunnelDns)
    if (-not $resolvers.Count) { return $false }
    $probe = Join-Path $root 'bin\dns-probe.exe'
    foreach ($resolver in $resolvers) {
        try {
            $result = Invoke-ProgramSplitProcess -FilePath $probe -ArgumentList @($resolver, 'example.com', 1000, 2) `
                -TimeoutMilliseconds 5000 -OutputLog (Join-Path $logs 'physical-resolver-probe.log') `
                -ErrorLog (Join-Path $logs 'physical-resolver-probe-error.log')
            if ($result.ExitCode -eq 0 -and ($result.Output -match '^PASS:')) { return $true }
        } catch { }
    }
    return $false
}

function Test-LocalDns {
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $stdout = Join-Path $logs 'dns-dispatcher-health.log'
    $stderr = Join-Path $logs 'dns-dispatcher-health-error.log'
    $result = Invoke-ProgramSplitProcess -FilePath $probe -ArgumentList @('--system', 'example.com', 3) `
        -TimeoutMilliseconds 8000 -OutputLog $stdout -ErrorLog $stderr
    if ($result.TimedOut) { throw 'Local split-DNS health probe timed out.' }
    $output = $result.Output
    $errors = $result.Error
    if ($result.ExitCode -ne 0 -or -not ($output -match '^PASS:')) {
        $detail = $output + $errors -join ' '
        if (-not (Test-PhysicalResolverAnswers)) {
            # Hold: the dispatcher is forwarding to a resolver that is not answering, so the
            # probe cannot pass and a restart would only cycle the NRPT rule, dispatcher and
            # tunnel while unlisted names fail anyway.
            if (-not $script:resolverHoldLogged) {
                Write-ControllerLog ("Local split-DNS probe failed while the physical resolver is " +
                    "not answering; keeping the stack in place: $detail")
                $script:resolverHoldLogged = $true
            }
            return
        }
        throw "Local split-DNS health probe failed: $detail"
    }
    $script:resolverHoldLogged = $false
    Write-ControllerLog 'Local split-DNS health probe passed.'
}

function Invoke-DispatcherValidation {
    # The physical-network snapshot and the end-to-end probe follow the uplink, so an outage fails them with
    # every owned component intact. Mark those as transport failures; ownership and ETW failures stay unmarked.
    try {
        try { Invoke-Validation 'Invoke-DnsDispatcher.ps1' }
        catch {
            # A dispatcher that just ended is replaced by the supervisor within about a second; check its
            # successor once instead of repairing the stack around it.
            if ($_.Exception.Message -notmatch 'managed DNS dispatcher process is unavailable|has not loaded the current inputs') { throw }
            try {
                Wait-ProgramSplitProbe -Probe { if (-not (Test-ProgramSplitDispatcherReady -Root $root)) { throw 'not ready' } } `
                    -TimeoutMilliseconds 5000 -RetryMilliseconds 250 -StopEvent $stopEvent
            } catch { }
            Invoke-Validation 'Invoke-DnsDispatcher.ps1'
        }
    } catch {
        if ($_.Exception.Message -match ('physical route, source address, or DNS resolver changed|' +
                'Physical source address or pre-dispatch DNS resolver is unavailable|' +
                'No physical IPv4 default gateway|Local split-DNS health probe')) {
            $_.Exception.Data['ProgramSplitStage'] = 'Transport'
        }
        throw
    }
}

function Test-StackHealth {
    # The filters are repaired in place, so they are checked first and never wait on the uplink.
    try { Invoke-Validation 'Invoke-WfpFilters.ps1' }
    catch {
        $_.Exception.Data['ProgramSplitStage'] = 'Filters'
        throw
    }
    Invoke-Validation 'Invoke-LocalNrpt.ps1'
    Invoke-DispatcherValidation
    # NRPT and the dispatcher passed, so a failure from here on is VPN-side: the provider, the server or
    # the tunnel host. Mark it so recovery can keep the per-application components in place.
    try { Test-TunnelDns -TimeoutMilliseconds 1000 -Attempts 3 }
    catch {
        $_.Exception.Data['ProgramSplitStage'] = 'Tunnel'
        throw
    }
}

function Test-TunnelSettingsUnchanged {
    # The running filters and dispatcher were started with these addresses and keep them across a
    # tunnel-only restart. Any change needs the full restart that hands them the new values.
    try {
        $current = Get-ProgramSplitConfiguration -Root $root
        return $current.TunnelAddress -eq $configuration.TunnelAddress -and $current.TunnelDns -eq $configuration.TunnelDns
    } catch { return $false }
}

function Restart-Tunnel([string] $Reason, [switch] $StopFirst, [switch] $Adopt) {
    # Fail closed through a VPN-side outage. The payload filters, NRPT rule and dispatcher stay in place,
    # so selected applications bind to the absent tunnel address and fail instead of leaving directly.
    # Attempts share the repair backoff; the outage is logged and its evidence saved once. Adopting the
    # stack a shutdown kept is the normal boot path, not an outage: it saves no evidence, and a start
    # that fails there is logged as an outage by the retry that follows.
    if ($stopEvent -and $stopEvent.WaitOne(0)) { return }
    if ($Adopt) {
        Write-ControllerLog 'Adopting the per-application components kept across shutdown; starting the tunnel.'
    } elseif (-not $script:tunnelOutageLogged) {
        Write-ControllerLog ("Tunnel-side failure; keeping the filters, NRPT rule and dispatcher in place " +
            "and restarting only the tunnel: $Reason")
        Save-HealthFailureEvidence -Reason $Reason
        $script:tunnelOutageLogged = $true
    }
    if ((Get-ControllerElapsed) -lt $script:nextRepair) { return }
    # The dispatcher keeps the direct inputs it started with. If the uplink changed during the outage,
    # a hostname endpoint cannot resolve through them, so hand that failure to the full health path. A
    # physical resolver that does not answer fails only the final loopback probe, after the inputs have
    # matched; an address endpoint needs no physical DNS, so the tunnel starts instead of waiting out the
    # resolver outage with selected applications blocked. The health check then holds the stack.
    try { Invoke-DispatcherValidation }
    catch {
        if (-not ($_.Exception.Data['ProgramSplitStage'] -eq 'Transport' -and
                $_.Exception.Message -match 'Local split-DNS health probe' -and -not (Test-PhysicalResolverAnswers))) {
            $script:tunnelOutageLogged = $false
            Invoke-HealthFailure $_
            return
        }
    }
    try {
        if ($StopFirst) { Invoke-Component 'Invoke-Tunnel.ps1' 'Stop' }
        # After a boot nothing else loads the PIA driver, and until it registers its callouts the persistent
        # filters block selected applications even with the tunnel up. It loads alongside the tunnel start.
        $driverStart = if (-not (Test-PiaDriverReady)) { Start-Component 'Invoke-PiaDriver.ps1' 'Install' }
        try { Invoke-Component 'Invoke-Tunnel.ps1' 'Start' }
        finally { if ($driverStart) { Complete-Component $driverStart } }
        Wait-ProgramSplitProbe -Probe { Test-TunnelDns -TimeoutMilliseconds 750 } `
            -TimeoutMilliseconds 20000 -RetryMilliseconds 250 -StopEvent $stopEvent
        $script:repairDelaySeconds = 2
        $script:nextRepair = [TimeSpan]::Zero
        $script:tunnelOutageLogged = $false
        Write-ControllerLog 'Tunnel restarted; the per-application components stayed in place.'
        if (Test-Path -LiteralPath $tunnelRetryFile -PathType Leaf) {
            [IO.File]::WriteAllText($activeFile, (Get-Date).ToString('o'))
            Remove-Item -LiteralPath $tunnelRetryFile, $errorFile -Force -ErrorAction SilentlyContinue
            Write-ControllerLog 'Stack active after the tunnel answered.'
        }
    } catch {
        $script:nextRepair = (Get-ControllerElapsed) + [TimeSpan]::FromSeconds($script:repairDelaySeconds)
        $script:repairDelaySeconds = [Math]::Min(60, $script:repairDelaySeconds * 2)
    }
}

function Invoke-Repair {
    Invoke-RepairAttempt
}

function Invoke-RepairAttempt {
    # A stop requested during a restart must not rebuild the stack the stop handler then tears down.
    if ($stopEvent -and $stopEvent.WaitOne(0)) { return }
    if ((Get-ControllerElapsed) -lt $script:nextRepair) { return }
    try {
        Get-ProgramSplitPhysicalDefault -AdapterName $configuration.AdapterName | Out-Null
        $script:networkWaitLogged = $false
        $script:networkRetryMilliseconds = 250
    } catch {
        if (-not $script:networkWaitLogged) {
            Write-ControllerLog 'Waiting for a physical IPv4 default route.'
            $script:networkWaitLogged = $true
        }
        return
    }
    try {
        Start-Stack
        $script:repairDelaySeconds = 2
        $script:nextRepair = [TimeSpan]::Zero
        $script:tunnelOutageLogged = $false
    } catch {
        $script:nextRepair = (Get-ControllerElapsed) + [TimeSpan]::FromSeconds($script:repairDelaySeconds)
        $script:repairDelaySeconds = [Math]::Min(60, $script:repairDelaySeconds * 2)
    }
}

function Test-DispatcherIdentitiesCurrent {
    try {
        return [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $state 'resolved-identities.tsv'))) -ceq
            [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $state 'dns-dispatcher-loaded-identities.tsv')))
    } catch { return $false }
}

function Repair-Filters([string] $Reason) {
    # Reinstalling replaces the whole persistent set in one transaction; nothing else needs to stop.
    Write-ControllerLog "Payload filter verification failed; reinstalling the filters in place: $Reason"
    try {
        if (-not (Test-PiaDriverReady)) { Invoke-Component 'Invoke-PiaDriver.ps1' 'Install' }
        Invoke-Component 'Invoke-WfpFilters.ps1' 'Start'
        Invoke-Validation 'Invoke-WfpFilters.ps1'
        if (-not (Test-DispatcherIdentitiesCurrent)) {
            # The reinstall resolved an identity differently; the dispatcher loads the new record in place.
            Write-ControllerLog 'Resolved identities changed; the DNS dispatcher is loading them.'
            Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Start'
        }
        Write-ControllerLog 'Payload filters reinstalled; the rest of the stack stayed in place.'
    } catch {
        Write-ControllerLog "Stack health check failed; restarting the stack: $($_.Exception.Message)"
        Save-HealthFailureEvidence -Reason $Reason
        Stop-Stack
        Invoke-Repair
    }
}

function Invoke-HealthFailure($Failure) {
    $reason = $Failure.Exception.Message
    $stage = $Failure.Exception.Data['ProgramSplitStage']
    if ($stage -eq 'Filters') {
        $script:physicalHoldLogged = $false
        Repair-Filters -Reason $reason
    } elseif ($stage -in @('Tunnel', 'Transport') -and
        (-not (Test-ProgramSplitPhysicalInputs -AdapterName $configuration.AdapterName `
            -TunnelDns $configuration.TunnelDns) -or -not (Test-PhysicalResolverAnswers))) {
        # Hold: keep the filters, NRPT rule, dispatcher and tunnel in place so selected
        # applications stay fail-closed, and re-validate on the next interval. Validation
        # still restarts the stack once the uplink returns with different inputs. Only a
        # failure an uplink outage can cause is held; any other invariant is repaired.
        if (-not $script:physicalHoldLogged) {
            Write-ControllerLog ("Physical uplink inputs or the physical resolver are " +
                "unavailable; holding the stack and retrying: $reason")
            $script:physicalHoldLogged = $true
        }
    } elseif ($stage -eq 'Tunnel' -and (Test-TunnelSettingsUnchanged)) {
        $script:physicalHoldLogged = $false
        Restart-Tunnel -Reason $reason -StopFirst
    } else {
        $script:physicalHoldLogged = $false
        Write-ControllerLog "Stack health check failed; restarting the stack: $reason"
        Save-HealthFailureEvidence -Reason $reason
        Stop-Stack
        Invoke-Repair
    }
}

# Disable, or a profile import, which stops only the tunnel. The dispatcher then takes the new tunnel
# address and resolver in place when the stack starts again.
function Stop-StackForDisable([switch] $Import) {
    if ($Import) { Stop-Stack -ThrowOnFailure }
    else { Stop-Stack -RestoreCache -ThrowOnFailure -StopDns -RemoveFilters }
}

# A restoration is pending while any cache setting differs from its saved original, so one that was only
# partly done before a controller restart is retried. An unreadable record counts as pending.
function Test-DnsCacheRestorePending(
        [string] $RecordPath = (Join-Path $state 'dnscache-policy-original.json'),
        [string] $KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters') {
    if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) { return $false }
    try {
        $key = Get-Item -LiteralPath $KeyPath
        # Assigned first: Windows PowerShell passes a parsed JSON array down the pipeline as one object.
        $saved = [IO.File]::ReadAllText($RecordPath) | ConvertFrom-Json
        foreach ($item in $saved) {
            $actual = $key.GetValue([string]$item.Name, $null)
            if ($item.Exists) {
                if ($null -eq $actual -or [int]$actual -ne [int]$item.Value) { return $true }
            } elseif ($null -ne $actual) { return $true }
        }
        return $false
    } catch { return $true }
}

function Test-DnsCachePolicyReady {
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $state 'dnscache-policy-original.json') -PathType Leaf)) {
            return $false
        }
        $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        $positiveTtl = $key.GetValue('MaxCacheTtl', $null)
        $negativeTtl = $key.GetValue('MaxNegativeCacheTtl', $null)
        return $null -ne $positiveTtl -and $null -ne $negativeTtl -and
            [int]$positiveTtl -eq 1 -and [int]$negativeTtl -eq 0
    } catch { return $false }
}

function Test-PiaDriverReady {
    $driver = Get-Service -Name 'PiaWFPCallout' -ErrorAction SilentlyContinue
    $driverRoot = Join-Path $root 'drivers\pia'
    return $driver -and $driver.Status -eq 'Running' -and
        [string]$driver.ServiceType -eq 'KernelDriver' -and
        (Test-Path -LiteralPath (Join-Path $driverRoot 'PiaWFPCallout.inf') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $driverRoot 'PiaWfpCallout.sys') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $driverRoot 'piawfpcallout.cat') -PathType Leaf)
}

function Start-Stack {
    $stackTimer = [Diagnostics.Stopwatch]::StartNew()
    $script:configuration = Get-ProgramSplitConfiguration -Root $root
    $dispatcherWasRunning = [bool](Test-ManagedProcess 'dns-dispatcher.pid' `
        (Join-Path $root 'bin\dns-dispatcher.exe'))
    Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $activeFile, $tunnelRetryFile -Force -ErrorAction SilentlyContinue
    try {
        Write-ControllerLog 'Starting stack.'
        $startupComponents = [Collections.Generic.List[object]]::new()
        $startupFailures = [Collections.Generic.List[string]]::new()
        try {
            # Installing or replacing the persistent filters needs neither the tunnel nor the PIA driver: until
            # both are up, selected applications fail instead of leaving on the physical route. A reload or a
            # new tunnel address replaces the previous set in one transaction.
            Write-ControllerLog 'Installing persistent per-application WFP filters.'
            $startupComponents.Add((Start-Component 'Invoke-WfpFilters.ps1' 'Start'))
            # Independent of the filters and the dispatcher, so it runs alongside them.
            if (-not (Test-DnsCachePolicyReady)) {
                $startupComponents.Add((Start-Component 'Invoke-DnsCachePolicy.ps1' 'Enable'))
            } else { Write-ControllerLog 'DNS cache policy already ready; skipped repair.' }
            if (-not (Test-PiaDriverReady)) {
                $startupComponents.Add((Start-Component 'Invoke-PiaDriver.ps1' 'Install'))
            } else { Write-ControllerLog 'PIA WFP callout driver already running; skipped repair.' }
            $startupComponents.Add((Start-Component 'Invoke-Tunnel.ps1' 'Start'))
        } catch { $startupFailures.Add([string]$_) }
        # The dispatcher attributes by the identity record the filter install writes, so it starts after it.
        $filterInstall = @($startupComponents | Where-Object { $_.Name -eq 'Invoke-WfpFilters.ps1' })
        if ($filterInstall) {
            $null = $startupComponents.Remove($filterInstall[0])
            try { Complete-Component $filterInstall[0] } catch { $startupFailures.Add([string]$_) }
        }
        if (-not $startupFailures.Count) {
            # A running dispatcher takes the new inputs in place; otherwise the supervisor starts one.
            try {
                Write-ControllerLog 'Loading DNS dispatcher inputs.'
                $startupComponents.Insert(0, (Start-Component 'Invoke-DnsDispatcher.ps1' 'Start'))
            } catch { $startupFailures.Add([string]$_) }
        }
        foreach ($component in $startupComponents) {
            try { Complete-Component $component }
            catch { $startupFailures.Add([string]$_) }
        }
        if ($startupFailures.Count) { throw "Parallel startup failed: $($startupFailures -join ' | ')" }
        # Verify the filters, including the PIA driver's callout registration, during the tunnel readiness wait.
        $filterCheck = Start-Component 'Invoke-WfpFilters.ps1' 'Validate'
        $readinessFailure = $null
        try {
            Wait-ProgramSplitProbe -Probe { Test-TunnelDns -TimeoutMilliseconds 750 } `
                -TimeoutMilliseconds 20000 -RetryMilliseconds 250 -StopEvent $stopEvent
        } catch { $readinessFailure = $_ }
        Complete-Component $filterCheck
        if ($readinessFailure -and $stopEvent -and $stopEvent.WaitOne(0)) { throw $readinessFailure }
        # The DNS path needs no tunnel: selected names fail until it answers, unlisted ones resolve directly.
        Write-ControllerLog 'Enabling local split-DNS NRPT rule.'
        Invoke-Component 'Invoke-LocalNrpt.ps1' 'Enable'
        if ($dispatcherWasRunning) {
            Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Validate'
        } else { Test-LocalDns }
        if ($readinessFailure) {
            # Only the tunnel is missing, as in a reload during a provider outage. Keep the dispatcher, NRPT
            # rule and filters, so selected applications stay fail-closed, and hand over to the tunnel-only
            # restart with its backoff instead of tearing the DNS path down.
            [IO.File]::WriteAllText($tunnelRetryFile, (Get-Date).ToString('o'))
            $readinessFailure.Exception.Data['ProgramSplitStage'] = 'TunnelRetry'
            throw $readinessFailure
        }
        $activeAt = Get-Date
        [IO.File]::WriteAllText($activeFile, $activeAt.ToString('o'))
        Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
        $stackTimer.Stop()
        Write-ControllerLog "Stack active after tunnel readiness check in $($stackTimer.ElapsedMilliseconds) ms."
        try {
            $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            if (($activeAt - $boot).TotalMinutes -le 10) {
                $audit = [ordered]@{
                    Boot = $boot.ToString('o')
                    Active = $activeAt.ToString('o')
                    BootToActiveSeconds = [Math]::Round(($activeAt - $boot).TotalSeconds, 2)
                }
                [IO.File]::WriteAllText((Join-Path $state 'startup-audit.json'),
                    ($audit | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
                Write-ControllerLog "Cold boot to active: $($audit.BootToActiveSeconds) seconds."
            }
        } catch { Write-ControllerLog "Startup timing audit failed: $($_.Exception.Message)" }
    } catch {
        $message = $_ | Out-String
        [IO.File]::WriteAllText($errorFile, $message)
        Write-ControllerLog $message
        if ($_.Exception.Data['ProgramSplitStage'] -eq 'TunnelRetry') {
            Write-ControllerLog 'Tunnel DNS did not answer; the dispatcher, NRPT rule and filters stay for the tunnel-only restart.'
            throw
        }
        Stop-Stack
        throw
    }
}

$required = @(
    $includeFile,
    (Join-Path $root 'bin\dns-dispatcher.exe'),
    (Join-Path $root 'bin\dns-probe.exe'),
    (Join-Path $root 'bin\wfp-probe.exe'),
    $configuration.ProfilePath,
    $configuration.SettingsPath
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing controller input: $path" }
}
if (-not @([IO.File]::ReadAllLines($includeFile) | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })) {
    throw 'The included-app list is empty.'
}
if ($SelfTest) { Write-Output 'PASS: controller inputs and include list.'; exit 0 }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) { throw 'The controller must run as SYSTEM.' }
$mutex = $null
if (-not $StopEventHandle) {
    $mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitController')
    if (-not $mutex.WaitOne(0)) { exit 0 }
}

[IO.Directory]::CreateDirectory($state) | Out-Null
[IO.Directory]::CreateDirectory($logs) | Out-Null
$lastHealth = [TimeSpan]::Zero
$nextAdapterMaintenance = [TimeSpan]::Zero
$nextRepair = [TimeSpan]::Zero
$repairDelaySeconds = 2
$nextCleanup = [TimeSpan]::Zero
$cleanupDelaySeconds = 2
# A cache setting found changed at startup may be left from a restoration that failed before a restart.
$cacheRestorePending = Test-DnsCacheRestorePending
$stopRequestedAt = $null
$stopCleanupWindow = [TimeSpan]::FromSeconds(150)
$networkWaitLogged = $false
$physicalHoldLogged = $false
$tunnelOutageLogged = $false
# A tunnel found stopped on this controller's first pass is the stack a shutdown kept for adoption.
$adoptionPending = $true
$resolverHoldLogged = $false
$networkRetryMilliseconds = 250
$stopEvent = $null
try {
    if ($StopEventHandle) {
        $stopEvent = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset)
        $stopEvent.SafeWaitHandle = [Microsoft.Win32.SafeHandles.SafeWaitHandle]::new(
            [IntPtr]$StopEventHandle, $true)
    }
    while ($true) {
        if ($stopEvent -and $stopEvent.WaitOne(0)) {
            if (-not $stopRequestedAt) {
                Write-ControllerLog 'Controller service stop requested.'
                $stopRequestedAt = Get-ControllerElapsed
            }
            # The service host force-ends this process four minutes after the stop control. Retry
            # incomplete cleanup, but check the window after each attempt, which can itself take most
            # of a minute, so the failure is thrown and logged here instead of arriving as a forced end.
            # A service stop is an explicit stop: it removes the persistent payload filters too.
            try { Stop-Stack -RestoreCache -ThrowOnFailure -RemoveFilters -StopDns }
            catch {
                if ((Get-ControllerElapsed) - $stopRequestedAt -ge $stopCleanupWindow) { throw }
                Write-ControllerLog 'Service-stop cleanup incomplete; retrying.'
                Start-Sleep -Seconds 2
                continue
            }
            if (Test-StackPresent) {
                if ((Get-ControllerElapsed) - $stopRequestedAt -ge $stopCleanupWindow) {
                    throw 'Stack cleanup failed: the managed stack remains present.'
                }
                Write-ControllerLog 'Managed stack remains present; retrying service-stop cleanup.'
                Start-Sleep -Seconds 1
                continue
            }
            break
        }
        $desired = Test-Path -LiteralPath $enabledFile -PathType Leaf
        if ($desired) {
            $nextCleanup = [TimeSpan]::Zero
            $cleanupDelaySeconds = 2
            try { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
            catch {
                Write-ControllerLog $_.Exception.Message
                Start-Sleep -Seconds 2
                continue
            }
        }
        if (-not $desired) {
            # Check the backoff deadline before probing the stack, and probe it once per pass unless a
            # cleanup attempt has just changed it. A failed cache restoration is retried on its own. A
            # profile import swapping the tunnel profile stops only the tunnel and restores nothing.
            $keepFilters = Test-FilterHoldRequested
            $restorePending = $cacheRestorePending -and -not $keepFilters
            $stackPresent = $null
            if ((Get-ControllerElapsed) -ge $nextCleanup) {
                $stackPresent = Test-StackPresent -Import:$keepFilters
                if ($stackPresent -or $restorePending) {
                    $stackPresent = $null
                    try {
                        Stop-StackForDisable -Import:$keepFilters
                        if ($cleanupDelaySeconds -gt 2) {
                            Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
                            Write-ControllerLog 'Disable cleanup completed after retry.'
                        }
                        $cleanupDelaySeconds = 2
                    } catch {
                        # Keep supervising: exiting here only makes SCM restart the controller into the
                        # same failure. Record it for the tray and retry with bounded backoff. Recording
                        # is best effort so a log or state write error cannot end supervision either.
                        $cleanupFailure = $_ | Out-String
                        try { [IO.File]::WriteAllText($errorFile, $cleanupFailure) } catch { }
                        try { Write-ControllerLog "Disable cleanup incomplete; retrying in $cleanupDelaySeconds s." } catch { }
                        $nextCleanup = (Get-ControllerElapsed) + [TimeSpan]::FromSeconds($cleanupDelaySeconds)
                        $cleanupDelaySeconds = [Math]::Min(60, $cleanupDelaySeconds * 2)
                    }
                }
            }
            if ($null -eq $stackPresent) { $stackPresent = Test-StackPresent -Import:$keepFilters }
            if (-not $stackPresent -and -not ($cacheRestorePending -and -not $keepFilters)) {
                if (-not (Test-Path -LiteralPath $stackStoppedFile -PathType Leaf)) {
                    try { [IO.File]::WriteAllText($stackStoppedFile, (Get-Date -Format o)) }
                    catch { Write-ControllerLog $_.Exception.Message }
                }
            } else {
                Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
            }
        } elseif (Test-Path -LiteralPath $reloadFile) {
            Remove-Item -LiteralPath $reloadFile -Force -ErrorAction SilentlyContinue
            Stop-Stack -KeepTunnel
            Invoke-Repair
            $lastHealth = Get-ControllerElapsed
        } elseif (($stackState = Get-StackState) -ne 'Active') {
            # Adopt an existing owned tunnel; a stopped tunnel gets adapter preflight before start. A tunnel
            # host that stopped under intact components is started alone, so the filters stay in place.
            if ($stackState -eq 'TunnelDown' -and (Test-TunnelSettingsUnchanged)) {
                if (Test-Path -LiteralPath $tunnelRetryFile -PathType Leaf) {
                    Restart-Tunnel -Reason 'Tunnel DNS did not answer when the stack started.' -StopFirst
                } else { Restart-Tunnel -Reason 'The tunnel service is not running.' -Adopt:$adoptionPending }
                # The tunnel-only path validates nothing else, so a stack it completes is checked on the next
                # pass, including the driver's callouts, instead of after the full interval.
                $lastHealth = if (Test-StackActive) { (Get-ControllerElapsed) - [TimeSpan]::FromSeconds(31) }
                    else { Get-ControllerElapsed }
            } else {
                Invoke-Repair
                $lastHealth = Get-ControllerElapsed
            }
        } elseif ((Get-ControllerElapsed) - $lastHealth -gt [TimeSpan]::FromSeconds(30)) {
            try {
                try { Test-StackHealth }
                catch { Start-Sleep -Milliseconds 250; Test-StackHealth }
                $script:physicalHoldLogged = $false
                $script:tunnelOutageLogged = $false
            } catch { Invoke-HealthFailure $_ }
            $lastHealth = Get-ControllerElapsed
        }
        $adoptionPending = $false
        if ($desired -and (Get-ControllerElapsed) -ge $nextAdapterMaintenance -and (Test-StackActive)) {
            Invoke-AdapterMaintenance
        }
        $loopWaitMilliseconds = if ($desired -and $script:networkWaitLogged) {
            $script:networkRetryMilliseconds
        } else { 2000 }
        if ($desired -and $script:networkWaitLogged) {
            $script:networkRetryMilliseconds = [Math]::Min(2000, $script:networkRetryMilliseconds * 2)
        }
        if ($stopEvent) { $null = $stopEvent.WaitOne($loopWaitMilliseconds) }
        else { Start-Sleep -Milliseconds $loopWaitMilliseconds }
    }
} finally {
    Stop-ValidationWorker
    if ($stopEvent) { $stopEvent.Dispose() }
    if ($mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
