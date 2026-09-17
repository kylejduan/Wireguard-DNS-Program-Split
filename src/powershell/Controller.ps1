# SPDX-License-Identifier: GPL-3.0-or-later
param([switch] $SelfTest, [long] $StopEventHandle)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
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

function Write-ControllerLog([string] $message) {
    [IO.Directory]::CreateDirectory($logs) | Out-Null
    Add-Content -LiteralPath $logFile -Value "$(Get-Date -Format o) $message"
}

function Start-Component([string] $name, [string] $action) {
    $script = Join-Path $PSScriptRoot $name
    $key = [IO.Path]::GetFileNameWithoutExtension($name)
    $stdout = Join-Path $logs "$key-output.log"
    $stderr = Join-Path $logs "$key-error.log"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Action', $action
    ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    # Materialize the process handle before it can exit. Windows PowerShell 5.1 otherwise
    # exposes a null ExitCode for short-lived children created with Start-Process.
    $null = $process.Handle
    [pscustomobject]@{
        Name = $name; Action = $action; Process = $process
        Stdout = $stdout; Stderr = $stderr; Timer = $timer
    }
}

function Complete-Component($component) {
    $name = $component.Name
    $action = $component.Action
    $process = $component.Process
    $stdout = $component.Stdout
    $stderr = $component.Stderr
    $timer = $component.Timer
    if (-not $process.WaitForExit(45000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "$name $action timed out."
    }
    # Finalize redirected streams after the timed overload reports completion.
    $process.WaitForExit()
    $output = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    # Log what the component reported before judging its exit: a failed run's output records actions
    # it already took, such as resetting a stuck tunnel host, and the next run overwrites the file.
    if ($output) { Write-ControllerLog ($output -join ' ') }
    if ($process.ExitCode -ne 0) { throw "$name $action exited with code $($process.ExitCode): $($errors -join ' ')" }
    if ($errors) { throw "$name $action failed: $($errors -join ' ')" }
    $timer.Stop()
    try {
        $elapsedMilliseconds = [long][Math]::Round(($process.ExitTime - $process.StartTime).TotalMilliseconds)
    } catch { $elapsedMilliseconds = $timer.ElapsedMilliseconds }
    Write-ControllerLog "$name $action completed in $elapsedMilliseconds ms."
}

function Invoke-Component([string] $name, [string] $action) {
    Complete-Component (Start-Component -name $name -action $action)
}

function Get-ManagedProcess([string] $pidName, [string] $processName, [string] $expectedPath) {
    $path = Join-Path $state $pidName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $managedPid = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($path), [ref]$managedPid)) { return $null }
    $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq $processName -and
        [string]$process.Path -eq $expectedPath) { return $process }
    return $null
}

function Get-ExpectedProcesses([string] $processName, [string] $expectedPath) {
    @(Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $expectedPath
    })
}

function Test-StackActive {
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    $rule = Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName }
    return (Test-Path -LiteralPath $activeFile -PathType Leaf) -and
        $service -and $service.Status -eq 'Running' -and $rule -and
        (Test-Path -LiteralPath (Join-Path $state 'dns-etw-session.txt') -PathType Leaf) -and
        (Get-ManagedProcess 'dns-dispatcher.pid' 'dns-dispatcher' (Join-Path $root 'bin\dns-dispatcher.exe')) -and
        (Get-ManagedProcess 'wfp-filters.pid' 'wfp-probe' (Join-Path $root 'bin\wfp-probe.exe'))
}

function Test-StackPresent {
    if (Test-Path -LiteralPath $activeFile -PathType Leaf) { return $true }
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { return $true }
    if (Test-Path -LiteralPath (Join-Path $state 'dns-etw-session.txt') -PathType Leaf) { return $true }
    if (Test-Path -LiteralPath (Join-Path $state 'endpoint-route.txt') -PathType Leaf) { return $true }
    if (Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName }) { return $true }
    return [bool]((Get-ExpectedProcesses 'dns-dispatcher' (Join-Path $root 'bin\dns-dispatcher.exe')) -or
        (Get-ExpectedProcesses 'wfp-probe' (Join-Path $root 'bin\wfp-probe.exe')))
}

function Stop-Stack([switch] $RestoreCache, [switch] $ThrowOnFailure) {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $wfpStopped = $false
    try {
        Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop'
        $wfpStopped = $true
    } catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    if ($wfpStopped) {
        try { Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    }
    try { Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Stop' }
    catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    try { Invoke-Component 'Invoke-Tunnel.ps1' 'Stop' }
    catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    if ($RestoreCache) {
        try { Invoke-Component 'Invoke-DnsCachePolicy.ps1' 'Disable' }
        catch { $cleanupErrors.Add([string]$_); Write-ControllerLog $_ }
    }
    Remove-Item -LiteralPath $activeFile -Force -ErrorAction SilentlyContinue
    if ($ThrowOnFailure -and $cleanupErrors.Count) {
        throw "Stack cleanup failed: $($cleanupErrors -join ' | ')"
    }
}

function Test-TunnelDns([int] $TimeoutMilliseconds = 5000) {
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $stdout = Join-Path $logs 'dns-health.log'
    $stderr = Join-Path $logs 'dns-health-error.log'
    $process = Start-Process -FilePath $probe -ArgumentList @(
        $configuration.TunnelDns, 'example.com', $TimeoutMilliseconds
    ) `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    $null = $process.Handle
    if (-not $process.WaitForExit($TimeoutMilliseconds + 3000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Tunnel DNS health probe timed out.'
    }
    $process.WaitForExit()
    $output = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    if (-not ($output -match '^PASS:')) {
        $output += $errors
        throw "Tunnel DNS health probe failed: $($output -join ' ')"
    }
    Write-ControllerLog 'Tunnel DNS health probe passed.'
}

function Test-LocalDns {
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $stdout = Join-Path $logs 'dns-dispatcher-health.log'
    $stderr = Join-Path $logs 'dns-dispatcher-health-error.log'
    $process = Start-Process -FilePath $probe -ArgumentList @('--system', 'example.com') `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    $null = $process.Handle
    if (-not $process.WaitForExit(8000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Local split-DNS health probe timed out.'
    }
    $process.WaitForExit()
    $output = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    if ($process.ExitCode -ne 0 -or -not ($output -match '^PASS:')) {
        throw "Local split-DNS health probe failed: $($output + $errors -join ' ')"
    }
    Write-ControllerLog 'Local split-DNS health probe passed.'
}

function Test-StackHealth {
    Assert-ProgramSplitNoIpv6DefaultRoute
    Invoke-Component 'Invoke-LocalNrpt.ps1' 'Validate'
    Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Validate'
    Test-TunnelDns -TimeoutMilliseconds 1000
}

function Invoke-Repair {
    if ((Get-Date) -lt $script:nextRepair) { return }
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
        $script:nextRepair = [DateTime]::MinValue
    } catch {
        $script:nextRepair = (Get-Date).AddSeconds($script:repairDelaySeconds)
        $script:repairDelaySeconds = [Math]::Min(60, $script:repairDelaySeconds * 2)
    }
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
    $dispatcherWasRunning = [bool](Get-ManagedProcess 'dns-dispatcher.pid' 'dns-dispatcher' `
        (Join-Path $root 'bin\dns-dispatcher.exe'))
    Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $activeFile -Force -ErrorAction SilentlyContinue
    try {
        Write-ControllerLog 'Starting stack.'
        Assert-ProgramSplitNoIpv6DefaultRoute
        if (Get-ExpectedProcesses 'wfp-probe' (Join-Path $root 'bin\wfp-probe.exe')) {
            Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop'
        }
        if (Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
            Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName
        }) {
            Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable'
        }
        if (-not (Test-DnsCachePolicyReady)) { Invoke-Component 'Invoke-DnsCachePolicy.ps1' 'Enable' }
        else { Write-ControllerLog 'DNS cache policy already ready; skipped repair.' }

        $startupComponents = [Collections.Generic.List[object]]::new()
        $startupFailures = [Collections.Generic.List[string]]::new()
        try {
            if (-not (Test-PiaDriverReady)) {
                $startupComponents.Add((Start-Component 'Invoke-PiaDriver.ps1' 'Install'))
            } else { Write-ControllerLog 'PIA WFP callout driver already running; skipped repair.' }
            $startupComponents.Add((Start-Component 'Invoke-Tunnel.ps1' 'Start'))
            Write-ControllerLog 'Starting DNS dispatcher.'
            $startupComponents.Add((Start-Component 'Invoke-DnsDispatcher.ps1' 'Start'))
        } catch { $startupFailures.Add([string]$_) }
        foreach ($component in $startupComponents) {
            try { Complete-Component $component }
            catch { $startupFailures.Add([string]$_) }
        }
        if ($startupFailures.Count) { throw "Parallel startup failed: $($startupFailures -join ' | ')" }
        Wait-ProgramSplitProbe -Probe { Test-TunnelDns -TimeoutMilliseconds 750 } `
            -TimeoutMilliseconds 20000 -RetryMilliseconds 250
        Write-ControllerLog 'Enabling local split-DNS NRPT rule.'
        Invoke-Component 'Invoke-LocalNrpt.ps1' 'Enable'
        if ($dispatcherWasRunning) {
            Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Validate'
        } else { Test-LocalDns }
        Write-ControllerLog 'Starting per-application WFP filters.'
        Invoke-Component 'Invoke-WfpFilters.ps1' 'Start'
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
if (-not @(Get-Content -LiteralPath $includeFile | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })) {
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
$lastHealth = [DateTime]::MinValue
$nextRepair = [DateTime]::MinValue
$repairDelaySeconds = 2
$nextCleanup = [DateTime]::MinValue
$cleanupDelaySeconds = 2
$stopRequestedAt = $null
$stopCleanupWindow = [TimeSpan]::FromSeconds(150)
$networkWaitLogged = $false
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
                $stopRequestedAt = Get-Date
            }
            # The service host force-ends this process four minutes after the stop control. Retry
            # incomplete cleanup, but check the window after each attempt, which can itself take most
            # of a minute, so the failure is thrown and logged here instead of arriving as a forced end.
            try { Stop-Stack -RestoreCache -ThrowOnFailure }
            catch {
                if ((Get-Date) - $stopRequestedAt -ge $stopCleanupWindow) { throw }
                Write-ControllerLog 'Service-stop cleanup incomplete; retrying.'
                Start-Sleep -Seconds 2
                continue
            }
            if (Test-StackPresent) {
                if ((Get-Date) - $stopRequestedAt -ge $stopCleanupWindow) {
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
            $nextCleanup = [DateTime]::MinValue
            $cleanupDelaySeconds = 2
            try { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
            catch {
                Write-ControllerLog $_.Exception.Message
                Start-Sleep -Seconds 2
                continue
            }
        }
        if (-not $desired) {
            if ((Test-StackPresent) -and (Get-Date) -ge $nextCleanup) {
                try {
                    Stop-Stack -RestoreCache -ThrowOnFailure
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
                    $nextCleanup = (Get-Date).AddSeconds($cleanupDelaySeconds)
                    $cleanupDelaySeconds = [Math]::Min(60, $cleanupDelaySeconds * 2)
                }
            }
            if (-not (Test-StackPresent)) {
                if (-not (Test-Path -LiteralPath $stackStoppedFile -PathType Leaf)) {
                    try { [IO.File]::WriteAllText($stackStoppedFile, (Get-Date -Format o)) }
                    catch { Write-ControllerLog $_.Exception.Message }
                }
            } else {
                Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
            }
        } elseif (Test-Path -LiteralPath $reloadFile) {
            Remove-Item -LiteralPath $reloadFile -Force -ErrorAction SilentlyContinue
            Stop-Stack
            Invoke-Repair
            $lastHealth = Get-Date
        } elseif (-not (Test-StackActive)) {
            # Cold boot may have pre-started the WireGuard service; Start-Stack adopts it.
            Invoke-Repair
            $lastHealth = Get-Date
        } elseif ((Get-Date) - $lastHealth -gt [TimeSpan]::FromSeconds(30)) {
            try {
                try { Test-StackHealth }
                catch { Start-Sleep -Milliseconds 250; Test-StackHealth }
            } catch {
                Write-ControllerLog "Stack health check failed; restarting the stack: $($_.Exception.Message)"
                Stop-Stack
                Invoke-Repair
            }
            $lastHealth = Get-Date
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
    if ($stopEvent) { $stopEvent.Dispose() }
    if ($mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
