# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [ValidateSet('Start', 'Stop', 'Status', 'Validate')]
    [string] $Action = 'Status',
    [string] $IncludedAppsFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-ProgramSplit64BitPowerShell
$configuration = Get-ProgramSplitConfiguration -Root $root
if (-not $IncludedAppsFile) { $IncludedAppsFile = Join-Path $root 'state\included-apps.txt' }
$exe = Join-Path $root 'bin\dns-dispatcher.exe'
$pidFile = Join-Path $root 'state\dns-dispatcher.pid'
$stdout = Join-Path $root 'logs\dns-dispatcher.log'
$stderr = Join-Path $root 'logs\dns-dispatcher-error.log'
$networkState = Join-Path $root 'state\direct-network.json'
$traceState = Join-Path $root 'state\dns-etw-session.txt'
$healthOut = Join-Path $root 'logs\dns-dispatcher-health.log'
$healthError = Join-Path $root 'logs\dns-dispatcher-health-error.log'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-ManagedProcess {
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { return $null }
    $managedPid = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($pidFile), [ref]$managedPid)) { return $null }
    $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq 'dns-dispatcher' -and [string]$process.Path -eq $exe) {
        return $process
    }
    return $null
}

function Get-ExpectedProcesses {
    @(Get-Process -Name 'dns-dispatcher' -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $exe
    })
}

function Stop-ExpectedProcesses {
    foreach ($process in @(Get-ExpectedProcesses)) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
}

function Get-OwnedTraceNames {
    $stateValue = if (Test-Path -LiteralPath $traceState -PathType Leaf) {
        [IO.File]::ReadAllText($traceState)
    } else { $null }
    $commandLines = foreach ($process in @(Get-ExpectedProcesses)) {
        $record = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction SilentlyContinue
        if ($record) { [string]$record.CommandLine }
    }
    @(Get-ProgramSplitOwnedTraceNames -StateValue $stateValue -CommandLines @($commandLines))
}

function Set-OwnedTraceState([string] $TraceName) {
    $temporary = "$traceState.$PID.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, $TraceName, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $traceState -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Stop-OwnedTrace {
    $traceNames = @(Get-OwnedTraceNames)
    $dispatcherPresent = @(Get-ExpectedProcesses).Count -gt 0
    if (-not $traceNames.Count) {
        if ($dispatcherPresent) { throw 'The running DNS dispatcher has no recoverable ETW session name.' }
        Remove-Item -LiteralPath $traceState -Force -ErrorAction SilentlyContinue
        return
    }
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($traceName in $traceNames) {
        & logman.exe stop $traceName -ets 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            if ($dispatcherPresent) { $failures.Add($traceName); continue }
            & logman.exe query $traceName -ets 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $failures.Add($traceName) }
        }
    }
    if ($failures.Count) { throw "Owned DNS ETW session could not be stopped: $($failures -join ', ')" }
    Remove-Item -LiteralPath $traceState -Force -ErrorAction SilentlyContinue
}

function Get-DirectNetwork {
    $physical = Get-ProgramSplitPhysicalDefault -AdapterName $configuration.AdapterName
    $source = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
    $resolver = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex).ServerAddresses |
        Where-Object { $_ -notin @('127.0.0.1', $configuration.TunnelDns) } | Select-Object -First 1
    if (-not $source -or -not $resolver) { throw 'Physical source address or pre-dispatch DNS resolver is unavailable.' }
    [pscustomobject]@{ InterfaceIndex = $physical.InterfaceIndex; Source = $source; Resolver = $resolver }
}

if ($Action -eq 'Status') {
    $process = Get-ManagedProcess
    if ($process) { [pscustomobject]@{ State = 'Running'; ProcessId = $process.Id; IncludedAppsFile = $IncludedAppsFile } }
    else { Write-Output 'DNS dispatcher is stopped.' }
    exit 0
}

if ($Action -eq 'Validate') {
    $process = Get-ManagedProcess
    if (-not $process) { throw 'The managed DNS dispatcher process is unavailable.' }
    $traceNames = @(Get-OwnedTraceNames)
    if ($traceNames.Count -ne 1) { throw 'The managed DNS dispatcher must own exactly one ETW session.' }
    $udpEndpoint = Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $process.Id }
    $tcpEndpoint = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 53 -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $process.Id }
    if (-not $udpEndpoint -or -not $tcpEndpoint) { throw 'The managed DNS dispatcher does not own loopback port 53.' }
    if (-not (Test-Path -LiteralPath $networkState -PathType Leaf)) { throw 'Direct-network state is missing.' }
    $saved = Get-Content -LiteralPath $networkState -Raw | ConvertFrom-Json
    $current = Get-DirectNetwork
    if ($saved.InterfaceIndex -ne $current.InterfaceIndex -or $saved.Source -ne $current.Source -or
        $saved.Resolver -ne $current.Resolver) {
        throw 'The active physical route, source address, or DNS resolver changed.'
    }
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $health = Start-Process -FilePath $probe -ArgumentList @('--system', 'example.com') `
        -RedirectStandardOutput $healthOut -RedirectStandardError $healthError -WindowStyle Hidden -PassThru
    $null = $health.Handle
    if (-not $health.WaitForExit(8000)) {
        Stop-Process -Id $health.Id -Force -ErrorAction SilentlyContinue
        throw 'Local split-DNS health probe timed out.'
    }
    $health.WaitForExit()
    $output = @(Get-Content -LiteralPath $healthOut -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $healthError -ErrorAction SilentlyContinue)
    if ($health.ExitCode -ne 0 -or -not ($output -match '^PASS:')) {
        throw "Local split-DNS health probe failed: $($output + $errors -join ' ')"
    }
    Write-Output 'PASS: dispatcher ownership, direct-network inputs, ETW attribution, and loopback DNS are healthy.'
    exit 0
}

Assert-Administrator

$componentMutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitDnsDispatcherComponent')
$mutexHeld = $false
try {
    try { $mutexHeld = $componentMutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) { throw 'Timed out waiting for the DNS dispatcher component lock.' }

if ($Action -eq 'Stop') {
    $wfp = Join-Path $PSScriptRoot 'Invoke-WfpFilters.ps1'
    if (Test-Path -LiteralPath $wfp -PathType Leaf) { & $wfp -Action Stop | Out-Null }
    $nrpt = Join-Path $PSScriptRoot 'Invoke-LocalNrpt.ps1'
    if (Test-Path -LiteralPath $nrpt -PathType Leaf) { & $nrpt -Action Disable | Out-Null }
    $traceFailure = $null
    try { Stop-OwnedTrace } catch { $traceFailure = $_ }
    Stop-ExpectedProcesses
    if (Test-Path -LiteralPath $pidFile) { [IO.File]::Delete($pidFile) }
    if (Test-Path -LiteralPath $networkState) { [IO.File]::Delete($networkState) }
    if ($traceFailure) { throw $traceFailure }
    Write-Output 'DNS dispatcher stopped.'
    exit 0
}

foreach ($path in @($exe, $IncludedAppsFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing dispatcher input: $path" }
}
$includedPaths = @(Get-Content -LiteralPath $IncludedAppsFile |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if (-not $includedPaths) { throw 'The included-app list is empty.' }
foreach ($path in $includedPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Included application does not exist: $path" }
}
$existing = Get-ManagedProcess
if ($existing) { Write-Output 'DNS dispatcher already running.'; exit 0 }
Stop-OwnedTrace
Stop-ExpectedProcesses

$network = Get-DirectNetwork
$source = $network.Source
$resolver = $network.Resolver
$traceName = "WireGuardProgramSplitDnsEtw-$([guid]::NewGuid().ToString('N'))"

[IO.Directory]::CreateDirectory((Split-Path -Parent $stdout)) | Out-Null
Set-OwnedTraceState -TraceName $traceName
$arguments = @($IncludedAppsFile, $source, $resolver, $configuration.TunnelAddress,
    $configuration.TunnelDns, $traceName)
$process = $null
$started = $false
try {
    [IO.File]::WriteAllText($stdout, '')
    [IO.File]::WriteAllText($stderr, '')
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    [IO.File]::WriteAllText($pidFile, [string]$process.Id)
    [IO.File]::WriteAllText($networkState, ($network | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ($process.HasExited) { throw "DNS dispatcher exited: $([IO.File]::ReadAllText($stderr))" }
        if ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) -match '(?m)^READY:') {
            $started = $true
            Write-Output "DNS dispatcher ready for $($includedPaths.Count) included application(s)."
            exit 0
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'DNS dispatcher did not become ready.'
} finally {
    if (-not $started) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        try { Stop-OwnedTrace } catch { }
        Remove-Item -LiteralPath $pidFile, $networkState -Force -ErrorAction SilentlyContinue
    }
}
} finally {
    if ($mutexHeld) { $componentMutex.ReleaseMutex() }
    $componentMutex.Dispose()
}
