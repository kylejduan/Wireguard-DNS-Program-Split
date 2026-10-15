# SPDX-License-Identifier: GPL-3.0-or-later
# The dispatcher reads its inputs from state files and reloads them in place; controller-service.exe keeps
# it running while state\dns-dispatcher.supervised exists. Start writes the inputs and confirms the running
# dispatcher has loaded them, so repairs and included-app reloads never stop it. Stop ends supervision.
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
$stdout = Join-Path $root 'logs\dns-dispatcher-ready.log'
$diagnostics = Join-Path $root 'logs\dns-dispatcher.log'
$stderr = Join-Path $root 'logs\dns-dispatcher-error.log'
$networkState = Join-Path $root 'state\direct-network.json'
$inputsFile = Join-Path $root 'state\dns-dispatcher-inputs.txt'
$supervisedFile = Join-Path $root 'state\dns-dispatcher.supervised'
$statusFile = Join-Path $root 'state\dns-dispatcher-status.txt'
$loadedInputs = Join-Path $root 'state\dns-dispatcher-loaded-inputs.txt'
$traceState = Join-Path $root 'state\dns-etw-session.txt'
$healthOut = Join-Path $root 'logs\dns-dispatcher-health.log'
# wfp-probe.exe's identity record, and the copy the dispatcher last loaded. Attribution and the payload
# filters therefore share one resolution of the included-app list.
$identities = Join-Path $root 'state\resolved-identities.tsv'
$loadedIdentities = Join-Path $root 'state\dns-dispatcher-loaded-identities.tsv'
$healthError = Join-Path $root 'logs\dns-dispatcher-health-error.log'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-ManagedProcess {
    # The pid record, or if it was lost the process that published the loaded inputs (the supervisor
    # republishes the record); either counts only with the exact image path.
    foreach ($record in @($pidFile, $statusFile)) {
        $text = try { [IO.File]::ReadAllText($record) } catch { '' }
        $managedPid = 0
        if ($text -notmatch '^(?:pid=)?(\d{1,10})\r?(?:\n|$)' -or -not [int]::TryParse($Matches[1], [ref]$managedPid)) { continue }
        $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
        if ($process -and $process.ProcessName -eq 'dns-dispatcher' -and [string]$process.Path -eq $exe) {
            return $process
        }
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
        if (-not $process.WaitForExit(10000)) { throw "DNS dispatcher $($process.Id) did not stop." }
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

function Read-Bytes([string] $Path) {
    try { [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) } catch { $null }
}

# Ready with the current inputs: the managed process published them, under its own process ID.
function Test-LoadedInputs($Process) {
    if (-not $Process) { return $false }
    $status = try { [IO.File]::ReadAllText($statusFile) } catch { '' }
    if ($status -notmatch "(?m)^pid=$($Process.Id)\r?$") { return $false }
    $current = Read-Bytes $inputsFile
    $identity = Read-Bytes $identities
    return $current -and $identity -and $current -ceq (Read-Bytes $loadedInputs) -and $identity -ceq (Read-Bytes $loadedIdentities)
}

function Request-Reload {
    try {
        $event = [Threading.EventWaitHandle]::OpenExisting('Global\WireGuardProgramSplitDispatcherReload')
        try { $null = $event.Set() } finally { $event.Dispose() }
    } catch { }
}

function Get-DirectNetwork {
    $physical = Get-ProgramSplitPhysicalDefault -AdapterName $configuration.AdapterName
    $source = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
    # Every listed resolver, in order: the dispatcher passes over one that stops answering.
    $resolvers = @(Get-ProgramSplitPhysicalResolvers -AdapterName $configuration.AdapterName -TunnelDns $configuration.TunnelDns `
        -InterfaceIndex $physical.InterfaceIndex)
    if (-not $source -or -not $resolvers.Count) { throw 'Physical source address or pre-dispatch DNS resolver is unavailable.' }
    [pscustomobject]@{ InterfaceIndex = $physical.InterfaceIndex; Source = $source; Resolver = ($resolvers -join ',') }
}

if ($Action -eq 'Status') {
    $process = Get-ManagedProcess
    if ($process) { [pscustomobject]@{ State = 'Running'; ProcessId = $process.Id; IncludedAppsFile = $IncludedAppsFile } }
    else { Write-Output 'DNS dispatcher is stopped.' }
    exit 0
}

if ($Action -eq 'Validate') {
    $process = Get-ManagedProcess
    $health = $null
    try {
        if (-not $process) { throw 'The managed DNS dispatcher process is unavailable.' }
        $traceNames = @(Get-OwnedTraceNames)
        if ($traceNames.Count -ne 1) { throw 'The managed DNS dispatcher must own exactly one ETW session.' }
        $udpEndpoint = Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -eq $process.Id }
        $tcpEndpoint = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 53 -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -eq $process.Id }
        if (-not $udpEndpoint -or -not $tcpEndpoint) { throw 'The managed DNS dispatcher does not own loopback port 53.' }
        if (-not (Test-ProgramSplitDispatcherAnswers)) { throw 'The managed DNS dispatcher does not answer its liveness query.' }
        if (-not (Test-LoadedInputs $process)) {
            throw 'The DNS dispatcher has not loaded the current inputs and resolved identities.'
        }
        $inputs = @{}
        foreach ($line in [IO.File]::ReadAllLines($inputsFile)) {
            $pair = $line -split '=', 2
            if ($pair.Count -eq 2) { $inputs[$pair[0]] = $pair[1] }
        }
        $current = Get-DirectNetwork
        if ($inputs['direct-source'] -ne $current.Source -or $inputs['direct-dns'] -ne $current.Resolver) {
            throw 'The active physical route, source address, or DNS resolver changed.'
        }
        # The probe's result comes through pipes; its log files are a best-effort copy, so a reader holding
        # one open cannot fail validation and turn into a repair.
        $health = Invoke-ProgramSplitProcess -FilePath (Join-Path $root 'bin\dns-probe.exe') -ArgumentList @('--system', 'example.com', 3) `
            -TimeoutMilliseconds 8000 -OutputLog $healthOut -ErrorLog $healthError
        if ($health.TimedOut) { throw 'Local split-DNS health probe timed out.' }
        if ($health.ExitCode -ne 0 -or -not ($health.Output -match '^PASS:')) {
            throw "Local split-DNS health probe failed: $($health.Output + $health.Error -join ' ')"
        }
        Write-Output 'PASS: dispatcher ownership, direct-network inputs, ETW attribution, and loopback DNS are healthy.'
        exit 0
    } finally {
        if ($process) { $process.Dispose() }
    }
}

Assert-Administrator

$componentMutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitDnsDispatcherComponent')
$mutexHeld = $false
try {
    try { $mutexHeld = $componentMutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) { throw 'Timed out waiting for the DNS dispatcher component lock.' }

if ($Action -eq 'Stop') {
    # Unlisted applications' DNS must not point at a stopped dispatcher: the rule goes first. Supervision
    # ends under the lock the supervisor takes, so it cannot start another dispatcher meanwhile.
    $nrpt = Join-Path $PSScriptRoot 'Invoke-LocalNrpt.ps1'
    if (Test-Path -LiteralPath $nrpt -PathType Leaf) { & $nrpt -Action Disable | Out-Null }
    Remove-Item -LiteralPath $supervisedFile -Force -ErrorAction SilentlyContinue
    $traceFailure = $null
    try { Stop-OwnedTrace } catch { $traceFailure = $_ }
    Stop-ExpectedProcesses
    Remove-Item -LiteralPath $pidFile, $statusFile, $networkState -Force -ErrorAction SilentlyContinue
    if ($traceFailure) { throw $traceFailure }
    Write-Output 'DNS dispatcher stopped.'
    exit 0
}

# Start: the identity record is written by the filter install, which therefore runs first.
foreach ($path in @($exe, $identities)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing dispatcher input: $path" }
}
$network = Get-DirectNetwork
$text = "# wgps-dispatcher-inputs 1`r`ndirect-source=$($network.Source)`r`ndirect-dns=$($network.Resolver)`r`n" +
    "tunnel-source=$($configuration.TunnelAddress)`r`ntunnel-dns=$($configuration.TunnelDns)`r`n"
$temporary = "$inputsFile.$PID.tmp"
[IO.File]::WriteAllText($temporary, $text, [Text.UTF8Encoding]::new($false))
# One rename, so the dispatcher reads the old inputs or the new ones; a reader can block it for a moment.
foreach ($attempt in 1..20) {
    try { Move-Item -LiteralPath $temporary -Destination $inputsFile -Force; break }
    catch { if ($attempt -eq 20) { throw } else { Start-Sleep -Milliseconds 50 } }
}
[IO.File]::WriteAllText($supervisedFile, (Get-Date -Format o))
# A running dispatcher that lost its ETW session or port, or does not answer, cannot recover by reloading;
# the supervisor starts a fresh one about a second after this one ends.
$running = Get-ManagedProcess
$published = $running -and ([string](Get-Content -LiteralPath $statusFile -Raw -ErrorAction SilentlyContinue)) -match "(?m)^pid=$($running.Id)\r?$"
if ($published -and (@(Get-OwnedTraceNames).Count -ne 1 -or -not (Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 `
        -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $running.Id }) -or
        -not (Test-ProgramSplitDispatcherAnswers))) {
    # It may have ended meanwhile, which is what this wants.
    Stop-Process -Id $running.Id -Force -ErrorAction SilentlyContinue
    $null = $running.WaitForExit(10000)
}
} finally {
    if ($mutexHeld) { $componentMutex.ReleaseMutex() }
    $componentMutex.Dispose()
}

# Outside the lock, which the supervisor needs to start a dispatcher.
$timer = [Diagnostics.Stopwatch]::StartNew()
$lastRequest = $null
while ($timer.Elapsed.TotalSeconds -lt 20) {
    $process = Get-ManagedProcess
    if (Test-LoadedInputs $process) {
        $count = @([IO.File]::ReadAllLines($loadedIdentities) | Where-Object { $_ -and -not $_.StartsWith('#') }).Count
        Write-Output "DNS dispatcher $($process.Id) ready with the current inputs for $count resolved included application(s)."
        exit 0
    }
    if ($process -and (-not $lastRequest -or $timer.Elapsed - $lastRequest -ge [TimeSpan]::FromSeconds(2))) {
        Request-Reload
        $lastRequest = $timer.Elapsed
    }
    Start-Sleep -Milliseconds 100
}
throw "The DNS dispatcher did not load the current inputs: $([string](Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue))"
