# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [string] $Root = (Join-Path $env:ProgramFiles 'WireGuardProgramSplit'),
    [ValidateRange(1, 60)] [int] $SampleSeconds = 60
)

# Read-only operator diagnostics. In particular, this never toggles an offload,
# stops a driver/service, flushes DNS, or opens the private VPN profile.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from elevated Windows PowerShell so process ownership and CPU accounting are complete.'
}
$Root = [IO.Path]::GetFullPath($Root).TrimEnd('\')
$prefix = $Root + '\'
$records = @(Get-CimInstance Win32_Process)
$validationWorkerPresent = @($records | Where-Object {
    $_.Name -eq 'powershell.exe' -and $_.CommandLine -and
    $_.CommandLine.IndexOf($prefix + 'src\ValidationWorker.ps1', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
    $_.CommandLine -match '(?i)(?:^|\s)-Serve(?:\s|$)'
}).Count -gt 0
$owned = @{}
$recordsById = @{}
foreach ($record in $records) {
    $recordsById[[int]$record.ProcessId] = $record
    if (($record.ExecutablePath -and $record.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) -or
        ($record.Name -eq 'powershell.exe' -and $record.CommandLine -and
         $record.CommandLine.IndexOf($prefix + 'src\', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
         $record.ProcessId -ne $PID)) {
        $owned[[int]$record.ProcessId] = $true
    }
}
do {
    $added = $false
    foreach ($record in $records) {
        $parent = $recordsById[[int]$record.ParentProcessId]
        # ParentProcessId survives the parent's exit and can name a recycled PID.
        if ($owned.ContainsKey([int]$record.ParentProcessId) -and -not $owned.ContainsKey([int]$record.ProcessId) -and
            $parent -and $parent.CreationDate -and $record.CreationDate -and
            $record.CreationDate -ge $parent.CreationDate) {
            $owned[[int]$record.ProcessId] = $true
            $added = $true
        }
    }
} while ($added)

$samples = @()
$processes = @()
$unobserved = @()
try {
    foreach ($record in $records) {
        if (-not $owned.ContainsKey([int]$record.ProcessId)) { continue }
        $process = $null
        try {
            $process = Get-Process -Id $record.ProcessId -ErrorAction Stop
            $null = $process.Handle
            # CIM's creation timestamp can have less precision than GetProcessTimes.
            if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $record.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 1) {
                throw 'Process identity changed after the ownership snapshot.'
            }
            $processes += [pscustomobject]@{
                Process = $process; Name = $process.ProcessName; Id = $process.Id
                Cpu = $process.TotalProcessorTime.TotalSeconds
            }
        } catch {
            $unobserved += [pscustomobject]@{ Id = $record.ProcessId; Stage = 'Start'; Detail = $_.Exception.Message }
            if ($process) { $process.Dispose() }
        }
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds $SampleSeconds
    $timer.Stop()
    foreach ($entry in $processes) {
        $process = $entry.Process
        try {
            $process.Refresh()
            if ($process.HasExited) { throw 'Process exited during the sample.' }
            $samples += [pscustomobject]@{
                Name = $entry.Name; Id = $entry.Id
                OneCorePercent = 100 * ($process.TotalProcessorTime.TotalSeconds - $entry.Cpu) / $timer.Elapsed.TotalSeconds
                PrivateMiB = $process.PrivateMemorySize64 / 1MB
            }
        } catch {
            $unobserved += [pscustomobject]@{ Id = $entry.Id; Stage = 'End'; Detail = $_.Exception.Message }
        }
    }
} finally {
    foreach ($entry in $processes) { $entry.Process.Dispose() }
}

$rsc = @(foreach ($adapter in Get-NetAdapter -Physical | Where-Object Status -eq 'Up') {
    try {
        $state = Get-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop
        [pscustomobject]@{
            Name = $adapter.Name; LinkSpeed = [string]$adapter.LinkSpeed; Available = $true
            IPv4Enabled = [bool]$state.IPv4Enabled; IPv6Enabled = [bool]$state.IPv6Enabled
            IPv4Operational = [bool]$state.IPv4OperationalState; IPv6Operational = [bool]$state.IPv6OperationalState
            IPv4Reason = [string]$state.IPv4FailureReason; IPv6Reason = [string]$state.IPv6FailureReason
        }
    } catch {
        [pscustomobject]@{ Name = $adapter.Name; Available = $false; Detail = $_.Exception.Message }
    }
})
$notes = @(
    'CPU/private memory cover product processes and descendants present at sample start that are still running at the end. CPU includes their own user/kernel time; system-wide driver/DPC/interrupt work, work in other processes, and transient helpers are not measured.',
    'Wait about a minute after activation, then check ValidationWorkerPresentAtStart. A 60-second sample usually spans periodic health checks; a failed validation can dispose the worker.',
    'A service-off test leaves shared kernel drivers loaded. It cannot rule out a driver-level receive-offload cost.'
)
if (-not $validationWorkerPresent) {
    $notes += 'The validation worker was absent at sample start. This is not a complete warm steady-state process sample; wait for a completed periodic health check before comparing persistent process overhead.'
}
if (@($rsc | Where-Object { $_.Available -and
    ($_.IPv4Reason -eq 'WFPCompatibility' -or $_.IPv6Reason -eq 'WFPCompatibility') }).Count) {
    $notes += 'RSC is restricted by WFP compatibility. This may affect direct TCP receive performance; this observation does not identify which callout/provider is responsible. Check other security/VPN filters too. Do not force offloads or alter kernel callout flags.'
}
$oneCore = ($samples | Measure-Object -Property OneCorePercent -Sum).Sum
[pscustomobject]@{
    TimeUtc = [DateTime]::UtcNow.ToString('o'); SampleSeconds = $timer.Elapsed.TotalSeconds
    LogicalProcessors = [Environment]::ProcessorCount; OneCorePercent = $oneCore
    ValidationWorkerPresentAtStart = $validationWorkerPresent
    MachinePercent = $oneCore / [Environment]::ProcessorCount
    PrivateMiB = ($samples | Measure-Object -Property PrivateMiB -Sum).Sum
    Processes = $samples; UnobservedProcesses = $unobserved; PhysicalRsc = $rsc
    KernelDrivers = @(Get-CimInstance Win32_SystemDriver | Where-Object Name -in @('PiaWFPCallout', 'WireGuard') |
        Select-Object Name, State, StartMode)
    Notes = $notes
} | ConvertTo-Json -Depth 5
