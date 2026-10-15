# SPDX-License-Identifier: GPL-3.0-or-later
# Persistent WFP payload filters. Start installs or replaces the whole set in one transaction; it survives
# this script, the controller, a BFE restart and a reboot until Stop removes it. Status and Validate read.
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
# Removal reads no configuration: a missing or corrupt settings file or list must not keep the filters.
if (-not $IncludedAppsFile) { $IncludedAppsFile = Join-Path $root 'state\included-apps.txt' }
$exe = Join-Path $root 'bin\wfp-probe.exe'
# Written before an install and removed only after a complete removal, so it is present whenever owned
# objects may exist. The controller's per-pass check reads it instead of querying the filter engine.
$installedFile = Join-Path $root 'state\wfp-filters.installed'
# Earlier releases kept wfp-probe.exe running to own a dynamic session and recorded its process here.
$legacyPidFile = Join-Path $root 'state\wfp-filters.pid'
$log = Join-Path $root 'logs\wfp-filters.log'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Stop-LegacyHosts {
    # A dynamic-session host from an earlier release holds the PIA callout keys until it exits. The modes
    # this script runs are short-lived and serialized by the component lock, so they are left alone.
    $stopped = $false
    foreach ($process in @(Get-Process -Name 'wfp-probe' -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $exe
    })) {
        $record = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction SilentlyContinue
        if ($record -and [string]$record.CommandLine -match '^\s*("[^"]*"|\S+)\s+(install|verify|remove|status)\b') { continue }
        Stop-Process -Id $process.Id -Force
        if (-not $process.WaitForExit(10000)) { throw "Legacy WFP filter host $($process.Id) did not stop." }
        $stopped = $true
    }
    if (Test-Path -LiteralPath $legacyPidFile) { [IO.File]::Delete($legacyPidFile) }
    return $stopped
}

function Invoke-Probe([string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($exe, ($Arguments -join ' '))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch { }
            throw "wfp-probe.exe $($Arguments[0]) timed out."
        }
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $output.Result.Trim()
            Error = $errors.Result.Trim()
        }
    } finally { $process.Dispose() }
}

function Get-IncludedPaths {
    foreach ($path in @($exe, $IncludedAppsFile)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing WFP input: $path" }
    }
    # An absent executable is reported by wfp-probe.exe and keeps no filters; the others are unaffected.
    $includedPaths = @([IO.File]::ReadAllLines($IncludedAppsFile) |
        ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    if (-not $includedPaths) { throw 'The included-app list is empty.' }
    $includedPaths
}

function Get-ProbeWarnings($Result) {
    @($Result.Output -split "`r?`n" | Where-Object { $_ -like 'WARNING: *' } | ForEach-Object { $_.Substring(9) })
}

function Get-ProbeReport($Result) {
    (@($Result.Output -split "`r?`n" | Where-Object { $_ -and $_ -notlike 'WARNING: *' }) -join ' ')
}

if ($Action -eq 'Status') {
    if (Test-Path -LiteralPath $installedFile -PathType Leaf) {
        Write-Output 'Persistent WFP payload filters are installed; -Action Validate checks them against the included-app list.'
    } else { Write-Output 'Persistent WFP payload filters are not installed.' }
    exit 0
}

Assert-Administrator

$componentMutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitWfpComponent')
$mutexHeld = $false
try {
    try { $mutexHeld = $componentMutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) { throw 'Timed out waiting for the WFP component lock.' }

if ($Action -eq 'Stop') {
    $null = Stop-LegacyHosts
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        if (Test-Path -LiteralPath $installedFile) { throw "Missing WFP input: $exe" }
        Write-Output 'Persistent WFP payload filters are not installed.'
        exit 0
    }
    $result = Invoke-Probe @('remove')
    # A best-effort copy: a reader holding the log open must not fail the filters.
    try { [IO.File]::WriteAllText($log, (@($result.Output, $result.Error) -join [Environment]::NewLine)) } catch { }
    if ($result.ExitCode -ne 0) { throw "WFP filter removal failed with code $($result.ExitCode): $($result.Error)" }
    if (Test-Path -LiteralPath $installedFile) { [IO.File]::Delete($installedFile) }
    Write-Output 'Persistent WFP payload filters removed.'
    exit 0
}

$configuration = Get-ProgramSplitConfiguration -Root $root
$null = @(Get-IncludedPaths)
$inputs = @(('"{0}"' -f $IncludedAppsFile), $configuration.TunnelAddress)

if ($Action -eq 'Validate') {
    $result = Invoke-Probe (@('verify') + $inputs)
    if ($result.ExitCode -ne 0) { throw "Persistent WFP payload filters failed verification: $($result.Error)" }
    if (-not (Test-Path -LiteralPath $installedFile -PathType Leaf)) { throw 'The WFP filter installation marker is missing.' }
    # The supervisor logs a warning once per change; a returning executable fails verification instead.
    foreach ($warning in Get-ProbeWarnings $result) { Write-Warning $warning }
    Write-Output (Get-ProbeReport $result)
    exit 0
}

# Start: a redirect to the tunnel address is safe before the tunnel or PIA driver is up. Selected
# applications cannot connect until both are, instead of leaving on the physical route.
[IO.File]::WriteAllText($installedFile, (Get-Date -Format o))
$result = Invoke-Probe (@('install') + $inputs)
# An earlier release's filter host still owns the PIA callouts, so install committed the blocks without the
# redirect. The host's dynamic redirect uses the same tunnel address and passes those blocks; stop it only
# now, and finish once BFE has ended its session. A failed install leaves the host running.
if ($result.ExitCode -eq 3 -and (Stop-LegacyHosts)) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $result = Invoke-Probe (@('install') + $inputs)
        if ($result.ExitCode -ne 3) { break }
        Start-Sleep -Milliseconds 250
    } while ($timer.Elapsed.TotalSeconds -lt 10)
}
try { [IO.File]::WriteAllText($log, (@($result.Output, $result.Error) -join [Environment]::NewLine)) } catch { }
if ($result.ExitCode -ne 0) { throw "WFP filter installation failed with code $($result.ExitCode): $($result.Error)" }
# Component output is logged as it is; a warning stream would read as a failure there.
Write-Output $result.Output
$null = Stop-LegacyHosts
} finally {
    if ($mutexHeld) { $componentMutex.ReleaseMutex() }
    $componentMutex.Dispose()
}
