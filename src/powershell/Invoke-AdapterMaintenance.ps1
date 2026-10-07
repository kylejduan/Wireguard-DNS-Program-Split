# SPDX-License-Identifier: GPL-3.0-or-later
param([ValidateSet('Status', 'Repair')] [string] $Action = 'Status')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'AdapterMaintenance.ps1')
Assert-ProgramSplit64BitPowerShell

$mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitAdapterMaintenance')
$held = $false
try {
    try { $held = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { Write-Output 'Adapter maintenance is already running.'; return }
    if ($Action -eq 'Repair') {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Adapter repair requires Administrator rights.'
        }
        $marker = Get-Content -LiteralPath (Join-Path $root 'state\installation.json') -Raw | ConvertFrom-Json
        if ($marker.Product -ne 'WireGuardProgramSplit' -or $marker.Schema -ne 1) {
            throw 'Invalid installation ownership marker.'
        }
        $configuration = Get-ProgramSplitConfiguration -Root $root
        $service = Get-CimInstance Win32_Service -Filter "Name='$($configuration.ServiceName)'" -ErrorAction Stop
        if (-not $service -or $service.State -ne 'Running' -or
            -not (Test-ProgramSplitServiceOwnership -Service $service `
                -HostPath (Join-Path $root 'bin\tunnel-host.exe') -ArgumentPath $configuration.ProfilePath)) {
            throw 'Adapter repair requires the owned tunnel service to be running.'
        }
        $active = Get-NetAdapter -Name $configuration.AdapterName -ErrorAction Stop
        if ($active.Status -ne 'Up' -or $active.PnPDeviceID -notmatch '^SWD\\WireGuard\\\{[0-9a-f-]+\}$') {
            throw 'Adapter repair requires a healthy software-enumerated split tunnel.'
        }
    }
    Invoke-ProgramSplitAdapterMaintenance -Root $root -Repair:($Action -eq 'Repair')
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
