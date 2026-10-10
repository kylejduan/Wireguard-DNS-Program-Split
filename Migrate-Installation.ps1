# SPDX-License-Identifier: GPL-3.0-or-later
# Relocate an active legacy installation without regenerating its private configuration.
[CmdletBinding()]
param(
    [string] $SourceRoot = (Join-Path $env:ProgramData 'WireGuardProgramSplit'),
    [string] $DestinationRoot = (Join-Path $env:ProgramFiles 'WireGuardProgramSplit'),
    [switch] $PlanOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'src\powershell\Common.ps1')
Assert-ProgramSplit64BitPowerShell
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run Migrate-Installation.ps1 from elevated Windows PowerShell.'
}
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
$DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\')
if ($SourceRoot -eq $DestinationRoot -or
    $DestinationRoot.StartsWith($SourceRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetPathRoot($DestinationRoot).TrimEnd('\') -eq $DestinationRoot -or
    [IO.Path]::GetPathRoot($SourceRoot) -ne [IO.Path]::GetPathRoot($DestinationRoot)) {
    throw 'Migration requires distinct, non-nested directories on the same volume.'
}
if (Test-Path -LiteralPath $DestinationRoot) { throw 'Migration destination already exists.' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $DestinationRoot) -PathType Container)) {
    throw 'The destination parent must already exist.'
}
$mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitInstall')
$held = $false
$stopped = $false
$moved = $false
$starting = $false
$activeRoot = $SourceRoot
$controllerName = 'WireGuardProgramSplitController'
$tunnelName = 'WireGuardTunnel$WireGuardSplit'
$trayName = 'WireGuard Program Split Tray'
$scriptNames = @('Common.ps1', 'Controller.ps1', 'Invoke-Tunnel.ps1')
$backupRelative = 'state\migration-backup-' + [guid]::NewGuid().ToString('N')

function Set-ServiceCommand([string] $Name, [string] $Command) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{ PathName = $Command }
    if ($result.ReturnValue -ne 0) { throw "Service path update failed for $Name ($($result.ReturnValue))." }
    if ((Get-CimInstance Win32_Service -Filter "Name='$Name'").PathName -cne $Command) {
        throw "Service path readback failed for $Name."
    }
}
function Stop-Stack {
    Set-Service -Name $controllerName -StartupType Disabled
    Stop-ScheduledTask -TaskName $trayName -TaskPath '\'
    $service = Get-Service -Name $controllerName
    if ($service.Status -ne 'Stopped') {
        if ($service.Status -ne 'StopPending') { $service.Stop() }
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(250))
    }
    $service.Dispose()
    # Complete the normal cleanup if the controller left a component behind.
    foreach ($name in @('Invoke-WfpFilters.ps1', 'Invoke-LocalNrpt.ps1',
            'Invoke-DnsDispatcher.ps1', 'Invoke-Tunnel.ps1')) {
        $action = if ($name -eq 'Invoke-LocalNrpt.ps1') { 'Disable' } else { 'Stop' }
        & (Join-Path $activeRoot "src\$name") -Action $action | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $remaining = @(Get-CimInstance Win32_Process | Where-Object {
            ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($activeRoot + '\',
                [StringComparison]::OrdinalIgnoreCase)) -or
            ($_.Name -eq 'powershell.exe' -and $_.CommandLine -and
                $_.CommandLine.IndexOf($activeRoot + '\src\', [StringComparison]::OrdinalIgnoreCase) -ge 0)
        })
        if (-not $remaining) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Installed processes remain after the ordered stop; refusing to move files.'
}
function Start-And-Validate {
    Set-Service -Name $controllerName -StartupType Automatic
    Start-Service -Name $controllerName
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    while (-not (Test-Path -LiteralPath (Join-Path $activeRoot 'state\active'))) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Controller did not activate after relocation.' }
        Start-Sleep -Milliseconds 500
    }
    foreach ($name in @('Invoke-Tunnel.ps1', 'Invoke-LocalNrpt.ps1', 'Invoke-DnsDispatcher.ps1')) {
        & (Join-Path $activeRoot "src\$name") -Action Validate | Out-Null
    }
    Start-ScheduledTask -TaskName $trayName -TaskPath '\'
}
try {
    try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { throw 'Another installation or migration is running.' }
    $marker = Get-Content -LiteralPath (Join-Path $SourceRoot 'state\installation.json') -Raw | ConvertFrom-Json
    if ($marker.Product -ne 'WireGuardProgramSplit' -or $marker.Schema -ne 1) {
        throw 'Source installation ownership marker is invalid.'
    }
    # A same-volume rename preserves the protected tree ACL; do not traverse redirected paths.
    foreach ($path in @($SourceRoot, (Split-Path -Parent $DestinationRoot))) {
        $item = Get-Item -LiteralPath $path
        while ($item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point roots are not supported.' }
            $item = $item.Parent
        }
    }
    if (Get-ChildItem -LiteralPath $SourceRoot -Recurse -Force | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
        throw 'Source tree contains a reparse point.'
    }
    $sourceAcl = (Get-Acl -LiteralPath $SourceRoot).Sddl
    $controller = Get-CimInstance Win32_Service -Filter "Name='$controllerName'"
    $tunnel = Get-CimInstance Win32_Service -Filter "Name='$tunnelName'"
    foreach ($spec in @(@($controller, 'controller-service.exe', 'src\Controller.ps1'),
            @($tunnel, 'tunnel-host.exe', 'profiles\WireGuardSplit.conf'))) {
        if (-not $spec[0] -or -not (Test-ProgramSplitServiceOwnership -Service $spec[0] `
                -HostPath (Join-Path $SourceRoot "bin\$($spec[1])") -ArgumentPath (Join-Path $SourceRoot $spec[2]))) {
            throw 'A managed service is missing or its command belongs to a different installation.'
        }
    }
    if ($controller.State -ne 'Running' -or $controller.StartMode -ne 'Auto' -or
        $tunnel.State -ne 'Running' -or $tunnel.StartMode -ne 'Manual' -or
        -not (Test-Path -LiteralPath (Join-Path $SourceRoot 'state\enabled'))) {
        throw 'Migration requires an enabled, running installation with an Automatic controller and Manual tunnel.'
    }
    if (Get-ScheduledTask -TaskName 'WireGuard Program Split Controller' -TaskPath '\' -ErrorAction SilentlyContinue) {
        throw 'Upgrade the legacy controller scheduled task to a service before relocating.'
    }
    $tray = Get-ScheduledTask -TaskName $trayName -TaskPath '\'
    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-ProgramSplitTaskOwnership -Task $tray -PowerShellPath $powerShell `
            -ScriptPath (Join-Path $SourceRoot 'src\Tray.ps1'))) { throw 'Tray task ownership mismatch.' }
    $hashes = @{}
    foreach ($relative in @('config\settings.json', 'profiles\WireGuardSplit.conf',
            'state\included-apps.txt', 'state\enabled', 'state\installation.json')) {
        $hashes[$relative] = (Get-FileHash -LiteralPath (Join-Path $SourceRoot $relative)).Hash
    }
    foreach ($name in $scriptNames) {
        foreach ($path in @((Join-Path $SourceRoot "src\$name"),
                (Join-Path $PSScriptRoot "src\powershell\$name"))) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing migration input: $path" }
        }
    }
    $plan = [pscustomobject]@{ SourceRoot = $SourceRoot; DestinationRoot = $DestinationRoot
        ScriptBackup = Join-Path $DestinationRoot $backupRelative; ServicesRestarted = @($controllerName, $tunnelName) }
    if ($PlanOnly) { return $plan }
    # Keep original scripts inside the protected tree for rollback and later inspection.
    $backup = Join-Path $SourceRoot $backupRelative
    [IO.Directory]::CreateDirectory($backup) | Out-Null
    foreach ($name in $scriptNames) { Copy-Item -LiteralPath (Join-Path $SourceRoot "src\$name") -Destination $backup }
    $stopped = $true
    Stop-Stack
    Move-Item -LiteralPath $SourceRoot -Destination $DestinationRoot
    $moved = $true
    $activeRoot = $DestinationRoot
    if ((Get-Acl -LiteralPath $activeRoot).Sddl -cne $sourceAcl) { throw 'Root permissions changed during the move.' }
    foreach ($name in $scriptNames) {
        $target = Join-Path $activeRoot "src\$name"
        $acl = Get-Acl -LiteralPath $target
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "src\powershell\$name") -Destination $target -Force
        Set-Acl -LiteralPath $target -AclObject $acl
    }
    Set-ServiceCommand $controllerName (Get-ProgramSplitServiceCommand `
        -HostPath (Join-Path $activeRoot 'bin\controller-service.exe') -ArgumentPath (Join-Path $activeRoot 'src\Controller.ps1'))
    Set-ServiceCommand $tunnelName (Get-ProgramSplitServiceCommand `
        -HostPath (Join-Path $activeRoot 'bin\tunnel-host.exe') -ArgumentPath (Join-Path $activeRoot 'profiles\WireGuardSplit.conf'))
    $action = New-ScheduledTaskAction -Execute $powerShell -Argument (
        Get-ProgramSplitTaskArguments -ScriptPath (Join-Path $activeRoot 'src\Tray.ps1'))
    Set-ScheduledTask -TaskName $trayName -TaskPath '\' -Action $action | Out-Null
    foreach ($relative in $hashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $activeRoot $relative)).Hash -ne $hashes[$relative]) {
            throw "Preserved configuration hash mismatch: $relative"
        }
    }
    $starting = $true
    Start-And-Validate
    $plan
} catch {
    $failure = $_
    if ($stopped) {
        try {
            if ($moved) {
                if ($starting) { Stop-Stack }
                Move-Item -LiteralPath $DestinationRoot -Destination $SourceRoot
                $activeRoot = $SourceRoot
                foreach ($name in $scriptNames) {
                    Copy-Item -LiteralPath (Join-Path $SourceRoot "$backupRelative\$name") `
                        -Destination (Join-Path $SourceRoot "src\$name") -Force
                }
            }
            Set-ServiceCommand $controllerName $controller.PathName
            Set-ServiceCommand $tunnelName $tunnel.PathName
            Set-ScheduledTask -TaskName $trayName -TaskPath '\' -Action $tray.Actions | Out-Null
            Start-And-Validate
        } catch { throw "Migration failed: $($failure.Exception.Message). Rollback failed: $($_.Exception.Message). Inspect $activeRoot." }
    }
    throw $failure
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
