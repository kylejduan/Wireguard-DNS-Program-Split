[CmdletBinding()]
param(
    [string] $DestinationRoot = 'C:\ProgramData\WireGuardProgramSplit',
    [switch] $PlanOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($DestinationRoot -match '\s') { throw 'DestinationRoot cannot contain whitespace.' }
. (Join-Path $PSScriptRoot 'src\powershell\Common.ps1')

$plan = [pscustomobject]@{
    DestinationRoot = $DestinationRoot
    ServiceName = 'WireGuardTunnel$WireGuardSplit'
    ControllerTask = 'WireGuard Program Split Controller'
    TrayTask = 'WireGuard Program Split Tray'
    RemovePiaDriver = $false
}
if ($PlanOnly) { return $plan }

$fullRoot = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\')
if ([IO.Path]::GetPathRoot($fullRoot).TrimEnd('\') -eq $fullRoot) {
    throw 'Refusing to uninstall from a filesystem root.'
}
if (-not (Test-Path -LiteralPath $fullRoot -PathType Container)) {
    Write-Output 'WireGuard Program Split is not installed; nothing was changed.'
    exit 0
}
$markerPath = Join-Path $fullRoot 'state\installation.json'
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    throw 'Refusing to remove a directory without the WireGuard Program Split ownership marker.'
}
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.Product -ne 'WireGuardProgramSplit' -or $marker.Schema -ne 1) {
    throw 'The installation ownership marker is invalid.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run Uninstall.ps1 from an elevated Windows PowerShell session.'
}

$powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$taskScripts = @{
    $plan.ControllerTask = Join-Path $fullRoot 'src\Controller.ps1'
    $plan.TrayTask = Join-Path $fullRoot 'src\Tray.ps1'
}
$ownedTasks = @{}
foreach ($taskName in @($plan.ControllerTask, $plan.TrayTask)) {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($task -and -not (Test-ProgramSplitTaskOwnership -Task $task -PowerShellPath $powerShell `
            -ScriptPath $taskScripts[$taskName])) {
        throw "Refusing to remove the same-name foreign scheduled task: $taskName"
    }
    if ($task) { $ownedTasks[$taskName] = $task }
}
$hostExe = Join-Path $fullRoot 'bin\tunnel-host.exe'
$profilePath = Join-Path $fullRoot 'profiles\WireGuardSplit.conf'
$serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$($plan.ServiceName)'" -ErrorAction SilentlyContinue
if ($serviceRecord -and -not (Test-ProgramSplitServiceOwnership -Service $serviceRecord `
        -HostPath $hostExe -ProfilePath $profilePath)) {
    throw 'Refusing to remove a same-name foreign tunnel service.'
}

foreach ($taskName in @($plan.ControllerTask, $plan.TrayTask)) {
    if ($ownedTasks.ContainsKey($taskName)) {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    }
}

$errors = [Collections.Generic.List[string]]::new()
function Invoke-Cleanup([string] $ScriptName, [string] $Action) {
    $script = Join-Path $fullRoot "src\$ScriptName"
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { return }
    try { & $script -Action $Action | Out-Null }
    catch { $script:errors.Add("$ScriptName $Action failed: $($_.Exception.Message)") }
}

Invoke-Cleanup 'Invoke-LocalNrpt.ps1' 'Disable'
Invoke-Cleanup 'Invoke-WfpFilters.ps1' 'Stop'
Invoke-Cleanup 'Invoke-DnsDispatcher.ps1' 'Stop'
Invoke-Cleanup 'Invoke-Tunnel.ps1' 'Stop'
Invoke-Cleanup 'Invoke-DnsCachePolicy.ps1' 'Disable'

$browserState = Join-Path $fullRoot 'state\browser-dns-policy-original.json'
if (Test-Path -LiteralPath $browserState -PathType Leaf) {
    Invoke-Cleanup 'Invoke-BrowserDnsPolicy.ps1' 'Disable'
}

$service = if ($serviceRecord) { Get-Service -Name $plan.ServiceName -ErrorAction SilentlyContinue }
if ($serviceRecord) {
    if ($service -and $service.Status -ne 'Stopped') {
        try { Stop-Service -Name $plan.ServiceName -Force -ErrorAction Stop }
        catch { $errors.Add("Tunnel service stop failed: $($_.Exception.Message)") }
    }
    if (-not $errors) {
        & sc.exe delete $plan.ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { $errors.Add('Tunnel service deletion failed.') }
    }
}

if ($errors) { throw ($errors -join [Environment]::NewLine) }
if (Test-Path -LiteralPath $fullRoot) { Remove-Item -LiteralPath $fullRoot -Recurse -Force }

Write-Output 'WireGuard Program Split was removed. The shared PIA WFP driver package was left installed.'
