[CmdletBinding()]
param(
    [string] $DestinationRoot = 'C:\ProgramData\WireGuardProgramSplit',
    [switch] $PlanOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($DestinationRoot -match '\s') { throw 'DestinationRoot cannot contain whitespace.' }

$plan = [pscustomobject]@{
    DestinationRoot = $DestinationRoot
    ServiceName = 'WireGuardTunnel$WireGuardSplit'
    ControllerTask = 'WireGuard Program Split Controller'
    TrayTask = 'WireGuard Program Split Tray'
    RemovePiaDriver = $false
}
if ($PlanOnly) { return $plan }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run Uninstall.ps1 from an elevated Windows PowerShell session.'
}

$fullRoot = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\')
if ([IO.Path]::GetPathRoot($fullRoot).TrimEnd('\') -eq $fullRoot) {
    throw 'Refusing to uninstall from a filesystem root.'
}
if (Test-Path -LiteralPath $fullRoot) {
    $markerPath = Join-Path $fullRoot 'state\installation.json'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'Refusing to remove a directory without the WireGuard Program Split ownership marker.'
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.Product -ne 'WireGuardProgramSplit' -or $marker.Schema -ne 1) {
        throw 'The installation ownership marker is invalid.'
    }
}

foreach ($taskName in @($plan.ControllerTask, $plan.TrayTask)) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
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

$service = Get-Service -Name $plan.ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
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
