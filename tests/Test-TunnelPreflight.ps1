# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$tokens=$null; $errors=$null
$path = Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
$function = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-TunnelAfterPreflight'
},$true))
Assert-True ($function.Count -eq 1) 'one function owns the preflight-to-start sequence'
. ([scriptblock]::Create($function[0].Extent.Text))
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("wgps-preflight-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$helper = Join-Path $temporary 'Invoke-AdapterMaintenance.ps1'
[IO.File]::WriteAllText($helper, @'
param($Action)
if ($Action -ne 'BeforeStart') { throw 'Unexpected maintenance action' }
$global:wgpsTestEvents.Add('preflight')
if ($global:wgpsTestReject) { throw 'Orphan still exists' }
if ($global:wgpsTestRace) { $global:wgpsTestService.Status = 'Running' }
'@)
# Redirect only the helper lookup so the real sequencing function runs against an isolated fixture.
function Join-Path { param($Path,$ChildPath)
    if ($ChildPath -eq 'Invoke-AdapterMaintenance.ps1') { return $helper }
    Microsoft.PowerShell.Management\Join-Path $Path $ChildPath
}
$global:wgpsTestEvents = [Collections.Generic.List[string]]::new()
$global:wgpsTestReject = $false
$global:wgpsTestRace = $false
$global:wgpsTestService = [pscustomobject]@{Status='Stopped'}
$global:wgpsTestService | Add-Member ScriptMethod Refresh { }
$global:wgpsTestService | Add-Member ScriptMethod Start {
    $global:wgpsTestEvents.Add('start'); $this.Status = 'StartPending'
}
try {
    Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService
    Assert-True (($global:wgpsTestEvents -join ',') -eq 'preflight,start') 'cleanup finishes before the only service start'
    Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService
    $global:wgpsTestService.Status='Running'
    Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService
    Assert-True ($global:wgpsTestEvents.Count -eq 2) 'pending and running services are adopted without another creation'

    $global:wgpsTestService.Status='Stopped'; $global:wgpsTestEvents.Clear(); $global:wgpsTestReject=$true
    $blocked=$false
    try { Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService } catch { $blocked=$true }
    Assert-True ($blocked -and ($global:wgpsTestEvents -join ',') -eq 'preflight') 'failed cleanup cannot reach Start'

    $global:wgpsTestReject=$false; $global:wgpsTestRace=$true; $global:wgpsTestEvents.Clear()
    $blocked=$false
    try { Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService } catch { $blocked=$true }
    Assert-True ($blocked -and ($global:wgpsTestEvents -join ',') -eq 'preflight') 'a concurrent external start is detected after cleanup'

    $global:wgpsTestRace=$false; $global:wgpsTestService.Status='Stopped'; $global:wgpsTestEvents.Clear()
    Start-TunnelAfterPreflight -ServiceState $global:wgpsTestService
    Assert-True (($global:wgpsTestEvents -join ',') -eq 'preflight,start') 'failed attempts release the creation mutex for a later retry'
    $source=[IO.File]::ReadAllText($path)
    Assert-True ($source -match "'start=' 'demand'" -and $source -match 'Set-Service -Name \$serviceName -StartupType Manual' -and
        $source -notmatch "'start=' 'auto'|StartupType Automatic") 'SCM cannot bypass preflight through automatic tunnel startup'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
    Remove-Variable -Scope Global -Name wgpsTestEvents,wgpsTestReject,wgpsTestRace,wgpsTestService
}
Write-Output 'PASS: tunnel creation is serialized, preflight-gated, and idempotent.'
