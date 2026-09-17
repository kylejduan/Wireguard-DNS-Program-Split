# SPDX-License-Identifier: GPL-3.0-or-later
# Opt-in, elevated: runs the tunnel recovery functions from Invoke-Tunnel.ps1 against the real Service
# Control Manager using a throwaway service that hangs on purpose. It never touches the real tunnel.
param(
    [Parameter(Mandatory)] [string] $TunnelScript,
    [Parameter(Mandatory)] [string] $StubService
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    Write-Output "  ok: $Message"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this test from an elevated Windows PowerShell session.'
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($TunnelScript, [ref] $tokens, [ref] $parseErrors)
$functions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Get-OwnedServiceProcess', 'Reset-PendingService', 'Wait-ServiceRunning')
}, $true))
if ($functions.Count -ne 3) { throw 'The tunnel recovery functions were not found.' }
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

$suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$serviceName = "WgpsRecoveryTest$suffix"
$workDirectory = Join-Path $env:ProgramData "WgpsRecoveryTest-$suffix"
$hostExe = Join-Path $workDirectory 'pending-service.exe'
$adapterName = "WgpsNoAdapter$suffix"
$stuckHostSeconds = 8

function Set-StubMode([string] $mode) {
    $command = '"{0}" {1}' -f $hostExe, $mode
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        & sc.exe config $serviceName 'binPath=' $command | Out-Null
    } else {
        & sc.exe create $serviceName 'binPath=' $command 'type=' 'own' 'start=' 'demand' | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "sc.exe could not configure the throwaway service ($LASTEXITCODE)." }
}

function Get-StubProcess {
    Get-Process -Name 'pending-service' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Path -eq $hostExe }
}

function Start-StubPending {
    (Get-Service -Name $serviceName).Start()
    $service = Get-Service -Name $serviceName
    $deadline = (Get-Date).AddSeconds(10)
    while ($service.Status -ne 'StartPending' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200; $service.Refresh() }
    if ($service.Status -ne 'StartPending') { throw "The throwaway service is $($service.Status), not StartPending." }
}

try {
    [IO.Directory]::CreateDirectory($workDirectory) | Out-Null
    Copy-Item -LiteralPath $StubService -Destination $hostExe
    Write-Output 'Scenario 1: a service that never finishes starting'
    Set-StubMode 'start'
    Start-StubPending
    $stopRefused = $false
    try { (Get-Service -Name $serviceName).Stop() } catch { $stopRefused = $true }
    Assert-True $stopRefused 'Windows refuses a stop control while a service is StartPending (the premise of the reset)'

    $failure = $null
    try { Reset-PendingService -SettleSeconds 1 | Out-Null } catch { $failure = $_.Exception.Message }
    Assert-True ($failure -like '*still starting*' -and (Get-StubProcess)) 'a young starting host is refused and left alive'

    $failure = $null
    try { Wait-ServiceRunning -TimeoutSeconds 2 | Out-Null } catch { $failure = $_.Exception.Message }
    Assert-True ($failure -like '*next attempt can adopt it*' -and (Get-StubProcess)) `
        'the readiness wait leaves a slow start running for the next attempt'

    $realHost = $hostExe
    $hostExe = Join-Path $workDirectory 'some-other-host.exe'
    $failure = $null
    try { Reset-PendingService -SettleSeconds 0 | Out-Null } catch { $failure = $_.Exception.Message }
    $hostExe = $realHost
    Assert-True ($failure -like '*without an owned host process*' -and (Get-StubProcess)) `
        'a host at any other path is never terminated'

    Start-Sleep -Seconds $stuckHostSeconds
    $failure = $null
    $output = @()
    try { $output = @(Wait-ServiceRunning -TimeoutSeconds 1) } catch { $failure = $_.Exception.Message }
    Assert-True ($failure -like '*was reset so the next attempt starts clean*') 'a host pending past the limit is reset'
    Assert-True ((Get-Service -Name $serviceName).Status -eq 'Stopped' -and -not (Get-StubProcess)) `
        'Service Control Manager records the service as stopped once its host is terminated'

    Write-Output 'Scenario 2: a service that hangs while stopping'
    Set-StubMode 'stop'
    (Get-Service -Name $serviceName).Start()
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    (Get-Service -Name $serviceName).Stop()
    $service = Get-Service -Name $serviceName
    $deadline = (Get-Date).AddSeconds(10)
    while ($service.Status -ne 'StopPending' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200; $service.Refresh() }
    Assert-True ($service.Status -eq 'StopPending') 'the throwaway service hangs in StopPending'
    $output = @(Reset-PendingService -SettleSeconds 1)
    Assert-True ((Get-Service -Name $serviceName).Status -eq 'Stopped' -and -not (Get-StubProcess) -and
        ($output -join ' ') -match 'terminating owned host process') 'a hung stop is reset regardless of host age'

    Write-Output 'PASS: tunnel recovery works against the real Service Control Manager.'
} finally {
    Get-StubProcess | ForEach-Object { try { $_.Kill() } catch { } }
    Start-Sleep -Milliseconds 500
    & sc.exe delete $serviceName | Out-Null
    Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
