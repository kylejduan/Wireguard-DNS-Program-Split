# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$tunnelSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'))
Assert-True ($tunnelSource -match '(?s)function Get-OwnedServiceProcess.*?\$process\.Handle.*?\[string\]\$process\.Path -eq \$hostExe' -and
    $tunnelSource -match '(?s)function Reset-PendingService.*?StartPending.*?StopPending.*?Get-OwnedServiceProcess.*?\$process\.Kill\(\).*?WaitForStatus\(''Stopped''') `
    'pending tunnel-service reset terminates only the owned host process'
$tunnelStopBranch = $tunnelSource.IndexOf("if (`$Action -eq 'Stop')")
$tunnelStopReset = $tunnelSource.IndexOf('Reset-PendingService -SettleSeconds 10', $tunnelStopBranch)
Assert-True ($tunnelStopBranch -ge 0 -and $tunnelStopReset -gt $tunnelStopBranch -and
    $tunnelStopReset -lt $tunnelSource.IndexOf('$service.Stop()', $tunnelStopBranch) -and
    $tunnelSource -notmatch 'Stop-Service -Name \$serviceName') `
    'tunnel stop resets a pending service first and issues a non-blocking stop control'
Assert-True ($tunnelSource -match '(?s)\$serviceState\.Start\(\).*?\nWait-ServiceRunning\s*\n\$adapter = Wait-Adapter' -and
    $tunnelSource -notmatch 'Start-Service -Name \$serviceName') `
    'tunnel start issues a non-blocking start control bounded by the readiness wait'
Assert-True ($tunnelSource -match '(?s)catch \[System\.ServiceProcess\.TimeoutException\] \{ Reset-PendingService -SettleSeconds 0 \}') `
    'tunnel stop resets a stop that does not finish inside its wait'
Assert-True ($tunnelSource -match '(?s)if \(\$serviceState\.Status -eq ''StopPending''\) \{.*?Reset-PendingService -SettleSeconds 5\s.*?if \(\$serviceState\.Status -eq ''Stopped''\)') `
    'tunnel start clears a stuck stop inside a budget that leaves the readiness wait within the controller limit'
$tunnelTokens = $null
$tunnelParseErrors = $null
$tunnelAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'), [ref] $tunnelTokens, [ref] $tunnelParseErrors)
$resetFunctions = @($tunnelAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Get-OwnedServiceProcess', 'Reset-PendingService', 'Wait-ServiceRunning')
}, $true))
Assert-True ($resetFunctions.Count -eq 3) 'tunnel service-recovery helpers are each defined once'
Add-Type -AssemblyName System.ServiceProcess
$resetHarness = [scriptblock]::Create((@'
param([string[]] $Statuses, [string] $ProcessPath, [int] $ServicePid = 4242, [int] $HostAgeSeconds = 5,
[string] $Call = 'Reset', [int] $Seconds = 0, [switch] $KillFails)
$serviceName = 'WireGuardTunnel$WireGuardSplit'
$hostExe = 'C:\ProgramData\WireGuardProgramSplit\bin\tunnel-host.exe'
$adapterName = 'WireGuardSplit'
$stuckHostSeconds = 90
$killed = [Collections.Generic.List[int]]::new()
$queue = [Collections.Generic.Queue[string]]::new([string[]] $Statuses)
$fake = [pscustomobject]@{ Status = $queue.Dequeue(); Queue = $queue; Killed = $killed; KillFails = [bool] $KillFails }
$fake | Add-Member -MemberType ScriptMethod -Name Refresh -Value {
if ($this.Queue.Count) { $this.Status = $this.Queue.Dequeue() }
}
$fake | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
param($status, $timeout)
if ($this.Killed.Count -and -not $this.KillFails) { $this.Status = $status }
else { throw [System.ServiceProcess.TimeoutException]::new('stub timeout') }
}
$fakeProcess = [pscustomobject]@{
Id = 4242; Path = $ProcessPath; Handle = [IntPtr]::Zero
StartTime = [DateTime]::Now.AddSeconds(-$HostAgeSeconds); Killed = $killed
}
$fakeProcess | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.Killed.Add([int] $this.Id) }
function Get-Service { $fake }
function Get-CimInstance { if ($ServicePid -lt 0) { return $null }; [pscustomobject]@{ ProcessId = $ServicePid } }
function Get-Process { param($Id, $ErrorAction) if ([int] $Id -eq 4242) { $fakeProcess } }
function Get-NetAdapter { $null }
function Start-Sleep { }

'@) + (($resetFunctions | ForEach-Object { $_.Extent.Text }) -join "`n") + (@'

$failure = $null
$output = @()
try {
if ($Call -eq 'Wait') { $output = @(Wait-ServiceRunning -TimeoutSeconds $Seconds) }
else { $output = @(Reset-PendingService -SettleSeconds $Seconds) }
} catch { $failure = $_.Exception.Message }
[pscustomobject]@{ Killed = @($killed); Failure = $failure; Output = $output; FinalStatus = $fake.Status }
'@))
$ownedHost = 'C:\ProgramData\WireGuardProgramSplit\bin\tunnel-host.exe'
$stuckStart = & $resetHarness -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 120
Assert-True (-not $stuckStart.Failure -and @($stuckStart.Killed).Count -eq 1 -and $stuckStart.Killed[0] -eq 4242 -and
    ($stuckStart.Output -join ' ') -match 'terminating owned host process 4242') `
    'a tunnel service stuck in StartPending is reset by terminating its owned host process'
$youngStart = & $resetHarness -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 25 -Seconds 1
Assert-True (@($youngStart.Killed).Count -eq 0 -and $youngStart.Failure -like '*still starting*' -and
    $youngStart.FinalStatus -eq 'StartPending') `
    'pending-service reset never terminates a young starting host, so stop-as-cleanup cannot defeat a slow start'
$foreignHost = & $resetHarness -Statuses @('StopPending') -ProcessPath 'C:\Other\tunnel-host.exe'
Assert-True (@($foreignHost.Killed).Count -eq 0 -and $foreignHost.Failure -like '*without an owned host process*') `
    'pending-service reset refuses to terminate a process outside the installed host path'
foreach ($missingPid in 0, -1) {
    $noProcess = & $resetHarness -Statuses @('StartPending') -ProcessPath $ownedHost -ServicePid $missingPid
    Assert-True (@($noProcess.Killed).Count -eq 0 -and $noProcess.Failure -like '*without an owned host process*') `
        "pending-service reset terminates nothing when the service reports no process ($missingPid)"
}
$runningService = & $resetHarness -Statuses @('Running') -ProcessPath $ownedHost
Assert-True (-not $runningService.Failure -and @($runningService.Killed).Count -eq 0 -and
    $runningService.FinalStatus -eq 'Running') 'pending-service reset leaves a running tunnel service alone'
$settledService = & $resetHarness -Statuses @('StartPending', 'Running') -ProcessPath $ownedHost -Seconds 5
Assert-True (-not $settledService.Failure -and @($settledService.Killed).Count -eq 0 -and
    $settledService.FinalStatus -eq 'Running') 'pending-service reset lets a service settle inside its window before terminating anything'
$expiredSettle = & $resetHarness -Statuses @('StopPending') -ProcessPath $ownedHost -Seconds 1
Assert-True (-not $expiredSettle.Failure -and @($expiredSettle.Killed).Count -eq 1) `
    'pending-service reset terminates the owned host once the settle window expires'
$unkillable = & $resetHarness -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 120 -KillFails
Assert-True (@($unkillable.Killed).Count -eq 1 -and $unkillable.Failure) `
    'pending-service reset fails loudly when the service does not stop after its host was terminated'

$started = & $resetHarness -Call Wait -Statuses @('StartPending', 'Running') -ProcessPath $ownedHost -Seconds 5
Assert-True (-not $started.Failure -and @($started.Killed).Count -eq 0) 'tunnel readiness wait returns once the service runs'
$failedFast = & $resetHarness -Call Wait -Statuses @('StartPending', 'Stopped') -ProcessPath $ownedHost -Seconds 30
Assert-True (@($failedFast.Killed).Count -eq 0 -and $failedFast.Failure -like '*stopped while starting*') `
    'tunnel readiness wait reports a fast start failure at once without terminating anything'
$slowStart = & $resetHarness -Call Wait -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 25
Assert-True (@($slowStart.Killed).Count -eq 0 -and $slowStart.Failure -like '*next attempt can adopt it*' -and
    $slowStart.FinalStatus -eq 'StartPending') 'a slow tunnel start is left running for the next attempt to adopt'
$stuckHost = & $resetHarness -Call Wait -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 120
Assert-True (@($stuckHost.Killed).Count -eq 1 -and $stuckHost.Failure -like '*was reset so the next attempt starts clean*') `
    'a tunnel host pending far longer than any normal start is reset'

Write-Output 'PASS: tunnel service recovery refuses foreign and young hosts and resets stuck ones.'
