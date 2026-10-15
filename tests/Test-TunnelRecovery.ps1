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
Assert-True ($tunnelSource -match '(?s)Start-TunnelAfterPreflight -ServiceState \$serviceState\s*\nWait-ServiceRunning\s*\n\$adapter = Wait-Adapter' -and
    $tunnelSource -notmatch 'Start-Service -Name \$serviceName') `
    'tunnel start issues a non-blocking start control bounded by the readiness wait'
Assert-True ($tunnelSource -match '(?s)catch \[System\.ServiceProcess\.TimeoutException\] \{ Reset-PendingService -SettleSeconds 0 \}') `
    'tunnel stop resets a stop that does not finish inside its wait'
Assert-True ($tunnelSource -match '(?s)if \(\$serviceState\.Status -eq ''StopPending''\) \{.*?Reset-PendingService -SettleSeconds 5\s.*?Start-TunnelAfterPreflight -ServiceState \$serviceState') `
    'tunnel start clears a stuck stop inside a budget that leaves the readiness wait within the controller limit'
$tunnelTokens = $null
$tunnelParseErrors = $null
$tunnelAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'), [ref] $tunnelTokens, [ref] $tunnelParseErrors)
$resetFunctions = @($tunnelAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Get-OwnedServiceProcess', 'Reset-PendingService', 'Wait-ServiceRunning', 'Get-MonotonicSeconds', 'Get-PendingHostAge')
}, $true))
Assert-True ($resetFunctions.Count -eq 5) 'tunnel service-recovery helpers are each defined once'
Add-Type -AssemblyName System.ServiceProcess
$resetHarness = [scriptblock]::Create((@'
param([string[]] $Statuses, [string] $ProcessPath, [int] $ServicePid = 4242, [int] $HostAgeSeconds = 5,
[string] $Call = 'Reset', [int] $Seconds = 0, [switch] $KillFails, [int] $StartTimeOffsetSeconds = 0, [switch] $NotSeenBefore,
[string] $PendingSeen, [switch] $LockState, [long] $StartTicks = 0)
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
# HostAgeSeconds is how long the host has been seen pending on the monotonic clock. Its wall-clock start
# time agrees unless StartTimeOffsetSeconds models a clock step.
$fakeProcess = [pscustomobject]@{
Id = 4242; Path = $ProcessPath; Handle = [IntPtr]::Zero
StartTime = [DateTime]::Now.AddSeconds(-$HostAgeSeconds + $StartTimeOffsetSeconds); Killed = $killed
}
if ($StartTicks) { $fakeProcess.StartTime = [DateTime]::new($StartTicks, [DateTimeKind]::Utc).ToLocalTime() }
$pendingState = Join-Path ([IO.Path]::GetTempPath()) ("wgps-pending-{0}.json" -f [guid]::NewGuid())
$script:pendingReport = $null
$lock = $null
if ($LockState) {
# A state file nothing can read or replace: only the controller's sighting can carry the clock.
[IO.File]::WriteAllText($pendingState, 'held')
$lock = [IO.FileStream]::new($pendingState, 'Open', 'ReadWrite', 'None')
} elseif (-not $NotSeenBefore) {
[IO.File]::WriteAllText($pendingState, ([ordered]@{
Identity = "4242:$($fakeProcess.StartTime.ToUniversalTime().Ticks)"
FirstSeen = [Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency - $HostAgeSeconds
} | ConvertTo-Json -Compress))
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
if ($lock) { $lock.Dispose() }
$recorded = Test-Path -LiteralPath $pendingState
Remove-Item -LiteralPath $pendingState -Force -ErrorAction SilentlyContinue
[pscustomobject]@{ Killed = @($killed); Failure = $failure; Output = $output; FinalStatus = $fake.Status; Recorded = $recorded; Report = $script:pendingReport }
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
# Pending time is monotonic: a backward clock step that puts the host's start an hour in the future does
# not shield a stuck host, and a forward step that makes a young host look hours old does not end it.
foreach ($call in 'Wait', 'Reset') {
    $stepBack = & $resetHarness -Call $call -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 120 -StartTimeOffsetSeconds 3600
    Assert-True (@($stepBack.Killed).Count -eq 1) "$call resets a stuck host after a backward clock step"
    $stepForward = & $resetHarness -Call $call -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 20 -StartTimeOffsetSeconds -7200
    Assert-True (@($stepForward.Killed).Count -eq 0) "$call keeps a young host after a forward clock step"
    $firstSight = & $resetHarness -Call $call -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 7200 -NotSeenBefore
    Assert-True (@($firstSight.Killed).Count -eq 0 -and $firstSight.Recorded) "$call starts measuring a host seen pending for the first time"
    # The state file can be neither read nor replaced: the sighting the controller passes back still ages,
    # so the stuck host is reset after the limit.
    $hostStarted = [DateTime]::UtcNow.AddSeconds(-30).Ticks
    $unsaved = & $resetHarness -Call $call -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 0 -LockState -StartTicks $hostStarted
    Assert-True (@($unsaved.Killed).Count -eq 0 -and $unsaved.Report -match '^\d+:\d+\|') "$call reports its first sighting when it cannot save it: $($unsaved.Report)"
    $identity, $seen = $unsaved.Report -split '\|'
    $aged = '{0}|{1}' -f $identity, ([double]$seen - 95).ToString([Globalization.CultureInfo]::InvariantCulture)
    $later = & $resetHarness -Call $call -Statuses @('StartPending') -ProcessPath $ownedHost -HostAgeSeconds 0 -LockState -PendingSeen $aged -StartTicks $hostStarted
    Assert-True (@($later.Killed).Count -eq 1) "$call resets a stuck host by the controller's sighting while its state file is locked"
}

# Stop must stay available after the startup inputs become unusable, or a running tunnel can never be
# released. Run the real script against a root with settings but no runtime DLLs or profile. Unelevated it
# stops at the administrator check; elevated, the ownership check refuses any installed same-name service.
$fixture = Join-Path ([IO.Path]::GetTempPath()) ("wgps-tunnel-stop-{0}" -f [guid]::NewGuid())
try {
    $fixtureSource = Join-Path $fixture 'src'
    [IO.Directory]::CreateDirectory($fixtureSource) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'config')) | Out-Null
    foreach ($name in 'Invoke-Tunnel.ps1', 'Common.ps1') {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot "src\powershell\$name") -Destination $fixtureSource
    }
    [IO.File]::WriteAllText((Join-Path $fixture 'config\settings.json'),
        '{"TunnelAddress":"192.0.2.2","TunnelDns":"203.0.113.53"}')
    function Invoke-TunnelFixture([string] $Action) {
        $stdout = Join-Path $fixture "$Action-output.log"
        $stderr = Join-Path $fixture "$Action-error.log"
        $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f (Join-Path $fixtureSource 'Invoke-Tunnel.ps1')),
            '-Action', $Action
        ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
        $null = $process.Handle
        Assert-True ($process.WaitForExit(60000)) "tunnel $Action fixture completes"
        $process.WaitForExit()
        @(Get-Content -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue) -join ' '
    }
    $stopResult = Invoke-TunnelFixture 'Stop'
    Assert-True ($stopResult -notmatch 'Missing required file' -and
        $stopResult -match 'Administrator rights are required|Refusing to stop a same-name foreign tunnel service|Tunnel stopped') `
        'tunnel stop is dispatched without the startup inputs and keeps its ownership check'
    $startResult = Invoke-TunnelFixture 'Start'
    Assert-True ($startResult -match 'Missing required file') 'tunnel start still requires the runtime DLLs and profile'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'PASS: tunnel service recovery refuses foreign and young hosts and resets stuck ones.'
