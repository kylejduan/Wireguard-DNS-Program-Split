# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw "ASSERTION FAILED: $Message"}}
# Redirect only the native API type; another CI fixture declares PhysicalNetwork
# in the same PowerShell process. The production helper bodies stay identical.
$helpers=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\RecoveryStability.ps1'))
. ([scriptblock]::Create($helpers.Replace('ProgramSplit.PhysicalNetwork','ProgramSplit.StabilityNetwork')))
# These observations are monotonic seconds, without sleeps or network changes.
foreach($time in @(0,2,4,19,20,40,59)) {
    Assert-True (-not (Test-ProgramSplitSoftFailureReady 'Tunnel' $time)) 'a burst of failures cannot bypass the full minute'
}
Assert-True (Test-ProgramSplitSoftFailureReady 'Tunnel' 60) 'persistent failure is eligible after at least three spaced observations and a minute'
Clear-ProgramSplitSoftFailure
Assert-True (-not (Test-ProgramSplitSoftFailureReady 'Tunnel' 61)) 'a healthy round cancels prior failure evidence'
Assert-True (-not (Test-ProgramSplitSoftFailureReady 'Transport' 91)) 'different failure stages cannot accumulate into a tunnel restart'
Assert-True (-not (Test-ProgramSplitSoftFailureReady 'Transport' 200)) 'a long observation gap breaks confirmation'
Assert-True (-not (Test-ProgramSplitSoftFailureReady 'Transport' 100)) 'a backwards clock breaks confirmation'
Add-Type @'
namespace ProgramSplit {
 public static class StabilityNetwork {
  public static object Snapshot;
  public static object Read(System.Guid guid) { return Snapshot; }
 }
}
'@
$id=[guid]'00000000-0000-0000-0000-000000000001'
$script:inventoryFails=$false
function Get-NetAdapter {param($Name,$ErrorAction)
    if($script:inventoryFails){throw 'Simulated observation error'}
    [pscustomobject]@{InterfaceGuid=$id;Status='Up'}
}
[ProgramSplit.StabilityNetwork]::Snapshot=[pscustomobject]@{Guid=$id;ReceivedBytes=100}
Assert-True (Test-ProgramSplitTunnelTrafficProgress 'Fixture') 'a first counter observation defers a destructive action'
Assert-True (-not (Test-ProgramSplitTunnelTrafficProgress 'Fixture')) 'unchanged receive counters are not traffic progress'
[ProgramSplit.StabilityNetwork]::Snapshot.ReceivedBytes=101
Assert-True (Test-ProgramSplitTunnelTrafficProgress 'Fixture') 'positive incoming tunnel traffic cancels restart eligibility'
$script:inventoryFails=$true
Assert-True (Test-ProgramSplitTunnelTrafficProgress 'Fixture') 'unknown traffic observations defer rather than authorize a restart'
$script:inventoryFails=$false
$controller=Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($controller,[ref]$null,[ref]$null)
foreach($name in @('Restart-Tunnel','Invoke-HealthFailure','Invoke-HealthFailureCore','Invoke-ProgramSplitHealthRound','Get-StackState','Test-TunnelSettingsUnchanged')) {
    $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    Assert-True ($null -ne $definition) "the controller defines $name"
    . ([scriptblock]::Create($definition.Extent.Text))
}
$realSettingsCheck=${function:Test-TunnelSettingsUnchanged}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('wgps-stability-'+[guid]::NewGuid())
$root=$fixture;$state=$fixture
$activeFile=Join-Path $fixture 'active';$tunnelRetryFile=Join-Path $fixture 'tunnel-retry'
$filtersInstalledFile=Join-Path $fixture 'wfp-filters.installed';$dispatcherSupervisedFile=Join-Path $fixture 'dns-dispatcher.supervised'
$errorFile=Join-Path $fixture 'last-error.txt'
$configuration=[pscustomobject]@{ServiceName='Fixture';AdapterName='Fixture';TunnelDns='192.0.2.53'}
$stopEvent=$null;$driverStart=$null
$script:components=[Collections.Generic.List[string]]::new()
$script:messages=[Collections.Generic.List[string]]::new()
function Write-ControllerLog {param($Message) $script:messages.Add([string]$Message)}
function Save-HealthFailureEvidence {param($Reason)}
function Get-ControllerElapsed {[TimeSpan]::FromSeconds($script:now)}
function Get-Service {param($Name,$ErrorAction)
    if($script:serviceMissing){throw [Management.Automation.ErrorRecord]::new([Exception]::new('Service missing'),'NoServiceFoundForGivenName',[Management.Automation.ErrorCategory]::ObjectNotFound,$Name)}
    if($script:serviceUnknown){return $null}
    [pscustomobject]@{Status=$script:serviceStatus}
}
function Test-OwnedNrptRulePresent {$script:rulePresent}
function Test-TunnelDns {param($TimeoutMilliseconds,$Attempts) if(-not $script:dnsHealthy){throw 'Tunnel DNS failed'}}
function Invoke-DispatcherValidation {}
function Test-PiaDriverReady {$true}
function Invoke-Component {param($Name,$Action)
    $script:components.Add("$Name $Action")
    if($Name -eq 'Invoke-Tunnel.ps1' -and $Action -eq 'Start'){$script:dnsHealthy=$true}
}
function Wait-ProgramSplitProbe {param($Probe,$TimeoutMilliseconds,$RetryMilliseconds,$StopEvent) & $Probe}
function Add-ProgramSplitRepairAttempt {param($Root,$Reason) $script:charges++;$script:budgetAvailable}
function Test-ProgramSplitPhysicalInputs {param($AdapterName,$TunnelDns) if($script:resolverThrows){throw 'Simulated diagnosis failure'};$true}
function Test-PhysicalResolverAnswers {$true}
function Test-TunnelSettingsUnchanged {$script:settingsUnchanged}
function Get-ProgramSplitConfiguration {param($Root) throw 'Simulated settings read error'}
function Invoke-Validation {param($Name)}
function Clear-ProgramSplitRepairBudget {param($Root) throw 'Simulated ledger cleanup failure'}
function Start-Sleep {param($Milliseconds)}
function Test-StackHealth {if($script:healthFails){throw 'Unclassified diagnostic error'}}
function Stop-Stack {$script:components.Add('full stack teardown');throw 'A fixture must never attempt a full stack teardown'}
function Reset-Fixture {
    $script:now=0;$script:dnsHealthy=$false;$script:serviceStatus='Running';$script:serviceUnknown=$false;$script:serviceMissing=$false;$script:rulePresent=$true
    $script:settingsUnchanged=$true;$script:nextNrptRepair=[TimeSpan]::Zero
    $script:resolverThrows=$false;$script:healthFails=$false;$script:budgetAvailable=$true;$script:charges=0
    $script:tunnelOutageLogged=$false;$script:nextRepair=[TimeSpan]::Zero;$script:repairDelaySeconds=2
    $script:components.Clear();$script:messages.Clear();Clear-ProgramSplitSoftFailure
    $script:tunnelTrafficObservation=[pscustomobject]@{Guid=$id;ReceivedBytes=101}
    [ProgramSplit.StabilityNetwork]::Snapshot.ReceivedBytes=101
    Remove-Item -LiteralPath $activeFile,$tunnelRetryFile -Force -ErrorAction SilentlyContinue
}
try {
    [IO.Directory]::CreateDirectory($fixture)|Out-Null
    Reset-Fixture
    Assert-True (& $realSettingsCheck) 'an unavailable settings file preserves cached settings rather than requesting a full restart'
    $script:messages.Clear()
    [IO.File]::WriteAllText($tunnelRetryFile,'retry')
    $script:dnsHealthy=$true
    Restart-Tunnel 'Earlier startup timeout' -StopFirst
    Assert-True ($script:components.Count -eq 0 -and $script:charges -eq 0 -and (Test-Path $activeFile) -and -not (Test-Path $tunnelRetryFile)) 'self-recovered startup DNS marks active without stopping the working tunnel'
    Reset-Fixture
    foreach($time in @(0,30,59)){$script:now=$time;Restart-Tunnel 'DNS failure' -StopFirst}
    Assert-True ($script:components.Count -eq 0) 'repeated DNS failures still preserve the tunnel during the waiting period'
    $script:now=60;Restart-Tunnel 'DNS failure' -StopFirst
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Stop,Invoke-Tunnel.ps1 Start' -and $script:charges -eq 1) 'a sustained idle tunnel failure permits one budgeted tunnel-only repair'
    Reset-Fixture
    foreach($time in @(0,30,60,90,120)) {
        $script:now=$time;[ProgramSplit.StabilityNetwork]::Snapshot.ReceivedBytes++
        Restart-Tunnel 'Provider DNS outage' -StopFirst
    }
    Assert-True ($script:components.Count -eq 0 -and $script:charges -eq 0) 'a provider DNS outage never restarts a tunnel that keeps receiving traffic'
    Reset-Fixture
    $script:settingsUnchanged=$false
    $changed=[Management.Automation.ErrorRecord]::new([Exception]::new('Provider DNS outage'),'fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
    $changed.Exception.Data['ProgramSplitStage']='Tunnel'
    foreach($time in @(0,30,60,90)){
        $script:now=$time;[ProgramSplit.StabilityNetwork]::Snapshot.ReceivedBytes++
        Invoke-HealthFailure $changed
    }
    Assert-True ($script:components.Count -eq 0 -and $script:charges -eq 0) 'unapplied settings plus a DNS outage cannot bypass traffic protection or restart a working tunnel'
    Reset-Fixture
    foreach($time in @(0,30)){$script:now=$time;Restart-Tunnel 'Temporary DNS issue' -StopFirst}
    $script:dnsHealthy=$true;$script:now=45;Restart-Tunnel 'Recovered DNS' -StopFirst
    $script:dnsHealthy=$false;$script:now=60;Restart-Tunnel 'Another temporary DNS issue' -StopFirst
    Assert-True ($script:components.Count -eq 0) 'a passing probe breaks the chain of transient failures'
    Reset-Fixture
    $script:budgetAvailable=$false
    foreach($time in @(0,30,60)){$script:now=$time;Restart-Tunnel 'Persistent failure' -StopFirst}
    Assert-True ($script:components.Count -eq 0) 'an open repair circuit preserves a running tunnel'
    Reset-Fixture
    $script:serviceStatus='Stopped'
    Restart-Tunnel 'Stopped service' -StopFirst
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Start') 'a genuinely stopped service starts promptly without a needless stop'
    Reset-Fixture
    Invoke-ProgramSplitHealthRound
    Assert-True ($script:components.Count -eq 0 -and $script:messages.Count -eq 1 -and $script:messages[0] -like '*ledger*') 'cleanup failure after a passing health round only logs and cannot become a repair'
    $script:healthFails=$true
    Invoke-ProgramSplitHealthRound
    Assert-True ($script:components.Count -eq 0 -and $script:charges -eq 0) 'unclassified diagnostic errors preserve the running stack'
    $script:resolverThrows=$true
    $failure=[Management.Automation.ErrorRecord]::new([Exception]::new('DNS failed'),'fixture',[Management.Automation.ErrorCategory]::NotSpecified,$null)
    $failure.Exception.Data['ProgramSplitStage']='Tunnel'
    Invoke-HealthFailure $failure
    Assert-True ($script:components.Count -eq 0) 'an exception in recovery diagnosis is contained without teardown'
    Reset-Fixture
    foreach($file in @($activeFile,$filtersInstalledFile,$dispatcherSupervisedFile,(Join-Path $state 'dns-etw-session.txt'))){[IO.File]::WriteAllText($file,'fixture')}
    $script:serviceUnknown=$true
    Assert-True ((Get-StackState) -eq 'Unknown') 'an uncertain SCM observation does not request a stack rebuild'
    $script:serviceUnknown=$false;$script:rulePresent=$false
    Assert-True ((Get-StackState) -eq 'DnsRuleMissing') 'a suspended or missing NRPT rule requests only a DNS rule repair'
    $script:serviceMissing=$true
    Assert-True ((Get-StackState) -eq 'TunnelDown') 'a positively missing service requests recreation rather than permanent deferral'
    Restart-Tunnel 'Missing service after failed start' -StopFirst
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Start') 'the retry path recreates a missing service without a needless stop'
    Reset-Fixture
    $retryBranch=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst]},$true) |
        ForEach-Object {$_.Clauses} | Where-Object {$_.Item1.Extent.Text -eq '$stackState -eq ''TunnelDown'''})
    Assert-True ($retryBranch.Count -eq 1) 'the controller has one tunnel-retry loop branch'
    $script:settingsUnchanged=$false
    [IO.File]::WriteAllText($tunnelRetryFile,'retry')
    function Invoke-Repair {$script:components.Add('full stack repair')}
    $body=$retryBranch[0].Item2.Extent.Text
    & ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
    Assert-True ($script:components.Count -eq 0 -and $script:charges -eq 0) 'a retry marker and unapplied settings cannot trigger a full rebuild of a running tunnel'
    Reset-Fixture
    $ruleBranch=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst]},$true) |
        ForEach-Object {$_.Clauses} | Where-Object {$_.Item1.Extent.Text -eq '$stackState -eq ''DnsRuleMissing'''})
    Assert-True ($ruleBranch.Count -eq 1) 'the controller has one rule-only loop branch'
    $body=$ruleBranch[0].Item2.Extent.Text
    function Invoke-Component {param($Name,$Action)
        $script:components.Add("$Name $Action")
        throw 'Simulated no ready dispatcher; NRPT stays suspended'
    }
    $suspended=Join-Path $state 'nrpt-suspended';[IO.File]::WriteAllText($suspended,'supervisor owned')
    & ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
    Assert-True ($script:components.Count -eq 0) 'the controller leaves supervisor-suspended NRPT restoration to the supervisor'
    Remove-Item -LiteralPath $suspended
    & ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
    Assert-True (($script:components -join ',') -eq 'Invoke-LocalNrpt.ps1 Enable' -and
        $script:nextNrptRepair -eq [TimeSpan]::FromSeconds(10) -and $script:nextRepair -eq [TimeSpan]::Zero) 'failed rule restoration leaves tunnel and dispatcher alone with its own independent backoff'
    Write-Output 'PASS: recovery waits out transients, cancels on DNS or traffic recovery, respects budgets, and contains diagnostic errors.'
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
