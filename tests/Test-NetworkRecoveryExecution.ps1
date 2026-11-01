# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Exercise the real executor and durable budget with fake native observations.
# No real network adapter, service, profile or firewall is modified by this test.
Add-Type @'
namespace ProgramSplit {
 public static class PhysicalNetwork {
  public static object Snapshot,Fresh,Wireless;
  public static int Reads,Scans,Connections;
  [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)]
  static extern bool MoveFileEx(string a,string b,uint flags);
  public static void AtomicMove(string a,string b) { if(!MoveFileEx(a,b,9))throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error()); }
  public static object Read(System.Guid guid) { return ++Reads==1 ? Snapshot : Fresh; }
  public static ulong GetTickCount64() { return 300000; }
  public static object ReadWireless(System.Guid guid,string profile) { return Wireless; }
  public static void Scan(System.Guid guid) { Scans++; }
  public static void Connect(System.Guid guid,string profile) { Connections++; }
 }
}
'@
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('wgps-recovery-execution-'+[guid]::NewGuid())
$id=[guid]'00000000-0000-0000-0000-000000000001'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw "ASSERTION FAILED: $Message"}}
function Get-Service {param($Name,$ErrorAction) [pscustomobject]@{Status='Running'}}
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction) @()}
function Start-Sleep {param($Seconds,$Milliseconds) if($script:afterScan){& $script:afterScan}}
function Get-NetAdapter {param([switch]$IncludeHidden,$ErrorAction) if($script:afterInventory){& $script:afterInventory};$script:adapter}
function Invoke-ProgramSplitProcess {
    param($FilePath,$ArgumentList,$TimeoutMilliseconds,$Encoding)
    Assert-True ($ArgumentList.Count -eq 2 -and $ArgumentList[0] -eq '/restart-device' -and
        $ArgumentList[1] -eq 'PCI\FIXTURE') 'restart targets exactly one verified PnP instance'
    $script:resets++
    $reserved=Get-ProgramSplitRecoveryBudget $fixture
    Assert-True ($reserved[$id.ToString()].Resets -eq 1) 'attempt is durably reserved before reset'
    if($script:resetFails){throw 'Simulated native reset failure'}
    [pscustomobject]@{TimedOut=$false;ExitCode=0}
}
function Reset-Fixture {
    [ProgramSplit.PhysicalNetwork]::Reads=0
    [ProgramSplit.PhysicalNetwork]::Scans=0
    [ProgramSplit.PhysicalNetwork]::Connections=0
    [ProgramSplit.PhysicalNetwork]::Snapshot=[pscustomobject]@{Guid=$id;Type=6;Hardware=$true;AdminUp=$true;LowPower=$false;Paused=$true;LinkUp=$true;Index=22;SentBytes=100}
    [ProgramSplit.PhysicalNetwork]::Fresh=[ProgramSplit.PhysicalNetwork]::Snapshot.PSObject.Copy()
    $script:adapter=[pscustomobject]@{Name='Fixture adapter';InterfaceGuid=$id;HardwareInterface=$true;AdminStatus='Up';ifIndex=22;PnPDeviceID='PCI\FIXTURE'}
    $script:resets=0;$script:resetFails=$false;$script:afterScan=$null;$script:afterInventory=$null
    [IO.File]::WriteAllText((Join-Path $fixture 'state\network-recovery-budget.json'),'{"Schema":1,"Adapters":[]}')
    [IO.File]::WriteAllText((Join-Path $fixture 'state\enabled'),'1')
    [IO.File]::WriteAllText((Join-Path $fixture 'src\Invoke-WfpFilters.ps1'),'Write-Output "PASS: fixture filters"; exit 0')
    [IO.File]::WriteAllText((Join-Path $fixture 'config\network-recovery.json'),(@{Schema=1;Enabled=$true;Adapters=@(@{Guid=$id.ToString();Type=6;WifiProfile=''})}|ConvertTo-Json -Depth 4))
}
try {
    foreach($directory in @('src','state','config','logs')){[IO.Directory]::CreateDirectory((Join-Path $fixture $directory))|Out-Null}
    $source=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\NetworkRecovery.ps1'))
    [IO.File]::WriteAllText((Join-Path $fixture 'src\NetworkRecovery.ps1'),
        $source.Replace('Global\WireGuardProgramSplitPhysicalRecovery',('Global\WireGuardProgramSplitRecoveryTest-'+[guid]::NewGuid())))
    [IO.File]::WriteAllText((Join-Path $fixture 'src\PhysicalNetwork.ps1'),'# Native observations are provided by the test class.')
    [IO.File]::WriteAllText((Join-Path $fixture 'config\network-recovery.json'),(@{Schema=1;Enabled=$true;Adapters=@(@{Guid=$id.ToString();Type=6;WifiProfile=''})}|ConvertTo-Json -Depth 4))
    . (Join-Path $fixture 'src\NetworkRecovery.ps1')
    function Get-ProgramSplitWifiIntent {param($Guid,$Now) $script:wifiIntent}
    Reset-Fixture
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'src\powershell\Invoke-NetworkRecovery.ps1'),[ref]$tokens,[ref]$errors)
    $assignment=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$enrolled'},$true)
    $InterfaceAlias=@('Fixture adapter');$WifiProfile='';$adapters=@($script:adapter)
    Invoke-Expression $assignment.Extent.Text
    Assert-True ($enrolled.Count -eq 1 -and $enrolled[0].Guid -eq $id.ToString()) 'single-adapter enrollment keeps array shape under StrictMode'
    Reset-Fixture
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'PASS:*' -and $script:resets -eq 1) 'eligible pause resets exactly the enrolled physical interface'
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'DEFER:*' -and $script:resets -eq 1) 'persisted cooldown prevents another attempt'
    Reset-Fixture
    [ProgramSplit.PhysicalNetwork]::Fresh.Paused=$false
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'DEFER:*' -and $script:resets -eq 0) 'self-resolved pause cancels the pending reset'
    Reset-Fixture
    $script:afterInventory={ [ProgramSplit.PhysicalNetwork]::Fresh.Paused=$false }
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'DEFER:*' -and $script:resets -eq 0) 'pause resolved during slow CIM inventory cancels the reset'
    Reset-Fixture
    [ProgramSplit.PhysicalNetwork]::Fresh.SentBytes=101
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'DEFER:*' -and $script:resets -eq 0) 'transmit progress cancels a stale paused flag'
    Reset-Fixture
    Remove-Item (Join-Path $fixture 'state\network-recovery-budget.json')
    $failed=$false;try{Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3|Out-Null}catch{$failed=$true}
    Assert-True ($failed -and $script:resets -eq 0) 'a lost retry ledger never grants a fresh reset budget'
    Reset-Fixture
    $script:adapter.ifIndex=99
    $failed=$false;try{Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3|Out-Null}catch{$failed=$true}
    Assert-True ($failed -and $script:resets -eq 0) 'changed interface identity is not reset'
    Reset-Fixture
    [IO.File]::WriteAllText((Join-Path $fixture 'src\Invoke-WfpFilters.ps1'),'Write-Output "FAIL: missing fixture filter"; exit 1')
    $failed=$false;try{Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3|Out-Null}catch{$failed=$true}
    Assert-True ($failed -and $script:resets -eq 0) 'unverified payload protection prevents recovery'
    Assert-True ((Get-ProgramSplitRecoveryBudget $fixture).Count -eq 0) 'protection refusal consumes no attempt'
    Reset-Fixture
    $script:resetFails=$true
    $failed=$false;try{Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3|Out-Null}catch{$failed=$true}
    Assert-True ($failed -and $script:resets -eq 1) 'native action failures propagate'
    Assert-True ((Get-ProgramSplitRecoveryBudget $fixture)[$id.ToString()].Resets -eq 1) 'failed reset retains the durable retry charge'
    Reset-Fixture
    Remove-Item (Join-Path $fixture 'state\enabled')
    $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id 'ResetPaused' 3
    Assert-True ($result -like 'DEFER:*' -and $script:resets -eq 0) 'overall disable prevents physical recovery'
    foreach($action in @('ReconnectWifi','ResetWifi')){
        Reset-Fixture
        [ProgramSplit.PhysicalNetwork]::Snapshot.Type=71
        [ProgramSplit.PhysicalNetwork]::Fresh.Type=71
        [ProgramSplit.PhysicalNetwork]::Snapshot.Paused=$false
        [ProgramSplit.PhysicalNetwork]::Fresh.Paused=$false
        [ProgramSplit.PhysicalNetwork]::Wireless=[pscustomobject]@{State=4;RadioOn=$true;Visible=$true;Signal=80}
        $script:wifiIntent=[pscustomobject]@{Id=8002;Reason=163851;RecordId=100;Profile='Fixture network';Time=[datetime]::UtcNow.AddSeconds(-10)}
        [IO.File]::WriteAllText((Join-Path $fixture 'config\network-recovery.json'),(@{Schema=1;Enabled=$true;Adapters=@(@{Guid=$id.ToString();Type=71;WifiProfile='Fixture network'})}|ConvertTo-Json -Depth 4))
        if($action -eq 'ResetWifi'){
            $budget=@{Guid=$id.ToString();WindowUtc=[datetime]::UtcNow.ToString('o');ResetUtc=[datetime]::MinValue.ToString('o');SequenceUtc=[datetime]::UtcNow.AddSeconds(-30).ToString('o');Resets=0;RefreshRecord=99}
            [IO.File]::WriteAllText((Join-Path $fixture 'state\network-recovery-budget.json'),(@{Schema=1;Adapters=@($budget)}|ConvertTo-Json -Depth 4))
        }
        $script:afterScan={ $script:wifiIntent=[pscustomobject]@{Id=8003;RecordId=101} }
        $result=Invoke-ProgramSplitPhysicalRecovery $fixture $id $action 0
        Assert-True ($result -like 'DEFER:*' -and [ProgramSplit.PhysicalNetwork]::Scans -eq 1 -and
            [ProgramSplit.PhysicalNetwork]::Connections -eq 0) "$action respects a new disconnect during the scan wait"
    }
    Reset-Fixture
    $script:physicalRecoveryNext=[ProgramSplit.PhysicalNetwork]::GetTickCount64()/1000.0-90
    $script:physicalPauseSamples=@{$id.ToString()=2};$script:physicalRecoveryError='';$script:pollActions=0
    $script:physicalFirstSent=@{$id.ToString()=100};$script:physicalAdapterErrors=@{};$script:physicalNextAttempt=@{};$script:physicalGraceUntil=0
    function Invoke-Component {param($Name,$Action,$Switches) $script:pollActions++}
    function Write-ControllerLog {param($Message)}
    Test-ProgramSplitPhysicalRecovery $fixture
    Assert-True ($script:pollActions -eq 0 -and $script:physicalPauseSamples[$id.ToString()] -eq 1) 'sleep or a long polling gap breaks pause confirmation'
    Assert-True ($script:physicalGraceUntil -gt [ProgramSplit.PhysicalNetwork]::GetTickCount64()/1000.0) 'polling gap starts a fresh resume grace'
    Reset-Fixture
    [ProgramSplit.PhysicalNetwork]::Snapshot.LowPower=$true
    $script:physicalRecoveryNext=[ProgramSplit.PhysicalNetwork]::GetTickCount64()/1000.0-1
    $script:physicalPauseSamples[$id.ToString()]=2
    Test-ProgramSplitPhysicalRecovery $fixture
    Assert-True ($script:physicalPauseSamples[$id.ToString()] -eq 0) 'low-power observations never contribute to pause confirmation'
    Write-Output 'PASS: physical recovery execution, filter prerequisite, fresh identity, durable cooldown, cancellation and failed-action accounting.'
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
