# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\NetworkRecovery.ps1')
function Assert-Equal($Actual,$Expected,[string]$Message) {
    if($Actual -cne $Expected){throw "ASSERTION FAILED: $Message; expected '$Expected', got '$Actual'."}
}
$id='00000000-0000-0000-0000-000000000001'
$entry=[pscustomobject]@{Guid=$id;Type=6;WifiProfile=''}
$snapshot=[pscustomobject]@{Guid=$id;Type=6;Hardware=$true;AdminUp=$true;LowPower=$false;Paused=$true;LinkUp=$true}
$now=[datetime]::SpecifyKind([datetime]'2026-01-01T12:00:00',[DateTimeKind]::Utc)
$wireless=$null;$intent=$null;$budget=$null;$samples=3;$uptime=300
function Decide { Get-ProgramSplitRecoveryAction $entry $snapshot $wireless $intent $budget $samples $now $uptime }
Assert-Equal (Decide) 'ResetPaused' 'confirmed enrolled physical pause permits recovery'
foreach($samples in @(0,1,2)){Assert-Equal (Decide) '' 'transient pause is ignored'}
$samples=3;$uptime=89;Assert-Equal (Decide) '' 'boot grace';$uptime=300
foreach($field in @('Hardware','AdminUp','LinkUp')){
    $snapshot.$field=$false;Assert-Equal (Decide) '' "$field is required";$snapshot.$field=$true
}
$snapshot.LowPower=$true;Assert-Equal (Decide) '' 'do not fight power transitions';$snapshot.LowPower=$false
$snapshot.Paused=$false;Assert-Equal (Decide) '' 'DNS failure alone never resets Ethernet';$snapshot.Paused=$true
$snapshot.Guid='00000000-0000-0000-0000-000000000002';Assert-Equal (Decide) '' 'reused index or foreign identity';$snapshot.Guid=$id
$snapshot.Type=131;Assert-Equal (Decide) '' 'no tunnel reset';$snapshot.Type=6
$budget=[pscustomobject]@{WindowUtc=$now.AddMinutes(-20).ToString('o');ResetUtc=$now.AddMinutes(-5).ToString('o');SequenceUtc=$now.AddHours(-2).ToString('o');Resets=1;RefreshRecord=0}
Assert-Equal (Decide) '' 'cooldown persists across controller restarts'
$budget.ResetUtc=$now.AddMinutes(-11).ToString('o');Assert-Equal (Decide) 'ResetPaused' 'cooldown expires'
$budget.Resets=2;Assert-Equal (Decide) '' 'hourly reset cap'
$budget.WindowUtc=$now.AddHours(-2).ToString('o');Assert-Equal (Decide) 'ResetPaused' 'budget window expires'
$budget.WindowUtc=$now.AddSeconds(1).ToString('o');Assert-Equal (Decide) '' 'clock rollback does not unlock budget'
$budget=$null

$entry.Type=71;$entry.WifiProfile='Fixture network';$snapshot.Type=71;$snapshot.Paused=$false
$wireless=[pscustomobject]@{State=4;RadioOn=$true;Visible=$true;Signal=80}
$intent=[pscustomobject]@{Id=8002;Reason=163851;RecordId=100;Profile='Fixture network';Time=$now.AddSeconds(-10.5)}
Assert-Equal (Decide) 'ReconnectWifi' 'recent fractional-second failed request permits scan and retry'
$intent.Id=8003;Assert-Equal (Decide) '' 'manual disconnect is respected';$intent.Id=8002
$intent.Id=8000;Assert-Equal (Decide) '' 'do not interrupt an ongoing connection';$intent.Id=8002
$intent.Id=8001;Assert-Equal (Decide) '' 'successful connection cancels failure';$intent.Id=8002
$intent.Reason=131080;Assert-Equal (Decide) '' 'authentication failure is not a driver reset';$intent.Reason=163851
$intent.Profile='Different network';Assert-Equal (Decide) '' 'do not interfere with another requested network';$intent.Profile=$entry.WifiProfile
$intent.Time=$now.AddSeconds(-121);Assert-Equal (Decide) '' 'old failures are not replayed'
$intent.Time=$now.AddSeconds(1);Assert-Equal (Decide) '' 'future failure timestamps are refused';$intent.Time=$now.AddSeconds(-10)
$wireless.RadioOn=$false;Assert-Equal (Decide) '' 'radio off is respected';$wireless.RadioOn=$true
$wireless.State=1;Assert-Equal (Decide) '' 'a working Wi-Fi link is never reset';$wireless.State=4
$budget=[pscustomobject]@{WindowUtc=$now.AddMinutes(-20).ToString('o');ResetUtc=$now.AddHours(-2).ToString('o');SequenceUtc=$now.AddSeconds(-40).ToString('o');Resets=0;RefreshRecord=90}
Assert-Equal (Decide) 'ResetWifi' 'a new failure after the scan/retry can reset a visible requested AP'
$intent.RecordId=90;Assert-Equal (Decide) '' 'the same failure does not repeatedly reset';$intent.RecordId=100
$wireless.Visible=$false;Assert-Equal (Decide) '' 'an absent AP is not an adapter fault';$wireless.Visible=$true
$wireless.Signal=5;Assert-Equal (Decide) '' 'weak coverage is not an adapter fault';$wireless.Signal=80
$budget.SequenceUtc=$now.AddSeconds(-200).ToString('o');Assert-Equal (Decide) '' 'failed sequence backs off'
$budget.SequenceUtc=$now.AddSeconds(-601).ToString('o');Assert-Equal (Decide) 'ReconnectWifi' 'a fresh later request can retry'
$budget.SequenceUtc=$now.AddSeconds(1).ToString('o');Assert-Equal (Decide) '' 'clock rollback does not permit Wi-Fi retry'

$temp=Join-Path ([IO.Path]::GetTempPath()) ('wgps-recovery-'+[guid]::NewGuid())
try {
    [IO.Directory]::CreateDirectory((Join-Path $temp 'config'))|Out-Null
    Assert-Equal (Get-ProgramSplitRecoveryPolicy $temp) $null 'missing policy is disabled'
    $path=Join-Path $temp 'config\network-recovery.json'
    [IO.File]::WriteAllText($path,'{"Schema":1,"Enabled":false,"Adapters":[]}')
    Assert-Equal (Get-ProgramSplitRecoveryPolicy $temp) $null 'explicit opt-out'
    [IO.File]::WriteAllText($path,(@{Schema=1;Enabled=$true;Adapters=@($entry)}|ConvertTo-Json -Depth 4))
    Assert-Equal ((Get-ProgramSplitRecoveryPolicy $temp).Adapters.Count) 1 'explicit enrollment accepted'
    [IO.File]::WriteAllText($path,(@{Schema=1;Enabled=$true;Adapters=@($entry,$entry)}|ConvertTo-Json -Depth 4))
    $failed=$false;try{Get-ProgramSplitRecoveryPolicy $temp|Out-Null}catch{$failed=$true}
    Assert-Equal $failed $true 'duplicate identities rejected'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction) $script:events}
function New-FixtureEvent([string]$GuidText,[string]$Extra='') {
    $event=[pscustomobject]@{Id=8002;RecordId=10;TimeCreated=[datetime]::Now;
        Xml="<Event><EventData><Data Name='InterfaceGuid'>$GuidText</Data><Data Name='ProfileName'>Fixture network</Data><Data Name='ReasonCode'>163851</Data>$Extra</EventData></Event>"}
    $event|Add-Member ScriptMethod ToXml {return $this.Xml}
    return $event
}
$script:events=@((New-FixtureEvent 'invalid-guid'),(New-FixtureEvent $id "<Data Name='Empty'/>") )
$parsed=Get-ProgramSplitWifiIntent ([guid]$id) ([datetime]::UtcNow)
Assert-Equal $parsed.Id 8002 'malformed unrelated events and empty XML data do not abort intent parsing'
Write-Output 'PASS: physical recovery eligibility, boot grace, identity, radio and manual intent, stale events, cooldown and budgets.'
