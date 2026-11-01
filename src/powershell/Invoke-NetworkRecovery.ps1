# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [ValidateSet('Status','Enable','Disable','Recover')] [string] $Action = 'Status',
    [string[]] $InterfaceAlias = @(),
    [string] $WifiProfile = '',
    [guid] $InterfaceGuid,
    [Nullable[UInt64]] $PausedSentBytes = $null,
    [ValidateSet('ResetPaused','ReconnectWifi','ResetWifi')] [string] $RecoveryAction = 'ResetPaused',
    [ValidateRange(0,3)] [int] $PauseSamples = 0
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'NetworkRecovery.ps1')
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights are required.' }
$null=Get-ProgramSplitConfiguration $root
. (Join-Path $PSScriptRoot 'PhysicalNetwork.ps1')
if($Action -eq 'Recover') {
    Invoke-ProgramSplitPhysicalRecovery $root $InterfaceGuid $RecoveryAction $PauseSamples $PausedSentBytes
    exit 0
}
$path=Join-Path $root 'config\network-recovery.json'
if($Action -eq 'Status') {
    $policy=Get-ProgramSplitRecoveryPolicy $root
    if(-not $policy){Write-Output 'Physical network recovery is disabled.';exit 0}
    foreach($entry in $policy.Adapters){[ProgramSplit.PhysicalNetwork]::Read([guid]$entry.Guid)}
    exit 0
}
$lease=$null
try {
$wait=[Diagnostics.Stopwatch]::StartNew()
while(-not $lease){
    try {$lease=[IO.File]::Open((Join-Path $root 'state\network-recovery.lock'),'OpenOrCreate','ReadWrite','None')}
    catch [IO.IOException] {
        if($wait.Elapsed.TotalSeconds -ge 5){throw 'Physical recovery is running; retry the configuration change shortly.'}
        Start-Sleep -Milliseconds 100
    }
}
if($Action -eq 'Disable') {
    $temporary="$path.$PID.tmp"
    try {
        [IO.File]::WriteAllText($temporary, '{"Schema":1,"Enabled":false,"Adapters":[]}',[Text.UTF8Encoding]::new($false))
        [ProgramSplit.PhysicalNetwork]::AtomicMove($temporary,$path)
    } finally {Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
    Write-Output 'Physical network recovery is disabled; the retry budget is retained.'
    exit 0
}
if($InterfaceAlias.Count -eq 0 -or $InterfaceAlias.Count -gt 8){throw 'Name one to eight physical adapters explicitly.'}
$adapters=@(Get-NetAdapter -Physical)
$enrolled=@(foreach($name in $InterfaceAlias){
    $adapter=@($adapters | Where-Object {$_.Name -ceq $name})
    if($adapter.Count -ne 1){throw 'Each adapter name must identify exactly one physical adapter.'}
    $snapshot=[ProgramSplit.PhysicalNetwork]::Read([guid]$adapter[0].InterfaceGuid)
    if(-not $snapshot.Hardware -or $snapshot.Type -notin @(6,71)){throw 'Only physical Ethernet and Wi-Fi adapters can be enrolled.'}
    if($snapshot.Type -eq 71 -and (-not $WifiProfile -or $WifiProfile.Length -gt 255 -or
        $WifiProfile.Contains([char]0) -or -not [ProgramSplit.PhysicalNetwork]::HasAllUserProfile($snapshot.Guid,$WifiProfile))){
        throw 'Enrolling Wi-Fi requires an existing all-user profile accessible to the controller.'
    }
    [pscustomobject]@{Guid=$snapshot.Guid.ToString();Type=$snapshot.Type;WifiProfile=$(if($snapshot.Type -eq 71){$WifiProfile}else{''})}
})
if(@($enrolled.Guid | Select-Object -Unique).Count -ne $enrolled.Count){throw 'Duplicate adapter identity.'}
$temporary="$path.$PID.tmp"
$budgetPath=Join-Path $root 'state\network-recovery-budget.json'
if(-not [IO.File]::Exists($budgetPath)) {
    $budgetTemporary="$budgetPath.$PID.tmp"
    try {
        [IO.File]::WriteAllText($budgetTemporary,'{"Schema":1,"Adapters":[]}',[Text.UTF8Encoding]::new($false))
        [ProgramSplit.PhysicalNetwork]::AtomicMove($budgetTemporary,$budgetPath)
    } finally {Remove-Item -LiteralPath $budgetTemporary -Force -ErrorAction SilentlyContinue}
} else {$null=Get-ProgramSplitRecoveryBudget $root}
try {
    [IO.File]::WriteAllText($temporary,(@{Schema=1;Enabled=$true;Adapters=@($enrolled)}|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
    [ProgramSplit.PhysicalNetwork]::AtomicMove($temporary,$path)
} finally {Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
Write-Output 'Recovery enabled for the explicitly enrolled adapters. Existing retry budgets are retained.'
} finally {if($lease){$lease.Dispose()}}
