# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$Condition,[string]$Message) {if(-not $Condition){throw "ASSERTION FAILED: $Message"}}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'src\powershell\Invoke-DnsDispatcher.ps1'),[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'dispatcher script parses'
$fixture='Local\wgps-reload-access-'+[guid]::NewGuid()
foreach($name in @('Open-ReloadEvent','Assert-ReloadAccess','Request-Reload')) {
    $definition=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
    Assert-True ($definition.Count -eq 1) "one $name implementation exists"
    . ([scriptblock]::Create($definition[0].Extent.Text.Replace('Global\WireGuardProgramSplitDispatcherReload',$fixture)))
}
$script:managed=$true
function Get-ManagedProcess {if($script:managed){[pscustomobject]@{Id=1}}}
# A missing event during supervisor startup is retried, rather than reported as access denial.
Assert-ReloadAccess
Request-Reload
$created=$false
$event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$fixture,[ref]$created)
try {
    Assert-True $created 'fixture event is isolated from production'
    Assert-ReloadAccess
    Request-Reload
    Assert-True ($event.WaitOne(0)) 'permitted reload signals the event'
    $null=$event.Reset()
    $original=$event.GetAccessControl()
    $restricted=[Security.AccessControl.EventWaitHandleSecurity]::new()
    $restricted.SetAccessRuleProtection($true,$false)
    $sid=[Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WorldSid,$null)
    $restricted.AddAccessRule([Security.AccessControl.EventWaitHandleAccessRule]::new($sid,[Security.AccessControl.EventWaitHandleRights]::Synchronize,[Security.AccessControl.AccessControlType]::Allow))
    $event.SetAccessControl($restricted)
    foreach($action in @('Assert-ReloadAccess','Request-Reload')) {
        $denied=$false
        try {& $action} catch {$denied=$_.Exception.Message -like '*access denied*SYSTEM*'}
        Assert-True $denied "$action reports the permission failure without disguising it as a timeout"
        Assert-True (-not $event.WaitOne(0)) 'denied reload did not signal the fixture'
    }
    $script:managed=$false
    Assert-ReloadAccess
    $event.SetAccessControl($original)
} finally {$event.Dispose()}
Write-Output 'PASS: dispatcher reload access checks, startup retry and explicit permission errors.'
