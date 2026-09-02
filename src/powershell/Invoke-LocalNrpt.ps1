param(
    [ValidateSet('Enable', 'Disable', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
$displayName = $configuration.NrptDisplayName
$comment = 'Owned by WireGuardProgramSplit; safe to remove on recovery.'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-OwnedRule {
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {
        Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $displayName
    }
}

if ($Action -eq 'Status') {
    $rule = Get-OwnedRule
    if ($rule) { $rule | Select-Object Name, DisplayName, Namespace, NameServers }
    else { Write-Output 'Local split-DNS NRPT rule is disabled.' }
    exit 0
}

Assert-Administrator

if ($Action -eq 'Disable') {
    Get-OwnedRule | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    & ipconfig.exe /flushdns | Out-Null
    Write-Output 'Local split-DNS NRPT rule removed.'
    exit 0
}

$allRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
$sameNameCollision = $allRules | Where-Object {
    $_.DisplayName -eq $displayName -and
    -not (Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $displayName)
}
if ($sameNameCollision) { throw 'A foreign NRPT rule uses the WireGuard Program Split display name.' }
$foreignCatchAll = $allRules | Where-Object {
    $_.Namespace -contains '.' -and
    -not (Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $displayName)
}
if ($foreignCatchAll) { throw 'Another catch-all NRPT rule is active.' }
if (-not (Get-OwnedRule)) {
    Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment | Out-Null
}
& ipconfig.exe /flushdns | Out-Null
Write-Output 'Ordinary Windows DNS now enters the local per-process dispatcher.'
