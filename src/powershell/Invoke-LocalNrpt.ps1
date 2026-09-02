param(
    [ValidateSet('Enable', 'Disable', 'Status', 'Validate')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-ProgramSplit64BitPowerShell
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
    $wfpExe = Join-Path $root 'bin\wfp-probe.exe'
    if (Get-Process -Name 'wfp-probe' -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $wfpExe
    }) {
        throw 'Refusing to restore direct DNS while owned WFP payload filters are active.'
    }
    Get-OwnedRule | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    & ipconfig.exe /flushdns | Out-Null
    Write-Output 'Local split-DNS NRPT rule removed.'
    exit 0
}

$allRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
Assert-ProgramSplitNrptRulesCompatible -Rules $allRules -DisplayName $displayName `
    -RequireOwned:($Action -eq 'Validate')
if ($Action -eq 'Validate') {
    Assert-ProgramSplitEffectiveNrptPolicy -Policies @(
        Get-DnsClientNrptPolicy -Effective -ErrorAction Stop
    )
    Write-Output 'PASS: local split-DNS NRPT rule is owned and conflict-free.'
    exit 0
}
if (-not (Get-OwnedRule)) {
    Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment | Out-Null
}
& ipconfig.exe /flushdns | Out-Null
Assert-ProgramSplitEffectiveNrptPolicy -Policies @(
    Get-DnsClientNrptPolicy -Effective -ErrorAction Stop
)
Write-Output 'Ordinary Windows DNS now enters the local per-process dispatcher.'
