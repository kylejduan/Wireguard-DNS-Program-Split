# SPDX-License-Identifier: GPL-3.0-or-later
param(
    # Suspend and Resume are the dispatcher supervisor's: see dispatcher-supervisor.h.
    [ValidateSet('Enable', 'Disable', 'Status', 'Validate', 'Suspend', 'Resume')]
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
# Present while the supervisor has suspended the rule because no ready dispatcher answered.
$suspendedFile = Join-Path $root 'state\nrpt-suspended'

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

if ($Action -eq 'Suspend') {
    # No ready dispatcher has answered for 15 seconds: remove the rule so the rest of the host keeps DNS,
    # and remember to restore it. Selected applications' payload stays blocked by their filters.
    $result = Use-ProgramSplitNrptLock {
        if (Test-ProgramSplitDispatcherReady -Root $root) { return 'An owned dispatcher answers; the NRPT rule stays.' }
        $rules = @(Get-OwnedRule)
        if (-not $rules.Count) { return 'No owned NRPT rule to suspend.' }
        [IO.File]::WriteAllText($suspendedFile, (Get-Date -Format o))
        $rules | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
        & ipconfig.exe /flushdns | Out-Null
        'No ready DNS dispatcher for 15 seconds; local split-DNS NRPT rule suspended.'
    }
    Write-Output $result
    exit 0
}

if ($Action -eq 'Resume') {
    $result = Use-ProgramSplitNrptLock {
        if (-not (Test-Path -LiteralPath $suspendedFile -PathType Leaf)) { return 'The NRPT rule is not suspended.' }
        if (-not (Test-ProgramSplitDispatcherReady -Root $root)) { return 'No ready DNS dispatcher yet; the NRPT rule stays suspended.' }
        Assert-ProgramSplitNrptRulesCompatible -Rules @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue) -DisplayName $displayName
        if (-not (Get-OwnedRule)) {
            Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment | Out-Null
        }
        Remove-Item -LiteralPath $suspendedFile -Force
        & ipconfig.exe /flushdns | Out-Null
        'A ready DNS dispatcher answers again; local split-DNS NRPT rule restored.'
    }
    Write-Output $result
    exit 0
}

if ($Action -eq 'Disable') {
    # The persistent payload filters may stay in place; the rule must not outlive the dispatcher it names.
    # A disabled rule is not the supervisor's to restore.
    Use-ProgramSplitNrptLock {
        Get-OwnedRule | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
        Remove-Item -LiteralPath $suspendedFile -Force -ErrorAction SilentlyContinue
    }
    & ipconfig.exe /flushdns | Out-Null
    Write-Output 'Local split-DNS NRPT rule removed.'
    exit 0
}

$allRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
Assert-ProgramSplitNrptRulesCompatible -Rules $allRules -DisplayName $displayName `
    -RequireOwned:($Action -eq 'Validate')
if ($Action -eq 'Validate') {
    $effectivePolicies = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    Assert-ProgramSplitEffectiveNrptPolicy -Policies $effectivePolicies
    $foreignNamespaces = @(Get-ProgramSplitForeignNrptNamespaces -Rules $allRules -Policies $effectivePolicies `
        -DisplayName $displayName)
    if ($foreignNamespaces.Count) {
        Write-Warning "Foreign NRPT namespace rules bypass the dispatcher: $($foreignNamespaces -join ', ')"
    }
    Write-Output 'PASS: local split-DNS NRPT rule is owned and conflict-free.'
    exit 0
}
# The rule is added only while a ready owned dispatcher answers, checked under the lock the supervisor's
# Suspend takes. Otherwise it stays suspended, and the supervisor restores it once a dispatcher is ready.
Use-ProgramSplitNrptLock {
    if (-not (Get-OwnedRule)) {
        if (-not (Test-ProgramSplitDispatcherReady -Root $root)) {
            [IO.File]::WriteAllText($suspendedFile, (Get-Date -Format o))
            throw 'No ready owned DNS dispatcher; the NRPT rule stays suspended until the supervisor sees one ready.'
        }
        Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment | Out-Null
    }
    Remove-Item -LiteralPath $suspendedFile -Force -ErrorAction SilentlyContinue
}
& ipconfig.exe /flushdns | Out-Null
Assert-ProgramSplitEffectiveNrptPolicy -Policies @(
    Get-DnsClientNrptPolicy -Effective -ErrorAction Stop
)
Write-Output 'Ordinary Windows DNS now enters the local per-process dispatcher.'
