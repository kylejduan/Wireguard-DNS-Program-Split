# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [ValidateSet('Enable', 'Disable', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$stateFile = Join-Path $root 'state\browser-dns-policy-original.json'
$settings = @(
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name = 'Enabled'; Value = 0; Type = 'DWord' },
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name = 'Locked'; Value = 1; Type = 'DWord' },
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'DnsOverHttpsMode'; Value = 'off'; Type = 'String' },
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DnsOverHttpsMode'; Value = 'off'; Type = 'String' }
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-ValueState($setting) {
    $exists = Test-Path -LiteralPath $setting.Path
    $item = if ($exists) { Get-Item -LiteralPath $setting.Path } else { $null }
    $valueNames = if ($item) { @($item.GetValueNames()) } else { @() }
    $valueExists = $setting.Name -in $valueNames
    $currentValue = $null
    $currentType = $null
    if ($valueExists) {
        $currentValue = $item.GetValue($setting.Name, $null, 'DoNotExpandEnvironmentNames')
        $currentType = [string]$item.GetValueKind($setting.Name)
    }
    [pscustomobject]@{
        Path = $setting.Path
        Name = $setting.Name
        KeyExisted = $exists
        ValueExisted = $valueExists
        Value = $currentValue
        Type = $currentType
    }
}

if ($Action -eq 'Status') {
    foreach ($setting in $settings) {
        $state = Get-ValueState $setting
        [pscustomobject]@{
            Path = $setting.Path
            Name = $setting.Name
            EffectiveValue = $state.Value
            ExpectedValue = $setting.Value
            Matches = $state.ValueExisted -and [string]$state.Value -eq [string]$setting.Value
        }
    }
    exit 0
}

Assert-Administrator

if ($Action -eq 'Enable') {
    if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
        $original = @($settings | ForEach-Object { Get-ValueState $_ })
        [IO.Directory]::CreateDirectory((Split-Path -Parent $stateFile)) | Out-Null
        [IO.File]::WriteAllText($stateFile, ($original | ConvertTo-Json -Depth 4))
    }
    foreach ($setting in $settings) {
        if (-not (Test-Path -LiteralPath $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        if ($setting.Type -eq 'DWord') {
            New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value ([int]$setting.Value) `
                -PropertyType DWord -Force | Out-Null
        } else {
            New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value ([string]$setting.Value) `
                -PropertyType String -Force | Out-Null
        }
    }
    Write-Output 'Firefox, Chrome, and Edge now use the Windows DNS resolver; no resolver address was assigned.'
    exit 0
}

if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    throw 'Browser DNS policy recovery state is missing.'
}
$original = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
foreach ($entry in $original) {
    if ($entry.ValueExisted) {
        if (-not (Test-Path -LiteralPath $entry.Path)) {
            New-Item -Path $entry.Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.Value `
            -PropertyType $entry.Type -Force | Out-Null
    } elseif (Test-Path -LiteralPath $entry.Path) {
        Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
    }
}
foreach ($group in $original | Group-Object Path) {
    if (-not ($group.Group | Where-Object KeyExisted) -and (Test-Path -LiteralPath $group.Name)) {
        $key = Get-Item -LiteralPath $group.Name
        if ($key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0) {
            Remove-Item -LiteralPath $group.Name -Force
        }
    }
}
Write-Output 'Original browser DNS policies restored.'
