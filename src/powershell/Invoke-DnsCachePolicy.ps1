param(
    [ValidateSet('Enable', 'Disable', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$stateFile = Join-Path $root 'state\dnscache-policy-original.json'
$keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$names = @('MaxCacheTtl', 'MaxNegativeCacheTtl')
$desired = @{ MaxCacheTtl = 1; MaxNegativeCacheTtl = 0 }

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-OriginalState {
    $key = Get-Item -LiteralPath $keyPath
    $values = foreach ($name in $names) {
        $exists = $null -ne $key.GetValue($name, $null)
        [pscustomobject]@{ Name = $name; Exists = $exists; Value = if ($exists) { [int]$key.GetValue($name) } else { 0 } }
    }
    return @($values)
}

if ($Action -eq 'Status') {
    $key = Get-Item -LiteralPath $keyPath
    foreach ($name in $names) {
        [pscustomobject]@{ Name = $name; Value = $key.GetValue($name, $null); RecoveryState = Test-Path -LiteralPath $stateFile }
    }
    exit 0
}

Assert-Administrator

if ($Action -eq 'Enable') {
    if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
        $directory = Split-Path -Parent $stateFile
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $temp = "$stateFile.new"
        [IO.File]::WriteAllText($temp, (Get-OriginalState | ConvertTo-Json))
        Move-Item -LiteralPath $temp -Destination $stateFile -Force
    }
    foreach ($name in $names) {
        New-ItemProperty -LiteralPath $keyPath -Name $name -PropertyType DWord -Value $desired[$name] -Force | Out-Null
        if ((Get-Item -LiteralPath $keyPath).GetValue($name, $null) -ne $desired[$name]) {
            throw "Failed to apply DNS cache policy value: $name"
        }
    }
    Write-Output 'Windows DNS Client positive caching is capped at one second and negative caching is disabled.'
    exit 0
}

if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    Write-Output 'No DNS cache policy recovery state exists; nothing changed.'
    exit 0
}
$saved = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
foreach ($item in $saved) {
    if ($item.Name -notin $names) { throw 'Unexpected DNS cache policy recovery entry.' }
    if ($item.Exists) {
        New-ItemProperty -LiteralPath $keyPath -Name $item.Name -PropertyType DWord -Value ([int]$item.Value) -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $keyPath -Name $item.Name -ErrorAction SilentlyContinue
    }
}
$key = Get-Item -LiteralPath $keyPath
foreach ($item in $saved) {
    $actual = $key.GetValue($item.Name, $null)
    if (($item.Exists -and ($null -eq $actual -or [int]$actual -ne [int]$item.Value)) -or
        (-not $item.Exists -and $null -ne $actual)) {
        throw "Failed to restore DNS cache policy value: $($item.Name)"
    }
}
Write-Output 'Original Windows DNS Client cache policy restored.'
