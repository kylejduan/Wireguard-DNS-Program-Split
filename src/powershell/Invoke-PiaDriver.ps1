# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [ValidateSet('Validate', 'Install', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$driverDir = Join-Path $root 'drivers\pia'
$inf = Join-Path $driverDir 'PiaWFPCallout.inf'
$sys = Join-Path $driverDir 'PiaWfpCallout.sys'
$catalog = Join-Path $driverDir 'piawfpcallout.cat'
$serviceName = 'PiaWFPCallout'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Assert-SignedArtifact([string] $path, [string] $subject) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing driver artifact: $path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $subject) {
        throw "Unexpected or invalid signature on $path"
    }
}

function Assert-Inputs {
    if (-not (Test-Path -LiteralPath $inf -PathType Leaf)) { throw "Missing driver INF: $inf" }
    Assert-SignedArtifact $sys 'Private Internet Access|Microsoft Windows Hardware Compatibility Publisher'
    Assert-SignedArtifact $catalog 'Microsoft Windows Hardware Compatibility Publisher'
}

function Get-DriverService {
    Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='PiaWFPCallout'" -ErrorAction SilentlyContinue
}

Assert-Inputs

if ($Action -eq 'Validate') {
    Write-Output 'PASS: signed PIA WFP driver package is ready.'
    exit 0
}

if ($Action -eq 'Status') {
    $driver = Get-DriverService
    if ($driver) {
        $driver | Select-Object Name, State, StartMode, PathName
    } else {
        Write-Output 'PIA WFP driver is not installed.'
    }
    exit 0
}

Assert-Administrator
$driver = Get-DriverService
if (-not $driver) {
    & pnputil.exe /add-driver $inf /install
    if ($LASTEXITCODE -ne 0) { throw 'PnPUtil rejected the signed PIA driver package.' }

    $driver = Get-DriverService
    if (-not $driver) {
        & rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.ntamd64 132 $inf
        & rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.ntamd64.Services 132 $inf
        $driver = Get-DriverService
    }
    if (-not $driver) { throw 'The signed driver package was staged but its service was not installed.' }
}

if ($driver.State -ne 'Running') {
    & sc.exe start $serviceName | Out-Null
    if ($LASTEXITCODE -notin @(0, 1056)) { throw 'The signed PIA WFP driver failed to start.' }
}

$driver = Get-DriverService
if (-not $driver -or $driver.State -ne 'Running') { throw 'PIA WFP driver is not running.' }
Write-Output 'Signed PIA WFP callout driver is running.'
