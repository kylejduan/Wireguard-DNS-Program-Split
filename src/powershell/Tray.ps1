# SPDX-License-Identifier: GPL-3.0-or-later
# Compatibility entry point. New installations schedule bin\tray.exe directly.
param([switch] $SelfTest)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
if ($SelfTest) {
    & (Join-Path $PSScriptRoot 'TrayActions.ps1') -Action Status
    exit $LASTEXITCODE
}
$tray = Join-Path $root 'bin\tray.exe'
if (-not (Test-Path -LiteralPath $tray -PathType Leaf)) { throw 'Missing native tray executable.' }
# Wait preserves supervision for an existing PowerShell scheduled task until it is upgraded.
$process = Start-Process -FilePath $tray -PassThru -Wait
exit $process.ExitCode
