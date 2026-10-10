# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\Common.ps1')
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$current = Get-Process -Id $PID
$expected = $current.Path
Assert-True (Test-ProgramSplitProcessPath -ProcessId $PID -ExpectedPath $expected) 'live process path matches'
Assert-True (Test-ProgramSplitProcessPath -ProcessId $PID -ExpectedPath $expected.ToUpperInvariant()) `
    'Windows path comparison is case insensitive'
Assert-True (-not (Test-ProgramSplitProcessPath -ProcessId $PID -ExpectedPath ($expected + '.foreign'))) `
    'same live PID with a foreign executable path is rejected'
foreach ($invalid in @(0, -1, [int]::MaxValue)) {
    Assert-True (-not (Test-ProgramSplitProcessPath -ProcessId $invalid -ExpectedPath $expected)) `
        'missing, invalid or inaccessible processes do not establish ownership'
}
$child = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c exit 0' `
    -WindowStyle Hidden -PassThru
try {
    $null = $child.Handle
    Assert-True ($child.WaitForExit(10000)) 'disposable child exits'
    Assert-True (-not (Test-ProgramSplitProcessPath -ProcessId $child.Id `
        -ExpectedPath "$env:SystemRoot\System32\cmd.exe")) 'terminated process with a retained handle is rejected'
} finally {
    if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
    $child.Dispose()
    $current.Dispose()
}
Write-Output 'PASS: live process identity uses exact paths and rejects foreign, invalid and exited processes.'
