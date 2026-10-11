# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('wgps-worker-' + [guid]::NewGuid())
$worker = $null
$stage = 'startup'
$originalInputEncoding = [Console]::InputEncoding
# GitHub runners use a UTF-8 console; its StreamWriter preamble must not enter IPC.
[Console]::InputEncoding = [Text.UTF8Encoding]::new($true)
function Assert-True($condition, $message) { if (-not $condition) { throw "ASSERTION FAILED: $message" } }
try {
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    Copy-Item (Join-Path $RepositoryRoot 'src\powershell\ValidationWorker.ps1') $temporary
    $path = Join-Path $temporary 'ValidationWorker.ps1'
    . $path
    $fixture = Join-Path $temporary 'Invoke-LocalNrpt.ps1'
    [IO.File]::WriteAllText($fixture, @'
param($Action)
if ($Action -ne 'Validate') { throw 'Wrong action' }
if (Get-Variable requestLocal -Scope Script -ErrorAction SilentlyContinue) { throw 'Leaked script scope' }
$requestLocal = 'must disappear'
Write-Output "PASS: $PID $([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'input.txt')))"
exit 0
'@)
    [IO.File]::WriteAllText((Join-Path $temporary 'input.txt'), 'first')
    $worker = [ProgramSplit.ValidationWorker]::new($path)
    $workerId = $worker.ProcessId
    $stage = 'first request'
    $first = $worker.Validate('Invoke-LocalNrpt.ps1', 10000) | ConvertFrom-Json
    $changedInput = 'second' + [char]0x03bb
    [IO.File]::WriteAllText((Join-Path $temporary 'input.txt'), $changedInput)
    $stage = 'second request'
    $second = $worker.Validate('Invoke-LocalNrpt.ps1', 10000) | ConvertFrom-Json
    Assert-True ($first.Ok -and $first.Message -eq "PASS: $workerId first") 'first request passes'
    Assert-True ($second.Ok -and $second.Message -eq "PASS: $workerId $changedInput") 'worker reuses process but rereads inputs and resets script scope'
    [IO.File]::WriteAllText($fixture, "throw 'injected validation failure'")
    $stage = 'thrown failure'
    $failure = $worker.Validate('Invoke-LocalNrpt.ps1', 10000) | ConvertFrom-Json
    Assert-True (-not $failure.Ok -and $failure.Message -match 'injected') 'validation failures are returned'
    [IO.File]::WriteAllText($fixture, 'exit 7')
    $stage = 'nonzero script exit'
    Assert-True (-not ($worker.Validate('Invoke-LocalNrpt.ps1', 10000) | ConvertFrom-Json).Ok) 'nonzero script exit fails'
    $worker.Dispose(); $worker = $null
    Assert-True (-not (Get-Process -Id $workerId -ErrorAction SilentlyContinue)) 'idle disposal stops the worker'

    # A probe descendant must die with a timed-out worker, including on NTFS/SCM.
    [IO.File]::WriteAllText($fixture, @'
$p = Start-Process powershell.exe -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 60' -PassThru -WindowStyle Hidden
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'child.txt'), [string]$p.Id)
Start-Sleep -Seconds 60
'@)
    $stage = 'hang and descendant cleanup'
    $worker = [ProgramSplit.ValidationWorker]::new($path)
    $workerId = $worker.ProcessId
    $failed = $false
    try { $null = $worker.Validate('Invoke-LocalNrpt.ps1', 4000) } catch { $failed = $true }
    Assert-True $failed 'hanging request times out'
    $probeId = [int][IO.File]::ReadAllText((Join-Path $temporary 'child.txt'))
    Assert-True (-not (Get-Process -Id $workerId -ErrorAction SilentlyContinue)) 'timed-out worker is gone'
    Assert-True (-not (Get-Process -Id $probeId -ErrorAction SilentlyContinue)) 'timed-out descendant is gone'
    $worker.Dispose(); $worker = $null

    [IO.File]::WriteAllText($fixture, '[Environment]::Exit(9)')
    $worker = [ProgramSplit.ValidationWorker]::new($path)
    $failed = $false
    try { $null = $worker.Validate('Invoke-LocalNrpt.ps1', 10000) } catch { $failed = $true }
    Assert-True $failed 'worker crash is a failed check'
    $worker.Dispose(); $worker = $null
    [IO.File]::WriteAllText($fixture, "Write-Output 'PASS: recovered'; exit 0")
    $script:messages = @()
    function Write-ControllerLog($message) { $script:messages += $message }
    [IO.File]::WriteAllText($fixture, "throw 'supervised failure'")
    $failed = $false
    try { Invoke-Validation 'Invoke-LocalNrpt.ps1' } catch { $failed = $true }
    Assert-True ($failed -and -not $script:validationWorker) 'supervisor discards failed worker'
    [IO.File]::WriteAllText($fixture, "Write-Output 'PASS: recovered'; exit 0")
    $stage = 'supervisor recovery'
    Invoke-Validation 'Invoke-LocalNrpt.ps1'
    Assert-True ($messages -contains 'PASS: recovered') 'supervisor creates a fresh worker after failure'
    Stop-ValidationWorker
    [IO.File]::WriteAllText($fixture, '[Console]::WriteLine(("x" * 70000))')
    $worker = [ProgramSplit.ValidationWorker]::new($path)
    $failed = $false
    try { $null = $worker.Validate('Invoke-LocalNrpt.ps1', 10000) } catch { $failed = $true }
    Assert-True $failed 'oversized protocol output stops the worker'
    $worker.Dispose(); $worker = $null
    Write-Output 'PASS: validation worker reuse, isolation, fresh inputs, failures, timeout, descendants and restart.'
} catch {
    throw "Validation test stage: $stage. $($_.Exception.ToString())"
} finally {
    [Console]::InputEncoding = $originalInputEncoding
    if ($worker) { $worker.Dispose() }
    if (Get-Command Stop-ValidationWorker -ErrorAction SilentlyContinue) { Stop-ValidationWorker }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
