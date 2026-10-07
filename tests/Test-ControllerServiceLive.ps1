# SPDX-License-Identifier: GPL-3.0-or-later
# Run only on a Windows test host without an installed project controller.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$name = 'WireGuardProgramSplitController'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    throw 'Refusing to exercise the service host: the controller service already exists.'
}
$root = Join-Path $RepositoryRoot ("local\test-temp\controller-service-{0}" -f [guid]::NewGuid())
$script = Join-Path $root 'src\Controller.ps1'
$exe = Join-Path $RepositoryRoot 'build\controller-service.exe'
$command = '"{0}" /service "{1}"' -f $exe, $script
$created = $false
$process = $null
function Wait-Until([scriptblock] $Condition, [string] $Description) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out: $Description"
}
try {
    [IO.Directory]::CreateDirectory((Split-Path -Parent $script)) | Out-Null
    [IO.File]::WriteAllText($script, @'
param([long] $StopEventHandle)
$event = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset)
$event.SafeWaitHandle = [Microsoft.Win32.SafeHandles.SafeWaitHandle]::new([IntPtr]$StopEventHandle, $false)
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'crash')) { exit 7 }
foreach ($index in 1..2500) { [Console]::WriteLine(('x' * 4096)) }
[Console]::WriteLine('OUTPUT-DRAINED')
while (-not $event.WaitOne(100)) { }
[Console]::Error.WriteLine('FINAL-CHILD-ERROR')
$event.Dispose()
'@)
    New-Service -Name $name -BinaryPathName $command -StartupType Manual | Out-Null
    $created = $true
    Start-Service -Name $name
    $record = Get-CimInstance Win32_Service -Filter "Name='$name'"
    $process = Get-Process -Id $record.ProcessId
    $null = $process.Handle
    $log = Join-Path $root 'logs\controller-service.log'
    Wait-Until {
        (Test-Path -LiteralPath "$log.1") -and
        ([IO.File]::ReadAllText($log) -match 'OUTPUT-DRAINED')
    } 'child output rotation and drain'
    Stop-Service -Name $name
    if (-not $process.WaitForExit(10000)) { throw 'Stopped controller service host remained alive.' }
    $text = [IO.File]::ReadAllText($log)
    if ($text -notmatch 'FINAL-CHILD-ERROR' -or $text -notmatch 'service stop completed with clean stack cleanup') {
        throw 'Ordered service stop lost child stderr or the host exit record.'
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'logs') -File) {
        if ($file.Length -gt 8MB) { throw 'Service log exceeded its size limit.' }
    }
    [IO.File]::WriteAllText((Join-Path $root 'src\crash'), '')
    try { Start-Service -Name $name } catch { } # The deliberate child exit may race Start-Service.
    Wait-Until {
        (Get-Service -Name $name).Status -eq 'Stopped' -and
        ([IO.File]::ReadAllText($log) -match 'controller exited unexpectedly with code 7')
    } 'unexpected child exit reporting'
    $record = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($record.ExitCode -ne 1066 -or $record.ServiceSpecificExitCode -ne 7) {
        throw 'Unexpected child exit was not reported as an SCM service failure.'
    }
    Write-Output 'PASS: real controller SCM start, output rotation, ordered stop, stderr drain, and child-crash reporting.'
} finally {
    if ($created) {
        $record = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($record -and $record.PathName -ne $command) { throw 'Test service ownership changed; cleanup refused.' }
        if ($record) {
            Stop-Service -Name $name -ErrorAction SilentlyContinue
            & sc.exe delete $name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not delete owned test service.' }
        }
        if ($process) { $process.Dispose() }
        Wait-Until { -not (Get-Service -Name $name -ErrorAction SilentlyContinue) } 'test service deletion'
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
