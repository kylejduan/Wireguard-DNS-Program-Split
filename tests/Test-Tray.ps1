# SPDX-License-Identifier: GPL-3.0-or-later
# The real native action runner and PowerShell transactions operate only on a disposable tree.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ([Uri]::UnescapeDataString('wgps-tray-%C3%A9%E6%BC%A2-') + [guid]::NewGuid())
try {
    foreach ($dir in @('bin', 'src', 'config', 'profiles', 'state')) {
        [IO.Directory]::CreateDirectory((Join-Path $root $dir)) | Out-Null
    }
    foreach ($name in @('controller-service.exe', 'tray.exe')) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot "build\$name") -Destination (Join-Path $root 'bin')
    }
    foreach ($name in @('Common.ps1', 'TrayActions.ps1', 'Prepare-Profile.ps1')) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot "src\powershell\$name") -Destination (Join-Path $root 'src')
    }
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $root 'config\settings.json'), '{"TunnelAddress":"192.0.2.2","TunnelDns":"203.0.113.53"}')
    [IO.File]::WriteAllText((Join-Path $root 'profiles\WireGuardSplit.conf'), 'fixture profile')
    [IO.File]::WriteAllText((Join-Path $root 'state\installation.json'), '{"Product":"WireGuardProgramSplit","Schema":1}')
    $first = Join-Path $root 'First App.exe'
    $second = Join-Path $root ([Uri]::UnescapeDataString('Jos%C3%A9 & %E6%BC%A2%E5%AD%97.exe'))
    [IO.File]::WriteAllText($first, 'fixture'); [IO.File]::WriteAllText($second, 'fixture')
    $list = Join-Path $root 'state\included-apps.txt'
    [IO.File]::WriteAllLines($list, [string[]]@($first), $utf8)
    $runner = Join-Path $RepositoryRoot 'build\test-tray-action.exe'
    & $runner $root Status
    Assert-True ($LASTEXITCODE -eq 0) 'real bounded runner validates tray inputs'
    & $runner $root Add $second
    Assert-True ($LASTEXITCODE -eq 0 -and [IO.File]::ReadAllLines($list) -ccontains $second) 'Unicode and spaces survive the native command and PowerShell round trip'
    & $runner $root Remove $first
    Assert-True ($LASTEXITCODE -eq 0 -and [IO.File]::ReadAllText($list).Trim() -ceq $second) 'the selected application is removed'
    & $runner $root Remove $second
    Assert-True ($LASTEXITCODE -ne 0 -and [IO.File]::ReadAllText($list).Trim() -ceq $second) 'removing the last application fails without changing the list'
    & $runner $root Toggle
    Assert-True ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath (Join-Path $root 'state\enabled'))) 'enable affects only the fixture'
    [IO.File]::WriteAllText((Join-Path $root 'profiles\WireGuardSplit.conf.previous'), 'preserved')
    & $runner $root Import (Join-Path $root 'profiles\WireGuardSplit.conf')
    Assert-True ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath (Join-Path $root 'state\enabled')) -and
        [IO.File]::ReadAllText((Join-Path $root 'profiles\WireGuardSplit.conf.previous')) -eq 'preserved') 'import refuses unresolved backups before disabling the fixture'
    & $runner $root Toggle
    Assert-True ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $root 'state\enabled'))) 'disable affects only the fixture'
    $smokeError = Join-Path $root 'smoke-error.txt'
    $smoke = Start-Process -FilePath (Join-Path $root 'bin\tray.exe') -ArgumentList '--smoke-test' -RedirectStandardError $smokeError -PassThru
    $null = $smoke.Handle
    Assert-True ($smoke.WaitForExit(10000)) 'native window and tray icon lifecycle completes'
    $smoke.WaitForExit()
    Assert-True ($smoke.ExitCode -eq 0) ('native tray lifecycle succeeds; exit=' + $smoke.ExitCode + ': ' + [IO.File]::ReadAllText($smokeError))
    $smoke.Dispose()
    # Interrupt a real action while its PowerShell child is blocked. The runner's job must kill it.
    $pidFile = Join-Path $root 'child-pid.txt'
    [IO.File]::WriteAllText((Join-Path $root 'src\TrayActions.ps1'), '$PID | Set-Content -LiteralPath (Join-Path $PSScriptRoot ''..\child-pid.txt'')' + "`r`nStart-Sleep -Seconds 60")
    & $runner $root Cancel
    Assert-True ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $pidFile)) 'cancellation fixture started a real PowerShell child'
    $childId = [int][IO.File]::ReadAllText($pidFile).Trim()
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $child = Get-Process -Id $childId -ErrorAction SilentlyContinue
        if (-not $child -or $child.HasExited) { break }
        $child.Dispose()
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-True (-not $child -or $child.HasExited) 'closing the action kills its PowerShell descendant'
    if ($child) { $child.Dispose() }
    Write-Output 'PASS: native tray lifecycle, Unicode actions, import guard, last-app protection, and cancellation containment.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
