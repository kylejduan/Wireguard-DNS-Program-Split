# SPDX-License-Identifier: GPL-3.0-or-later
# The real native action runner and PowerShell transactions operate only on a disposable tree.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ([Uri]::UnescapeDataString('wgps-tray-%C3%A9%E6%BC%A2-') + [guid]::NewGuid())
$controller = $null
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
    # Only the mutex name changes in the copied helper, so a long fixture import
    # cannot contend with a real user's tray operation on this computer.
    $mutexName = 'Global\WireGuardProgramSplitTrayTest-' + [guid]::NewGuid()
    $helper = Join-Path $root 'src\TrayActions.ps1'
    [IO.File]::WriteAllText($helper, [IO.File]::ReadAllText($helper).Replace('Global\WireGuardProgramSplitTrayAction', $mutexName))
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
    $listHash = (Get-FileHash $list).Hash
    $heldMutex = [Threading.Mutex]::new($true, $mutexName)
    try {
        & $runner $root Add $first
        Assert-True ($LASTEXITCODE -ne 0 -and (Get-FileHash $list).Hash -eq $listHash) 'a concurrent action cannot mutate the include list'
    } finally { $heldMutex.ReleaseMutex(); $heldMutex.Dispose() }
    Remove-Item -LiteralPath (Join-Path $root 'profiles\WireGuardSplit.conf.previous')
    $controllerScript = Join-Path $root 'controller-fixture.ps1'
    [IO.File]::WriteAllText($controllerScript, @'
$ErrorActionPreference='Stop'
$state=Join-Path $PSScriptRoot 'state'
$until=[DateTime]::UtcNow.AddMinutes(3)
while([DateTime]::UtcNow -lt $until){
 try {
  $active=Join-Path $state 'active';$stopped=Join-Path $state 'stack-stopped'
  if(Test-Path (Join-Path $state 'enabled')){
   Remove-Item $stopped -Force -ErrorAction SilentlyContinue
   $settings=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'config\settings.json'))|ConvertFrom-Json
   if($settings.TunnelAddress -eq '192.0.2.254') {Remove-Item $active -Force -ErrorAction SilentlyContinue}
   elseif(-not (Test-Path $active)){[IO.File]::WriteAllText($active,'fixture')}
  }else{
   Remove-Item $active -Force -ErrorAction SilentlyContinue
   if(-not (Test-Path $stopped)){[IO.File]::WriteAllText($stopped,'fixture')}
  }
 }catch{}
 Start-Sleep -Milliseconds 100
}
'@)
    $controller = Start-Process powershell.exe -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $controllerScript + '"') -PassThru -WindowStyle Hidden
    $null = $controller.Handle
    $profileInput = Join-Path $root 'import.conf'
    $key = ('A' * 43) + '='
    function Write-FixtureProfile([string] $Address) {
        [IO.File]::WriteAllText($profileInput, "[Interface]`nPrivateKey = $key`nAddress = $Address/32`nDNS = 203.0.113.53`n[Peer]`nPublicKey = $key`nAllowedIPs = 0.0.0.0/0`nEndpoint = 198.51.100.10:51820`n")
    }
    & $runner $root Toggle
    Write-FixtureProfile '192.0.2.3'
    & $runner $root Import $profileInput
    Assert-True ($LASTEXITCODE -eq 0 -and ([IO.File]::ReadAllText((Join-Path $root 'config\settings.json')) | ConvertFrom-Json).TunnelAddress -eq '192.0.2.3') 'the real profile transaction commits after the fixture confirms readiness'
    Assert-True (-not (Test-Path (Join-Path $root 'profiles\WireGuardSplit.conf.previous')) -and -not (Test-Path (Join-Path $root 'state\keep-filters.request'))) 'successful import removes recovery backups and the temporary filter hold'
    $profileHash = (Get-FileHash (Join-Path $root 'profiles\WireGuardSplit.conf')).Hash
    $settingsHash = (Get-FileHash (Join-Path $root 'config\settings.json')).Hash
    Write-FixtureProfile '192.0.2.254'
    & $runner $root Import $profileInput
    Assert-True ($LASTEXITCODE -ne 0 -and (Get-FileHash (Join-Path $root 'profiles\WireGuardSplit.conf')).Hash -eq $profileHash -and
        (Get-FileHash (Join-Path $root 'config\settings.json')).Hash -eq $settingsHash) 'readiness failure restores the exact previous profile and settings'
    Assert-True ((Test-Path (Join-Path $root 'state\enabled')) -and -not (Test-Path (Join-Path $root 'state\keep-filters.request'))) 'rollback restores the enabled intent and releases its filter hold'
    $preparePath = Join-Path $root 'src\Prepare-Profile.ps1'
    $prepareSource = [IO.File]::ReadAllText($preparePath)
    [IO.File]::WriteAllText($preparePath, @'
param($InputPath,$OutputPath,$SettingsPath,[switch]$SkipAcl)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot '..\prepare-pid.txt'),[string]$PID)
$child=Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText((Join-Path $PSScriptRoot '..\prepare-child.txt'),[string]$child.Id)
Start-Sleep -Seconds 60
'@)
    & $runner $root Import $profileInput
    Assert-True ($LASTEXITCODE -ne 0 -and (Get-FileHash (Join-Path $root 'profiles\WireGuardSplit.conf')).Hash -eq $profileHash -and
        (Get-FileHash (Join-Path $root 'config\settings.json')).Hash -eq $settingsHash -and (Test-Path (Join-Path $root 'state\enabled'))) 'timed-out preparation leaves the original pair intact and restores the enabled intent'
    foreach ($name in @('prepare-pid.txt', 'prepare-child.txt')) {
        $preparedId = [int][IO.File]::ReadAllText((Join-Path $root $name))
        $preparedProcess = Get-Process -Id $preparedId -ErrorAction SilentlyContinue
        if ($preparedProcess) { $null = $preparedProcess.WaitForExit(5000) }
        Assert-True (-not $preparedProcess -or $preparedProcess.HasExited) 'timed-out preparation and its descendant are contained'
        if ($preparedProcess) { $preparedProcess.Dispose() }
    }
    [IO.File]::WriteAllText($preparePath, $prepareSource)
    $controller.Kill(); $null = $controller.WaitForExit(5000); $controller.Dispose(); $controller = $null
    & (Join-Path $RepositoryRoot 'build\test-tray-dialog.exe') (Join-Path $root 'bin\tray.exe') $runner $root
    Assert-True ($LASTEXITCODE -eq 0) 'both real file pickers cancel without selecting a file'
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
    Remove-Item -LiteralPath $pidFile
    [IO.File]::WriteAllText((Join-Path $root 'src\TrayActions.ps1'), '$PID | Set-Content -LiteralPath (Join-Path $PSScriptRoot ''..\child-pid.txt'')' + "`r`nStart-Sleep -Seconds 2`r`n" + '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''..\finished.txt''), ''done'')')
    & $runner $root Finish
    Assert-True ($LASTEXITCODE -eq 0) 'the mutation fixture starts before its UI owner exits'
    $finishDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path (Join-Path $root 'finished.txt')) -and [DateTime]::UtcNow -lt $finishDeadline) { Start-Sleep -Milliseconds 100 }
    Assert-True (Test-Path (Join-Path $root 'finished.txt')) 'an already-started mutation finishes after its UI owner exits'
    Write-Output 'PASS: native tray and pickers, Unicode actions, serialized mutations, profile commit/rollback, last-app protection, and cancellation containment.'
} finally {
    if ($controller) { try { if (-not $controller.HasExited) { $controller.Kill(); $null = $controller.WaitForExit(5000) } } finally { $controller.Dispose() } }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
