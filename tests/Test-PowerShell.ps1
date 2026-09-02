param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$scripts = Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1' -File
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref] $tokens, [ref] $errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "PowerShell syntax errors in $($script.Name): $($errors -join '; ')"
}

foreach ($name in @('Invoke-BrowserDnsPolicy.ps1', 'Invoke-DnsCachePolicy.ps1')) {
    $source = [IO.File]::ReadAllText((Join-Path $RepositoryRoot "src\powershell\$name"))
    Assert-True ($source -notmatch '@\(\s*Get-Content[^\r\n]+ConvertFrom-Json') `
        "$name must enumerate a JSON array on Windows PowerShell 5.1"
}

$controllerSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'))
Assert-True ($controllerSource -match '(?s)\.Handle.*?WaitForExit\(45000\).*?WaitForExit\(\).*?\.ExitCode') `
    'controller retains the child handle and finalizes its wait before reading ExitCode'
Assert-True ($controllerSource -notmatch 'Start-Sleep -Seconds 2\s+Test-TunnelDns') `
    'controller startup has no fixed pre-probe sleep'
$stopStack = $controllerSource.IndexOf('function Stop-Stack')
$stopWfp = $controllerSource.IndexOf("Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop'", $stopStack)
$stopNrpt = $controllerSource.IndexOf("Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable'", $stopStack)
Assert-True ($stopWfp -gt $stopStack -and $stopWfp -lt $stopNrpt) `
    'controller removes payload filters before restoring direct DNS'
Assert-True ($controllerSource -match "Invoke-Component 'Invoke-LocalNrpt.ps1' 'Validate'") `
    'controller health validates the active NRPT namespace'
$tunnelProbeSource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Test-TunnelDns'),
    $controllerSource.IndexOf('function Invoke-Repair') - $controllerSource.IndexOf('function Test-TunnelDns'))
Assert-True ($tunnelProbeSource -match '(?s)\.Handle.*?WaitForExit\(\$TimeoutMilliseconds \+ 3000\).*?WaitForExit\(\)') `
    'tunnel DNS probe drains redirected output before evaluating it'
$startStackSource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Start-Stack'),
    $controllerSource.IndexOf('$required = @(') - $controllerSource.IndexOf('function Start-Stack'))
Assert-True ($startStackSource -match '(?s)if \(\$dispatcherWasRunning\).*?Invoke-Component ''Invoke-DnsDispatcher\.ps1'' ''Validate''.*?else \{ Test-LocalDns \}') `
    'fresh startup uses the native DNS gate while an adopted dispatcher receives full validation'
Assert-True ($controllerSource -match '(?s)\$wfpStopped\s*=.*?if \(\$wfpStopped\).*?Invoke-LocalNrpt') `
    'controller does not restore direct DNS after a WFP-stop failure'
Assert-True ($controllerSource -match 'Test-Path -LiteralPath \$activeFile -PathType Leaf') `
    'controller adopts only a stack that completed its readiness gates'
Assert-True ($controllerSource -match 'Test-Path -LiteralPath \(Join-Path \$state ''dns-etw-session\.txt''\)') `
    'controller treats owned ETW session state as a managed stack component'

$probeOut = Join-Path ([IO.Path]::GetTempPath()) "wgps-exit-$([guid]::NewGuid()).out"
$probeError = "$probeOut.err"
try {
    $probe = Start-Process cmd.exe -ArgumentList @('/d', '/c', 'exit', '7') `
        -RedirectStandardOutput $probeOut -RedirectStandardError $probeError -WindowStyle Hidden -PassThru
    $null = $probe.Handle
    Assert-True ($probe.WaitForExit(5000)) 'exit-code probe completes'
    $probe.WaitForExit()
    Assert-True ($probe.ExitCode -eq 7) 'Windows PowerShell reports the retained child exit code'
} finally {
    Remove-Item -LiteralPath $probeOut, $probeError -Force -ErrorAction SilentlyContinue
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("WireGuardProgramSplit-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    $common = Join-Path $RepositoryRoot 'src\powershell\Common.ps1'
    . $common

    Assert-ProgramSplit64BitPowerShell
    $wowPowerShell = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $wowPowerShell -PathType Leaf) {
        $escapedCommon = $common.Replace("'", "''")
        $wowCommand = ". '$escapedCommon'; try { Assert-ProgramSplit64BitPowerShell; exit 1 } catch { exit 0 }"
        $wowEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wowCommand))
        $wowProbe = Start-Process -FilePath $wowPowerShell -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-EncodedCommand', $wowEncoded
        ) -WindowStyle Hidden -PassThru
        $null = $wowProbe.Handle
        Assert-True ($wowProbe.WaitForExit(5000)) '32-bit PowerShell guard probe completes'
        $wowProbe.WaitForExit()
        Assert-True ($wowProbe.ExitCode -eq 0) '32-bit PowerShell is rejected before ownership cleanup'
    }

    $traceNames = @(Get-ProgramSplitOwnedTraceNames -StateValue 'broken' -CommandLines @(
        'dns-dispatcher.exe args WireGuardProgramSplitDnsEtw-0123456789abcdef0123456789abcdef'
    ))
    Assert-True ($traceNames.Count -eq 1 -and
        $traceNames[0] -eq 'WireGuardProgramSplitDnsEtw-0123456789abcdef0123456789abcdef') `
        'ETW ownership recovers from a strict dispatcher command-line name when state is corrupt'
    $traceNames = @(Get-ProgramSplitOwnedTraceNames `
        -StateValue 'WireGuardProgramSplitDnsEtw-0123456789abcdef0123456789abcdef' `
        -CommandLines @('WireGuardProgramSplitDnsEtw-0123456789abcdef0123456789abcdef'))
    Assert-True ($traceNames.Count -eq 1) 'ETW ownership de-duplicates state and command-line evidence'

    $probeAttempts = 0
    Wait-ProgramSplitProbe -Probe { ++$script:probeAttempts } -TimeoutMilliseconds 100
    Assert-True ($probeAttempts -eq 1) 'probe wait returns immediately on success'
    $probeAttempts = 0
    Wait-ProgramSplitProbe -Probe {
        ++$script:probeAttempts
        if ($script:probeAttempts -lt 3) { throw 'not ready' }
    } -TimeoutMilliseconds 100 -RetryMilliseconds 0
    Assert-True ($probeAttempts -eq 3) 'probe wait tolerates a transient readiness race'
    $probeFailed = $false
    try { Wait-ProgramSplitProbe -Probe { throw 'still unavailable' } -TimeoutMilliseconds 0 }
    catch { $probeFailed = $_.Exception.Message -eq 'still unavailable' }
    Assert-True $probeFailed 'probe wait preserves the terminal readiness error'

    $lockedStaging = Join-Path $temporary 'locked-install-staging'
    [IO.Directory]::CreateDirectory($lockedStaging) | Out-Null
    $lockedProfile = Join-Path $lockedStaging 'WireGuardSplit.conf'
    [IO.File]::WriteAllText($lockedProfile, 'test profile')
    $profileLock = [IO.File]::Open($lockedProfile, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $cleanupFailure = $null
    try { Remove-ProgramSplitStagingDirectory -Path $lockedStaging }
    catch { $cleanupFailure = $_.Exception.Message }
    finally { $profileLock.Dispose() }
    Assert-True ($cleanupFailure -like 'Sensitive installer staging could not be removed:*') `
        'staging cleanup reports a plaintext-profile deletion failure'
    Assert-True (Test-Path -LiteralPath $lockedStaging) `
        'failed staging cleanup leaves the locked directory visible for recovery'
    Remove-ProgramSplitStagingDirectory -Path $lockedStaging
    Assert-True (-not (Test-Path -LiteralPath $lockedStaging)) `
        'staging cleanup confirms deletion after the lock is released'

    $scopeStaging = Join-Path $temporary 'locked-installer-scope'
    [IO.Directory]::CreateDirectory($scopeStaging) | Out-Null
    $scopeProfile = Join-Path $scopeStaging 'WireGuardSplit.conf'
    [IO.File]::WriteAllText($scopeProfile, 'test profile')
    $scopeLock = [IO.File]::Open($scopeProfile, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $scopeMutexName = "Global\WireGuardProgramSplitTest-$([guid]::NewGuid())"
    $scopeMutex = [Threading.Mutex]::new($false, $scopeMutexName)
    Assert-True ($scopeMutex.WaitOne(0)) 'installer-scope test acquires its named mutex'
    $scopeFailure = $null
    try { Close-ProgramSplitInstallScope -StagingPath $scopeStaging -Mutex $scopeMutex -MutexHeld $true }
    catch { $scopeFailure = $_.Exception.Message }
    finally { $scopeLock.Dispose() }
    $probeCommand = @"
`$mutex = [Threading.Mutex]::new(`$false, '$scopeMutexName')
try {
    if (-not `$mutex.WaitOne(0)) { exit 1 }
    `$mutex.ReleaseMutex()
    exit 0
} finally { `$mutex.Dispose() }
"@
    $encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeCommand))
    $mutexProbe = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-NonInteractive',
        '-EncodedCommand', $encodedProbe) -WindowStyle Hidden -PassThru
    $null = $mutexProbe.Handle
    Assert-True ($mutexProbe.WaitForExit(5000)) 'installer-scope mutex probe completes'
    $mutexProbe.WaitForExit()
    Assert-True ($scopeFailure -like 'Sensitive installer staging could not be removed:*') `
        'installer scope propagates its staging-cleanup failure'
    Assert-True ($mutexProbe.ExitCode -eq 0) `
        'installer scope releases its machine-wide mutex even when staging cleanup fails'
    try { $scopeMutex.ReleaseMutex() } catch { }
    try { $scopeMutex.Dispose() } catch { }
    Remove-ProgramSplitStagingDirectory -Path $scopeStaging

    $powerShell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $controller = 'C:\ProgramData\WireGuardProgramSplit\src\Controller.ps1'
    $taskArguments = Get-ProgramSplitTaskArguments -ScriptPath $controller
    $ownedTask = [pscustomobject]@{ Actions = @([pscustomobject]@{
        Execute = $powerShell
        Arguments = $taskArguments
    }) }
    Assert-True (Test-ProgramSplitTaskOwnership -Task $ownedTask -PowerShellPath $powerShell `
        -ScriptPath $controller) 'task ownership accepts the exact executable and script action'
    $foreignTask = [pscustomobject]@{ Actions = @([pscustomobject]@{
        Execute = $powerShell
        Arguments = (Get-ProgramSplitTaskArguments -ScriptPath 'C:\Other\Controller.ps1')
    }) }
    Assert-True (-not (Test-ProgramSplitTaskOwnership -Task $foreignTask -PowerShellPath $powerShell `
        -ScriptPath $controller)) 'task ownership rejects a same-name foreign action'
    $malformedTask = [pscustomobject]@{ Actions = @([pscustomobject]@{ Arguments = $taskArguments }) }
    Assert-True (-not (Test-ProgramSplitTaskOwnership -Task $malformedTask -PowerShellPath $powerShell `
        -ScriptPath $controller)) 'task ownership rejects an action without an executable'

    $hostExe = 'C:\ProgramData\WireGuardProgramSplit\bin\tunnel-host.exe'
    $profilePath = 'C:\ProgramData\WireGuardProgramSplit\profiles\WireGuardSplit.conf'
    $ownedService = [pscustomobject]@{ PathName = "$hostExe /service $profilePath" }
    Assert-True (Test-ProgramSplitServiceOwnership -Service $ownedService -HostPath $hostExe `
        -ProfilePath $profilePath) 'service ownership accepts the exact tunnel host command'
    $foreignService = [pscustomobject]@{ PathName = 'C:\Other\service.exe' }
    Assert-True (-not (Test-ProgramSplitServiceOwnership -Service $foreignService -HostPath $hostExe `
        -ProfilePath $profilePath)) 'service ownership rejects a same-name foreign command'

    $ownedNrpt = [pscustomobject]@{
        DisplayName = 'WireGuard Program Split local dispatcher'
        Namespace = @('.')
        NameServers = @('127.0.0.1')
        Comment = 'Owned by WireGuardProgramSplit; safe to remove on recovery.'
    }
    Assert-True (Test-ProgramSplitNrptRuleOwnership -Rule $ownedNrpt `
        -DisplayName $ownedNrpt.DisplayName) 'NRPT ownership accepts the exact local dispatcher rule'
    $foreignNrpt = $ownedNrpt.PSObject.Copy()
    $foreignNrpt.NameServers = @('203.0.113.53')
    Assert-True (-not (Test-ProgramSplitNrptRuleOwnership -Rule $foreignNrpt `
        -DisplayName $ownedNrpt.DisplayName)) 'NRPT ownership rejects a same-name foreign resolver'
    Assert-ProgramSplitNrptRulesCompatible -Rules @($ownedNrpt) -DisplayName $ownedNrpt.DisplayName `
        -RequireOwned
    $foreignCatchAll = $ownedNrpt.PSObject.Copy()
    $foreignCatchAll.DisplayName = 'Another VPN'
    $foreignCatchAll.NameServers = @('203.0.113.53')
    $nrptCollisionFailed = $false
    try {
        Assert-ProgramSplitNrptRulesCompatible -Rules @($ownedNrpt, $foreignCatchAll) `
            -DisplayName $ownedNrpt.DisplayName -RequireOwned
    } catch { $nrptCollisionFailed = $true }
    Assert-True $nrptCollisionFailed 'NRPT validation rejects a foreign catch-all rule'
    $nrptMissingFailed = $false
    try {
        Assert-ProgramSplitNrptRulesCompatible -Rules @() -DisplayName $ownedNrpt.DisplayName `
            -RequireOwned
    } catch { $nrptMissingFailed = $true }
    Assert-True $nrptMissingFailed 'NRPT validation requires the owned rule while active'
    Assert-ProgramSplitEffectiveNrptPolicy -Policies @([pscustomobject]@{
        Namespace = @('.'); NameServers = @('127.0.0.1')
    })
    $effectiveCollisionFailed = $false
    try {
        Assert-ProgramSplitEffectiveNrptPolicy -Policies @([pscustomobject]@{
            Namespace = @('.'); NameServers = @('10.2.0.1')
        })
    } catch { $effectiveCollisionFailed = $true }
    Assert-True $effectiveCollisionFailed 'effective NRPT validation rejects an overriding resolver'

    $dispatcherScriptSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-DnsDispatcher.ps1'))
    Assert-True ($dispatcherScriptSource -match 'dns-etw-session\.txt' -and
        $dispatcherScriptSource -match 'WireGuardProgramSplitDnsEtw-') `
        'dispatcher persists a unique owned ETW session name'
    Assert-True ($dispatcherScriptSource -match "'--system'") `
        'dispatcher validation probes the Windows DNS Client path'
    Assert-True ($dispatcherScriptSource -match 'Get-ExpectedProcesses') `
        'dispatcher can recover an exact-path child after PID-state loss'
    $wfpScriptSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-WfpFilters.ps1'))
    Assert-True ($wfpScriptSource -match 'Get-ExpectedProcesses') `
        'WFP cleanup can recover exact-path filter hosts after PID-state loss'
    $nrptScriptSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-LocalNrpt.ps1'))
    Assert-True ($nrptScriptSource -match 'Refusing to restore direct DNS while owned WFP payload filters are active') `
        'NRPT disable independently guards the WFP-before-DNS teardown invariant'
    $nativeProbeSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\native\dns-probe.cpp'))
    Assert-True ($nativeProbeSource -match 'DnsQuery_A') 'native probe supports Windows DNS Client validation'
    Assert-True ($nativeProbeSource -match 'peer\.sin_addr\.s_addr' -and
        $nativeProbeSource -match 'response\[3\].*0x0f') `
        'raw tunnel readiness rejects foreign-source and DNS-error responses'
    $buildSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'scripts\build-wsl.sh'))
    Assert-True ($buildSource -match 'dns-probe\.exe.*-ldnsapi') 'native DNS probe links the Windows DNS API'
    $uninstallSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'Uninstall.ps1'))
    Assert-True ($uninstallSource -match '(?s)Invoke-Cleanup ''Invoke-WfpFilters\.ps1'' ''Stop''.*?if \(\$wfpStopped\).*?Invoke-Cleanup ''Invoke-LocalNrpt\.ps1'' ''Disable''') `
        'uninstaller restores direct DNS only after WFP filters stop'
    Assert-True ($uninstallSource -match 'Assert-ProgramSplit64BitPowerShell') `
        'uninstaller refuses cross-bitness process ownership checks'

    Assert-ProgramSplitInstallNamesAvailable -Tasks @() -Service $null
    $collisionFailed = $false
    try { Assert-ProgramSplitInstallNamesAvailable -Tasks @($foreignTask) -Service $null }
    catch { $collisionFailed = $true }
    Assert-True $collisionFailed 'installation refuses an existing same-name task'
    $collisionFailed = $false
    try { Assert-ProgramSplitInstallNamesAvailable -Tasks @() -Service $foreignService }
    catch { $collisionFailed = $true }
    Assert-True $collisionFailed 'installation refuses an existing same-name service'

    $backupFailureProfile = Join-Path $temporary 'backup-failure.conf'
    $backupFailureSettings = Join-Path $temporary 'backup-failure.json'
    $backupFailurePreparedProfile = "$backupFailureProfile.new"
    $backupFailurePreparedSettings = "$backupFailureSettings.new"
    [IO.File]::WriteAllText($backupFailureProfile, 'trusted profile')
    [IO.File]::WriteAllText($backupFailureSettings, 'trusted settings')
    [IO.File]::WriteAllText($backupFailurePreparedProfile, 'new profile')
    [IO.File]::WriteAllText($backupFailurePreparedSettings, 'new settings')
    $script:injectedCopyCalls = 0
    function Copy-Item {
        param([string] $LiteralPath, [string] $Destination, [switch] $Force)
        ++$script:injectedCopyCalls
        if ($script:injectedCopyCalls -eq 1) {
            [IO.File]::WriteAllText($Destination, 'partial backup')
            throw 'Injected backup-copy failure.'
        }
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    }
    $backupCreationFailed = $false
    try {
        Install-ProgramSplitProfilePair -ActiveProfile $backupFailureProfile `
            -ActiveSettings $backupFailureSettings -PreparedProfile $backupFailurePreparedProfile `
            -PreparedSettings $backupFailurePreparedSettings | Out-Null
    } catch { $backupCreationFailed = $true }
    finally { Remove-Item Function:\Copy-Item -Force }
    Assert-True $backupCreationFailed 'profile-pair replacement reports backup-creation failure'
    Assert-True ([IO.File]::ReadAllText($backupFailureProfile) -eq 'trusted profile') `
        'an incomplete backup is never copied over the trusted active profile'

    $activeProfile = Join-Path $temporary 'active.conf'
    $activeSettings = Join-Path $temporary 'active.json'
    $preparedProfile = Join-Path $temporary 'active.conf.new'
    $missingPreparedSettings = Join-Path $temporary 'active.json.new'
    [IO.File]::WriteAllText($activeProfile, 'old profile')
    [IO.File]::WriteAllText($activeSettings, 'old settings')
    [IO.File]::WriteAllText($preparedProfile, 'new profile')
    $replacementFailed = $false
    try {
        Install-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -PreparedProfile $preparedProfile -PreparedSettings $missingPreparedSettings | Out-Null
    } catch { $replacementFailed = $true }
    Assert-True $replacementFailed 'profile-pair replacement reports a partial replacement failure'
    Assert-True ([IO.File]::ReadAllText($activeProfile) -eq 'old profile') `
        'profile-pair replacement restores the old profile after failure'
    Assert-True ([IO.File]::ReadAllText($activeSettings) -eq 'old settings') `
        'profile-pair replacement restores the old settings after failure'
    Assert-True (-not (Test-Path -LiteralPath "$activeProfile.previous")) `
        'failed profile-pair replacement removes its profile backup'
    Assert-True (-not (Test-Path -LiteralPath "$activeSettings.previous")) `
        'failed profile-pair replacement removes its settings backup'

    [IO.File]::WriteAllText($activeProfile, 'new profile')
    [IO.File]::WriteAllText($activeSettings, 'new settings')
    [IO.File]::WriteAllText("$activeProfile.previous", 'old profile')
    [IO.File]::WriteAllText("$activeSettings.previous", 'old settings')
    $stackStopped = Join-Path $temporary 'stack-stopped'
    $restoreFailed = $false
    try {
        Restore-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -StoppedMarker $stackStopped -TimeoutSeconds 0
    } catch { $restoreFailed = $true }
    Assert-True $restoreFailed 'profile-pair restore refuses to race an active controller'
    Assert-True ([IO.File]::ReadAllText($activeProfile) -eq 'new profile') `
        'failed restore leaves the active profile untouched'
    Assert-True (Test-Path -LiteralPath "$activeProfile.previous") `
        'failed restore preserves the old profile backup'
    [IO.File]::WriteAllText($stackStopped, 'stopped')

    $settingsLock = [IO.File]::Open($activeSettings, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $restoreFailed = $false
    try {
        Restore-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -StoppedMarker $stackStopped -TimeoutSeconds 0
    } catch { $restoreFailed = $true }
    finally { $settingsLock.Dispose() }
    Assert-True $restoreFailed 'profile-pair restore reports a partial copy failure'
    Assert-True ((Test-Path -LiteralPath "$activeProfile.previous") -and
        (Test-Path -LiteralPath "$activeSettings.previous")) `
        'partial restore preserves both backups for recovery'

    Restore-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
        -StoppedMarker $stackStopped -TimeoutSeconds 0
    Assert-True ([IO.File]::ReadAllText($activeProfile) -eq 'old profile') `
        'profile-pair restore reinstates the old profile after controller acknowledgement'
    Assert-True ([IO.File]::ReadAllText($activeSettings) -eq 'old settings') `
        'profile-pair restore reinstates the old settings after controller acknowledgement'
    Assert-True (-not (Test-Path -LiteralPath "$activeProfile.previous")) `
        'successful profile-pair restore removes its backups'

    [IO.File]::WriteAllText("$activeProfile.previous", 'preserved profile')
    [IO.File]::WriteAllText("$activeSettings.previous", 'preserved settings')
    [IO.File]::WriteAllText($preparedProfile, 'retry profile')
    [IO.File]::WriteAllText($missingPreparedSettings, 'retry settings')
    $replacementFailed = $false
    try {
        Install-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -PreparedProfile $preparedProfile -PreparedSettings $missingPreparedSettings | Out-Null
    } catch { $replacementFailed = $true }
    Assert-True $replacementFailed 'profile-pair replacement refuses to overwrite recovery backups'
    Assert-True ([IO.File]::ReadAllText("$activeProfile.previous") -eq 'preserved profile') `
        'a retry preserves the last known-good profile backup'
    Remove-Item -LiteralPath "$activeProfile.previous", "$activeSettings.previous", $preparedProfile,
        $missingPreparedSettings -Force

    $lockedMarker = Join-Path $temporary 'locked-stack-stopped'
    [IO.File]::WriteAllText($lockedMarker, 'stale')
    $markerLock = [IO.File]::Open($lockedMarker, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    $clearFailed = $false
    try { Clear-ProgramSplitStoppedMarker -Path $lockedMarker }
    catch { $clearFailed = $true }
    finally { $markerLock.Dispose() }
    Assert-True $clearFailed 'stopped-marker clearing fails closed when the stale marker is locked'
    Assert-True (Test-Path -LiteralPath $lockedMarker) 'failed marker clearing leaves the marker visible'
    Clear-ProgramSplitStoppedMarker -Path $lockedMarker
    Assert-True (-not (Test-Path -LiteralPath $lockedMarker)) 'stopped-marker clearing confirms absence'

    $traySource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Tray.ps1'))
    $controllerSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'))
    Assert-True ($traySource -match '(?s)catch \{.*Restore-ProgramSplitProfilePair.*-StoppedMarker \$stackStoppedFile') `
        'tray delegates rollback to the stopped-controller profile-pair restore'
    Assert-True ($controllerSource -match 'Join-Path \$state ''stack-stopped''' -and
        $controllerSource -match '(?s)if \(-not \(Test-StackPresent\)\).*WriteAllText\(\$stackStoppedFile') `
        'controller publishes the stopped acknowledgement only after the managed stack is absent'
    Assert-True ($controllerSource -match '\$service\.Status -ne ''Stopped''') `
        'controller treats pending tunnel-service states as stack-present'
    Assert-True ([regex]::Matches($traySource, 'Clear-ProgramSplitStoppedMarker').Count -ge 3) `
        'tray clears and verifies stopped acknowledgements before every transition that relies on freshness'
    $recoveryPreflight = $traySource.IndexOf('Test-Path -LiteralPath "$activeProfile.previous"')
    $replacementFlag = $traySource.IndexOf('$replacementAttempted = $true')
    Assert-True ($recoveryPreflight -ge 0 -and $recoveryPreflight -lt $replacementFlag) `
        'tray refuses stale recovery backups before treating profile replacement as started'
    Assert-True ($controllerSource -match '(?s)if \(\$desired\).*Clear-ProgramSplitStoppedMarker.*continue') `
        'controller refuses to start while a stale stopped acknowledgement cannot be cleared'

    $tunnelSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'))
    $stopBranch = $tunnelSource.IndexOf("if (`$Action -eq 'Stop')")
    $stopCall = $tunnelSource.IndexOf('Stop-Service', $stopBranch)
    $stopOwnershipCheck = $tunnelSource.IndexOf('Test-ProgramSplitServiceOwnership', $stopBranch)
    Assert-True ($stopBranch -ge 0 -and $stopOwnershipCheck -gt $stopBranch -and
        $stopOwnershipCheck -lt $stopCall) 'tunnel stop verifies service ownership before stopping it'

    $configRoot = Join-Path $temporary 'runtime'
    [IO.Directory]::CreateDirectory((Join-Path $configRoot 'config')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $configRoot 'config\settings.json'), '{"TunnelAddress":"192.0.2.2","TunnelDns":"203.0.113.53"}')
    $runtime = Get-ProgramSplitConfiguration -Root $configRoot
    Assert-True ($runtime.AdapterName -eq 'WireGuardSplit') 'runtime uses the neutral adapter name'
    Assert-True ($runtime.ServiceName -eq 'WireGuardTunnel$WireGuardSplit') 'runtime uses the neutral service name'
    Assert-True ($runtime.TunnelAddress -eq '192.0.2.2') 'runtime reads tunnel address from local settings'
    Assert-True ($runtime.TunnelDns -eq '203.0.113.53') 'runtime reads tunnel DNS from local settings'

    $prepare = Join-Path $RepositoryRoot 'src\powershell\Prepare-Profile.ps1'
    $input = Join-Path $temporary 'input.conf'
    $output = Join-Path $temporary 'WireGuardSplit.conf'
    $settings = Join-Path $temporary 'settings.json'
    $dummyKey = ('A' * 43) + '='
    $valid = @"
[Interface]
PrivateKey = $dummyKey
Address = 192.0.2.2/32
DNS = 203.0.113.53

[Peer]
PublicKey = $dummyKey
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
PersistentKeepalive = 25
"@
    [IO.File]::WriteAllText($input, $valid)
    & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl

    $prepared = [IO.File]::ReadAllText($output)
    $configuration = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    Assert-True ($prepared -match '(?m)^Table = off\r?$') 'prepared profile has Table = off'
    Assert-True ($prepared -notmatch '(?im)^DNS\s*=') 'prepared profile omits global adapter DNS'
    Assert-True ($prepared -match '(?m)^PersistentKeepalive = 25\r?$') `
        'profile preparation preserves optional Proton peer settings'
    Assert-True ($configuration.TunnelAddress -eq '192.0.2.2') 'settings retain the tunnel IPv4 address'
    Assert-True ($configuration.TunnelDns -eq '203.0.113.53') 'settings retain the tunnel DNS address'

    [IO.File]::WriteAllText($input, ($valid -replace '(?m)^DNS = .+\r?\n', ''))
    $missingDnsFailed = $false
    try { & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl } catch { $missingDnsFailed = $true }
    Assert-True $missingDnsFailed 'profile import rejects a missing DNS resolver'

    [IO.File]::WriteAllText($input, ($valid -replace 'Address = 192\.0\.2\.2/32', 'Address = 192.0.2.2/32, 2001:db8::2/128'))
    $ipv6Failed = $false
    try { & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl } catch { $ipv6Failed = $true }
    Assert-True $ipv6Failed 'profile import rejects IPv6 until IPv6 routing is implemented'

    function Assert-ProfileRejected(
        [string] $Text, [string] $Message, [string] $InputPath,
        [string] $OutputPath, [string] $SettingsPath
    ) {
        [IO.File]::WriteAllText($InputPath, $Text)
        $failed = $false
        try { & $prepare -InputPath $InputPath -OutputPath $OutputPath -SettingsPath $SettingsPath -SkipAcl }
        catch { $failed = $true }
        Assert-True $failed $Message
    }
    Assert-ProfileRejected ($valid + "`n[Peer]`nPublicKey = $dummyKey`nAllowedIPs = 0.0.0.0/0`nEndpoint = 198.51.100.11:51820`n") `
        'profile import rejects multiple peer sections' $input $output $settings
    Assert-ProfileRejected ($valid -replace '(?m)^DNS = .+$', "DNS = 203.0.113.53`nDNS = 203.0.113.54") `
        'profile import rejects duplicate required fields' $input $output $settings
    Assert-ProfileRejected ($valid -replace "PrivateKey = $([regex]::Escape($dummyKey))", 'PrivateKey =') `
        'profile import rejects an empty private key' $input $output $settings
    $spacedKey = $dummyKey.Insert(10, ' ')
    Assert-ProfileRejected ($valid -replace "PrivateKey = $([regex]::Escape($dummyKey))", "PrivateKey = $spacedKey") `
        'profile import rejects a noncanonical WireGuard key' $input $output $settings
    Assert-ProfileRejected ($valid -replace ':51820', ':70000') `
        'profile import rejects an invalid endpoint port' $input $output $settings
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "PASS: $($scripts.Count) PowerShell scripts parse and profile import is provider-neutral."
