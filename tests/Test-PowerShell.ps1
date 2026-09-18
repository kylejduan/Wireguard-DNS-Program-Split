# SPDX-License-Identifier: GPL-3.0-or-later
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
$dnsCacheSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-DnsCachePolicy.ps1'))
Assert-True ($dnsCacheSource -match 'Failed to restore DNS cache policy value') `
    'DNS cache teardown verifies restored registry values'
$commonSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Common.ps1'))
Assert-True ($commonSource -match "(?s)function Assert-ProgramSplitNoIpv6DefaultRoute.*?Get-NetRoute -AddressFamily IPv6.*?'::/0'.*?-ErrorAction SilentlyContinue.*?throw") `
    'shared IPv4-only guard treats a missing IPv6 default as healthy'

$controllerSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'))
Assert-True ($controllerSource -match '(?s)\.Handle.*?WaitForExit\(45000\).*?WaitForExit\(\).*?\.ExitCode') `
    'controller retains the child handle and finalizes its wait before reading ExitCode'
Assert-True ($controllerSource -match '(?s)function Invoke-Component.*?Start-Component.*?Complete-Component') `
    'ordinary component calls retain the isolated start-and-complete path'
Assert-True ($controllerSource -notmatch 'Start-Sleep -Seconds 2\s+Test-TunnelDns') `
    'controller startup has no fixed pre-probe sleep'
Assert-True ($controllerSource -match 'function Test-DnsCachePolicyReady' -and
    $controllerSource -match "(?s)if \(-not \(Test-DnsCachePolicyReady\)\).*?Invoke-Component 'Invoke-DnsCachePolicy\.ps1' 'Enable'") `
    'controller skips DNS cache repair only when persisted policy state is already ready'
$cacheReadySource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Test-DnsCachePolicyReady'),
    $controllerSource.IndexOf('function Test-PiaDriverReady') -
        $controllerSource.IndexOf('function Test-DnsCachePolicyReady'))
Assert-True ($cacheReadySource -match 'dnscache-policy-original\.json.*?-PathType Leaf' -and
    $cacheReadySource -match '\$null -ne \$positiveTtl' -and
    $cacheReadySource -match '\$null -ne \$negativeTtl' -and
    $cacheReadySource -match '\[int\]\$positiveTtl -eq 1' -and
    $cacheReadySource -match '\[int\]\$negativeTtl -eq 0') `
    'DNS cache fast path requires recovery state and both exact non-null policy values'
Assert-True ($controllerSource -match '(?s)function Test-PiaDriverReady.*?Get-Service -Name ''PiaWFPCallout''.*?Status -eq ''Running''' -and
    $controllerSource -match "(?s)if \(-not \(Test-PiaDriverReady\)\).*?Start-Component 'Invoke-PiaDriver\.ps1' 'Install'") `
    'controller skips PIA driver setup only when the driver is already running'
$piaReadySource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Test-PiaDriverReady'),
    $controllerSource.IndexOf('function Start-Stack') -
        $controllerSource.IndexOf('function Test-PiaDriverReady'))
Assert-True ($piaReadySource -match 'ServiceType.*?KernelDriver' -and
    $piaReadySource -match 'PiaWFPCallout\.inf' -and $piaReadySource -match 'PiaWfpCallout\.sys' -and
    $piaReadySource -match 'piawfpcallout\.cat') `
    'PIA fast path requires the kernel driver type and installed package files'
Assert-True ($controllerSource -match '(?s)\.ExitTime.*?\.StartTime.*?completed in \$elapsedMilliseconds ms') `
    'controller records each parallel child process actual runtime instead of queueing delay'
Assert-True ($controllerSource -match 'Stack active after tunnel readiness check in \$\(\$stackTimer\.ElapsedMilliseconds\) ms') `
    'controller records total stack startup timing'
$stopStack = $controllerSource.IndexOf('function Stop-Stack')
$stopWfp = $controllerSource.IndexOf("Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop'", $stopStack)
$stopNrpt = $controllerSource.IndexOf("Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable'", $stopStack)
Assert-True ($stopWfp -gt $stopStack -and $stopWfp -lt $stopNrpt) `
    'controller removes payload filters before restoring direct DNS'
Assert-True ($controllerSource -match "Invoke-Component 'Invoke-LocalNrpt.ps1' 'Validate'") `
    'controller health validates the active NRPT namespace'
$stackHealthSource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Test-StackHealth'),
    $controllerSource.IndexOf('function Invoke-Repair') -
        $controllerSource.IndexOf('function Test-StackHealth'))
Assert-True ($stackHealthSource -match 'Assert-ProgramSplitNoIpv6DefaultRoute') `
    'controller health rejects an IPv6 default route that appears after startup'
$tunnelProbeSource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Test-TunnelDns'),
    $controllerSource.IndexOf('function Invoke-Repair') - $controllerSource.IndexOf('function Test-TunnelDns'))
Assert-True ($tunnelProbeSource -match '(?s)\.Handle.*?WaitForExit\(\$TimeoutMilliseconds \* \$Attempts \+ 3000\).*?WaitForExit\(\)') `
    'tunnel DNS probe drains redirected output before evaluating it'
$startStackSource = $controllerSource.Substring(
    $controllerSource.IndexOf('function Start-Stack'),
    $controllerSource.IndexOf('$required = @(') - $controllerSource.IndexOf('function Start-Stack'))
Assert-True ($startStackSource.IndexOf('Assert-ProgramSplitNoIpv6DefaultRoute') -ge 0 -and
    $startStackSource.IndexOf('Assert-ProgramSplitNoIpv6DefaultRoute') -lt
        $startStackSource.IndexOf('$startupComponents')) `
    'controller rejects persistent IPv6 before launching repair components'
Assert-True ($startStackSource -match '(?s)if \(\$dispatcherWasRunning\).*?Invoke-Component ''Invoke-DnsDispatcher\.ps1'' ''Validate''.*?else \{ Test-LocalDns \}') `
    'fresh startup uses the native DNS gate while an adopted dispatcher receives full validation'
$tunnelParallelStart = $startStackSource.IndexOf("Start-Component 'Invoke-Tunnel.ps1' 'Start'")
$dispatcherParallelStart = $startStackSource.IndexOf("Start-Component 'Invoke-DnsDispatcher.ps1' 'Start'")
$parallelCompletion = $startStackSource.IndexOf('Complete-Component', [Math]::Max($tunnelParallelStart, $dispatcherParallelStart))
$tunnelReadiness = $startStackSource.IndexOf('Wait-ProgramSplitProbe', $parallelCompletion)
Assert-True ($tunnelParallelStart -ge 0 -and $dispatcherParallelStart -ge 0 -and
    $parallelCompletion -gt $tunnelParallelStart -and $parallelCompletion -gt $dispatcherParallelStart -and
    $tunnelReadiness -gt $parallelCompletion) `
    'controller overlaps independent tunnel and dispatcher startup before enforcing tunnel readiness'
Assert-True ($startStackSource -match '(?s)startupFailures.*?foreach \(\$component in \$startupComponents\).*?Complete-Component.*?if \(\$startupFailures\.Count\).*?throw') `
    'parallel startup drains every launched component before propagating a failure'
Assert-True ($controllerSource -match '(?s)\$wfpStopped\s*=.*?if \(\$wfpStopped\).*?Invoke-LocalNrpt') `
    'controller does not restore direct DNS after a WFP-stop failure'
Assert-True ($controllerSource -match 'Test-Path -LiteralPath \$activeFile -PathType Leaf') `
    'controller adopts only a stack that completed its readiness gates'
Assert-True ($controllerSource -match 'Test-Path -LiteralPath \(Join-Path \$state ''dns-etw-session\.txt''\)') `
    'controller treats owned ETW session state as a managed stack component'
Assert-True ($controllerSource -match '(?s)StopEventHandle.*?SafeWaitHandle.*?WaitOne\(0\).*?Stop-Stack -RestoreCache.*?break') `
    'controller cooperatively cleans the stack before a service stop'
Assert-True ($controllerSource -match '(?s)Stop-Stack -RestoreCache.*?Test-StackPresent.*?continue.*?break') `
    'controller verifies cleanup before completing a service stop'
Assert-True ($controllerSource -match '(?s)function Stop-Stack.*?ThrowOnFailure.*?cleanupErrors.*?throw' -and
    $controllerSource -match '\$stopCleanupWindow = \[TimeSpan\]::FromSeconds\(150\)' -and
    $controllerSource -match '(?s)\$stopRequestedAt = Get-Date.*?try \{ Stop-Stack -RestoreCache -ThrowOnFailure \}\s*catch \{\s*if \(\(Get-Date\) - \$stopRequestedAt -ge \$stopCleanupWindow\) \{ throw \}.*?continue') `
    'service stop retries cleanup and checks its window after each attempt, well inside the host deadline'
Assert-True ($controllerSource -match '(?s)if \(-not \$desired\).*?try \{.*?Stop-Stack -RestoreCache -ThrowOnFailure.*?\} catch \{.*?try \{ \[IO\.File\]::WriteAllText\(\$errorFile, \$cleanupFailure\) \} catch \{ \}.*?\$nextCleanup = \(Get-Date\)\.AddSeconds\(\$cleanupDelaySeconds\).*?\[Math\]::Min\(60, \$cleanupDelaySeconds \* 2\)') `
    'interactive disable records cleanup failures best-effort and retries with bounded backoff instead of exiting'
Assert-True ($controllerSource -match '(?s)if \(\$desired\) \{\s*\$nextCleanup = \[DateTime\]::MinValue\s*\$cleanupDelaySeconds = 2') `
    'enabling the stack clears disable-cleanup backoff so a later disable is not deferred'
$completeComponent = $controllerSource.Substring($controllerSource.IndexOf('function Complete-Component'))
Assert-True ($completeComponent.IndexOf('Write-ControllerLog ($output') -ge 0 -and
    $completeComponent.IndexOf('Write-ControllerLog ($output') -lt $completeComponent.IndexOf('$process.ExitCode -ne 0')) `
    'controller logs a component''s output before judging its exit so a failed run keeps its action record'
Assert-True ($controllerSource -match '(?s)Write-ControllerLog "Stack health check failed.*?\$_\.Exception\.Message.*?Stop-Stack\s*Invoke-Repair') `
    'controller logs why a health check failed before restarting the stack'
Assert-True ($controllerSource -match 'Test-Path -LiteralPath \(Join-Path \$state ''endpoint-route\.txt''\)') `
    'controller treats endpoint-route recovery state as a managed stack component'
Assert-True ($controllerSource -match '(?s)if \(-not \$StopEventHandle\).*?Global\\WireGuardProgramSplitController') `
    'service-mode controller relies on SCM ownership instead of a spoofable global mutex'
Assert-True ($controllerSource -match '(?s)Get-ProgramSplitPhysicalDefault.*?catch \{.*?return.*?Start-Stack') `
    'controller waits for a physical default route without entering repair backoff'
Assert-True ($controllerSource -match '\$networkRetryMilliseconds\s*=\s*250' -and
    $controllerSource -match '(?s)\$loopWaitMilliseconds\s*=\s*if \(\$desired -and \$script:networkWaitLogged\).*?\$script:networkRetryMilliseconds.*?2000' -and
    $controllerSource -match '\[Math\]::Min\(2000, \$script:networkRetryMilliseconds \* 2\)' -and
    $controllerSource -match 'WaitOne\(\$loopWaitMilliseconds\)' -and
    $controllerSource -match 'Start-Sleep -Milliseconds \$loopWaitMilliseconds') `
    'controller checks network readiness quickly with bounded backoff only while waiting for the physical route'

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

    $ownedEndpointState = [pscustomobject]@{
        DestinationPrefix = '203.0.113.8/32'; InterfaceIndex = 7
        NextHop = '192.0.2.1'; RouteMetric = 1
    }
    $ownedEndpointRoute = [pscustomobject]@{
        DestinationPrefix = '203.0.113.8/32'; InterfaceIndex = 7
        NextHop = '192.0.2.1'; RouteMetric = 1
    }
    $foreignEndpointRoute = [pscustomobject]@{
        DestinationPrefix = '203.0.113.8/32'; InterfaceIndex = 19
        NextHop = '198.51.100.1'; RouteMetric = 1
    }
    Assert-True (Test-ProgramSplitEndpointRouteOwnership -Route $ownedEndpointRoute `
        -State $ownedEndpointState) 'endpoint route ownership accepts the exact recorded tuple'
    Assert-True (-not (Test-ProgramSplitEndpointRouteOwnership -Route $foreignEndpointRoute `
        -State $ownedEndpointState)) 'endpoint route ownership rejects a foreign same-prefix route'
    foreach ($field in @('InterfaceIndex', 'NextHop', 'RouteMetric')) {
        $differentEndpointRoute = $ownedEndpointRoute.PSObject.Copy()
        if ($field -eq 'InterfaceIndex') { $differentEndpointRoute.InterfaceIndex = 8 }
        elseif ($field -eq 'NextHop') { $differentEndpointRoute.NextHop = '192.0.2.2' }
        else { $differentEndpointRoute.RouteMetric = 2 }
        Assert-True (-not (Test-ProgramSplitEndpointRouteOwnership -Route $differentEndpointRoute `
            -State $ownedEndpointState)) "endpoint route ownership rejects a $field mismatch"
    }

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
        Assert-True ($wowProbe.WaitForExit(30000)) '32-bit PowerShell guard probe completes'
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
    } -TimeoutMilliseconds 5000 -RetryMilliseconds 0
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
        -ArgumentPath $profilePath) 'service ownership accepts the exact tunnel host command'
    $foreignService = [pscustomobject]@{ PathName = 'C:\Other\service.exe' }
    Assert-True (-not (Test-ProgramSplitServiceOwnership -Service $foreignService -HostPath $hostExe `
        -ArgumentPath $profilePath)) 'service ownership rejects a same-name foreign command'
    $controllerHost = 'C:\ProgramData\WireGuardProgramSplit\bin\controller-service.exe'
    $controllerScript = 'C:\ProgramData\WireGuardProgramSplit\src\Controller.ps1'
    $ownedControllerService = [pscustomobject]@{ PathName = "$controllerHost /service $controllerScript" }
    Assert-True (Test-ProgramSplitServiceOwnership -Service $ownedControllerService `
        -HostPath $controllerHost -ArgumentPath $controllerScript) `
        'service ownership accepts the exact controller host command'

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
    $dispatcherValidateStart = $dispatcherScriptSource.IndexOf("if (`$Action -eq 'Validate')")
    $dispatcherValidateEnd = $dispatcherScriptSource.IndexOf('$componentMutex =', $dispatcherValidateStart)
    $dispatcherValidateSource = $dispatcherScriptSource.Substring(
        $dispatcherValidateStart, $dispatcherValidateEnd - $dispatcherValidateStart)
    $dispatcherStartSource = $dispatcherScriptSource.Substring(
        $dispatcherScriptSource.IndexOf('$process = $null'))
    Assert-True ($dispatcherValidateSource -match 'Get-NetUDPEndpoint' -and
        $dispatcherValidateSource -match 'Get-NetTCPConnection') `
        'dispatcher health validation retains independent socket ownership checks'
    Assert-True ($dispatcherStartSource -match "\(\?m\)\^READY:" -and
        $dispatcherStartSource -notmatch 'Get-NetUDPEndpoint|Get-NetTCPConnection') `
        'dispatcher startup uses its flushed native readiness signal without slow endpoint cmdlets'
    $clearIndex = $dispatcherStartSource.IndexOf('[IO.File]::WriteAllText($stdout')
    $startIndex = $dispatcherStartSource.IndexOf('Start-Process')
    $pollIndex = $dispatcherStartSource.IndexOf("-match '(?m)^READY:'")
    Assert-True ($clearIndex -ge 0 -and $startIndex -gt $clearIndex -and $pollIndex -gt $startIndex) `
        'dispatcher clears stale readiness output before launch and polling'
    Assert-True ("HINT example.com`r`nREADY: dispatcher" -match '(?m)^READY:') `
        'dispatcher readiness pattern accepts a preceding ETW hint line'
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
    $nativeDispatcherSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\native\dns-dispatcher.cpp'))
    $listenIndex = $nativeDispatcherSource.IndexOf('listen(gTcpListener')
    $readyIndex = $nativeDispatcherSource.IndexOf('logLine(L"READY: ETW split-DNS dispatcher')
    Assert-True ($listenIndex -ge 0 -and $readyIndex -gt $listenIndex -and
        $nativeDispatcherSource -match '(?s)logLine\(L"READY: ETW split-DNS dispatcher.*?std::to_wstring\(trace\.frequency\(\)\), true\);') `
        'native dispatcher serializes and flushes READY after UDP/TCP bind and TCP listen succeed'
    $tunnelSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-Tunnel.ps1'))
    Assert-True ($tunnelSource -notmatch 'InterfaceAlias -ne \$adapterName' -and
        $tunnelSource -notmatch 'Add-ActiveRoute -prefix "\$endpoint/32"' -and
        $tunnelSource -match 'Test-ProgramSplitEndpointRouteOwnership') `
        'tunnel cleanup removes only a recorded exact endpoint-route tuple'
    Assert-True ($tunnelSource -match 'DestinationPrefix\s*=\s*"\$endpoint/32"' -and
        $tunnelSource -match 'InterfaceIndex\s*=\s*\[uint32\]\s*\$physical\.InterfaceIndex' -and
        $tunnelSource -match 'NextHop\s*=\s*\[string\]\s*\$physical\.NextHop' -and
        $tunnelSource -match 'RouteMetric\s*=\s*1') `
        'endpoint-route recovery state records the complete created route identity'
    $endpointStateIndex = $tunnelSource.IndexOf('Set-OwnedEndpointRouteState $routeState')
    $endpointCreateIndex = $tunnelSource.IndexOf('New-NetRoute', $endpointStateIndex)
    Assert-True ($tunnelSource -match '(?s)\$existingEndpointRoute\s*=\s*Get-NetRoute.*?if \(-not \$existingEndpointRoute\).*?New-NetRoute' -and
        $endpointStateIndex -ge 0 -and $endpointCreateIndex -gt $endpointStateIndex) `
        'tunnel leaves a pre-existing exact route untouched and records ownership before creation'
    $buildSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'scripts\build-wsl.sh'))
    Assert-True ($buildSource -match 'dns-probe\.exe.*-ldnsapi') 'native DNS probe links the Windows DNS API'
    Assert-True ($buildSource -match 'controller-service\.exe') 'build includes the native controller service host'
    $controllerServiceSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\native\controller-service.cpp'))
    $controllerHandlerSource = $controllerServiceSource.Substring(
        $controllerServiceSource.IndexOf('DWORD WINAPI controlHandler'),
        $controllerServiceSource.IndexOf('void WINAPI serviceMain') -
            $controllerServiceSource.IndexOf('DWORD WINAPI controlHandler'))
    Assert-True ($controllerHandlerSource -notmatch 'reportStatus') `
        'controller service serializes status updates on its service-main thread'
    Assert-True ($controllerServiceSource -match 'SERVICE_ACCEPT_STOP \| SERVICE_ACCEPT_SHUTDOWN \| SERVICE_ACCEPT_PRESHUTDOWN' -and
        $controllerServiceSource -match 'control == SERVICE_CONTROL_SHUTDOWN \|\| control == SERVICE_CONTROL_PRESHUTDOWN' -and
        $controllerHandlerSource -match '(?s)isShutdownControl\(control\)\) \{\s*if \(gShutdownEvent\) SetEvent\(gShutdownEvent\);\s*return NO_ERROR;') `
        'controller service accepts shutdown and pre-shutdown without signalling stack cleanup'
    Assert-True ([regex]::Matches($controllerServiceSource, 'appendHostLog\(describeStop\(').Count -eq 3) `
        'controller service records which path ended it on every stop'
    Assert-True ($controllerServiceSource -match '(?s)HANDLE waits\[\] = \{gStopEvent, child, gShutdownEvent\};.*?WAIT_OBJECT_0 \+ 2\) \{\s*//[^\r\n]*\s*reportStatus\(SERVICE_STOPPED\);' -and
        $controllerServiceSource -match '(?s)duringShutdown = systemShuttingDown\(kShutdownGraceMilliseconds\);.*?unrequestedExitReport\(duringShutdown') `
        'controller service reports a shutdown-ended controller as a clean stop and other exits as failures'
    Assert-True ($controllerServiceSource -notmatch 'Global\\\\WireGuardProgramSplitControllerStop' -and
        $controllerServiceSource -match 'CreateEventW\(&eventAttributes, TRUE, FALSE, nullptr\)' -and
        $controllerServiceSource -match '-StopEventHandle') `
        'controller service uses an inherited unnamed stop event'
    Assert-True ($controllerServiceSource -match 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE' -and
        $controllerServiceSource -match 'JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK') `
        'controller service preserves adoptable data-plane children across supervisor recovery'
    Assert-True ($controllerServiceSource -match '(?s)controller-service\.log.*?GENERIC_WRITE,\s*FILE_SHARE_READ\s*\|\s*FILE_SHARE_WRITE') `
        'controller service can reopen its log while adoptable children retain inherited handles'
    Assert-True ($controllerServiceSource -match 'kStopTimeoutMilliseconds = 240000' -and
        $controllerServiceSource -match '(?s)TerminateJobObject.*?SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR') `
        'controller service gives ordered cleanup time and reports forced stop as failure'
    $uninstallSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'Uninstall.ps1'))
    Assert-True ($uninstallSource -match '(?s)Invoke-Cleanup ''Invoke-WfpFilters\.ps1'' ''Stop''.*?if \(\$wfpStopped\).*?Invoke-Cleanup ''Invoke-LocalNrpt\.ps1'' ''Disable''') `
        'uninstaller restores direct DNS only after WFP filters stop'
    Assert-True ($uninstallSource -match 'Assert-ProgramSplit64BitPowerShell') `
        'uninstaller refuses cross-bitness process ownership checks'
    Assert-True ($uninstallSource -match '(?s)Set-Service -Name \$plan\.ControllerServiceName -StartupType Disabled.*?failureflag.*?0.*?Stop-Service -Name \$plan\.ControllerServiceName') `
        'uninstaller disables startup and recovery before stopping the controller service'
    Assert-True ($uninstallSource -match 'if \(\$controllerService\.Status -ne ''StopPending''\)') `
        'uninstaller waits for an existing controller stop instead of issuing a duplicate control'

    Assert-ProgramSplitInstallNamesAvailable -Tasks @() -Services @()
    $collisionFailed = $false
    try { Assert-ProgramSplitInstallNamesAvailable -Tasks @($foreignTask) -Services @() }
    catch { $collisionFailed = $true }
    Assert-True $collisionFailed 'installation refuses an existing same-name task'
    $collisionFailed = $false
    try { Assert-ProgramSplitInstallNamesAvailable -Tasks @() -Services @($null, $foreignService) }
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
    $stopCall = $tunnelSource.IndexOf('$service.Stop()', $stopBranch)
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
