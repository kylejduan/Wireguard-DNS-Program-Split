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
