# SPDX-License-Identifier: GPL-3.0-or-later
# Short-lived mutations for the native tray. Profile transactions deliberately
# retain the established PowerShell implementation and its fail-closed rollback.
param(
    [ValidateSet('Status', 'Toggle', 'Add', 'Remove', 'Import')]
    [string] $Action = 'Status',
    [string] $InputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-ProgramSplit64BitPowerShell
$configuration = Get-ProgramSplitConfiguration -Root $root
$state = Join-Path $root 'state'
$includeFile = Join-Path $state 'included-apps.txt'
$enabledFile = Join-Path $state 'enabled'
$activeFile = Join-Path $state 'active'
$stackStoppedFile = Join-Path $state 'stack-stopped'
$reloadFile = Join-Path $state 'reload.request'
$keepFiltersFile = Join-Path $state 'keep-filters.request'
$activeProfile = $configuration.ProfilePath
$activeSettings = $configuration.SettingsPath

function Get-IncludedApps {
    if (-not (Test-Path -LiteralPath $includeFile -PathType Leaf)) { return @() }
    return @([IO.File]::ReadAllLines($includeFile) | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') })
}

function Save-IncludedApps([string[]] $apps) {
    $unique = @($apps | Sort-Object -Unique)
    if (-not $unique) { throw 'Keep at least one included application.' }
    $temp = "$includeFile.new"
    [IO.File]::WriteAllLines($temp, $unique, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $includeFile -Force
    [IO.File]::WriteAllText($reloadFile, (Get-Date -Format o))
}

function Import-Profile([string] $InputPath) {
    $wasEnabled = $false
    $disableRequested = $false
    $stopConfirmed = $false
    $replacementAttempted = $false
    $holdWritten = $false
    $resumeRequested = $false
    $resumeConfirmed = $false
    try {
        if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw 'Profile input does not exist.' }
        $wasEnabled = Test-Path -LiteralPath $enabledFile -PathType Leaf
        if ((Test-Path -LiteralPath "$activeProfile.previous") -or
            (Test-Path -LiteralPath "$activeSettings.previous")) {
            throw 'A preserved recovery backup exists; resolve it before importing another profile.'
        }
        Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile
        # Swapping the profile is not a disable: the persistent payload filters stay, so selected
        # applications fail closed until the stack returns with the new tunnel address.
        if ($wasEnabled) {
            [IO.File]::WriteAllText($keepFiltersFile, (Get-Date -Format o))
            $holdWritten = $true
        }
        Remove-Item -LiteralPath $enabledFile -Force -ErrorAction SilentlyContinue
        $disableRequested = $true
        $stopWait = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $stackStoppedFile -PathType Leaf) -and $stopWait.Elapsed.TotalSeconds -lt 60) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path -LiteralPath $stackStoppedFile -PathType Leaf)) { throw 'The controller did not stop the managed stack.' }
        $stopConfirmed = $true

        $prepared = "$activeProfile.new"
        $preparedSettings = "$activeSettings.new"
        $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $preparation = Invoke-ProgramSplitProcess -FilePath $powerShell -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $PSScriptRoot 'Prepare-Profile.ps1'), '-InputPath', $InputPath,
            '-OutputPath', $prepared, '-SettingsPath', $preparedSettings, '-SkipAcl'
        ) -TimeoutMilliseconds 30000 -Encoding Oem
        if ($preparation.TimedOut) { throw 'Profile preparation timed out.' }
        if ($preparation.ExitCode -ne 0 -or $preparation.OutputTruncated -or $preparation.ErrorTruncated) {
            throw "Profile preparation failed: $(@($preparation.Error + $preparation.Output) -join ' ')"
        }
        $replacementAttempted = $true
        Install-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -PreparedProfile $prepared -PreparedSettings $preparedSettings | Out-Null

        if ($wasEnabled) {
            Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile
            [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
            $resumeRequested = $true
            $startWait = [Diagnostics.Stopwatch]::StartNew()
            while (-not (Test-Path -LiteralPath $activeFile -PathType Leaf) -and $startWait.Elapsed.TotalSeconds -lt 50) { Start-Sleep -Milliseconds 500 }
            if (-not (Test-Path -LiteralPath $activeFile -PathType Leaf)) {
                throw 'The imported profile failed its tunnel-DNS readiness check.'
            }
            $resumeConfirmed = $true
        }
        try {
            Remove-Item -LiteralPath "$activeProfile.previous", "$activeSettings.previous" -Force -ErrorAction Stop
        } catch {
            Write-Output "WARNING: The new profile is active, but recovery-backup cleanup failed: $($_.Exception.Message)"
            return
        }
        Write-Output 'The WireGuard profile passed validation.'
    } catch {
        $failure = $_.Exception.Message
        if ($disableRequested) {
            $resumeRequested = $false
            Remove-Item -LiteralPath $enabledFile -Force -ErrorAction SilentlyContinue
        }
        $rollbackErrors = [Collections.Generic.List[string]]::new()
        if ($replacementAttempted) {
            try { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
            catch { $rollbackErrors.Add($_.Exception.Message) }
            if (-not $rollbackErrors.Count) {
                try {
                    Restore-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
                        -StoppedMarker $stackStoppedFile -TimeoutSeconds 60
                } catch { $rollbackErrors.Add($_.Exception.Message) }
            }
        }
        Remove-Item -LiteralPath "$activeProfile.new", "$activeSettings.new" -Force -ErrorAction SilentlyContinue
        if ($wasEnabled -and $disableRequested -and ($stopConfirmed -or -not $replacementAttempted) -and -not $rollbackErrors.Count) {
            try {
                if ($stopConfirmed) { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
                [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
                $resumeRequested = $true
            } catch { $rollbackErrors.Add($_.Exception.Message) }
        }
        if ($rollbackErrors.Count) {
            $failure += " Rollback also failed; the tunnel remains disabled: $($rollbackErrors -join '; ')"
        } elseif ($disableRequested -and $resumeRequested) {
            $failure += ' The previous enabled state was requested again.'
        } elseif ($disableRequested) {
            $failure += ' The split remains disabled.'
        }
        throw $failure
    }
    finally {
        # An unconfirmed re-enable may race a controller pass that sampled the
        # disabled intent. A new active marker proves that pass has completed,
        # so successful imports can clear the hold without leaving stale state.
        if ($holdWritten -and (-not $resumeRequested -or $resumeConfirmed)) {
            Remove-Item -LiteralPath $keepFiltersFile -Force -ErrorAction SilentlyContinue
        }
    }
}

$mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitTrayAction')
$held = $false
try {
    try { $held = $mutex.WaitOne(5000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { throw 'Another tray operation is still running.' }
    foreach ($path in @($includeFile, $activeProfile, $activeSettings, (Join-Path $PSScriptRoot 'Prepare-Profile.ps1'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing tray input: $path" }
    }
    switch ($Action) {
        'Status' {
            if (-not (Get-IncludedApps)) { throw 'The included-app list is empty.' }
            Write-Output 'PASS: tray inputs and include list.'
        }
        'Toggle' {
            if (Test-Path -LiteralPath $enabledFile -PathType Leaf) {
                Remove-Item -LiteralPath $keepFiltersFile -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $enabledFile -Force
                Write-Output 'Disabling the split tunnel.'
            } else {
                [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
                Write-Output 'Starting the split tunnel and DNS dispatcher.'
            }
        }
        'Add' {
            $path = (Get-Item -LiteralPath $InputPath -ErrorAction Stop).FullName
            if ([IO.Path]::GetExtension($path) -ine '.exe') { throw 'Select an .exe file.' }
            Save-IncludedApps (@(Get-IncludedApps) + $path)
            Write-Output 'Application added; routing is reloading.'
        }
        'Remove' {
            Save-IncludedApps @(Get-IncludedApps | Where-Object { $_ -ine $InputPath })
            Write-Output 'Application removed; routing is reloading.'
        }
        'Import' { Import-Profile $InputPath }
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit 0
