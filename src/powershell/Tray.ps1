# SPDX-License-Identifier: GPL-3.0-or-later
param([switch] $SelfTest)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
$state = Join-Path $root 'state'
$logs = Join-Path $root 'logs'
$includeFile = Join-Path $state 'included-apps.txt'
$enabledFile = Join-Path $state 'enabled'
$activeFile = Join-Path $state 'active'
$stackStoppedFile = Join-Path $state 'stack-stopped'
$reloadFile = Join-Path $state 'reload.request'
$errorFile = Join-Path $state 'last-error.txt'
$activeProfile = $configuration.ProfilePath
$activeSettings = $configuration.SettingsPath

function Get-IncludedApps {
    if (-not (Test-Path -LiteralPath $includeFile -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $includeFile | ForEach-Object { $_.Trim() } |
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

function Get-StatusText {
    if (Test-Path -LiteralPath $activeFile -PathType Leaf) { return 'Enabled' }
    if (Test-Path -LiteralPath $enabledFile -PathType Leaf) { return 'Starting / recovering' }
    return 'Disabled'
}

foreach ($path in @($includeFile, $activeProfile, $activeSettings, (Join-Path $PSScriptRoot 'Prepare-Profile.ps1'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing tray input: $path" }
}
if ($SelfTest) {
    if (-not (Get-IncludedApps)) { throw 'The included-app list is empty.' }
    Write-Output 'PASS: tray inputs and include list.'
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitTray')
if (-not $mutex.WaitOne(0)) { exit 0 }

$icon = [Windows.Forms.NotifyIcon]::new()
$icon.Icon = [Drawing.SystemIcons]::Shield
$icon.Text = 'WireGuard Program Split'
$icon.Visible = $true
$menu = [Windows.Forms.ContextMenuStrip]::new()
$statusItem = $menu.Items.Add('Status: checking')
$statusItem.Enabled = $false
$toggleItem = $menu.Items.Add('Enable')
$menu.Items.Add([Windows.Forms.ToolStripSeparator]::new()) | Out-Null
$addItem = $menu.Items.Add('Add application...')
$removeMenu = [Windows.Forms.ToolStripMenuItem]::new('Remove application')
$menu.Items.Add($removeMenu) | Out-Null
$importItem = $menu.Items.Add('Import WireGuard profile...')
$menu.Items.Add([Windows.Forms.ToolStripSeparator]::new()) | Out-Null
$logsItem = $menu.Items.Add('Open logs')
$errorItem = $menu.Items.Add('Show last error')
$exitItem = $menu.Items.Add('Exit tray (VPN stays as set)')
$icon.ContextMenuStrip = $menu

function Show-Notice([string] $title, [string] $message, [Windows.Forms.ToolTipIcon] $kind = 'Info') {
    $icon.BalloonTipTitle = $title
    $icon.BalloonTipText = $message
    $icon.BalloonTipIcon = $kind
    $icon.ShowBalloonTip(5000)
}

function Update-Ui {
    $status = Get-StatusText
    $statusItem.Text = "Status: $status"
    $toggleItem.Text = if (Test-Path -LiteralPath $enabledFile) { 'Disable' } else { 'Enable' }
    $icon.Text = "WireGuard Program Split - $status"
}

function Rebuild-RemoveMenu {
    $removeMenu.DropDownItems.Clear()
    foreach ($path in Get-IncludedApps) {
        $item = [Windows.Forms.ToolStripMenuItem]::new($path)
        $item.Tag = $path
        $item.add_Click({
            param($sender, $eventArgs)
            try {
                $remaining = @(Get-IncludedApps | Where-Object { $_ -ine [string]$sender.Tag })
                Save-IncludedApps $remaining
                Show-Notice 'WireGuard Program Split' 'Application removed; routing is reloading.'
            } catch { Show-Notice 'Remove failed' $_.Exception.Message 'Error' }
        })
        $removeMenu.DropDownItems.Add($item) | Out-Null
    }
}

$toggleItem.add_Click({
    try {
        if (Test-Path -LiteralPath $enabledFile) {
            Remove-Item -LiteralPath $enabledFile -Force
            Show-Notice 'WireGuard Program Split' 'Disabling the split tunnel.'
        } else {
            [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
            Show-Notice 'WireGuard Program Split' 'Starting the split tunnel and DNS dispatcher.'
        }
        Update-Ui
    } catch { Show-Notice 'Toggle failed' $_.Exception.Message 'Error' }
})

$addItem.add_Click({
    $dialog = [Windows.Forms.OpenFileDialog]::new()
    $dialog.Filter = 'Applications (*.exe)|*.exe'
    $dialog.CheckFileExists = $true
    try {
        if ($dialog.ShowDialog() -eq 'OK') {
            $path = (Get-Item -LiteralPath $dialog.FileName).FullName
            if ([IO.Path]::GetExtension($path) -ine '.exe') { throw 'Select an .exe file.' }
            Save-IncludedApps (@(Get-IncludedApps) + $path)
            Show-Notice 'WireGuard Program Split' 'Application added; routing is reloading.'
        }
    } catch { Show-Notice 'Add failed' $_.Exception.Message 'Error' }
    finally { $dialog.Dispose() }
})

$removeMenu.add_DropDownOpening({ Rebuild-RemoveMenu })

$importItem.add_Click({
    $dialog = [Windows.Forms.OpenFileDialog]::new()
    $dialog.Filter = 'WireGuard profiles (*.conf)|*.conf'
    $dialog.CheckFileExists = $true
    $wasEnabled = $false
    $disableRequested = $false
    $stopConfirmed = $false
    $replacementAttempted = $false
    try {
        if ($dialog.ShowDialog() -ne 'OK') { return }
        $wasEnabled = Test-Path -LiteralPath $enabledFile
        if ((Test-Path -LiteralPath "$activeProfile.previous") -or
            (Test-Path -LiteralPath "$activeSettings.previous")) {
            throw 'A preserved recovery backup exists; resolve it before importing another profile.'
        }
        Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile
        Remove-Item -LiteralPath $enabledFile -Force -ErrorAction SilentlyContinue
        $disableRequested = $true
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path -LiteralPath $stackStoppedFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path -LiteralPath $stackStoppedFile)) { throw 'The controller did not stop the managed stack.' }
        $stopConfirmed = $true

        $prepared = "$activeProfile.new"
        $preparedSettings = "$activeSettings.new"
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Prepare-Profile.ps1') `
            -InputPath $dialog.FileName -OutputPath $prepared -SettingsPath $preparedSettings -SkipAcl 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Profile preparation failed: $($output -join ' ')" }
        $replacementAttempted = $true
        Install-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
            -PreparedProfile $prepared -PreparedSettings $preparedSettings | Out-Null

        if ($wasEnabled) {
            Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile
            [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
            $deadline = (Get-Date).AddSeconds(50)
            while (-not (Test-Path -LiteralPath $activeFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
            if (-not (Test-Path -LiteralPath $activeFile)) {
                throw 'The imported profile failed its tunnel-DNS readiness check.'
            }
        }
        try {
            Remove-Item -LiteralPath "$activeProfile.previous", "$activeSettings.previous" -Force -ErrorAction Stop
        } catch {
            Show-Notice 'Profile imported with warning' `
                "The new profile is active, but recovery-backup cleanup failed: $($_.Exception.Message)" 'Warning'
            return
        }
        Show-Notice 'Profile imported' 'The WireGuard profile passed validation.'
    } catch {
        $failure = $_.Exception.Message
        if ($disableRequested) {
            Remove-Item -LiteralPath $enabledFile -Force -ErrorAction SilentlyContinue
        }
        $rollbackErrors = [Collections.Generic.List[string]]::new()
        if ($replacementAttempted) {
            try { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
            catch { $rollbackErrors.Add($_.Exception.Message) }
            if (-not $rollbackErrors.Count) {
                try {
                    Restore-ProgramSplitProfilePair -ActiveProfile $activeProfile -ActiveSettings $activeSettings `
                        -StoppedMarker $stackStoppedFile
                } catch { $rollbackErrors.Add($_.Exception.Message) }
            }
        }
        Remove-Item -LiteralPath "$activeProfile.new", "$activeSettings.new" -Force -ErrorAction SilentlyContinue
        if ($wasEnabled -and $disableRequested -and $stopConfirmed -and -not $rollbackErrors.Count) {
            try {
                Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile
                [IO.File]::WriteAllText($enabledFile, (Get-Date -Format o))
            } catch { $rollbackErrors.Add($_.Exception.Message) }
        }
        if ($rollbackErrors.Count) {
            $failure += " Rollback also failed; the tunnel remains disabled: $($rollbackErrors -join '; ')"
        }
        Show-Notice 'Profile import failed' $failure 'Error'
    }
    finally { $dialog.Dispose(); Update-Ui }
})

$logsItem.add_Click({ Start-Process explorer.exe $logs })
$errorItem.add_Click({
    $message = if (Test-Path -LiteralPath $errorFile) { Get-Content -LiteralPath $errorFile -Raw } else { 'No controller error is recorded.' }
    [Windows.Forms.MessageBox]::Show($message, 'WireGuard Program Split', 'OK', 'Information') | Out-Null
})
$exitItem.add_Click({ [Windows.Forms.Application]::Exit() })
$icon.add_DoubleClick({ $toggleItem.PerformClick() })
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 2000
$timer.add_Tick({ Update-Ui })
$timer.Start()
Update-Ui

try { [Windows.Forms.Application]::Run() }
finally {
    $timer.Dispose()
    $icon.Visible = $false
    $icon.Dispose()
    $menu.Dispose()
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
