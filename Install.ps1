[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Profile,
    [Parameter(Mandatory)] [string[]] $Applications,
    [Parameter(Mandatory)] [string] $WireGuardRuntimeDirectory,
    [Parameter(Mandatory)] [string] $PiaDriverDirectory,
    [string] $BuildDirectory = (Join-Path $PSScriptRoot 'build'),
    [string] $DestinationRoot = 'C:\ProgramData\WireGuardProgramSplit',
    [switch] $DisableBrowserSecureDns,
    [switch] $PlanOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$destinationCreated = $false
. (Join-Path $PSScriptRoot 'src\powershell\Common.ps1')

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Install.ps1 from an elevated Windows PowerShell session.'
    }
}

function Assert-ValidSignature([string] $Path, [string] $SubjectPattern) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $SubjectPattern) {
        throw "Unexpected or invalid signature on $Path"
    }
}

$profilePath = (Get-Item -LiteralPath $Profile -ErrorAction Stop).FullName
if ($DestinationRoot -match '\s') { throw 'DestinationRoot cannot contain whitespace.' }
$fullDestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
if ([IO.Path]::GetPathRoot($fullDestinationRoot).TrimEnd('\') -eq $fullDestinationRoot.TrimEnd('\')) {
    throw 'DestinationRoot cannot be a filesystem root.'
}
$DestinationRoot = $fullDestinationRoot.TrimEnd('\')
$applicationPaths = @($Applications | ForEach-Object {
    $item = Get-Item -LiteralPath $_ -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Extension -ine '.exe') { throw "Included application must be an .exe file: $_" }
    $item.FullName
} | Sort-Object -Unique)
if (-not $applicationPaths) { throw 'At least one application is required.' }

$runtimeFiles = @('tunnel.dll', 'wireguard.dll')
$driverFiles = @('PiaWFPCallout.inf', 'PiaWfpCallout.sys', 'piawfpcallout.cat')
$projectExecutables = @('dns-dispatcher.exe', 'dns-probe.exe', 'tunnel-host.exe', 'wfp-probe.exe')
foreach ($path in @(
    $runtimeFiles | ForEach-Object { Join-Path $WireGuardRuntimeDirectory $_ }
    $driverFiles | ForEach-Object { Join-Path $PiaDriverDirectory $_ }
    $projectExecutables | ForEach-Object { Join-Path $BuildDirectory $_ }
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing installation input: $path" }
}

$installMutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitInstall')
$installMutexHeld = $false
$staging = $null
try {
    try { $installMutexHeld = $installMutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $installMutexHeld = $true }
    if (-not $installMutexHeld) { throw 'Another WireGuard Program Split installation is already running.' }

    $stagingNamePattern = '^WireGuardProgramSplit-install-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'WireGuardProgramSplit-install-*' `
        -ErrorAction Stop | Where-Object {
            $_.Name -match $stagingNamePattern -and
            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        } | ForEach-Object { Remove-ProgramSplitStagingDirectory -Path $_.FullName }

    $staging = Join-Path ([IO.Path]::GetTempPath()) ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid())
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    $stagedProfile = Join-Path $staging 'WireGuardSplit.conf'
    $stagedSettings = Join-Path $staging 'settings.json'
    & (Join-Path $PSScriptRoot 'src\powershell\Prepare-Profile.ps1') -InputPath $profilePath `
        -OutputPath $stagedProfile -SettingsPath $stagedSettings | Out-Null
    $derived = Get-Content -LiteralPath $stagedSettings -Raw | ConvertFrom-Json

    $plan = [pscustomobject]@{
        DestinationRoot = $DestinationRoot
        ServiceName = 'WireGuardTunnel$WireGuardSplit'
        ServiceStartType = 'Automatic'
        ControllerTask = 'WireGuard Program Split Controller'
        TrayTask = 'WireGuard Program Split Tray'
        InstallationMarker = 'state\installation.json'
        TunnelAddress = [string] $derived.TunnelAddress
        TunnelDns = [string] $derived.TunnelDns
        ApplicationCount = $applicationPaths.Count
    }
    if ($PlanOnly) { return $plan }

    Assert-ProgramSplit64BitPowerShell
    Assert-Administrator
    if (Test-Path -LiteralPath $DestinationRoot) {
        throw "An installation already exists at $DestinationRoot. Run Uninstall.ps1 before reinstalling."
    }
    $existingTasks = @(foreach ($taskName in @($plan.ControllerTask, $plan.TrayTask)) {
        Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    })
    $existingService = Get-CimInstance Win32_Service -Filter "Name='$($plan.ServiceName)'" -ErrorAction SilentlyContinue
    Assert-ProgramSplitInstallNamesAvailable -Tasks $existingTasks -Service $existingService
    Assert-ValidSignature (Join-Path $WireGuardRuntimeDirectory 'tunnel.dll') 'WireGuard|Proton'
    Assert-ValidSignature (Join-Path $WireGuardRuntimeDirectory 'wireguard.dll') 'WireGuard|Proton|Microsoft Windows Hardware Compatibility Publisher'
    Assert-ValidSignature (Join-Path $PiaDriverDirectory 'PiaWfpCallout.sys') 'Private Internet Access|Microsoft Windows Hardware Compatibility Publisher'
    Assert-ValidSignature (Join-Path $PiaDriverDirectory 'piawfpcallout.cat') 'Microsoft Windows Hardware Compatibility Publisher'

    [IO.Directory]::CreateDirectory($DestinationRoot) | Out-Null
    $destinationCreated = $true
    foreach ($directory in @('bin', 'config', 'drivers\pia', 'logs', 'profiles', 'src', 'state')) {
        [IO.Directory]::CreateDirectory((Join-Path $DestinationRoot $directory)) | Out-Null
    }
    [IO.File]::WriteAllText((Join-Path $DestinationRoot $plan.InstallationMarker),
        ([ordered]@{ Product = 'WireGuardProgramSplit'; Schema = 1 } | ConvertTo-Json),
        [Text.UTF8Encoding]::new($false))
    & icacls.exe $DestinationRoot /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to normalize the ProgramData installation ACL.' }
    & icacls.exe $DestinationRoot /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to lock the ProgramData installation root.' }
    & icacls.exe (Join-Path $DestinationRoot '*') /inheritance:e /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to inherit the protected ProgramData ACL.' }

    Copy-Item -Path (Join-Path $PSScriptRoot 'src\powershell\*.ps1') -Destination (Join-Path $DestinationRoot 'src')
    foreach ($name in $projectExecutables) {
        Copy-Item -LiteralPath (Join-Path $BuildDirectory $name) -Destination (Join-Path $DestinationRoot "bin\$name")
    }
    foreach ($name in $runtimeFiles) {
        Copy-Item -LiteralPath (Join-Path $WireGuardRuntimeDirectory $name) -Destination (Join-Path $DestinationRoot "bin\$name")
    }
    foreach ($name in $driverFiles) {
        Copy-Item -LiteralPath (Join-Path $PiaDriverDirectory $name) -Destination (Join-Path $DestinationRoot "drivers\pia\$name")
    }
    Copy-Item -LiteralPath $stagedProfile -Destination (Join-Path $DestinationRoot 'profiles\WireGuardSplit.conf')
    Copy-Item -LiteralPath $stagedSettings -Destination (Join-Path $DestinationRoot 'config\settings.json')
    [IO.File]::WriteAllLines((Join-Path $DestinationRoot 'state\included-apps.txt'), $applicationPaths,
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $DestinationRoot 'state\enabled'), (Get-Date -Format o))

    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $controllerAction = New-ScheduledTaskAction -Execute $powerShell -Argument (
        Get-ProgramSplitTaskArguments -ScriptPath (Join-Path $DestinationRoot 'src\Controller.ps1'))
    $controllerSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $plan.ControllerTask -TaskPath '\' -Action $controllerAction `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings $controllerSettings -Description 'Owns per-application WireGuard payload and DNS routing.' | Out-Null

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $trayAction = New-ScheduledTaskAction -Execute $powerShell -Argument (
        Get-ProgramSplitTaskArguments -ScriptPath (Join-Path $DestinationRoot 'src\Tray.ps1'))
    $traySettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $plan.TrayTask -TaskPath '\' -Action $trayAction `
        -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $currentUser) `
        -Principal (New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest) `
        -Settings $traySettings -Description 'Tray controls for WireGuard Program Split.' | Out-Null

    if ($DisableBrowserSecureDns) {
        & (Join-Path $DestinationRoot 'src\Invoke-BrowserDnsPolicy.ps1') -Action Enable | Out-Null
    }
    Start-ScheduledTask -TaskName $plan.ControllerTask
    $deadline = (Get-Date).AddSeconds(60)
    $activeFile = Join-Path $DestinationRoot 'state\active'
    while (-not (Test-Path -LiteralPath $activeFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path -LiteralPath $activeFile)) {
        $errorPath = Join-Path $DestinationRoot 'state\last-error.txt'
        $detail = if (Test-Path -LiteralPath $errorPath) { Get-Content -LiteralPath $errorPath -Raw } else { 'No controller error was recorded.' }
        throw "The controller did not activate: $detail"
    }
    Start-ScheduledTask -TaskName $plan.TrayTask
    $plan
} catch {
    $installError = $_
    if ($destinationCreated -and (Test-Path -LiteralPath $DestinationRoot)) {
        try { & (Join-Path $PSScriptRoot 'Uninstall.ps1') -DestinationRoot $DestinationRoot | Out-Null }
        catch { Write-Warning "Automatic rollback was incomplete: $($_.Exception.Message)" }
    }
    throw $installError
} finally {
    Close-ProgramSplitInstallScope -StagingPath $staging -Mutex $installMutex -MutexHeld $installMutexHeld
}
