param([switch] $SelfTest)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
$state = Join-Path $root 'state'
$logs = Join-Path $root 'logs'
$enabledFile = Join-Path $state 'enabled'
$activeFile = Join-Path $state 'active'
$stackStoppedFile = Join-Path $state 'stack-stopped'
$reloadFile = Join-Path $state 'reload.request'
$errorFile = Join-Path $state 'last-error.txt'
$logFile = Join-Path $logs 'controller.log'
$includeFile = Join-Path $state 'included-apps.txt'

function Write-ControllerLog([string] $message) {
    [IO.Directory]::CreateDirectory($logs) | Out-Null
    Add-Content -LiteralPath $logFile -Value "$(Get-Date -Format o) $message"
}

function Invoke-Component([string] $name, [string] $action) {
    $script = Join-Path $PSScriptRoot $name
    $key = [IO.Path]::GetFileNameWithoutExtension($name)
    $stdout = Join-Path $logs "$key-output.log"
    $stderr = Join-Path $logs "$key-error.log"
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-Action', $action
    ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    # Materialize the process handle before it can exit. Windows PowerShell 5.1 otherwise
    # exposes a null ExitCode for short-lived children created with Start-Process.
    $null = $process.Handle
    if (-not $process.WaitForExit(45000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "$name $action timed out."
    }
    # Finalize redirected streams after the timed overload reports completion.
    $process.WaitForExit()
    $output = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    if ($process.ExitCode -ne 0) { throw "$name $action exited with code $($process.ExitCode): $($errors -join ' ')" }
    if ($errors) { throw "$name $action failed: $($errors -join ' ')" }
    if ($output) { Write-ControllerLog ($output -join ' ') }
}

function Get-ManagedProcess([string] $pidName, [string] $processName) {
    $path = Join-Path $state $pidName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $managedPid = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($path), [ref]$managedPid)) { return $null }
    $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq $processName) { return $process }
    return $null
}

function Test-StackActive {
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    $rule = Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName }
    return $service -and $service.Status -eq 'Running' -and $rule -and
        (Get-ManagedProcess 'dns-dispatcher.pid' 'dns-dispatcher') -and
        (Get-ManagedProcess 'wfp-filters.pid' 'wfp-probe')
}

function Test-StackPresent {
    if (Test-Path -LiteralPath $activeFile -PathType Leaf) { return $true }
    $service = Get-Service -Name $configuration.ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { return $true }
    if (Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $configuration.NrptDisplayName }) { return $true }
    return [bool]((Get-ManagedProcess 'dns-dispatcher.pid' 'dns-dispatcher') -or
        (Get-ManagedProcess 'wfp-filters.pid' 'wfp-probe'))
}

function Stop-Stack([switch] $RestoreCache) {
    try { Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable' } catch { Write-ControllerLog $_ }
    try { Invoke-Component 'Invoke-WfpFilters.ps1' 'Stop' } catch { Write-ControllerLog $_ }
    try { Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Stop' } catch { Write-ControllerLog $_ }
    try { Invoke-Component 'Invoke-Tunnel.ps1' 'Stop' } catch { Write-ControllerLog $_ }
    if ($RestoreCache) {
        try { Invoke-Component 'Invoke-DnsCachePolicy.ps1' 'Disable' } catch { Write-ControllerLog $_ }
    }
    Remove-Item -LiteralPath $activeFile -Force -ErrorAction SilentlyContinue
}

function Test-TunnelDns {
    $probe = Join-Path $root 'bin\dns-probe.exe'
    $stdout = Join-Path $logs 'dns-health.log'
    $stderr = Join-Path $logs 'dns-health-error.log'
    $process = Start-Process -FilePath $probe -ArgumentList @($configuration.TunnelDns, 'example.com') `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(8000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Tunnel DNS health probe timed out.'
    }
    $output = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue)
    $errors = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    if (-not ($output -match '^PASS:')) {
        $output += $errors
        throw "Tunnel DNS health probe failed: $($output -join ' ')"
    }
    Write-ControllerLog 'Tunnel DNS health probe passed.'
}

function Invoke-Repair {
    if ((Get-Date) -lt $script:nextRepair) { return }
    try {
        Start-Stack
        $script:repairDelaySeconds = 2
        $script:nextRepair = [DateTime]::MinValue
    } catch {
        $script:nextRepair = (Get-Date).AddSeconds($script:repairDelaySeconds)
        $script:repairDelaySeconds = [Math]::Min(60, $script:repairDelaySeconds * 2)
    }
}

function Start-Stack {
    $script:configuration = Get-ProgramSplitConfiguration -Root $root
    Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $activeFile -Force -ErrorAction SilentlyContinue
    try {
        Write-ControllerLog 'Starting stack.'
        Invoke-Component 'Invoke-LocalNrpt.ps1' 'Disable'
        Invoke-Component 'Invoke-DnsCachePolicy.ps1' 'Enable'
        Invoke-Component 'Invoke-PiaDriver.ps1' 'Install'
        Invoke-Component 'Invoke-Tunnel.ps1' 'Start'
        Start-Sleep -Seconds 2
        Test-TunnelDns
        Write-ControllerLog 'Starting DNS dispatcher.'
        Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Start'
        Write-ControllerLog 'Enabling local split-DNS NRPT rule.'
        Invoke-Component 'Invoke-LocalNrpt.ps1' 'Enable'
        Write-ControllerLog 'Starting per-application WFP filters.'
        Invoke-Component 'Invoke-WfpFilters.ps1' 'Start'
        $activeAt = Get-Date
        [IO.File]::WriteAllText($activeFile, $activeAt.ToString('o'))
        Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
        Write-ControllerLog 'Stack active after tunnel readiness check.'
        try {
            $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            if (($activeAt - $boot).TotalMinutes -le 10) {
                $audit = [ordered]@{
                    Boot = $boot.ToString('o')
                    Active = $activeAt.ToString('o')
                    BootToActiveSeconds = [Math]::Round(($activeAt - $boot).TotalSeconds, 2)
                }
                [IO.File]::WriteAllText((Join-Path $state 'startup-audit.json'),
                    ($audit | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
                Write-ControllerLog "Cold boot to active: $($audit.BootToActiveSeconds) seconds."
            }
        } catch { Write-ControllerLog "Startup timing audit failed: $($_.Exception.Message)" }
    } catch {
        $message = $_ | Out-String
        [IO.File]::WriteAllText($errorFile, $message)
        Write-ControllerLog $message
        Stop-Stack
        throw
    }
}

$required = @(
    $includeFile,
    (Join-Path $root 'bin\dns-dispatcher.exe'),
    (Join-Path $root 'bin\dns-probe.exe'),
    (Join-Path $root 'bin\wfp-probe.exe'),
    $configuration.ProfilePath,
    $configuration.SettingsPath
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing controller input: $path" }
}
if (-not @(Get-Content -LiteralPath $includeFile | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })) {
    throw 'The included-app list is empty.'
}
if ($SelfTest) { Write-Output 'PASS: controller inputs and include list.'; exit 0 }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) { throw 'The controller must run as SYSTEM.' }
$mutex = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitController')
if (-not $mutex.WaitOne(0)) { exit 0 }

[IO.Directory]::CreateDirectory($state) | Out-Null
[IO.Directory]::CreateDirectory($logs) | Out-Null
$lastHealth = [DateTime]::MinValue
$nextRepair = [DateTime]::MinValue
$repairDelaySeconds = 2
try {
    while ($true) {
        $desired = Test-Path -LiteralPath $enabledFile -PathType Leaf
        if ($desired) {
            try { Clear-ProgramSplitStoppedMarker -Path $stackStoppedFile }
            catch {
                Write-ControllerLog $_.Exception.Message
                Start-Sleep -Seconds 2
                continue
            }
        }
        if (-not $desired) {
            if (Test-StackPresent) { Stop-Stack -RestoreCache }
            if (-not (Test-StackPresent)) {
                if (-not (Test-Path -LiteralPath $stackStoppedFile -PathType Leaf)) {
                    try { [IO.File]::WriteAllText($stackStoppedFile, (Get-Date -Format o)) }
                    catch { Write-ControllerLog $_.Exception.Message }
                }
            } else {
                Remove-Item -LiteralPath $stackStoppedFile -Force -ErrorAction SilentlyContinue
            }
        } elseif (Test-Path -LiteralPath $reloadFile) {
            Remove-Item -LiteralPath $reloadFile -Force -ErrorAction SilentlyContinue
            Stop-Stack
            Invoke-Repair
            $lastHealth = Get-Date
        } elseif (-not (Test-StackActive)) {
            # Cold boot may have pre-started the WireGuard service; Start-Stack adopts it.
            Invoke-Repair
            $lastHealth = Get-Date
        } elseif ((Get-Date) - $lastHealth -gt [TimeSpan]::FromSeconds(30)) {
            try {
                Invoke-Component 'Invoke-DnsDispatcher.ps1' 'Validate'
                Test-TunnelDns
            } catch { Stop-Stack; Invoke-Repair }
            $lastHealth = Get-Date
        }
        Start-Sleep -Seconds 2
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
