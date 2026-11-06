# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\Common.ps1')
function Assert-True([bool] $Value, [string] $Message) { if (-not $Value) { throw "ASSERTION FAILED: $Message" } }
$root = Join-Path ([IO.Path]::GetTempPath()) ('wgps-tray-maintenance-' + [guid]::NewGuid())
$children = @()
$taskName = 'Wgps Tray Test ' + [guid]::NewGuid()
$taskRoot = $null
$registered = $false
try {
    New-Item -ItemType Directory -Path (Join-Path $root 'bin'), (Join-Path $root 'foreign') -Force | Out-Null
    $image = Join-Path $root 'bin\tray.exe'
    $foreignImage = Join-Path $root 'foreign\tray.exe'
    foreach ($path in @($image, $foreignImage)) { Copy-Item (Join-Path $RepositoryRoot 'build\test-tray-stub.exe') $path }
    $owned = Start-Process $image -PassThru -WindowStyle Hidden
    $foreign = Start-Process $foreignImage -PassThru -WindowStyle Hidden
    $children += $owned, $foreign
    $null = $owned.Handle; $null = $foreign.Handle
    $mutation = Enter-ProgramSplitTrayMutationLock
    try { Stop-ProgramSplitTrayProcesses -Root $root -TimeoutMilliseconds 5000 }
    finally { $mutation.ReleaseMutex(); $mutation.Dispose() }
    Assert-True ($owned.HasExited -and -not $foreign.HasExited) 'maintenance stops only the native tray in its own root'

    $runnerPath = Join-Path $root 'bin\controller-service.exe'
    Copy-Item (Join-Path $RepositoryRoot 'build\test-tray-stub.exe') $runnerPath
    $runner = Start-Process $runnerPath -ArgumentList '--run' -PassThru -WindowStyle Hidden
    $children += $runner; $null = $runner.Handle
    $failed = $false
    try { Stop-ProgramSplitTrayProcesses -Root $root -TimeoutMilliseconds 300 } catch { $failed = $true }
    Assert-True ($failed -and -not $runner.HasExited) 'maintenance refuses a live bounded runner without killing it'
    $runner.Kill(); $null = $runner.WaitForExit(5000)

    $name = 'Global\WgpsTrayMutexTest-' + [guid]::NewGuid()
    $ready = Join-Path $root 'mutex-ready'
    $holder = Start-Process $foreignImage -ArgumentList ('--hold "' + $name + '" "' + $ready + '"') -PassThru -WindowStyle Hidden
    $children += $holder; $null = $holder.Handle
    $until = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path $ready) -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 50 }
    Assert-True (Test-Path $ready) 'mutex fixture started'
    $observer = [Threading.Mutex]::OpenExisting($name)
    try {
        $failed = $false
        try { $unexpected = Enter-ProgramSplitTrayMutationLock -Name $name -TimeoutMilliseconds 100 } catch { $failed = $true }
        Assert-True $failed 'maintenance waits for active mutations'
        $holder.Kill(); $null = $holder.WaitForExit(5000)
        $recovered = Enter-ProgramSplitTrayMutationLock -Name $name -TimeoutMilliseconds 1000
        $recovered.ReleaseMutex(); $recovered.Dispose()
    } finally { $observer.Dispose() }

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # SYSTEM never executes a file in an unprotected, user-writable staging tree.
        $taskRoot = Join-Path $env:ProgramData ([Uri]::UnescapeDataString('Wgps Tray Test %C3%A9%E6%BC%A2 ') + [guid]::NewGuid())
        [IO.Directory]::CreateDirectory($taskRoot) | Out-Null
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $security.SetOwner($admins); $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        Set-Acl $taskRoot $security
        New-Item -ItemType Directory -Path (Join-Path $taskRoot 'bin') | Out-Null
        $scheduledImage = Join-Path $taskRoot 'bin\tray.exe'
        Copy-Item (Join-Path $RepositoryRoot 'build\test-tray-stub.exe') $scheduledImage
        $fileAcl = Get-Acl $scheduledImage; $fileAcl.SetOwner($admins); Set-Acl $scheduledImage $fileAcl
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action (New-ScheduledTaskAction -Execute $scheduledImage) `
            -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) | Out-Null
        $registered = $true
        Assert-True (Test-ProgramSplitTrayTaskOwnership -Task (Get-ScheduledTask -TaskName $taskName) -Root $taskRoot) 'real task action round-trips with exact ownership'
        Start-ScheduledTask -TaskName $taskName
        $until = [DateTime]::UtcNow.AddSeconds(15)
        do {
            $running = @(Get-CimInstance Win32_Process -Filter "Name='tray.exe'" | Where-Object { $_.ExecutablePath -eq $scheduledImage })
            if ($running.Count -eq 1 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Running') { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $until)
        Assert-True ($running.Count -eq 1 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Running') 'Task Scheduler launches a spaced Unicode executable path with no stray arguments'
        Stop-ScheduledTask -TaskName $taskName
        Stop-ProgramSplitTrayProcesses -Root $taskRoot -TimeoutMilliseconds 10000
    } else { Write-Output 'SKIPPED: real scheduled-task launch needs elevation; CI runs it elevated.' }
    Write-Output 'PASS: tray maintenance ownership, helper refusal, mutation serialization and task registration.'
} finally {
    if ($registered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    foreach ($child in $children) {
        try { if (-not $child.HasExited) { $child.Kill(); $null = $child.WaitForExit(5000) } } finally { $child.Dispose() }
    }
    if ($taskRoot -and (Test-Path $taskRoot)) { Remove-ProgramSplitTree -Path $taskRoot }
    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
}
