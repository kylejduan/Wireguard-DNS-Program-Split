# SPDX-License-Identifier: GPL-3.0-or-later

# Windows servicing can materialize old driver-installation nodes under ROOT\WIREGUARD.
# Real Windows 11 WireGuard tunnels use SWD\WireGuard. See the upstream diagnosis:
# https://github.com/WireGuard/wireguard-nt/commit/b0d305a1865c9b23fa677d9ddeb564a60d315973
# This compatibility guard is deliberately narrower than upstream's cleanup: no registry
# deletion, SWD removal, driver uninstall, active adapter removal, or network reconfiguration.
function Get-ProgramSplitStrayAdapterSnapshot([string] $InstanceId) {
    if ($InstanceId -notmatch '^ROOT\\WIREGUARD\\[0-9]{4}$') { throw 'Not a root WireGuard device.' }
    $device = Get-PnpDevice -InstanceId $InstanceId -ErrorAction Stop
    $properties = @{}
    Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName @(
        'DEVPKEY_Device_Service', 'DEVPKEY_Device_ClassGuid', 'DEVPKEY_Device_HardwareIds',
        'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_FirstInstallDate'
    ) -ErrorAction Stop | ForEach-Object { $properties[$_.KeyName] = $_.Data }
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object { $_.PnPDeviceID -eq $InstanceId })
    if ($adapters.Count -ne 1) { throw 'Device does not have exactly one inspectable network adapter.' }
    $adapter = $adapters[0]
    $statistics = $adapter | Get-NetAdapterStatistics -ErrorAction Stop
    [pscustomobject]@{
        InstanceId = [string] $device.InstanceId
        Class = [string] $device.Class
        Service = [string] $properties['DEVPKEY_Device_Service']
        ClassGuid = [string] $properties['DEVPKEY_Device_ClassGuid']
        HardwareIds = @($properties['DEVPKEY_Device_HardwareIds'])
        Provider = [string] $properties['DEVPKEY_Device_DriverProvider']
        FirstInstallDate = [string] $properties['DEVPKEY_Device_FirstInstallDate']
        Name = [string] $adapter.Name
        InterfaceGuid = [string] $adapter.InterfaceGuid
        InterfaceIndex = [uint32] $adapter.ifIndex
        Status = [string] $adapter.Status
        ReceivedBytes = $statistics.ReceivedBytes
        SentBytes = $statistics.SentBytes
        Addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            Select-Object IPAddress,PrefixOrigin)
        Routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            Select-Object DestinationPrefix,NextHop)
    }
}

function Test-ProgramSplitStrayAdapter($Snapshot) {
    if ($Snapshot.InstanceId -notmatch '^ROOT\\WIREGUARD\\[0-9]{4}$' -or
        $Snapshot.Class -ne 'Net' -or $Snapshot.Service -ne 'WireGuard' -or
        $Snapshot.ClassGuid -ne '{4d36e972-e325-11ce-bfc1-08002be10318}' -or
        $Snapshot.Provider -ne 'WireGuard LLC' -or $Snapshot.HardwareIds.Count -ne 1 -or
        $Snapshot.HardwareIds[0] -ne 'WireGuard' -or -not $Snapshot.FirstInstallDate -or
        $Snapshot.Name -eq 'WireGuardSplit' -or -not $Snapshot.InterfaceGuid -or
        $Snapshot.InterfaceIndex -eq 0 -or $Snapshot.Status -ne 'Disconnected' -or
        $null -eq $Snapshot.ReceivedBytes -or $null -eq $Snapshot.SentBytes -or
        $Snapshot.ReceivedBytes -ne 0 -or $Snapshot.SentBytes -ne 0) { return $false }
    foreach ($address in $Snapshot.Addresses) {
        $ip = $null
        if ($address.PrefixOrigin -eq 'Manual' -or
            -not [Net.IPAddress]::TryParse($address.IPAddress, [ref] $ip)) { return $false }
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            $bytes = $ip.GetAddressBytes()
            if ($bytes[0] -ne 169 -or $bytes[1] -ne 254) { return $false }
        } elseif (-not $ip.IsIPv6LinkLocal) { return $false }
    }
    $localPrefixes = @('169.254.0.0/16', '224.0.0.0/4', '255.255.255.255/32', 'fe80::/64', 'ff00::/8')
    foreach ($address in $Snapshot.Addresses) {
        $suffix = if ($address.IPAddress -match ':') { '/128' } else { '/32' }
        $localPrefixes += $address.IPAddress + $suffix
    }
    foreach ($route in $Snapshot.Routes) {
        if ($route.NextHop -notin @('0.0.0.0', '::') -or
            $route.DestinationPrefix -notin $localPrefixes) { return $false }
    }
    return $true
}

function Remove-ProgramSplitStrayDevice([string] $InstanceId, [string] $LogDirectory) {
    # The caller rechecks the full device immediately before this exact-instance operation.
    if ($InstanceId -notmatch '^ROOT\\WIREGUARD\\[0-9]{4}$') { throw 'Not a root WireGuard device.' }
    $stdout = Join-Path $LogDirectory 'adapter-removal-output.log'
    $stderr = Join-Path $LogDirectory 'adapter-removal-error.log'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\pnputil.exe" `
        -ArgumentList @('/remove-device', $InstanceId) -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    $null = $process.Handle
    if (-not $process.WaitForExit(10000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Device removal timed out; inspect the removal log before retrying.'
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Device removal returned $($process.ExitCode); no reboot or driver removal was requested."
    }
    if (@(Get-PnpDevice -Class Net -ErrorAction Stop |
            Where-Object { $_.InstanceId -eq $InstanceId }).Count -ne 0) {
        throw 'Device is still enumerated after removal.'
    }
}

function Invoke-ProgramSplitAdapterMaintenance([string] $Root, [switch] $Repair) {
    # Cheap no-op in the ordinary case; do not enumerate every adapter every health check.
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\WIREGUARD'
    if (-not (Test-Path -LiteralPath $registryPath -ErrorAction Stop)) { return }
    $candidates = @(Get-ChildItem -LiteralPath $registryPath -ErrorAction Stop |
        Where-Object { $_.PSChildName -match '^[0-9]{4}$' })
    foreach ($candidate in $candidates) {
        $id = 'ROOT\WIREGUARD\' + $candidate.PSChildName
        $attemptedRemoval = $false
        try {
            $snapshot = Get-ProgramSplitStrayAdapterSnapshot -InstanceId $id
            if (-not (Test-ProgramSplitStrayAdapter $snapshot)) {
                Write-Output "Adapter maintenance preserved ${id}: identity, configuration, or activity is not eligible."
                continue
            }
            if (-not $Repair) {
                Write-Output "Adapter maintenance found inactive servicing device $id ($($snapshot.Name))."
                continue
            }
            $logDirectory = Join-Path $Root 'logs'
            # Preserve metadata before removal; the bounded file holds the latest attempted cleanup.
            $evidence = Join-Path $logDirectory 'adapter-removal-before.json'
            [IO.File]::WriteAllText($evidence, ($snapshot | ConvertTo-Json -Depth 5),
                [Text.UTF8Encoding]::new($false))
            $current = Get-ProgramSplitStrayAdapterSnapshot -InstanceId $id
            if (-not (Test-ProgramSplitStrayAdapter $current) -or
                $current.InterfaceGuid -ne $snapshot.InterfaceGuid -or
                $current.InterfaceIndex -ne $snapshot.InterfaceIndex -or
                $current.FirstInstallDate -ne $snapshot.FirstInstallDate) {
                throw 'Device changed during inspection; preserving it.'
            }
            $attemptedRemoval = $true
            Remove-ProgramSplitStrayDevice -InstanceId $id -LogDirectory $logDirectory
            Write-Output "Adapter maintenance removed inactive servicing device $id ($($snapshot.Name))."
        } catch {
            # Maintenance is independent of tunnel health. Uncertainty retains the device and
            # must never induce a tunnel restart or widen the removal to a shared driver package.
            Write-Output "Adapter maintenance incomplete for $id; no further action: $($_.Exception.Message)"
        }
        # Keep each component invocation bounded even if servicing left several root devices.
        if ($attemptedRemoval) { break }
    }
}

function Assert-ProgramSplitAdapterPreflight([string] $Root) {
    Invoke-ProgramSplitAdapterMaintenance -Root $Root -Repair
    # Registry-only remnants are not network adapters and remain outside this guard's ownership.
    # A visible root device that cannot be safely removed blocks new adapter creation instead.
    $remaining = @(Get-PnpDevice -Class Net -ErrorAction Stop |
        Where-Object { $_.InstanceId -match '^ROOT\\WIREGUARD\\[0-9]{4}$' })
    if ($remaining.Count) {
        throw "Tunnel creation deferred: root WireGuard devices remain ($($remaining.InstanceId -join ', ')). Inspect the maintenance log before retrying."
    }
    Write-Output 'PASS: no enumerated root WireGuard devices remain before tunnel creation.'
}
