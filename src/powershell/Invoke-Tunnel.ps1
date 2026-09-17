# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [ValidateSet('Validate', 'Start', 'Stop', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
$bin = Join-Path $root 'bin'
$config = $configuration.ProfilePath
$hostExe = Join-Path $bin 'tunnel-host.exe'
$serviceName = $configuration.ServiceName
$adapterName = $configuration.AdapterName
$tunnelAddress = $configuration.TunnelAddress
$tunnelDns = $configuration.TunnelDns
$tunnelDefaultMetric = $configuration.TunnelDefaultMetric
$endpointState = Join-Path $root 'state\endpoint-route.txt'
# A pending tunnel host older than this has outlived any plausible start, including a first driver install.
$stuckHostSeconds = 90

function Assert-Inputs {
    foreach ($path in @($config, $hostExe, (Join-Path $bin 'tunnel.dll'), (Join-Path $bin 'wireguard.dll'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing required file: $path" }
    }
    $text = [IO.File]::ReadAllText($config)
    if ($text -notmatch '(?im)^Table\s*=\s*off\s*$') { throw 'Working profile must contain Table = off.' }
    if ($text -match '(?im)^DNS\s*=') { throw 'Working profile must not publish adapter DNS.' }
    if ($text -match '::/0') { throw 'Working profile must be IPv4-only.' }
    if ($text -notmatch '(?im)^Endpoint\s*=\s*([^:\s]+):\d+\s*$') { throw 'Profile endpoint must be an IPv4 address or hostname.' }
    return $Matches[1]
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Wait-Adapter {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq 'Up') { return $adapter }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'WireGuard adapter did not become ready.'
}

function Get-OwnedServiceProcess {
    $record = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if (-not $record -or -not $record.ProcessId) { return $null }
    $process = Get-Process -Id $record.ProcessId -ErrorAction SilentlyContinue
    if (-not $process) { return $null }
    # Pin the process before checking its image so the identifier cannot be reused underneath the check.
    try { $null = $process.Handle } catch { return $null }
    if ([string]$process.Path -eq $hostExe) { return $process }
    return $null
}

function Reset-PendingService([int] $SettleSeconds) {
    # A tunnel service that stays in StartPending or StopPending cannot accept a stop control, so a
    # stop fails until reboot and every later start waits on the same stuck host. After a bounded
    # settle window, terminate only the owned host process; Service Control Manager then records the
    # service as stopped and the next start begins from a clean state. A start that is merely slow is
    # never terminated, whichever action asks: the controller runs Stop as cleanup after a start
    # timeout, and ending a young host there would make a slow tunnel unable to ever come up.
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds($SettleSeconds)
    while (($service.Status -eq 'StartPending' -or $service.Status -eq 'StopPending') -and
        [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $service.Refresh()
    }
    if ($service.Status -ne 'StartPending' -and $service.Status -ne 'StopPending') { return }
    $process = Get-OwnedServiceProcess
    if (-not $process) { throw "The tunnel service is stuck in $($service.Status) without an owned host process." }
    if ($service.Status -eq 'StartPending') {
        $hostAge = [int]([DateTime]::Now - $process.StartTime).TotalSeconds
        if ($hostAge -lt $stuckHostSeconds) {
            throw "The tunnel service is still starting (host age $hostAge s); it is left to finish and is reset only after $stuckHostSeconds seconds."
        }
    }
    Write-Output "Tunnel service stuck in $($service.Status); terminating owned host process $($process.Id)."
    $process.Kill()
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
    $adapterDeadline = [DateTime]::UtcNow.AddSeconds(3)
    while ((Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) -and
        [DateTime]::UtcNow -lt $adapterDeadline) { Start-Sleep -Milliseconds 500 }
    if (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) {
        Write-Output "The $adapterName adapter is still present after the host process ended."
    }
}

function Wait-ServiceRunning([int] $TimeoutSeconds = 20) {
    # Poll rather than WaitForStatus so a service that fails fast is reported at once. A start that
    # is merely slow is left running: the next repair attempt adopts the same pending service and
    # keeps waiting. Only a host that has outlived any plausible start is treated as stuck and reset.
    $service = Get-Service -Name $serviceName
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        $service.Refresh()
        if ($service.Status -eq 'Running') { return }
        if ($service.Status -eq 'Stopped') {
            throw 'The tunnel service stopped while starting; check the profile and the matched runtime DLL pair.'
        }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 250
    }
    $status = $service.Status
    $process = Get-OwnedServiceProcess
    $hostAge = if ($process) { [int]([DateTime]::Now - $process.StartTime).TotalSeconds } else { 0 }
    if ($process -and $hostAge -ge $stuckHostSeconds) {
        Reset-PendingService -SettleSeconds 0
        throw "The tunnel service stayed $status for $hostAge seconds; its host process was reset so the next attempt starts clean."
    }
    throw "The tunnel service is still $status after $TimeoutSeconds seconds (host age $hostAge s); leaving it to finish so the next attempt can adopt it."
}

function Add-ActiveRoute([string] $prefix, [uint32] $index, [string] $nextHop, [uint16] $metric) {
    $existing = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $index -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $nextHop }
    if (-not $existing) {
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $index -NextHop $nextHop -RouteMetric $metric -PolicyStore ActiveStore | Out-Null
    } elseif ($existing.RouteMetric -ne $metric) {
        $existing | Set-NetRoute -RouteMetric $metric | Out-Null
    }
}

function Read-OwnedEndpointRouteState {
    if (-not (Test-Path -LiteralPath $endpointState -PathType Leaf)) { return $null }
    try {
        $saved = Get-Content -LiteralPath $endpointState -Raw | ConvertFrom-Json
        $address = ([string] $saved.DestinationPrefix) -replace '/32$', ''
        $parsedAddress = $null
        $parsedNextHop = $null
        if ([int] $saved.Schema -ne 1 -or [string] $saved.DestinationPrefix -ne "$address/32" -or
            -not [Net.IPAddress]::TryParse($address, [ref] $parsedAddress) -or
            $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            -not [Net.IPAddress]::TryParse([string] $saved.NextHop, [ref] $parsedNextHop) -or
            $parsedNextHop.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            [uint32] $saved.InterfaceIndex -eq 0 -or [uint16] $saved.RouteMetric -ne 1) { return $null }
        return [pscustomobject]@{
            DestinationPrefix = "$address/32"
            InterfaceIndex = [uint32] $saved.InterfaceIndex
            NextHop = $parsedNextHop.IPAddressToString
            RouteMetric = [uint16] $saved.RouteMetric
        }
    } catch { return $null }
}

function Remove-OwnedEndpointRoute {
    $hadState = Test-Path -LiteralPath $endpointState -PathType Leaf
    $saved = Read-OwnedEndpointRouteState
    if ($hadState -and -not $saved) {
        Write-Output 'Ignored legacy or invalid endpoint-route state; no route was removed.'
    }
    if ($saved) {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $saved.DestinationPrefix `
            -InterfaceIndex $saved.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { Test-ProgramSplitEndpointRouteOwnership -Route $_ -State $saved } |
            Remove-NetRoute -Confirm:$false
    }
    if ($hadState) { [IO.File]::Delete($endpointState) }
}

function Set-OwnedEndpointRouteState($routeState) {
    [IO.Directory]::CreateDirectory((Split-Path -Parent $endpointState)) | Out-Null
    $temporary = "$endpointState.$PID.tmp"
    try {
        [IO.File]::WriteAllText($temporary, ($routeState | ConvertTo-Json -Compress),
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $endpointState -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

$endpointHost = Assert-Inputs
if ($Action -eq 'Validate') {
    Write-Output 'PASS: tunnel host and DNS-free Table=off profile are ready.'
    exit 0
}

if ($Action -eq 'Status') {
    Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
    Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue | Select-Object Name, Status, ifIndex, InterfaceDescription
    Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq $adapterName -or $_.DestinationPrefix -eq "$tunnelDns/32" } |
        Select-Object DestinationPrefix, InterfaceAlias, InterfaceIndex, NextHop, RouteMetric
    exit 0
}

Assert-Administrator

if ($Action -eq 'Stop') {
    $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($serviceRecord -and -not (Test-ProgramSplitServiceOwnership -Service $serviceRecord `
            -HostPath $hostExe -ArgumentPath $config)) {
        throw 'Refusing to stop a same-name foreign tunnel service.'
    }
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Reset-PendingService -SettleSeconds 10
        $service.Refresh()
        if ($service.Status -ne 'Stopped') {
            # ServiceController.Stop returns once the control is issued. A stop that does not finish
            # inside the wait is reset here instead of consuming the controller's whole component budget.
            try { $service.Stop() }
            catch [InvalidOperationException] {
                $service.Refresh()
                if ($service.Status -ne 'Stopped' -and $service.Status -ne 'StopPending') { throw }
            }
            try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20)) }
            catch [System.ServiceProcess.TimeoutException] { Reset-PendingService -SettleSeconds 0 }
        }
    }
    if ($service) { Set-Service -Name $serviceName -StartupType Manual }
    Remove-OwnedEndpointRoute
    Write-Output 'Tunnel stopped; active-store tunnel routes were removed with the adapter.'
    exit 0
}

Assert-ProgramSplitNoIpv6DefaultRoute
if (Get-DnsClientNrptPolicy -Effective | Where-Object { $_.Namespace -contains '.' }) {
    throw 'A foreign catch-all NRPT policy is active; disconnect the other VPN first.'
}

$physical = Get-ProgramSplitPhysicalDefault -AdapterName $adapterName
$endpointIp = $null
if ([Net.IPAddress]::TryParse($endpointHost, [ref]$endpointIp) -and $endpointIp.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    $endpoint = $endpointIp.IPAddressToString
} else {
    $endpoint = (Resolve-DnsName -Name $endpointHost -Type A -ErrorAction Stop | Select-Object -First 1 -ExpandProperty IPAddress)
}

$routeState = [ordered]@{
    Schema = 1
    DestinationPrefix = "$endpoint/32"
    InterfaceIndex = [uint32] $physical.InterfaceIndex
    NextHop = [string] $physical.NextHop
    RouteMetric = 1
}
$savedRouteState = Read-OwnedEndpointRouteState
$ownedEndpointRoute = if ($savedRouteState -and
    (Test-ProgramSplitEndpointRouteOwnership -Route $routeState -State $savedRouteState)) {
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $savedRouteState.DestinationPrefix `
        -InterfaceIndex $savedRouteState.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { Test-ProgramSplitEndpointRouteOwnership -Route $_ -State $savedRouteState } |
        Select-Object -First 1
}
if (-not $ownedEndpointRoute) { Remove-OwnedEndpointRoute }

$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
$expectedCommand = '{0} /service {1}' -f $hostExe, $config
if (-not $service) {
    $createOutput = & sc.exe create $serviceName 'binPath=' $expectedCommand 'type=' 'own' 'start=' 'auto' 'error=' 'normal' 'depend=' 'Nsi/TcpIp' 'DisplayName=' 'WireGuard Program Split' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the tunnel service: $($createOutput -join ' ')" }
    & sc.exe sidtype $serviceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure the tunnel service SID.' }
} elseif (-not (Test-ProgramSplitServiceOwnership -Service $service -HostPath $hostExe -ArgumentPath $config)) {
    throw 'An unexpected service already uses the WireGuard Program Split tunnel name.'
}

Set-Service -Name $serviceName -StartupType Automatic

$existingEndpointRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$endpoint/32" `
    -InterfaceIndex $physical.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq $physical.NextHop } | Select-Object -First 1
if (-not $existingEndpointRoute) {
    Set-OwnedEndpointRouteState $routeState
    try {
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix $routeState.DestinationPrefix `
            -InterfaceIndex $routeState.InterfaceIndex -NextHop $routeState.NextHop `
            -RouteMetric $routeState.RouteMetric -PolicyStore ActiveStore | Out-Null
    } catch {
        $failure = $_
        try { [IO.File]::Delete($endpointState) }
        catch { throw "$($failure.Exception.Message) Endpoint-route ownership state cleanup also failed: $($_.Exception.Message)" }
        throw $failure
    }
}
$serviceState = Get-Service -Name $serviceName
if ($serviceState.Status -eq 'StopPending') {
    # A stop that never completed would otherwise hold this start for the full readiness wait. The
    # settle window is short so that reset plus the readiness wait stays inside the controller's limit.
    Reset-PendingService -SettleSeconds 5
    $serviceState.Refresh()
}
if ($serviceState.Status -eq 'Stopped') {
    # ServiceController.Start returns once the control is issued; Wait-ServiceRunning bounds the rest.
    try { $serviceState.Start() }
    catch [InvalidOperationException] {
        $serviceState.Refresh()
        if ($serviceState.Status -eq 'Stopped') { throw }
    }
}
Wait-ServiceRunning
$adapter = Wait-Adapter

if (-not (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -IPAddress $tunnelAddress -ErrorAction SilentlyContinue)) {
    throw "The tunnel adapter does not own its configured address $tunnelAddress."
}
Add-ActiveRoute -prefix "$tunnelDns/32" -index $adapter.ifIndex -nextHop '0.0.0.0' -metric 1
Add-ActiveRoute -prefix '0.0.0.0/0' -index $adapter.ifIndex -nextHop '0.0.0.0' -metric $tunnelDefaultMetric

$winner = Get-ProgramSplitPhysicalDefault -AdapterName $adapterName
if ($winner.InterfaceIndex -ne $physical.InterfaceIndex) { throw 'The direct default route changed away from the physical adapter.' }
$tunnelRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore -ErrorAction Stop |
    Where-Object { $_.NextHop -eq '0.0.0.0' } | Select-Object -First 1
$tunnelInterface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
$physicalInterface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex -ErrorAction Stop
if ($tunnelRoute.RouteMetric -ne $tunnelDefaultMetric) { throw 'The losing tunnel default route has the wrong metric.' }
if (($physical.RouteMetric + $physicalInterface.InterfaceMetric) -ge ($tunnelRoute.RouteMetric + $tunnelInterface.InterfaceMetric)) {
    throw 'The tunnel default route would win over the physical default route.'
}
$publishedDns = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
if ($publishedDns.Count -gt 0) { throw 'The tunnel unexpectedly published global DNS.' }

Write-Output "Tunnel ready: $adapterName ifIndex $($adapter.ifIndex); direct default remains $($physical.InterfaceAlias)."
