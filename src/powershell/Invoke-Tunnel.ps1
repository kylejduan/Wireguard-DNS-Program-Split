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
    if ($process -and [string]$process.Path -eq $hostExe) { return $process }
    return $null
}

function Reset-PendingService([int] $SettleSeconds) {
    # A tunnel service that stays in StartPending or StopPending cannot accept a stop control, so
    # Stop-Service fails until reboot and every later start waits on the same stuck host. After a
    # bounded settle window, terminate only the owned host process; Service Control Manager then
    # records the service as stopped and the next start begins from a clean state.
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
    Write-Output "Tunnel service stuck in $($service.Status); terminating owned host process $($process.Id)."
    Stop-Process -Id $process.Id -Force -ErrorAction Stop
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    $adapterDeadline = [DateTime]::UtcNow.AddSeconds(5)
    while ((Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) -and
        [DateTime]::UtcNow -lt $adapterDeadline) { Start-Sleep -Milliseconds 500 }
    if (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) {
        Write-Output "The $adapterName adapter remains after the host process ended; the next start will report it."
    }
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
            Stop-Service -Name $serviceName -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
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
    # A stop that never completed would otherwise hold this start for the full readiness wait.
    Reset-PendingService -SettleSeconds 10
    $serviceState.Refresh()
}
if ($serviceState.Status -eq 'Stopped') {
    # ServiceController.Start returns once the control is issued; the readiness wait below bounds it.
    $serviceState.Start()
}
try { $serviceState.WaitForStatus('Running', [TimeSpan]::FromSeconds(20)) }
catch [System.ServiceProcess.TimeoutException] {
    # The service never reported Running, so adapter creation did not complete. Reset the stuck host
    # now so the controller's next repair attempt starts from Stopped instead of the same pending host.
    Reset-PendingService -SettleSeconds 0
    throw 'The tunnel service did not report Running within 20 seconds; its host process was reset for the next attempt.'
}
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
