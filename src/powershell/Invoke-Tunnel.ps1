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

function Add-ActiveRoute([string] $prefix, [uint32] $index, [string] $nextHop, [uint16] $metric) {
    $existing = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $index -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $nextHop }
    if (-not $existing) {
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $index -NextHop $nextHop -RouteMetric $metric -PolicyStore ActiveStore | Out-Null
    } elseif ($existing.RouteMetric -ne $metric) {
        $existing | Set-NetRoute -RouteMetric $metric | Out-Null
    }
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
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    if ($service) { Set-Service -Name $serviceName -StartupType Manual }
    if (Test-Path -LiteralPath $endpointState -PathType Leaf) {
        $previousEndpoint = [IO.File]::ReadAllText($endpointState).Trim()
        $parsedEndpoint = $null
        if ([Net.IPAddress]::TryParse($previousEndpoint, [ref] $parsedEndpoint) -and
            $parsedEndpoint.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$previousEndpoint/32" `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceAlias -ne $adapterName -and $_.RouteMetric -eq 1 } |
                Remove-NetRoute -Confirm:$false
        }
        [IO.File]::Delete($endpointState)
    }
    Write-Output 'Tunnel stopped; active-store tunnel routes were removed with the adapter.'
    exit 0
}

if (Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -PolicyStore ActiveStore `
    -ErrorAction SilentlyContinue) {
    throw 'An IPv6 default route is active; this IPv4-only release refuses partial routing.'
}
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

if (Test-Path -LiteralPath $endpointState -PathType Leaf) {
    $previousEndpoint = [IO.File]::ReadAllText($endpointState).Trim()
    if ($previousEndpoint -match '^\d{1,3}(\.\d{1,3}){3}$' -and $previousEndpoint -ne $endpoint) {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$previousEndpoint/32" `
            -InterfaceIndex $physical.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $physical.NextHop -and $_.RouteMetric -eq 1 } |
            Remove-NetRoute -Confirm:$false
    }
}

$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
$expectedCommand = '{0} /service {1}' -f $hostExe, $config
if (-not $service) {
    $createOutput = & sc.exe create $serviceName 'binPath=' $expectedCommand 'type=' 'own' 'start=' 'auto' 'error=' 'normal' 'depend=' 'Nsi/TcpIp' 'DisplayName=' 'WireGuard Program Split' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the tunnel service: $($createOutput -join ' ')" }
    & sc.exe sidtype $serviceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure the tunnel service SID.' }
} elseif ($service.PathName -ne $expectedCommand) {
    throw 'An unexpected service already uses the WireGuard Program Split tunnel name.'
}

Set-Service -Name $serviceName -StartupType Automatic

Add-ActiveRoute -prefix "$endpoint/32" -index $physical.InterfaceIndex -nextHop $physical.NextHop -metric 1
[IO.Directory]::CreateDirectory((Split-Path -Parent $endpointState)) | Out-Null
[IO.File]::WriteAllText($endpointState, $endpoint)
$serviceState = Get-Service -Name $serviceName
if ($serviceState.Status -ne 'Running') { Start-Service -Name $serviceName }
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
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
