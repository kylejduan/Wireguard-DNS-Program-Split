Set-StrictMode -Version Latest

function Get-ProgramSplitConfiguration {
    param([Parameter(Mandatory)] [string] $Root)

    $settingsPath = Join-Path $Root 'config\settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw "Missing local settings: $settingsPath"
    }
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    foreach ($name in @('TunnelAddress', 'TunnelDns')) {
        $value = [string] $settings.$name
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($value, [ref] $parsed) -or
            $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Local setting $name must be one IPv4 address."
        }
    }

    [pscustomobject]@{
        Root = $Root
        AdapterName = 'WireGuardSplit'
        ServiceName = 'WireGuardTunnel$WireGuardSplit'
        ControllerTask = 'WireGuard Program Split Controller'
        TrayTask = 'WireGuard Program Split Tray'
        NrptDisplayName = 'WireGuard Program Split local dispatcher'
        ProfilePath = Join-Path $Root 'profiles\WireGuardSplit.conf'
        SettingsPath = $settingsPath
        TunnelAddress = [string] $settings.TunnelAddress
        TunnelDns = [string] $settings.TunnelDns
        TunnelDefaultMetric = 9999
    }
}

function Get-ProgramSplitPhysicalDefault {
    param([Parameter(Mandatory)] [string] $AdapterName)

    $candidates = foreach ($route in Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
        -PolicyStore ActiveStore -ErrorAction Stop) {
        $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction SilentlyContinue
        if ($interface -and $route.InterfaceAlias -ne $AdapterName) {
            [pscustomobject]@{
                Route = $route
                EffectiveMetric = [int64] $route.RouteMetric + [int64] $interface.InterfaceMetric
            }
        }
    }
    $winner = $candidates | Sort-Object EffectiveMetric | Select-Object -First 1
    if (-not $winner) { throw 'No physical IPv4 default gateway found.' }
    return $winner.Route
}
