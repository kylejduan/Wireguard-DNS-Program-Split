# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$Condition,[string]$Message) {
    if(-not $Condition) {throw "ASSERTION FAILED: $Message"}
}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'src\powershell\Common.ps1'),[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'Common.ps1 parses'
foreach($name in @('Get-ProgramSplitPhysicalDefault','Get-ProgramSplitPhysicalResolvers','Test-ProgramSplitPhysicalInputs')) {
    $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
    Assert-True ($definition.Count -eq 1) "one $name implementation exists"
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
function Get-NetRoute {param($AddressFamily,$DestinationPrefix,$PolicyStore,$ErrorAction)
    if($script:routeUnknown){throw 'Unknown route inventory'}
    $script:routes
}
$script:routeUnknown=$false
function Get-NetIPAddress {param($AddressFamily,$InterfaceIndex,$ErrorAction)
    if($InterfaceIndex -eq 18){[pscustomobject]@{AddressState='Preferred';IPAddress='203.0.113.10'}}
    else {[pscustomobject]@{AddressState='Tentative';IPAddress='198.51.100.10'}}
}
function Get-NetIPInterface {param($AddressFamily,$InterfaceIndex,$ErrorAction) $script:interfaces[[int]$InterfaceIndex]}
function Get-DnsClientServerAddress {
    param($AddressFamily,$InterfaceIndex,$ErrorAction)
    [pscustomobject]@{ServerAddresses=@($script:resolvers[[int]$InterfaceIndex])}
}
$script:routes=@(
    [pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='Ethernet 3';InterfaceIndex=10;RouteMetric=0},
    [pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='Ethernet';InterfaceIndex=18;RouteMetric=0},
    [pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceAlias='WireGuardSplit';InterfaceIndex=28;RouteMetric=0}
)
$script:interfaces=@{
    10=[pscustomobject]@{InterfaceMetric=5;ConnectionState='Disconnected'}
    18=[pscustomobject]@{InterfaceMetric=20;ConnectionState='Connected'}
    28=[pscustomobject]@{InterfaceMetric=1;ConnectionState='Connected'}
}
$script:resolvers=@{10=@('198.51.100.53');18=@('203.0.113.53');28=@('10.2.0.1')}
Assert-True ((Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit').InterfaceIndex -eq 18) 'a disconnected lower-metric adapter cannot displace the connected uplink'
$chosen=@(Get-ProgramSplitPhysicalResolvers -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')
Assert-True ($chosen.Count -eq 1 -and $chosen[0] -eq '203.0.113.53') 'DNS resolvers follow the connected uplink'
Assert-True (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1') 'the controller accepts the new connected uplink while the old source is tentative'
$script:interfaces[10].ConnectionState='Connected'
Assert-True ((Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit').InterfaceIndex -eq 10) 'connected physical adapters still use effective metric ordering'
$script:routes[0].RouteMetric=50
Assert-True ((Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit').InterfaceIndex -eq 18) 'route metric and interface metric both contribute to the winner'
$script:routes[0].RouteMetric=0
$script:interfaces[10].InterfaceMetric=50
Assert-True ((Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit').InterfaceIndex -eq 18) 'the tunnel is excluded even when it has the lowest metric'
$script:interfaces.Remove(10)
Assert-True ((Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit').InterfaceIndex -eq 18) 'a vanished physical interface cannot retain a stale default'
$script:interfaces[10]=[pscustomobject]@{InterfaceMetric=5;ConnectionState='Disconnected'}
$script:interfaces[18].ConnectionState='Disconnected'
$rejected=$false
try {$null=Get-ProgramSplitPhysicalDefault -AdapterName 'WireGuardSplit'} catch {$rejected=$true}
Assert-True $rejected 'no connected physical uplink fails instead of selecting a stale route'
Assert-True (-not (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) 'controller holds repairs when only stale physical routes remain'
$script:interfaces[18].ConnectionState='Connected'
$configuration=[pscustomobject]@{AdapterName='WireGuardSplit';TunnelDns='10.2.0.1'}
$dispatcher=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'src\powershell\Invoke-DnsDispatcher.ps1'),[ref]$tokens,[ref]$errors)
$direct=$dispatcher.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-DirectNetwork'},$true)
. ([scriptblock]::Create($direct.Extent.Text))
$network=Get-DirectNetwork
Assert-True ($network.InterfaceIndex -eq 18 -and $network.Source -eq '203.0.113.10' -and $network.Resolver -eq '203.0.113.53') 'dispatcher source and resolver belong to the same connected uplink'
$script:interfaces[18].ConnectionState='Disconnected'
# Compose the recovery gate with the actual selector, not a stubbed winner.
. (Join-Path $RepositoryRoot 'src\powershell\NetworkRecovery.ps1')
function Get-ProgramSplitConfiguration {param($Root) [pscustomobject]@{AdapterName='WireGuardSplit'}}
Assert-True (Test-ProgramSplitRecoveryRouteSafe 'fixture' 18 'ReconnectWifi') 'only stale defaults allow enrolled Wi-Fi reconnect'
Assert-True (-not (Test-ProgramSplitRecoveryRouteSafe 'fixture' 18 'ResetPaused')) 'only stale defaults do not permit an Ethernet reset'
$script:interfaces[18].ConnectionState='Connected'
Assert-True (Test-ProgramSplitRecoveryRouteSafe 'fixture' 18 'ResetPaused') 'stale preferred route cannot mask the connected enrolled adapter'
Assert-True (-not (Test-ProgramSplitRecoveryRouteSafe 'fixture' 10 'ResetPaused')) 'a connected alternative protects against resetting another adapter'
$script:routeUnknown=$true
Assert-True (-not (Test-ProgramSplitRecoveryRouteSafe 'fixture' 18 'ReconnectWifi')) 'unknown route inventory fails closed'
$script:routeUnknown=$false
# Check the real CIM enum contract on Windows without modifying any adapter.
$live=@(NetTCPIP\Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop)
Assert-True (@($live | Where-Object {$_.ConnectionState -eq 'Connected'}).Count -gt 0) 'real CIM ConnectionState supports the Connected comparison'
Write-Output 'PASS: connected physical uplink, DNS inputs, recovery gating and CIM state contract.'

