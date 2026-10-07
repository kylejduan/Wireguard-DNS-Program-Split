# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\AdapterMaintenance.ps1')
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function New-StraySnapshot {
    [pscustomobject]@{
        InstanceId = 'ROOT\WIREGUARD\0007'; Class = 'Net'; Service = 'WireGuard'
        ClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}'
        HardwareIds = @('WireGuard'); Provider = 'WireGuard LLC'; FirstInstallDate = '2026-01-01'
        Name = 'Local Area Connection'; InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'
        InterfaceIndex = 99; Status = 'Disconnected'; ReceivedBytes = 0; SentBytes = 0
        Addresses = @([pscustomobject]@{IPAddress='169.254.1.2';PrefixOrigin='WellKnown'})
        Routes = @([pscustomobject]@{DestinationPrefix='224.0.0.0/4';NextHop='0.0.0.0'})
    }
}
Assert-True (Test-ProgramSplitStrayAdapter (New-StraySnapshot)) 'an unused servicing device is eligible'
$cases = @(
    @{Field='InstanceId';Value='SWD\WireGuard\{11111111-1111-1111-1111-111111111111}'},
    @{Field='InstanceId';Value='ROOT\OTHER\0007'}, @{Field='InstanceId';Value='ROOT\WIREGUARD\0007\child'},
    @{Field='Class';Value='Other'}, @{Field='Service';Value='Other'}, @{Field='ClassGuid';Value='other'},
    @{Field='HardwareIds';Value=@('Other')}, @{Field='HardwareIds';Value=@('WireGuard','Other')},
    @{Field='Provider';Value='Other'}, @{Field='FirstInstallDate';Value=''},
    @{Field='Name';Value='WireGuardSplit'}, @{Field='InterfaceGuid';Value=''},
    @{Field='InterfaceIndex';Value=0}, @{Field='Status';Value='Up'}, @{Field='Status';Value='Disabled'},
    @{Field='ReceivedBytes';Value=1}, @{Field='SentBytes';Value=1}, @{Field='ReceivedBytes';Value=$null},
    @{Field='Addresses';Value=@([pscustomobject]@{IPAddress='10.0.0.2';PrefixOrigin='Dhcp'})},
    @{Field='Addresses';Value=@([pscustomobject]@{IPAddress='169.254.1.2';PrefixOrigin='Manual'})},
    @{Field='Addresses';Value=@([pscustomobject]@{IPAddress='2001:db8::2';PrefixOrigin='RouterAdvertisement'})},
    @{Field='Addresses';Value=@([pscustomobject]@{IPAddress='invalid';PrefixOrigin='WellKnown'})},
    @{Field='Routes';Value=@([pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='0.0.0.0'})},
    @{Field='Routes';Value=@([pscustomobject]@{DestinationPrefix='203.0.113.0/24';NextHop='0.0.0.0'})},
    @{Field='Routes';Value=@([pscustomobject]@{DestinationPrefix='224.0.0.0/4';NextHop='192.0.2.1'})}
)
foreach ($case in $cases) {
    $snapshot = New-StraySnapshot
    $snapshot.($case.Field) = $case.Value
    Assert-True (-not (Test-ProgramSplitStrayAdapter $snapshot)) "preserves device with changed $($case.Field)"
}
$snapshot = New-StraySnapshot
$snapshot.Addresses += [pscustomobject]@{IPAddress='fe80::123';PrefixOrigin='WellKnown'}
$snapshot.Routes += @(
    [pscustomobject]@{DestinationPrefix='169.254.1.2/32';NextHop='0.0.0.0'},
    [pscustomobject]@{DestinationPrefix='fe80::123/128';NextHop='::'},
    [pscustomobject]@{DestinationPrefix='fe80::/64';NextHop='::'},
    [pscustomobject]@{DestinationPrefix='ff00::/8';NextHop='::'}
)
Assert-True (Test-ProgramSplitStrayAdapter $snapshot) 'automatic link-local addressing alone is eligible'

# Exercise the production orchestration against an in-memory Windows device inventory. No actual
# device, driver, registry entry, route, service, or adapter is changed by this test.
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("wgps-adapter-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory((Join-Path $temporary 'logs')) | Out-Null
$script:registryPresent = $true
$script:devicePresent = $true
$script:reads = 0
$script:removed = [Collections.Generic.List[string]]::new()
$script:change = ''
function Test-Path { param($LiteralPath, $ErrorAction) return $script:registryPresent }
function Get-ChildItem { param($LiteralPath, $ErrorAction)
    if ($script:devicePresent) { [pscustomobject]@{PSChildName='0007'} }
    [pscustomobject]@{PSChildName='foreign-name'}
}
function Get-ProgramSplitStrayAdapterSnapshot([string] $InstanceId) {
    $script:reads++
    if ($script:change -eq 'inspection-failure') { throw 'Device inventory unavailable' }
    $s = New-StraySnapshot
    if ($script:reads -gt 1) {
        switch ($script:change) {
            'up' { $s.Status = 'Up' }
            'traffic' { $s.SentBytes = 128 }
            'guid' { $s.InterfaceGuid = '{22222222-2222-2222-2222-222222222222}' }
            'index' { $s.InterfaceIndex = 100 }
            'recreated' { $s.FirstInstallDate = '2026-01-02' }
        }
    }
    return $s
}
function Remove-ProgramSplitStrayDevice([string] $InstanceId, [string] $LogDirectory) {
    if ($script:change -eq 'remove-failure') { throw 'Access denied' }
    $script:removed.Add($InstanceId)
    $script:devicePresent = $false
}
try {
    $script:registryPresent = $false
    Invoke-ProgramSplitAdapterMaintenance -Root $temporary -Repair | Out-Null
    Assert-True ($script:reads -eq 0) 'an absent ROOT key skips expensive device enumeration'
    $script:registryPresent = $true
    $output = Invoke-ProgramSplitAdapterMaintenance -Root $temporary
    Assert-True ($script:removed.Count -eq 0 -and $output -match 'found inactive') 'status never removes a device'
    foreach ($change in @('up','traffic','guid','index','recreated','inspection-failure','remove-failure')) {
        $script:change = $change; $script:reads = 0
        $output = Invoke-ProgramSplitAdapterMaintenance -Root $temporary -Repair
        Assert-True ($script:removed.Count -eq 0 -and $output -match 'incomplete') "retains device on $change without throwing"
    }
    $script:change = ''; $script:reads = 0
    $output = Invoke-ProgramSplitAdapterMaintenance -Root $temporary -Repair
    Assert-True ($script:removed.Count -eq 1 -and $script:removed[0] -eq 'ROOT\WIREGUARD\0007' -and
        $script:reads -eq 2 -and $output -match 'removed inactive') 'removes only the verified exact instance after reinspection'
    $evidence = [IO.File]::ReadAllText((Join-Path $temporary 'logs\adapter-removal-before.json')) | ConvertFrom-Json
    Assert-True ($evidence.InstanceId -eq 'ROOT\WIREGUARD\0007') 'retains the pre-removal device snapshot'
    Invoke-ProgramSplitAdapterMaintenance -Root $temporary -Repair | Out-Null
    Assert-True ($script:removed.Count -eq 1) 'repeat maintenance is a no-op after removal'
} finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $temporary -Recurse -Force
}

# The controller schedules this independently of health repair. A failure must not escape into
# the restart path, and repeated loop iterations must not continuously enumerate PnP devices.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'), [ref] $tokens, [ref] $errors)
$function = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-AdapterMaintenance'
}, $true))
Assert-True ($function.Count -eq 1) 'controller defines one maintenance scheduler'
. ([scriptblock]::Create($function[0].Extent.Text))
$script:calls = 0
$script:messages = [Collections.Generic.List[string]]::new()
function Invoke-Component { param($name,$action) $script:calls++; throw 'Mock maintenance failure' }
function Write-ControllerLog([string] $message) { $script:messages.Add($message) }
$script:nextAdapterMaintenance = [DateTime]::MinValue
Invoke-AdapterMaintenance
Invoke-AdapterMaintenance
Assert-True ($script:calls -eq 1 -and $script:messages[0] -match 'keeping the stack active' -and
    $script:nextAdapterMaintenance -gt (Get-Date).AddMinutes(4)) 'failure stays nonfatal and backs off for five minutes'
function Write-ControllerLog([string] $message) { throw 'Mock disk failure' }
$script:nextAdapterMaintenance = [DateTime]::MinValue
Invoke-AdapterMaintenance
Assert-True ($script:calls -eq 2) 'even a maintenance logging failure does not escape into service recovery'
Write-Output 'PASS: adapter maintenance preserves active/foreign devices, rechecks identity, and isolates failures.'
