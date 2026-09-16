# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [Parameter(Mandatory)] [string] $InputPath,
    [Parameter(Mandatory)] [string] $OutputPath,
    [Parameter(Mandatory)] [string] $SettingsPath,
    [switch] $SkipAcl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw 'The WireGuard profile was not found.' }

$lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $InputPath))
$result = [Collections.Generic.List[string]]::new()
$section = ''
$sawPrivateKey = $false
$sawAddress = $false
$sawDns = $false
$sawPublicKey = $false
$sawEndpoint = $false
$sawAllowedIps = $false
$tableWritten = $false
$tunnelAddress = $null
$tunnelDns = $null
$interfaceSections = 0
$peerSections = 0
$seenRequiredFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

function Add-TableOff {
    if ($script:section -eq 'interface' -and -not $script:tableWritten) {
        $script:result.Add('Table = off')
        $script:tableWritten = $true
    }
}

function Assert-WireGuardKey([string] $Value, [string] $Name) {
    if ($Value -notmatch '^[A-Za-z0-9+/]{43}=$') {
        throw "$Name must use canonical WireGuard base64 syntax."
    }
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { throw "$Name must be a valid base64 WireGuard key." }
    if ($bytes.Length -ne 32) { throw "$Name must decode to 32 bytes." }
}

foreach ($line in $lines) {
    $trimmed = $line.Trim()
    if ($trimmed -match '^\[(.+)\]$') {
        Add-TableOff
        $section = $Matches[1].ToLowerInvariant()
        if ($section -eq 'interface') { ++$interfaceSections }
        if ($section -eq 'peer') { ++$peerSections }
        $result.Add($line)
        continue
    }

    if ($trimmed -match '^([^#;=]+?)\s*=\s*(.*)$') {
        $key = $Matches[1].Trim().ToLowerInvariant()
        $value = $Matches[2].Trim()

        $requiredField = ($section -eq 'interface' -and $key -in @('privatekey', 'address', 'dns')) -or
            ($section -eq 'peer' -and $key -in @('publickey', 'allowedips', 'endpoint'))
        if ($requiredField -and -not $seenRequiredFields.Add("$section.$key")) {
            throw "Duplicate required WireGuard field: $section.$key"
        }

        if ($section -eq 'interface') {
            if ($key -eq 'privatekey') {
                Assert-WireGuardKey $value 'PrivateKey'
                $sawPrivateKey = $true
            }
            if ($key -eq 'dns') {
                $dnsValues = @($value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $parsedDns = $null
                if ($dnsValues.Count -ne 1 -or -not [Net.IPAddress]::TryParse($dnsValues[0], [ref] $parsedDns) -or
                    $parsedDns.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
                    throw 'Expected exactly one IPv4 DNS address.'
                }
                $tunnelDns = $parsedDns.IPAddressToString
                $sawDns = $true
                continue
            }
            if ($key -eq 'table') { continue }
            if ($key -eq 'address') {
                $addresses = @($value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($addresses.Count -ne 1 -or $addresses[0] -notmatch '^(?<ip>\d{1,3}(\.\d{1,3}){3})/(?<prefix>\d{1,2})$') {
                    throw 'Expected exactly one IPv4 interface address.'
                }
                $parsedAddress = $null
                if (-not [Net.IPAddress]::TryParse($Matches.ip, [ref] $parsedAddress) -or
                    $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
                    [int] $Matches.prefix -gt 32) {
                    throw 'The WireGuard interface IPv4 address is invalid.'
                }
                $tunnelAddress = $parsedAddress.IPAddressToString
                $result.Add("Address = $($addresses[0])")
                $sawAddress = $true
                continue
            }
        }

        if ($section -eq 'peer') {
            if ($key -eq 'publickey') {
                Assert-WireGuardKey $value 'PublicKey'
                $sawPublicKey = $true
            }
            if ($key -eq 'endpoint') {
                if ($value -notmatch '^(?<host>[^:\s]+):(?<port>\d{1,5})$' -or
                    [int] $Matches.port -lt 1 -or [int] $Matches.port -gt 65535 -or
                    [Uri]::CheckHostName($Matches.host) -eq [UriHostNameType]::Unknown) {
                    throw 'Endpoint must be an IPv4 address or hostname with a valid port.'
                }
                $sawEndpoint = $true
            }
            if ($key -eq 'allowedips') {
                if (-not $value) { throw 'AllowedIPs cannot be empty.' }
                $result.Add('AllowedIPs = 0.0.0.0/0')
                $sawAllowedIps = $true
                continue
            }
        }
    }

    $result.Add($line)
}
Add-TableOff

if ($interfaceSections -ne 1 -or $peerSections -ne 1) {
    throw 'Expected exactly one [Interface] section and one [Peer] section.'
}
if (-not ($sawPrivateKey -and $sawAddress -and $sawDns -and $sawPublicKey -and $sawEndpoint -and $sawAllowedIps)) {
    throw 'The WireGuard profile is missing a required field.'
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
$settingsParent = Split-Path -Parent $SettingsPath
if ($settingsParent) { [IO.Directory]::CreateDirectory($settingsParent) | Out-Null }
$tempPath = "$OutputPath.tmp"
$tempSettings = "$SettingsPath.tmp"
[IO.File]::WriteAllLines($tempPath, $result, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($tempSettings, ([ordered]@{
    TunnelAddress = $tunnelAddress
    TunnelDns = $tunnelDns
} | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $tempPath -Destination $OutputPath -Force
Move-Item -LiteralPath $tempSettings -Destination $SettingsPath -Force

if (-not $SkipAcl) {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($identity in @($current, $system, $admins)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, $rights, $allow))
    }
    foreach ($path in @($OutputPath, $SettingsPath)) { Set-Acl -LiteralPath $path -AclObject $acl }
}

Write-Output 'Prepared IPv4 WireGuard profile and local routing settings without exposing key material.'
