# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [Parameter(Mandatory)] [string] $InputPath,
    [string] $OutputPath,
    [string] $SettingsPath,
    # Validates the profile and returns the derived settings without writing anything.
    [switch] $ValidateOnly,
    # The caller writes into a directory it has already protected; files inherit its ACL.
    [switch] $SkipAcl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw 'The WireGuard profile was not found.' }

$lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $InputPath).ProviderPath)
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

if ($ValidateOnly) {
    return [pscustomobject]@{ TunnelAddress = $tunnelAddress; TunnelDns = $tunnelDns }
}
if (-not $OutputPath -or -not $SettingsPath) { throw 'OutputPath and SettingsPath are required unless -ValidateOnly is used.' }

# Each file is protected when it is created, before any key byte is written: unless the caller has protected
# the directory itself (-SkipAcl), the file's descriptor grants SYSTEM and Administrators only.
function Write-PreparedText([string] $Path, [string] $Text) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    if ($SkipAcl) {
        [IO.File]::WriteAllBytes($Path, $bytes)
        return
    }
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
    }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
$settingsParent = Split-Path -Parent $SettingsPath
if ($settingsParent) { [IO.Directory]::CreateDirectory($settingsParent) | Out-Null }
$tempPath = "$OutputPath.tmp"
$tempSettings = "$SettingsPath.tmp"
Write-PreparedText $tempPath ((@($result) -join "`r`n") + "`r`n")
Write-PreparedText $tempSettings ([ordered]@{
    TunnelAddress = $tunnelAddress
    TunnelDns = $tunnelDns
} | ConvertTo-Json)
Move-Item -LiteralPath $tempPath -Destination $OutputPath -Force
Move-Item -LiteralPath $tempSettings -Destination $SettingsPath -Force

Write-Output 'Prepared IPv4 WireGuard profile and local routing settings without exposing key material.'
