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

function Add-TableOff {
    if ($script:section -eq 'interface' -and -not $script:tableWritten) {
        $script:result.Add('Table = off')
        $script:tableWritten = $true
    }
}

foreach ($line in $lines) {
    $trimmed = $line.Trim()
    if ($trimmed -match '^\[(.+)\]$') {
        Add-TableOff
        $section = $Matches[1].ToLowerInvariant()
        $result.Add($line)
        continue
    }

    if ($trimmed -match '^([^#;=]+?)\s*=\s*(.*)$') {
        $key = $Matches[1].Trim().ToLowerInvariant()
        $value = $Matches[2].Trim()

        if ($section -eq 'interface') {
            if ($key -eq 'privatekey') { $sawPrivateKey = $true }
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
            if ($key -eq 'publickey') { $sawPublicKey = $true }
            if ($key -eq 'endpoint') { $sawEndpoint = $true }
            if ($key -eq 'allowedips') {
                $result.Add('AllowedIPs = 0.0.0.0/0')
                $sawAllowedIps = $true
                continue
            }
        }
    }

    $result.Add($line)
}
Add-TableOff

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
