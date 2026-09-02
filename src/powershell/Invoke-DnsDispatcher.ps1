param(
    [ValidateSet('Start', 'Stop', 'Status', 'Validate')]
    [string] $Action = 'Status',
    [string] $IncludedAppsFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
if (-not $IncludedAppsFile) { $IncludedAppsFile = Join-Path $root 'state\included-apps.txt' }
$exe = Join-Path $root 'bin\dns-dispatcher.exe'
$pidFile = Join-Path $root 'state\dns-dispatcher.pid'
$stdout = Join-Path $root 'logs\dns-dispatcher.log'
$stderr = Join-Path $root 'logs\dns-dispatcher-error.log'
$networkState = Join-Path $root 'state\direct-network.json'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Get-ManagedProcess {
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { return $null }
    $managedPid = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($pidFile), [ref]$managedPid)) { return $null }
    $process = Get-Process -Id $managedPid -ErrorAction SilentlyContinue
    if (-not $process) { return $null }
    if ($process.ProcessName -ne 'dns-dispatcher') { return $null }
    return $process
}

function Get-DirectNetwork {
    $physical = Get-ProgramSplitPhysicalDefault -AdapterName $configuration.AdapterName
    $source = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
    $resolver = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex).ServerAddresses |
        Where-Object { $_ -notin @('127.0.0.1', $configuration.TunnelDns) } | Select-Object -First 1
    if (-not $source -or -not $resolver) { throw 'Physical source address or pre-dispatch DNS resolver is unavailable.' }
    [pscustomobject]@{ InterfaceIndex = $physical.InterfaceIndex; Source = $source; Resolver = $resolver }
}

if ($Action -eq 'Status') {
    $process = Get-ManagedProcess
    if ($process) { [pscustomobject]@{ State = 'Running'; ProcessId = $process.Id; IncludedAppsFile = $IncludedAppsFile } }
    else { Write-Output 'DNS dispatcher is stopped.' }
    exit 0
}

if ($Action -eq 'Validate') {
    if (-not (Test-Path -LiteralPath $networkState -PathType Leaf)) { throw 'Direct-network state is missing.' }
    $saved = Get-Content -LiteralPath $networkState -Raw | ConvertFrom-Json
    $current = Get-DirectNetwork
    if ($saved.InterfaceIndex -ne $current.InterfaceIndex -or $saved.Source -ne $current.Source -or
        $saved.Resolver -ne $current.Resolver) {
        throw 'The active physical route, source address, or DNS resolver changed.'
    }
    Write-Output 'PASS: direct-network inputs are current.'
    exit 0
}

Assert-Administrator

if ($Action -eq 'Stop') {
    $nrpt = Join-Path $PSScriptRoot 'Invoke-LocalNrpt.ps1'
    if (Test-Path -LiteralPath $nrpt -PathType Leaf) { & $nrpt -Action Disable | Out-Null }
    $process = Get-ManagedProcess
    if ($process) {
        & logman.exe stop 'WireGuardProgramSplitDnsEtw' -ets 2>$null | Out-Null
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    if (Test-Path -LiteralPath $pidFile) { [IO.File]::Delete($pidFile) }
    if (Test-Path -LiteralPath $networkState) { [IO.File]::Delete($networkState) }
    Write-Output 'DNS dispatcher stopped.'
    exit 0
}

foreach ($path in @($exe, $IncludedAppsFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing dispatcher input: $path" }
}
$includedPaths = @(Get-Content -LiteralPath $IncludedAppsFile |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if (-not $includedPaths) { throw 'The included-app list is empty.' }
foreach ($path in $includedPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Included application does not exist: $path" }
}
$existing = Get-ManagedProcess
if ($existing) { Write-Output 'DNS dispatcher already running.'; exit 0 }

$network = Get-DirectNetwork
$source = $network.Source
$resolver = $network.Resolver

[IO.Directory]::CreateDirectory((Split-Path -Parent $stdout)) | Out-Null
$arguments = @($IncludedAppsFile, $source, $resolver, $configuration.TunnelAddress, $configuration.TunnelDns)
$process = Start-Process -FilePath $exe -ArgumentList $arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText($pidFile, [string]$process.Id)
[IO.File]::WriteAllText($networkState, ($network | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    if ($process.HasExited) { throw "DNS dispatcher exited: $([IO.File]::ReadAllText($stderr))" }
    $udpEndpoint = Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $process.Id }
    $tcpEndpoint = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 53 -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $process.Id }
    if ($udpEndpoint -and $tcpEndpoint) {
        Write-Output "DNS dispatcher ready for $($includedPaths.Count) included application(s)."
        exit 0
    }
    Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
throw 'DNS dispatcher did not become ready.'
