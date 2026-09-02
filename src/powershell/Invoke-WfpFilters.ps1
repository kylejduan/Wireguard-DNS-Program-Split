param(
    [ValidateSet('Start', 'Stop', 'Status')]
    [string] $Action = 'Status',
    [string] $IncludedAppsFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
$configuration = Get-ProgramSplitConfiguration -Root $root
if (-not $IncludedAppsFile) { $IncludedAppsFile = Join-Path $root 'state\included-apps.txt' }
$exe = Join-Path $root 'bin\wfp-probe.exe'
$pidFile = Join-Path $root 'state\wfp-filters.pid'
$stdout = Join-Path $root 'logs\wfp-filters.log'
$stderr = Join-Path $root 'logs\wfp-filters-error.log'

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
    if ($process.ProcessName -ne 'wfp-probe') { return $null }
    return $process
}

if ($Action -eq 'Status') {
    $process = Get-ManagedProcess
    if ($process) { [pscustomobject]@{ State = 'Running'; ProcessId = $process.Id; IncludedAppsFile = $IncludedAppsFile } }
    else { Write-Output 'Dynamic WFP filters are stopped.' }
    exit 0
}

Assert-Administrator

if ($Action -eq 'Stop') {
    $process = Get-ManagedProcess
    if ($process) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    if (Test-Path -LiteralPath $pidFile) { [IO.File]::Delete($pidFile) }
    Write-Output 'Dynamic WFP filters stopped and removed.'
    exit 0
}

foreach ($path in @($exe, $IncludedAppsFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing WFP input: $path" }
}
$includedPaths = @(Get-Content -LiteralPath $IncludedAppsFile |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if (-not $includedPaths) { throw 'The included-app list is empty.' }
foreach ($path in $includedPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Included application does not exist: $path" }
}
if ((Get-Service PiaWFPCallout -ErrorAction Stop).Status -ne 'Running') { throw 'PIA WFP callout driver is not running.' }
if (-not (Get-NetIPAddress -InterfaceAlias $configuration.AdapterName -AddressFamily IPv4 `
        -IPAddress $configuration.TunnelAddress -ErrorAction SilentlyContinue)) {
    throw "Tunnel address $($configuration.TunnelAddress) is unavailable."
}
$existing = Get-ManagedProcess
if ($existing) { Write-Output 'Dynamic WFP filters are already running.'; exit 0 }

[IO.Directory]::CreateDirectory((Split-Path -Parent $stdout)) | Out-Null
$process = Start-Process -FilePath $exe -ArgumentList @($IncludedAppsFile, $configuration.TunnelAddress) -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText($pidFile, [string]$process.Id)
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    if ($process.HasExited) { throw "WFP filter host exited: $([IO.File]::ReadAllText($stderr))" }
    if ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) -match '^READY:') {
        Write-Output "Dynamic WFP payload filters ready for $($includedPaths.Count) included application(s)."
        exit 0
    }
    Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
throw 'WFP filter host did not become ready.'
