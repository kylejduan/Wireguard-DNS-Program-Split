param(
    [ValidateSet('Start', 'Stop', 'Status')]
    [string] $Action = 'Status',
    [string] $IncludedAppsFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-ProgramSplit64BitPowerShell
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
    if ($process -and $process.ProcessName -eq 'wfp-probe' -and [string]$process.Path -eq $exe) {
        return $process
    }
    return $null
}

function Get-ExpectedProcesses {
    @(Get-Process -Name 'wfp-probe' -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.Path -eq $exe
    })
}

function Stop-ExpectedProcesses {
    foreach ($process in @(Get-ExpectedProcesses)) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
}

if ($Action -eq 'Status') {
    $process = Get-ManagedProcess
    if ($process) { [pscustomobject]@{ State = 'Running'; ProcessId = $process.Id; IncludedAppsFile = $IncludedAppsFile } }
    else { Write-Output 'Dynamic WFP filters are stopped.' }
    exit 0
}

Assert-Administrator

if ($Action -eq 'Stop') {
    Stop-ExpectedProcesses
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
Stop-ExpectedProcesses

[IO.Directory]::CreateDirectory((Split-Path -Parent $stdout)) | Out-Null
$process = $null
$started = $false
try {
    $process = Start-Process -FilePath $exe -ArgumentList @(
        $IncludedAppsFile, $configuration.TunnelAddress
    ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    [IO.File]::WriteAllText($pidFile, [string]$process.Id)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ($process.HasExited) { throw "WFP filter host exited: $([IO.File]::ReadAllText($stderr))" }
        if ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) -match '^READY:') {
            $started = $true
            Write-Output "Dynamic WFP payload filters ready for $($includedPaths.Count) included application(s)."
            exit 0
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'WFP filter host did not become ready.'
} finally {
    if (-not $started) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }
}
