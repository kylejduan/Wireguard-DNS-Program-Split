param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("WireGuardProgramSplit-install-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    $profile = Join-Path $temporary 'provider.conf'
    $application = Join-Path $temporary 'sample.exe'
    $runtime = Join-Path $temporary 'runtime'
    $driver = Join-Path $temporary 'driver'
    $build = Join-Path $temporary 'build'
    foreach ($directory in @($runtime, $driver, $build)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    foreach ($path in @(
        $application,
        (Join-Path $runtime 'tunnel.dll'), (Join-Path $runtime 'wireguard.dll'),
        (Join-Path $driver 'PiaWFPCallout.inf'), (Join-Path $driver 'PiaWfpCallout.sys'),
        (Join-Path $driver 'piawfpcallout.cat'),
        (Join-Path $build 'dns-dispatcher.exe'), (Join-Path $build 'dns-probe.exe'),
        (Join-Path $build 'tunnel-host.exe'), (Join-Path $build 'wfp-probe.exe')
    )) { [IO.File]::WriteAllText($path, 'test') }

    $dummyKey = ('A' * 43) + '='
    [IO.File]::WriteAllText($profile, @"
[Interface]
PrivateKey = $dummyKey
Address = 192.0.2.2/32
DNS = 203.0.113.53
[Peer]
PublicKey = $dummyKey
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
"@)

    $plan = & (Join-Path $RepositoryRoot 'Install.ps1') -Profile $profile -Applications $application `
        -WireGuardRuntimeDirectory $runtime -PiaDriverDirectory $driver -BuildDirectory $build `
        -DestinationRoot 'C:\ProgramData\WireGuardProgramSplit\' -PlanOnly
    Assert-True ($plan.DestinationRoot -eq 'C:\ProgramData\WireGuardProgramSplit') `
        'installer normalizes the destination root before planning resource ownership'
    Assert-True ($plan.ServiceName -eq 'WireGuardTunnel$WireGuardSplit') 'installer plans the neutral tunnel service'
    Assert-True ($plan.ServiceStartType -eq 'Automatic') 'installer pre-starts WireGuard at boot'
    Assert-True ($plan.ControllerTask -eq 'WireGuard Program Split Controller') 'installer plans the controller task'
    Assert-True ($plan.InstallationMarker -eq 'state\installation.json') 'installer marks the exact owned tree'
    Assert-True ($plan.TunnelAddress -eq '192.0.2.2') 'installer derives the tunnel address from the profile'
    Assert-True ($plan.TunnelDns -eq '203.0.113.53') 'installer derives tunnel DNS from the profile'
    Assert-True ($plan.ApplicationCount -eq 1) 'installer retains the explicit application list'
    $installerSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'Install.ps1'))
    Assert-True ($installerSource -match 'if \(\$destinationCreated -and \(Test-Path') `
        'installer rollback removes only a destination created by the current run'

    $removal = & (Join-Path $RepositoryRoot 'Uninstall.ps1') `
        -DestinationRoot 'C:\ProgramData\WireGuardProgramSplit' -PlanOnly
    Assert-True ($removal.ServiceName -eq 'WireGuardTunnel$WireGuardSplit') 'uninstaller scopes the tunnel service'
    Assert-True ($removal.ControllerTask -eq $plan.ControllerTask) 'installer and uninstaller own the same controller task'
    Assert-True ($removal.RemovePiaDriver -eq $false) 'uninstaller leaves the potentially shared PIA driver installed'

    $missingRoot = Join-Path $temporary 'not-installed'
    $notInstalled = & (Join-Path $RepositoryRoot 'Uninstall.ps1') -DestinationRoot $missingRoot
    Assert-True ($notInstalled -eq 'WireGuard Program Split is not installed; nothing was changed.') `
        'uninstaller is a no-op when the owned installation root is absent'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'PASS: installer produces a provider-neutral, automatic-service deployment plan.'
