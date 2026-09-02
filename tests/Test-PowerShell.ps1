param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$scripts = Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1' -File
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref] $tokens, [ref] $errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "PowerShell syntax errors in $($script.Name): $($errors -join '; ')"
}

foreach ($name in @('Invoke-BrowserDnsPolicy.ps1', 'Invoke-DnsCachePolicy.ps1')) {
    $source = [IO.File]::ReadAllText((Join-Path $RepositoryRoot "src\powershell\$name"))
    Assert-True ($source -notmatch '@\(\s*Get-Content[^\r\n]+ConvertFrom-Json') `
        "$name must enumerate a JSON array on Windows PowerShell 5.1"
}

$controllerSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'))
Assert-True ($controllerSource -match '(?s)\.Handle.*?WaitForExit\(45000\).*?WaitForExit\(\).*?\.ExitCode') `
    'controller retains the child handle and finalizes its wait before reading ExitCode'

$probeOut = Join-Path ([IO.Path]::GetTempPath()) "wgps-exit-$([guid]::NewGuid()).out"
$probeError = "$probeOut.err"
try {
    $probe = Start-Process cmd.exe -ArgumentList @('/d', '/c', 'exit', '7') `
        -RedirectStandardOutput $probeOut -RedirectStandardError $probeError -WindowStyle Hidden -PassThru
    $null = $probe.Handle
    Assert-True ($probe.WaitForExit(5000)) 'exit-code probe completes'
    $probe.WaitForExit()
    Assert-True ($probe.ExitCode -eq 7) 'Windows PowerShell reports the retained child exit code'
} finally {
    Remove-Item -LiteralPath $probeOut, $probeError -Force -ErrorAction SilentlyContinue
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("WireGuardProgramSplit-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    $common = Join-Path $RepositoryRoot 'src\powershell\Common.ps1'
    . $common
    $configRoot = Join-Path $temporary 'runtime'
    [IO.Directory]::CreateDirectory((Join-Path $configRoot 'config')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $configRoot 'config\settings.json'), '{"TunnelAddress":"192.0.2.2","TunnelDns":"203.0.113.53"}')
    $runtime = Get-ProgramSplitConfiguration -Root $configRoot
    Assert-True ($runtime.AdapterName -eq 'WireGuardSplit') 'runtime uses the neutral adapter name'
    Assert-True ($runtime.ServiceName -eq 'WireGuardTunnel$WireGuardSplit') 'runtime uses the neutral service name'
    Assert-True ($runtime.TunnelAddress -eq '192.0.2.2') 'runtime reads tunnel address from local settings'
    Assert-True ($runtime.TunnelDns -eq '203.0.113.53') 'runtime reads tunnel DNS from local settings'

    $prepare = Join-Path $RepositoryRoot 'src\powershell\Prepare-Profile.ps1'
    $input = Join-Path $temporary 'input.conf'
    $output = Join-Path $temporary 'WireGuardSplit.conf'
    $settings = Join-Path $temporary 'settings.json'
    $dummyKey = ('A' * 43) + '='
    $valid = @"
[Interface]
PrivateKey = $dummyKey
Address = 192.0.2.2/32
DNS = 203.0.113.53

[Peer]
PublicKey = $dummyKey
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
"@
    [IO.File]::WriteAllText($input, $valid)
    & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl

    $prepared = [IO.File]::ReadAllText($output)
    $configuration = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    Assert-True ($prepared -match '(?m)^Table = off\r?$') 'prepared profile has Table = off'
    Assert-True ($prepared -notmatch '(?im)^DNS\s*=') 'prepared profile omits global adapter DNS'
    Assert-True ($configuration.TunnelAddress -eq '192.0.2.2') 'settings retain the tunnel IPv4 address'
    Assert-True ($configuration.TunnelDns -eq '203.0.113.53') 'settings retain the tunnel DNS address'

    [IO.File]::WriteAllText($input, ($valid -replace '(?m)^DNS = .+\r?\n', ''))
    $missingDnsFailed = $false
    try { & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl } catch { $missingDnsFailed = $true }
    Assert-True $missingDnsFailed 'profile import rejects a missing DNS resolver'

    [IO.File]::WriteAllText($input, ($valid -replace 'Address = 192\.0\.2\.2/32', 'Address = 192.0.2.2/32, 2001:db8::2/128'))
    $ipv6Failed = $false
    try { & $prepare -InputPath $input -OutputPath $output -SettingsPath $settings -SkipAcl } catch { $ipv6Failed = $true }
    Assert-True $ipv6Failed 'profile import rejects IPv6 until IPv6 routing is implemented'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "PASS: $($scripts.Count) PowerShell scripts parse and profile import is provider-neutral."
