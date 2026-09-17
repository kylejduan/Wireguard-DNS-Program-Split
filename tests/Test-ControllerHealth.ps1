# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$controllerPath = Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'
$controllerSource = [IO.File]::ReadAllText($controllerPath)
$dispatcherSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\powershell\Invoke-DnsDispatcher.ps1'))

Assert-True ($controllerSource -match '(?s)function Test-StackHealth.*?Test-TunnelDns -TimeoutMilliseconds 1000 -Attempts 3') `
    'periodic health check retransmits the tunnel DNS probe before declaring the tunnel unhealthy'
Assert-True ($controllerSource -match '(?s)function Test-TunnelDns\(\[int\] \$TimeoutMilliseconds = 5000, \[int\] \$Attempts = 1\).*?\$TimeoutMilliseconds, \$Attempts.*?WaitForExit\(\$TimeoutMilliseconds \* \$Attempts \+ 3000\)') `
    'tunnel DNS probe wait covers every retransmission'
Assert-True ($controllerSource -match "(?s)function Test-LocalDns.*?'--system', 'example\.com', 3") `
    'startup local split-DNS probe retries a transient refusal'
Assert-True ($dispatcherSource -match "'--system', 'example\.com', 3") `
    'dispatcher validation retries a transient refusal'
Assert-True ($controllerSource -match 'Wait-ProgramSplitProbe -Probe \{ Test-TunnelDns -TimeoutMilliseconds 750 \}') `
    'startup gate keeps single-shot probes because its own loop already retries'
Assert-True ($controllerSource -match '(?s)Stack health check failed.*?Save-HealthFailureEvidence -Reason \$_\.Exception\.Message\s*Stop-Stack') `
    'controller snapshots component logs before the restart that overwrites them'

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($controllerPath, [ref] $tokens, [ref] $parseErrors)
$evidenceFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Save-HealthFailureEvidence'
}, $true))
Assert-True ($evidenceFunction.Count -eq 1) 'controller defines the health-failure evidence snapshot once'
. ([scriptblock]::Create($evidenceFunction[0].Extent.Text))
$controllerLog = [Collections.Generic.List[string]]::new()
function Write-ControllerLog([string] $message) { $controllerLog.Add($message) }

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("wgps-health-{0}" -f [guid]::NewGuid())
try {
    $logs = Join-Path $temporary 'logs'
    [IO.Directory]::CreateDirectory($logs) | Out-Null
    [IO.File]::WriteAllText((Join-Path $logs 'dns-dispatcher.log'), 'BLOCKED (no process hint) example.com')
    [IO.File]::WriteAllText((Join-Path $logs 'dns-health-error.log'), 'ERROR: No DNS response after 3 attempts')
    [IO.File]::WriteAllText((Join-Path $logs 'controller.log'), 'supervisor history that is never rewritten')
    [IO.File]::WriteAllText((Join-Path $logs 'controller-service.log'), 'host history that is never rewritten')
    # A running component keeps its redirected log open for writing and shares only read access.
    $held = [IO.FileStream]::new((Join-Path $logs 'dns-dispatcher.log'), 'Open', 'Write', 'Read')
    try { Save-HealthFailureEvidence -Reason 'Tunnel DNS health probe failed: test reason' }
    finally { $held.Dispose() }

    $snapshots = @(Get-ChildItem -LiteralPath (Join-Path $logs 'health-failures') -Directory)
    Assert-True ($snapshots.Count -eq 1) 'a failed health check produces one evidence snapshot'
    $snapshot = $snapshots[0].FullName
    Assert-True ((Get-Content -LiteralPath (Join-Path $snapshot 'dns-dispatcher.log') -Raw) -match 'no process hint') `
        'evidence snapshot copies a log that a running component still holds open for writing'
    Assert-True ((Get-Content -LiteralPath (Join-Path $snapshot 'dns-health-error.log') -Raw) -match 'No DNS response') `
        'evidence snapshot keeps the probe error that the next probe overwrites'
    Assert-True ((Get-Content -LiteralPath (Join-Path $snapshot 'reason.txt') -Raw) -match 'test reason') `
        'evidence snapshot records why the health check failed'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $snapshot 'controller.log')) -and
        -not (Test-Path -LiteralPath (Join-Path $snapshot 'controller-service.log'))) `
        'evidence snapshot skips the append-only supervisor logs'
    Assert-True (($controllerLog -join ' ') -match 'evidence saved') 'evidence snapshot location is written to the controller log'

    foreach ($index in 1..12) {
        [IO.Directory]::CreateDirectory((Join-Path $logs ("health-failures\20000101-0000{0:d2}-000" -f $index))) | Out-Null
    }
    Save-HealthFailureEvidence -Reason 'second failure'
    $retained = @(Get-ChildItem -LiteralPath (Join-Path $logs 'health-failures') -Directory | Sort-Object Name)
    Assert-True ($retained.Count -eq 10) 'evidence snapshots are pruned to the ten most recent'
    Assert-True ($retained[-1].Name -notlike '2000*' -and $retained[0].Name -like '2000*') `
        'evidence pruning removes the oldest snapshots and keeps the newest'

    $logs = Join-Path $temporary 'missing\logs'
    $threw = $false
    try { Save-HealthFailureEvidence -Reason 'no log directory yet' } catch { $threw = $true }
    Assert-True (-not $threw) 'evidence snapshot never throws into the supervision loop'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'PASS: controller health checks retry their probes and preserve failure evidence.'
