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
Assert-True ($controllerSource -match '(?s)catch \{\s*if \(-not \(Test-ProgramSplitPhysicalInputs.*?holding the stack.*?\} else \{.*?Stop-Stack') `
    'a health failure without physical uplink inputs holds the stack instead of stopping it'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?if \(-not \(Test-PhysicalResolverAnswers\)\).*?not answering; keeping the stack in place.*?return') `
    'a local split-DNS probe failure holds the stack when the physical resolver itself is silent'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?\$script:resolverHoldLogged = \$true.*?\}\s*return') `
    'the resolver hold logs once instead of on every retry'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?\$script:resolverHoldLogged = \$false\s*Write-ControllerLog ''Local split-DNS health probe passed') `
    'the resolver hold flag resets once the probe passes again'
Assert-True ($controllerSource -match '(?s)function Test-PhysicalResolverAnswers.*?Get-ProgramSplitPhysicalResolver.*?if \(-not \$resolver\) \{ return \$false \}') `
    'an unknown physical resolver counts as unanswered rather than healthy'
Assert-True ($controllerSource -match 'Test-ProgramSplitPhysicalInputs -AdapterName \$configuration\.AdapterName `\s*-TunnelDns \$configuration\.TunnelDns\) -or -not \(Test-PhysicalResolverAnswers\)') `
    'the periodic health path holds for a silent physical resolver as well as missing uplink inputs'
Assert-True ($controllerSource -match '(?s)try \{ Test-StackHealth \}.*?\$script:physicalHoldLogged = \$false') `
    'a passing health check clears the hold notice so a later outage is logged again'

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

# Behaviour of the uplink-input test itself, with the network cmdlets stubbed.
$commonPath = Join-Path $RepositoryRoot 'src\powershell\Common.ps1'
$commonTokens = $null; $commonErrors = $null
$commonAst = [Management.Automation.Language.Parser]::ParseFile($commonPath, [ref] $commonTokens, [ref] $commonErrors)
$inputsFunction = @($commonAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-ProgramSplitPhysicalInputs'
}, $true))
Assert-True ($inputsFunction.Count -eq 1) 'Common defines the physical-input test once'
. ([scriptblock]::Create($inputsFunction[0].Extent.Text))
$resolverFunction = @($commonAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ProgramSplitPhysicalResolver'
}, $true))
Assert-True ($resolverFunction.Count -eq 1) 'Common defines the physical-resolver lookup once'
. ([scriptblock]::Create($resolverFunction[0].Extent.Text))
$script:physicalRoute = [pscustomobject]@{ InterfaceIndex = 15 }
$script:addresses = @([pscustomobject]@{ AddressState = 'Preferred'; IPAddress = '192.168.1.100' })
$script:servers = @([pscustomobject]@{ ServerAddresses = @('192.168.1.1') })
function Get-ProgramSplitPhysicalDefault { param([string] $AdapterName) if (-not $script:physicalRoute) { throw 'No physical IPv4 default gateway found.' } $script:physicalRoute }
function Get-NetIPAddress { param($AddressFamily, $InterfaceIndex, $ErrorAction) $script:addresses }
function Get-DnsClientServerAddress { param($AddressFamily, $InterfaceIndex, $ErrorAction) $script:servers }
Assert-True (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1') `
    'a preferred physical address and a foreign resolver count as usable uplink inputs'
$script:physicalRoute = $null
Assert-True (-not (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'a missing physical default route reports unusable uplink inputs'
$script:physicalRoute = [pscustomobject]@{ InterfaceIndex = 15 }
$script:addresses = @([pscustomobject]@{ AddressState = 'Preferred'; IPAddress = '169.254.9.9' })
Assert-True (-not (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'an APIPA-only physical address reports unusable uplink inputs'
$script:addresses = @([pscustomobject]@{ AddressState = 'Preferred'; IPAddress = '192.168.1.100' })
$script:servers = @([pscustomobject]@{ ServerAddresses = @('127.0.0.1', '10.2.0.1') })
Assert-True (-not (Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'only loopback and tunnel resolvers report unusable uplink inputs'
Assert-True ($null -eq (Get-ProgramSplitPhysicalResolver -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'loopback and tunnel resolvers alone yield no forwarding resolver'
$script:servers = @([pscustomobject]@{ ServerAddresses = @('127.0.0.1', '192.168.1.1', '10.2.0.1') })
Assert-True ((Get-ProgramSplitPhysicalResolver -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1') -eq '192.168.1.1') `
    'the forwarding resolver is the first address that is neither loopback nor the tunnel'
$script:physicalRoute = $null
Assert-True ($null -eq (Get-ProgramSplitPhysicalResolver -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'a missing physical default route yields no forwarding resolver'
$script:physicalRoute = [pscustomobject]@{ InterfaceIndex = 15 }
$script:servers = @([pscustomobject]@{ ServerAddresses = @('192.168.1.1') })

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

    # A long-running dispatcher log can be far larger than anything worth copying whole, and it is the
    # file a DNS failure most needs. Keep its tail instead of skipping it.
    $largeLog = Join-Path $logs 'dns-dispatcher.log'
    $stream = [IO.File]::Create($largeLog)
    try {
        $filler = [byte[]]::new(1MB)
        foreach ($chunk in 1..3) { $stream.Write($filler, 0, $filler.Length) }
        $tail = [Text.Encoding]::ASCII.GetBytes("`nFAILED final-line-before-the-restart`n")
        $stream.Write($tail, 0, $tail.Length)
    } finally { $stream.Dispose() }
    Save-HealthFailureEvidence -Reason 'large log'
    $largeSnapshot = Get-ChildItem -LiteralPath (Join-Path $logs 'health-failures') -Directory | Sort-Object Name | Select-Object -Last 1
    $copied = Get-Item -LiteralPath (Join-Path $largeSnapshot.FullName 'dns-dispatcher.log')
    Assert-True ($copied.Length -gt 0 -and $copied.Length -le 2MB) 'an oversized log is snapshotted as a bounded tail, not skipped or copied whole'
    Assert-True ((Get-Content -LiteralPath $copied.FullName -Raw) -match 'final-line-before-the-restart') `
        'the snapshot of an oversized log keeps its most recent lines'
    Assert-True ((Get-Content -LiteralPath (Join-Path $largeSnapshot.FullName 'reason.txt') -Raw) -match 'dns-dispatcher\.log.*truncated') `
        'the snapshot records which logs were truncated'
    Remove-Item -LiteralPath $largeLog -Force

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

$hostSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\native\controller-service.cpp'))
$stopBranch = $hostSource.Substring($hostSource.IndexOf('if (forced && stopFailure == NO_ERROR)'))
$stopBranch = $stopBranch.Substring(0, $stopBranch.IndexOf('} else {'))
Assert-True ($stopBranch.IndexOf('appendHostLog(') -ge 0 -and
    $stopBranch.IndexOf('appendHostLog(') -lt $stopBranch.IndexOf('reportStatus(SERVICE_STOPPED')) `
    'service host records a service stop before reporting stopped, after which the process may end at any moment'
$exitBranch = $hostSource.Substring($hostSource.IndexOf('const bool duringShutdown'))
$exitBranch = $exitBranch.Substring(0, $exitBranch.IndexOf('CloseHandle(child);'))
Assert-True ($exitBranch.IndexOf('appendHostLog(') -ge 0 -and
    $exitBranch.IndexOf('appendHostLog(') -lt $exitBranch.IndexOf('reportStatus(SERVICE_STOPPED')) `
    'service host records an unrequested controller exit before reporting stopped'
Assert-True ($hostSource -match '(?s)StartServiceCtrlDispatcherW\(services\).*?WaitForSingleObject\(gServiceMainDone, 2000\)') `
    'service host lets the shutdown path finish its log line before the process exits'
$probeSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\native\dns-probe.cpp'))
Assert-True ($probeSource -match 'GetTickCount64\(\) - started >= 3000') `
    'system-mode probe starts no new attempt late enough to overrun its callers'' eight-second wait'

Write-Output 'PASS: controller health checks retry their probes and preserve failure evidence.'
