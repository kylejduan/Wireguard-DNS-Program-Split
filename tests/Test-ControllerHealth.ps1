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
Assert-True ($controllerSource -match '(?s)function Test-TunnelDns\(\[int\] \$TimeoutMilliseconds = 5000, \[int\] \$Attempts = 1\).*?\$TimeoutMilliseconds, \$Attempts.*?-TimeoutMilliseconds \(\$TimeoutMilliseconds \* \$Attempts \+ 3000\)') `
    'tunnel DNS probe wait covers every retransmission'
Assert-True ($controllerSource -match "(?s)function Test-LocalDns.*?'--system', 'example\.com', 3") `
    'startup local split-DNS probe retries a transient refusal'
Assert-True ($dispatcherSource -match "'--system', 'example\.com', 3") `
    'dispatcher validation retries a transient refusal'
Assert-True ($controllerSource -match 'Wait-ProgramSplitProbe -Probe \{ Test-TunnelDns -TimeoutMilliseconds 750 \}') `
    'startup gate keeps single-shot probes because its own loop already retries'
Assert-True ($controllerSource -match '(?s)Stack health check failed.*?Save-HealthFailureEvidence -Reason \$reason\s*Stop-Stack\s*Invoke-Repair') `
    'controller snapshots component logs before the restart that overwrites them'
Assert-True ($controllerSource -match '(?s)catch \{ Invoke-HealthFailure \$_ \}' -and
    $controllerSource -match '(?s)function Invoke-HealthFailure.*?\$stage -in @\(''Tunnel'', ''Transport''\) -and\s*\(-not \(Test-ProgramSplitPhysicalInputs.*?holding the stack.*?\} else \{.*?Stop-Stack') `
    'a transport or tunnel failure without physical uplink inputs holds the stack instead of stopping it'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?if \(-not \(Test-PhysicalResolverAnswers\)\).*?not answering; keeping the stack in place.*?return') `
    'a local split-DNS probe failure holds the stack when the physical resolver itself is silent'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?\$script:resolverHoldLogged = \$true.*?\}\s*return') `
    'the resolver hold logs once instead of on every retry'
Assert-True ($controllerSource -match '(?s)function Test-LocalDns.*?\$script:resolverHoldLogged = \$false\s*Write-ControllerLog ''Local split-DNS health probe passed') `
    'the resolver hold flag resets once the probe passes again'
Assert-True ($controllerSource -match '(?s)function Test-PhysicalResolverAnswers.*?Get-ProgramSplitPhysicalResolvers.*?if \(-not \$resolvers\.Count\) \{ return \$false \}') `
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
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-ProgramSplitPhysicalResolver', 'Get-ProgramSplitPhysicalResolvers')
}, $true))
Assert-True ($resolverFunction.Count -eq 2) 'Common defines the physical-resolver lookups once'
foreach ($function in $resolverFunction) { . ([scriptblock]::Create($function.Extent.Text)) }
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
$script:servers = @([pscustomobject]@{ ServerAddresses = @('192.168.1.1', '127.0.0.1', '1.1.1.1', '192.168.1.1', 'fe80::1', '8.8.8.8', '9.9.9.9') })
Assert-True ((@(Get-ProgramSplitPhysicalResolvers -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1') -join ',') -eq '192.168.1.1,1.1.1.1,8.8.8.8') `
    'the forwarding resolvers keep the interface order, unique IPv4 addresses only, at most three'
# With the interface already chosen, resolvers come from that one interface without selecting it again.
$script:defaultSelections = 0
$script:askedInterface = $null
function Get-ProgramSplitPhysicalDefault { param([string] $AdapterName) $script:defaultSelections++; if (-not $script:physicalRoute) { throw 'No physical IPv4 default gateway found.' } $script:physicalRoute }
function Get-DnsClientServerAddress { param($AddressFamily, $InterfaceIndex, $ErrorAction) $script:askedInterface = $InterfaceIndex; $script:servers }
$chosen = @(Get-ProgramSplitPhysicalResolvers -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1' -InterfaceIndex 7)
Assert-True ($chosen.Count -eq 3 -and $script:askedInterface -eq 7 -and $script:defaultSelections -eq 0) `
    'resolvers come from the interface the caller already chose, without selecting one again'
$null = Test-ProgramSplitPhysicalInputs -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1'
Assert-True ($script:defaultSelections -eq 1 -and $script:askedInterface -eq 15) 'the uplink check selects the physical interface once'
$script:physicalRoute = $null
Assert-True ($null -eq (Get-ProgramSplitPhysicalResolver -AdapterName 'WireGuardSplit' -TunnelDns '10.2.0.1')) `
    'a missing physical default route yields no forwarding resolver'
$script:physicalRoute = [pscustomobject]@{ InterfaceIndex = 15 }
$script:servers = @([pscustomobject]@{ ServerAddresses = @('192.168.1.1') })
# A dead primary with a live secondary is not a physical-resolver outage: the dispatcher fails over to it.
$answersFunction = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-PhysicalResolverAnswers'
}, $true))
Assert-True ($answersFunction.Count -eq 1) 'controller defines the physical-resolver check once'
. ([scriptblock]::Create($answersFunction[0].Extent.Text))
$configuration = [pscustomobject]@{ AdapterName = 'WireGuardSplit'; TunnelDns = '10.2.0.1' }
$root = 'C:\fixture'
$logs = 'C:\fixture\logs'
$script:asked = [Collections.Generic.List[string]]::new()
$script:liveResolvers = @('1.1.1.1')
function Invoke-ProgramSplitProcess { param($FilePath, $ArgumentList, $TimeoutMilliseconds, $OutputLog, $ErrorLog)
    $script:asked.Add($ArgumentList[0])
    if ($script:liveResolvers -contains $ArgumentList[0]) { [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Output = @('PASS: answered'); Error = @() } }
    else { [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Output = @(); Error = @('ERROR: No DNS response') } }
}
$script:servers = @([pscustomobject]@{ ServerAddresses = @('192.168.1.1', '1.1.1.1') })
Assert-True ((Test-PhysicalResolverAnswers) -and ($script:asked -join ',') -eq '192.168.1.1,1.1.1.1') `
    'a dead first resolver with a live second counts as answering'
$script:liveResolvers = @()
Assert-True (-not (Test-PhysicalResolverAnswers)) 'no answering resolver is a physical-resolver outage'
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

# Loop-path helpers against stubs: the per-pass active check, payload-filter lifecycle, tunnel-preserving
# reloads, pending cache restoration, health-failure categories and a restart that a service stop overtakes.
$loopFunctions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Test-OwnedNrptRulePresent', 'Get-StackState', 'Test-StackActive', 'Test-StackPresent',
            'Test-FilterHoldRequested', 'Stop-Stack', 'Stop-StackForDisable', 'Test-DnsCacheRestorePending',
            'Test-DispatcherIdentitiesCurrent',
            'Invoke-Repair', 'Invoke-RepairAttempt', 'Invoke-DispatcherValidation',
            'Test-StackHealth', 'Restart-Tunnel', 'Repair-Filters', 'Invoke-HealthFailure', 'Start-Stack')
}, $true))
Assert-True ($loopFunctions.Count -eq 17) 'controller defines each loop-path helper once'
foreach ($function in $loopFunctions) { . ([scriptblock]::Create($function.Extent.Text)) }
Assert-True (-not ($controllerSource -match 'DnsHold|KeepNrpt|dns-hold') -and
    -not ([IO.File]::ReadAllText($commonPath) -match 'DnsHold')) `
    'no DNS hold record or watchdog remains: the dispatcher supervisor alone bounds a dispatcher outage'
$realStartStack = ${function:Start-Stack}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("wgps-loop-{0}" -f [guid]::NewGuid())
try {
    $root = $temporary
    $state = Join-Path $temporary 'state'
    [IO.Directory]::CreateDirectory($state) | Out-Null
    $activeFile = Join-Path $state 'active'
    $filtersInstalledFile = Join-Path $state 'wfp-filters.installed'
    $keepFiltersFile = Join-Path $state 'keep-filters.request'
    $keepFiltersSeenFile = Join-Path $state 'keep-filters.seen.json'
    $script:keepFiltersSeen = $null
    $tunnelRetryFile = Join-Path $state 'tunnel-retry'
    $dispatcherSupervisedFile = Join-Path $state 'dns-dispatcher.supervised'
    $stackStoppedFile = Join-Path $state 'stack-stopped'
    $errorFile = Join-Path $state 'last-error.txt'
    $configuration = [pscustomobject]@{
        ServiceName = 'WireGuardTunnel$WireGuardSplit'; AdapterName = 'WireGuardSplit'; NrptDisplayName = 'owned'
        TunnelAddress = '192.0.2.2'; TunnelDns = '203.0.113.53'
    }
    $script:serviceStatus = 'Running'
    $script:serviceQueries = 0
    $script:nrptQueries = 0
    $script:nrptRules = @([pscustomobject]@{ Owned = $true })
    function Get-Service { param($Name, $ErrorAction) $script:serviceQueries++; [pscustomobject]@{ Status = $script:serviceStatus } }
    function Get-DnsClientNrptRule { param($ErrorAction) throw 'The per-pass check must not query NRPT through CIM.' }
    function Get-ProgramSplitLocalNrptRules { $script:nrptQueries++; $script:nrptRules }
    function Test-ProgramSplitNrptRuleOwnership { param($Rule, $DisplayName) [bool] $Rule.Owned }
    $script:dispatcherRunning = $true
    function Test-ManagedProcess([string] $pidName, [string] $expectedPath) { $script:dispatcherRunning }
    function Get-ExpectedProcesses([string] $processName, [string] $expectedPath) { @() }
    Assert-True (-not (Test-StackActive) -and $script:serviceQueries -eq 0 -and $script:nrptQueries -eq 0) `
        'an inactive stack is reported from state files without service or NRPT queries'
    [IO.File]::WriteAllText($activeFile, 'active')
    [IO.File]::WriteAllText((Join-Path $state 'dns-etw-session.txt'), 'session')
    [IO.File]::WriteAllText($dispatcherSupervisedFile, 'supervised')
    Assert-True ((Get-StackState) -eq 'Inactive' -and $script:serviceQueries -eq 0) `
        'a missing filter install marker needs the full repair, found without service or NRPT queries'
    [IO.File]::WriteAllText($filtersInstalledFile, 'installed')
    $script:serviceStatus = 'Stopped'
    Assert-True ((Get-StackState) -eq 'TunnelDown' -and $script:serviceQueries -eq 1) `
        'a stopped tunnel host under intact per-application components is reported as tunnel-only'
    $script:serviceStatus = 'Running'
    Assert-True ((Test-StackActive) -and $script:nrptQueries -eq 2) 'a complete stack is active'
    $script:dispatcherRunning = $false
    Assert-True (Test-StackActive) 'a dispatcher between supervised processes needs no stack repair'
    $script:dispatcherRunning = $true
    $script:nrptRules = @()
    Assert-True (-not (Test-StackActive)) 'a missing owned NRPT rule still fails the per-pass active check'
    $script:serviceStatus = 'Stopped'
    Assert-True ((Get-StackState) -eq 'Inactive') 'a stopped tunnel without the owned NRPT rule needs the full repair'

    # Presence for disable and service-stop cleanup: the filters count until they are removed, unless a
    # profile import holds them.
    Remove-Item -LiteralPath $activeFile, (Join-Path $state 'dns-etw-session.txt'), $dispatcherSupervisedFile
    Assert-True (Test-StackPresent) 'installed persistent filters keep the stack present for disable cleanup'
    [IO.File]::WriteAllText($dispatcherSupervisedFile, 'supervised')
    Assert-True (-not (Test-StackPresent -Import)) 'a profile import counts only the tunnel, keeping the filters and DNS'
    Remove-Item -LiteralPath $dispatcherSupervisedFile
    Assert-True (-not (Test-FilterHoldRequested)) 'no hold is requested without the tray''s request file'
    # The hold runs five minutes on the monotonic clock from its first sighting; wall-clock steps (here the
    # request file's time moved by hours either way) change nothing.
    $script:monotonic = 1000.0
    function Get-ControllerElapsed { [TimeSpan]::FromSeconds($script:monotonic) }
    [IO.File]::WriteAllText($keepFiltersFile, 'import 1')
    [IO.File]::SetLastWriteTimeUtc($keepFiltersFile, [DateTime]::UtcNow.AddHours(-3))
    Assert-True (Test-FilterHoldRequested) 'a fresh profile-import request holds the filters even if its file time is hours old'
    $script:monotonic += 240
    Assert-True (Test-FilterHoldRequested) 'the hold lasts five monotonic minutes'
    [IO.File]::SetLastWriteTimeUtc($keepFiltersFile, [DateTime]::UtcNow.AddHours(3))
    $script:monotonic += 61
    Assert-True (-not (Test-FilterHoldRequested)) 'an abandoned profile-import request expires after five monotonic minutes, whatever the file time says'
    # A restarted controller keeps the first sighting from state.
    $script:keepFiltersSeen = $null
    Assert-True (-not (Test-FilterHoldRequested)) 'a restarted controller does not restart an expired hold'
    [IO.File]::WriteAllText($keepFiltersFile, 'import 2')
    Assert-True (Test-FilterHoldRequested) 'a new import request starts a new hold'
    Remove-Item -LiteralPath $keepFiltersFile
    Assert-True (-not (Test-FilterHoldRequested) -and -not (Test-Path -LiteralPath $keepFiltersSeenFile)) 'a withdrawn request ends the hold and its record'
    Remove-Item -LiteralPath $filtersInstalledFile
    Assert-True (-not (Test-StackPresent)) 'a stopped tunnel, no rule and no filters leave nothing present'
    $script:serviceStatus = 'Running'

    $script:components = [Collections.Generic.List[string]]::new()
    $script:failCache = $true
    $script:failFilterRemoval = $false
    function Stop-ValidationWorker { }
    $logs = Join-Path $temporary 'logs'
    function Get-ControllerElapsed { [TimeSpan]::FromMinutes(1) }
    function Invoke-Component([string] $name, [string] $action, [string[]] $switches = @()) {
        $script:components.Add((@($name, $action) + $switches) -join ' ')
        if ($name -eq 'Invoke-DnsCachePolicy.ps1' -and $script:failCache) { throw 'Mock cache restore failure' }
        if ($name -eq 'Invoke-WfpFilters.ps1' -and $action -eq 'Stop' -and $script:failFilterRemoval) { throw 'Mock removal failure' }
    }
    Stop-Stack -KeepTunnel
    Assert-True ($script:components.Count -eq 0) `
        'a reload stops nothing: the tunnel, filters, NRPT rule and dispatcher stay, and the dispatcher reloads in place'
    Stop-Stack
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Stop') `
        'a repair stops only the tunnel, keeping the filters, the NRPT rule and the supervised dispatcher'
    $script:components.Clear()
    $script:failCache = $false
    Stop-Stack -RestoreCache -ThrowOnFailure -RemoveFilters -StopDns
    $nrptDisable = $script:components.IndexOf('Invoke-LocalNrpt.ps1 Disable')
    Assert-True ($script:components[0] -eq 'Invoke-WfpFilters.ps1 Stop' -and $nrptDisable -gt 0 -and
        $script:components.IndexOf('Invoke-DnsDispatcher.ps1 Stop') -gt $nrptDisable) `
        'an explicit stop removes the payload filters, then the NRPT rule before the dispatcher it names'
    $script:components.Clear()
    $script:failFilterRemoval = $true
    $threw = $false
    try { Stop-Stack -RestoreCache -ThrowOnFailure -RemoveFilters -StopDns } catch { $threw = $true }
    Assert-True ($threw -and $script:components -contains 'Invoke-LocalNrpt.ps1 Disable' -and
        $script:components -contains 'Invoke-DnsDispatcher.ps1 Stop') `
        'a failed filter removal is retried, and unlisted DNS is still restored with the dispatcher stopped'
    $script:failFilterRemoval = $false
    $script:failCache = $true
    $script:cacheRestorePending = $false
    $threw = $false
    try { Stop-Stack -RestoreCache -ThrowOnFailure } catch { $threw = $true }
    Assert-True ($threw -and $script:cacheRestorePending) 'a failed cache restoration stays pending after networking stops'
    $script:failCache = $false
    Stop-Stack -RestoreCache -ThrowOnFailure
    Assert-True (-not $script:cacheRestorePending) 'a completed cache restoration clears the pending state'
    # A profile import stops only the tunnel: the dispatcher, NRPT rule, cache policy and filters stay,
    # and the dispatcher takes the new tunnel settings in place when the stack starts again.
    $script:components.Clear()
    Stop-StackForDisable -Import
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Stop') 'a profile import stops only the tunnel'
    $script:components.Clear()
    Stop-StackForDisable
    Assert-True ($script:components[0] -eq 'Invoke-WfpFilters.ps1 Stop' -and $script:components -contains 'Invoke-LocalNrpt.ps1 Disable' -and
        $script:components -contains 'Invoke-DnsDispatcher.ps1 Stop' -and $script:components -contains 'Invoke-DnsCachePolicy.ps1 Disable') `
        'a disable stops everything and restores the cache policy'
    # Restoration stays pending while any setting differs from its saved original, including after a
    # partial restore and a controller restart.
    $policyKey = 'HKCU:\Software\WireGuardProgramSplitTest-' + [guid]::NewGuid().ToString('N')
    $policyRecord = Join-Path $state 'policy-original.json'
    New-Item -Path $policyKey -Force | Out-Null
    try {
        [IO.File]::WriteAllText($policyRecord, (@(
            [pscustomobject]@{ Name = 'MaxCacheTtl'; Exists = $true; Value = 86400 },
            [pscustomobject]@{ Name = 'MaxNegativeCacheTtl'; Exists = $false; Value = 0 }) | ConvertTo-Json))
        New-ItemProperty -Path $policyKey -Name MaxCacheTtl -PropertyType DWord -Value 1 | Out-Null
        New-ItemProperty -Path $policyKey -Name MaxNegativeCacheTtl -PropertyType DWord -Value 0 | Out-Null
        Assert-True (Test-DnsCacheRestorePending -RecordPath $policyRecord -KeyPath $policyKey) 'an applied policy is pending restoration'
        Set-ItemProperty -Path $policyKey -Name MaxCacheTtl -Value 86400
        Assert-True (Test-DnsCacheRestorePending -RecordPath $policyRecord -KeyPath $policyKey) 'a partial restoration stays pending'
        Remove-ItemProperty -Path $policyKey -Name MaxNegativeCacheTtl
        Assert-True (-not (Test-DnsCacheRestorePending -RecordPath $policyRecord -KeyPath $policyKey)) 'a complete restoration is not pending'
        Assert-True (-not (Test-DnsCacheRestorePending -RecordPath (Join-Path $state 'absent.json') -KeyPath $policyKey)) `
            'without a record nothing is pending'
        [IO.File]::WriteAllText($policyRecord, 'not json')
        Assert-True (Test-DnsCacheRestorePending -RecordPath $policyRecord -KeyPath $policyKey) 'an unreadable record counts as pending'
    } finally { Remove-Item -Path $policyKey -Recurse -Force -ErrorAction SilentlyContinue }

    $script:starts = 0
    function Start-Stack { $script:starts++ }
    function Get-ControllerElapsed { [TimeSpan]::FromMinutes(1) }
    function Get-ProgramSplitPhysicalDefault { param($AdapterName) [pscustomobject]@{ InterfaceIndex = 15 } }
    $script:nextRepair = [TimeSpan]::Zero
    $script:repairDelaySeconds = 2
    $script:networkWaitLogged = $false
    $stopEvent = [Threading.ManualResetEvent]::new($true)
    try {
        Invoke-Repair
        Assert-True ($script:starts -eq 0) 'a pending service stop skips the stack rebuild'
        $null = $stopEvent.Reset()
        Invoke-Repair
        Assert-True ($script:starts -eq 1) 'repair rebuilds the stack when no stop is pending'
    } finally { $stopEvent.Dispose() }
    $stopEvent = $null
    # A dispatcher that died is the supervisor's: a repair, even one deferred by its backoff, never
    # removes the rule or stops the dispatcher.
    $script:nrptRules = @([pscustomobject]@{ Owned = $true })
    $script:components.Clear()
    $script:dispatcherRunning = $false
    $script:nextRepair = [TimeSpan]::FromMinutes(5)
    Invoke-Repair
    Assert-True ($script:components.Count -eq 0) 'a deferred repair leaves a dead dispatcher to the supervisor'
    $script:dispatcherRunning = $true
    $script:nextRepair = [TimeSpan]::Zero
    $script:nrptRules = @()
    # Health recovery: a filter mismatch is reinstalled in place, a VPN-side failure restarts only the
    # tunnel, an uplink outage holds, and every other failure restarts the stack. None removes the filters.
    $script:evidence = 0
    $script:tunnelDnsFails = $true
    $script:settingsUnchanged = $true
    $script:uplinkPresent = $true
    $script:tunnelOutageLogged = $false
    $script:physicalHoldLogged = $false
    $script:validationFailures = @{}
    $script:validations = [Collections.Generic.List[string]]::new()
    function Save-HealthFailureEvidence([string] $Reason) { $script:evidence++ }
    function Test-ProgramSplitPhysicalInputs { param($AdapterName, $TunnelDns) $script:uplinkPresent }
    function Test-PhysicalResolverAnswers { $true }
    function Test-TunnelSettingsUnchanged { $script:settingsUnchanged }
    function Test-PiaDriverReady { $true }
    $script:identitiesCurrent = $true
    function Test-DispatcherIdentitiesCurrent { $script:identitiesCurrent }
    function Wait-ProgramSplitProbe { param($Probe, $TimeoutMilliseconds, $RetryMilliseconds, $StopEvent)
        if ($script:tunnelDnsFails) { throw 'Tunnel DNS health probe failed: no answer' }
    }
    $script:validationFailOnce = @{}
    function Invoke-Validation([string] $Name) {
        $script:validations.Add($Name)
        if ($script:validationFailures.ContainsKey($Name)) { throw $script:validationFailures[$Name] }
        if ($script:validationFailOnce.ContainsKey($Name)) {
            $message = $script:validationFailOnce[$Name]
            $script:validationFailOnce.Remove($Name)
            throw $message
        }
    }
    function Test-TunnelDns { param($TimeoutMilliseconds, $Attempts) throw 'Tunnel DNS health probe failed: no answer' }
    function Get-HealthFailure {
        $failure = $null
        try { Test-StackHealth } catch { $failure = $_ }
        Assert-True ($null -ne $failure) 'the stubbed health check fails'
        $failure
    }
    function Reset-Recovery {
        $script:components.Clear(); $script:starts = 0; $controllerLog.Clear(); $script:validations.Clear()
        $script:nextRepair = [TimeSpan]::Zero; $script:repairDelaySeconds = 2
    }

    $failure = Get-HealthFailure
    Assert-True ($failure.Exception.Data['ProgramSplitStage'] -eq 'Tunnel' -and
        $script:validations[0] -eq 'Invoke-WfpFilters.ps1') `
        'health verifies the filters first and marks a tunnel DNS failure after NRPT and dispatcher validation VPN-side'
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Stop,Invoke-Tunnel.ps1 Start' -and
        $script:starts -eq 0 -and $script:evidence -eq 1 -and $script:nextRepair -gt [TimeSpan]::FromMinutes(1)) `
        'a tunnel-side failure keeps the filters, NRPT rule and dispatcher and restarts only the tunnel with backoff'
    Invoke-HealthFailure $failure
    Assert-True ($script:components.Count -eq 2 -and $script:evidence -eq 1 -and
        @($controllerLog | Where-Object { $_ -match 'restarting only the tunnel' }).Count -eq 1) `
        'a continuing outage waits out the backoff and logs and snapshots once'
    $script:tunnelDnsFails = $false
    $script:nextRepair = [TimeSpan]::Zero
    Invoke-HealthFailure $failure
    Assert-True ($script:components.Count -eq 4 -and -not $script:tunnelOutageLogged -and $script:repairDelaySeconds -eq 2) `
        'a tunnel restart that answers again ends the outage and resets the backoff'
    $script:settingsUnchanged = $false
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True ($script:components -contains 'Invoke-Tunnel.ps1 Stop' -and $script:starts -eq 1 -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop') `
        'changed tunnel settings fall back to the full restart, which keeps the filters for Start-Stack to replace'
    $script:settingsUnchanged = $true

    # A filter mismatch is repaired in place, even while the uplink is down.
    $script:validationFailures['Invoke-WfpFilters.ps1'] = 'Persistent WFP payload filters failed verification'
    $failure = Get-HealthFailure
    Assert-True ($failure.Exception.Data['ProgramSplitStage'] -eq 'Filters') 'a filter verification failure is marked for in-place repair'
    $script:validationFailures.Clear()
    $script:uplinkPresent = $false
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True (($script:components -join ',') -eq 'Invoke-WfpFilters.ps1 Start' -and $script:starts -eq 0 -and
        @($script:validations | Where-Object { $_ -eq 'Invoke-WfpFilters.ps1' }).Count -eq 1 -and
        -not $script:physicalHoldLogged) `
        'a filter mismatch reinstalls the filters alone and is never held for the uplink'
    $script:validationFailures['Invoke-WfpFilters.ps1'] = 'PIA driver has not registered its callouts'
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True ($script:components[0] -eq 'Invoke-WfpFilters.ps1 Start' -and $script:starts -eq 1 -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop') `
        'a filter reinstall that does not verify falls back to the full restart without removing the filters'
    $script:validationFailures.Clear()
    # A reinstall that resolved an identity differently has the running dispatcher load the new record.
    $script:identitiesCurrent = $false
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True (($script:components -join ',') -eq 'Invoke-WfpFilters.ps1 Start,Invoke-DnsDispatcher.ps1 Start' -and
        $script:starts -eq 0) `
        'changed resolved identities are reloaded by the running dispatcher, with nothing stopped'
    $script:identitiesCurrent = $true

    # Only failures an uplink outage can cause are held for it (Codex #4).
    $script:validationFailures['Invoke-LocalNrpt.ps1'] = 'The owned local split-DNS NRPT rule is missing or duplicated.'
    $failure = Get-HealthFailure
    Assert-True (-not $failure.Exception.Data['ProgramSplitStage']) 'an NRPT invariant failure is not a transport failure'
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True ($script:starts -eq 1 -and -not $script:physicalHoldLogged -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop') `
        'an NRPT invariant failure is repaired, not held, while the uplink is down'
    $script:validationFailures.Clear()
    # A dispatcher killed during the check: its supervised successor is validated instead of repairing.
    $script:validationFailOnce['Invoke-DnsDispatcher.ps1'] = 'Invoke-DnsDispatcher.ps1 Validate failed: The managed DNS dispatcher process is unavailable.'
    $script:validations.Clear()
    $failure = Get-HealthFailure
    Assert-True ($failure.Exception.Data['ProgramSplitStage'] -eq 'Tunnel' -and
        @($script:validations | Where-Object { $_ -eq 'Invoke-DnsDispatcher.ps1' }).Count -eq 2) `
        'a dispatcher replaced during a health check passes once its successor is ready'
    $script:validationFailures['Invoke-DnsDispatcher.ps1'] = 'Invoke-DnsDispatcher.ps1 Validate failed: The managed DNS dispatcher process is unavailable.'
    $failure = Get-HealthFailure
    Assert-True (-not $failure.Exception.Data['ProgramSplitStage']) 'a dispatcher ownership failure is not a transport failure'
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True ($script:starts -eq 1 -and -not $script:physicalHoldLogged) 'a dispatcher ownership failure is repaired while the uplink is down'
    foreach ($message in @('The active physical route, source address, or DNS resolver changed.',
            'Local split-DNS health probe failed: SERVFAIL')) {
        $script:validationFailures['Invoke-DnsDispatcher.ps1'] = "Invoke-DnsDispatcher.ps1 Validate failed: $message"
        $failure = Get-HealthFailure
        Assert-True ($failure.Exception.Data['ProgramSplitStage'] -eq 'Transport') "an uplink-dependent dispatcher check is a transport failure: $message"
        Reset-Recovery
        $script:physicalHoldLogged = $false
        Invoke-HealthFailure $failure
        Assert-True ($script:starts -eq 0 -and $script:components.Count -eq 0 -and $script:physicalHoldLogged) `
            "a transport failure during an uplink outage holds the stack: $message"
    }
    $script:uplinkPresent = $true
    Reset-Recovery
    Invoke-HealthFailure $failure
    Assert-True ($script:starts -eq 1 -and $script:components -contains 'Invoke-Tunnel.ps1 Stop' -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop' -and
        $script:components -notcontains 'Invoke-LocalNrpt.ps1 Disable' -and
        $script:components -notcontains 'Invoke-DnsDispatcher.ps1 Stop') `
        'a transport failure with the uplink present restarts the stack and keeps the filters, NRPT rule and dispatcher'
    Reset-Recovery
    Restart-Tunnel -Reason 'The tunnel service is not running.'
    Assert-True ($script:components -notcontains 'Invoke-Tunnel.ps1 Start' -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop' -and $script:starts -eq 1) `
        'a stopped tunnel with stale dispatcher inputs gets the full restart instead of a tunnel-only start'
    $script:validationFailures.Clear()

    # A reload, which Tray.ps1 requests after an included-app change, is one transactional replacement.
    Set-Item -Path function:Start-Stack -Value $realStartStack
    function Get-ProgramSplitConfiguration { param($Root) $configuration }
    function Test-DnsCachePolicyReady { $true }
    function Test-LocalDns { }
    function Get-CimInstance { [pscustomobject]@{ LastBootUpTime = (Get-Date).AddDays(-1) } }
    # Component processes: launches are recorded, and the dispatcher's input load can be made to fail.
    $script:dispatcherReady = $true
    function Start-Component([string] $name, [string] $action, [string[]] $switches = @()) {
        $script:components.Add("launch $name $action")
        [pscustomobject]@{ Name = $name; Action = $action }
    }
    function Complete-Component($component) {
        Invoke-Component $component.Name $component.Action
        if ($component.Name -eq 'Invoke-DnsDispatcher.ps1' -and -not $script:dispatcherReady) {
            throw 'The DNS dispatcher did not load the current inputs.'
        }
    }
    $script:clock = [TimeSpan]::FromMinutes(10)
    function Get-ControllerElapsed { $script:clock }
    # A reload replaces the filters once and the dispatcher's inputs in place; nothing is stopped.
    $script:nrptRules = @([pscustomobject]@{ Owned = $true })
    Reset-Recovery
    Stop-Stack -KeepTunnel
    Invoke-Repair
    $filterActions = @($script:components | Where-Object { $_ -like 'Invoke-WfpFilters.ps1 *' })
    $filterInstalled = $script:components.IndexOf('Invoke-WfpFilters.ps1 Start')
    $dispatcherLaunch = $script:components.IndexOf('launch Invoke-DnsDispatcher.ps1 Start')
    Assert-True ($script:starts -eq 0 -and ($filterActions -join ',') -eq 'Invoke-WfpFilters.ps1 Start,Invoke-WfpFilters.ps1 Validate' -and
        $filterInstalled -ge 0 -and $dispatcherLaunch -gt $filterInstalled -and
        -not @($script:components | Where-Object { $_ -match ' Stop$|Invoke-LocalNrpt\.ps1 Disable' }).Count -and
        (Test-Path -LiteralPath $activeFile)) `
        'a reload replaces the filters, then has the running dispatcher load the identities they wrote, stopping nothing'
    # A dispatcher that cannot load the inputs fails the start; the rule stays for the supervisor to manage.
    $script:dispatcherReady = $false
    Reset-Recovery
    Stop-Stack
    Invoke-Repair
    Assert-True ($script:components -notcontains 'Invoke-LocalNrpt.ps1 Disable' -and
        $script:components -notcontains 'Invoke-DnsDispatcher.ps1 Stop' -and
        $script:components -notcontains 'Invoke-WfpFilters.ps1 Stop' -and
        $script:components -notcontains 'Invoke-LocalNrpt.ps1 Enable' -and
        -not (Test-Path -LiteralPath $activeFile) -and $script:nextRepair -gt $script:clock) `
        'a dispatcher that does not load the inputs fails the start and backs off without touching the NRPT rule'
    $script:dispatcherReady = $true

    # A reload during a provider outage: the dispatcher comes back but tunnel DNS does not answer. The
    # dispatcher, NRPT rule and filters stay, and the tunnel-only restart takes over.
    $script:tunnelDnsFails = $true
    Reset-Recovery
    Stop-Stack -KeepTunnel
    Invoke-Repair
    Assert-True ($script:components -notcontains 'Invoke-LocalNrpt.ps1 Disable' -and
        $script:components -notcontains 'Invoke-DnsDispatcher.ps1 Stop' -and
        $script:components -contains 'Invoke-LocalNrpt.ps1 Enable' -and
        (Test-Path -LiteralPath $tunnelRetryFile) -and -not (Test-Path -LiteralPath $activeFile) -and
        $script:nextRepair -gt $script:clock) `
        'a tunnel that does not answer at startup keeps the dispatcher, NRPT rule and filters and backs off'
    $script:serviceStatus = 'Running'
    [IO.File]::WriteAllText((Join-Path $state 'dns-etw-session.txt'), 'session')
    [IO.File]::WriteAllText($filtersInstalledFile, 'installed')
    [IO.File]::WriteAllText($dispatcherSupervisedFile, 'supervised')
    Assert-True ((Get-StackState) -eq 'TunnelDown') 'the stack waiting for its tunnel is handed to the tunnel-only restart'
    $script:tunnelDnsFails = $false
    $script:nextRepair = [TimeSpan]::Zero
    $script:components.Clear()
    Restart-Tunnel -Reason 'Tunnel DNS did not answer when the stack started.' -StopFirst
    Assert-True (($script:components -join ',') -eq 'Invoke-Tunnel.ps1 Stop,Invoke-Tunnel.ps1 Start' -and
        (Test-Path -LiteralPath $activeFile) -and -not (Test-Path -LiteralPath $tunnelRetryFile) -and
        (Get-StackState) -eq 'Active') `
        'once the tunnel answers, the tunnel-only restart reports the stack active without touching DNS'
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

Write-Output 'PASS: controller health checks retry their probes, preserve failure evidence, and keep loop checks cheap.'
