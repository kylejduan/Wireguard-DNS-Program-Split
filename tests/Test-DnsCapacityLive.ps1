# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only. This fixture owns loopback port 53 and a unique NRPT namespace.
param(
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [Parameter(Mandatory)] [string] $Dispatcher,
    [switch] $ExpectStarvation,
    [switch] $ImageStalls
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -and $env:WGPS_DISPOSABLE_HOST -ne '1') {
    throw 'DNS capacity testing requires an explicitly disposable Windows host.'
}
if (Get-Service WireGuardProgramSplitController -ErrorAction SilentlyContinue) {
    throw 'Never run the DNS capacity fixture on an installed host.'
}
$addresses = @('0.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3')
if (@(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object LocalAddress -in $addresses).Count -or
    @(Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object LocalAddress -in $addresses).Count) {
    throw 'DNS capacity fixture requires unused loopback DNS ports.'
}
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $RepositoryRoot "local\test-temp\capacity-$id"
$zone = "capacity-$id.invalid"
$trace = "WireGuardProgramSplitDnsEtw-$id"
$children = [Collections.Generic.List[object]]::new()
$rule = $null
function Read-Text([string] $Name) {
    $path = Join-Path $root $Name
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try { [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
}
function Launch([string] $Exe, [string[]] $Arguments, [string] $Label) {
    $process = Start-Process -FilePath $Exe -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $root "$Label.out") -RedirectStandardError (Join-Path $root "$Label.err")
    $null = $process.Handle
    $children.Add($process)
    return $process
}
function Wait-Ready($Process, [string] $Label) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 15) {
        if ($Process.HasExited) { throw "$Label exited: $(Read-Text "$Label.err")" }
        if ((Read-Text "$Label.out") -match 'READY') { return }
        Start-Sleep -Milliseconds 50
    }
    throw "$Label did not become ready."
}
function Wait-Client($Process, [string] $Label) {
    if (-not $Process.WaitForExit(60000)) { throw "$Label exceeded its deadline." }
    if ($Process.ExitCode -ne 0) { throw "$Label failed: $(Read-Text "$Label.err")" }
}
function Test-ImageStalls([string] $DirectExe, [string[]] $StalledApps) {
    # The direct process warms its own identity before the stalled executables
    # start. Four stuck identities may refuse new misses; cached identities must
    # still progress and ordering sentinels must not sit behind repeated waits.
    $ordinary = Launch $DirectExe @('direct', $zone, '20', '12', '--warm') 'image-direct'
    $ready = [Diagnostics.Stopwatch]::StartNew()
    while ((Read-Text 'image-direct.err') -notmatch 'READY pid=') {
        if ($ordinary.HasExited -or $ready.Elapsed.TotalSeconds -gt 10) { throw 'Normal DNS process did not warm before image stalls.' }
        Start-Sleep -Milliseconds 25
    }
    $stalled = @()
    for ($i = 0; $i -lt $StalledApps.Count; ++$i) {
        $label = "stalled-$i"
        $stalled += [pscustomobject]@{ Label = $label; Process = (Launch $StalledApps[$i] @($label, $zone, '1', '1') $label) }
    }
    foreach ($client in $stalled) {
        Wait-Client $client.Process $client.Label
        if ((Read-Text "$($client.Label).out" | ConvertFrom-Json).directAnswers) { throw 'A stalled selected process received direct DNS.' }
    }
    Wait-Client $ordinary 'image-direct'
    $result = Read-Text 'image-direct.out' | ConvertFrom-Json
    if ($result.successes -lt $result.started * 0.99 -or $result.p99_ms -gt 1000) {
        throw 'Image stalls disrupted ordinary cached-process DNS.'
    }
    $drain = [Diagnostics.Stopwatch]::StartNew()
    do {
        $log = Read-Text 'dispatcher.log'
        $decisions = [regex]::Matches($log, '(?m)^DNS direct-[^\r\n]* -> DIRECT').Count
        $received = [regex]::Matches((Read-Text 'resolver.out'), '(?m)^DIRECT direct-').Count
        if ($decisions -ge $result.successes -and $received -ge $result.successes) { break }
        Start-Sleep -Milliseconds 25
    } while ($drain.Elapsed.TotalSeconds -lt 3)
    if ($decisions -lt $result.successes -or $received -lt $result.successes) { throw 'Image-stall positive evidence did not drain.' }
    if ($log -notmatch '(?m)^HINT stalled-[^\r\n]*identity=pending') { throw 'The image-resolution fault was not exercised.' }
    if ($log -match '(?m)^LOG QUEUE DROPPED|^BARRIER INCOMPLETE' -or
        $log -match ("(?m)^HINT [^\r\n]*pid=$($ordinary.Id)\s[^\r\n]*identity=(pending|none)")) {
        throw 'A stalled image blocked attribution, lost evidence, or affected the warmed process identity.'
    }
    if ((Read-Text 'resolver.out') -match '(?m)^DIRECT stalled-') { throw 'A stalled selected name reached the direct resolver.' }
    Write-Output ("OBSERVED: 20 stalled selected image lookups; normal DNS=$($result|ConvertTo-Json -Compress); " +
        'no ordering-barrier failure, no direct resolver received a stalled selected name.')
    Write-Output 'PASS: real DNS/ETW image-stall isolation.'
}
try {
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $selected = Join-Path $root 'selected.exe'
    $direct = Join-Path $root 'direct.exe'
    Copy-Item (Join-Path $RepositoryRoot 'build\test-dns-load.exe') $selected
    Copy-Item (Join-Path $RepositoryRoot 'build\test-dns-load.exe') $direct
    $probe = Join-Path $root 'selected-probe.exe'
    Copy-Item (Join-Path $RepositoryRoot 'build\test-net-probe.exe') $probe
    $includes = Join-Path $root 'included.txt'
    $stalledApps = @()
    if ($ImageStalls) {
        foreach ($i in 0..19) {
            $path = Join-Path $root "stall-$i.exe"
            Copy-Item (Join-Path $RepositoryRoot 'build\test-dns-load.exe') $path
            $stalledApps += $path
        }
    }
    [IO.File]::WriteAllLines($includes, @($selected, $probe) + $stalledApps, [Text.UTF8Encoding]::new($false))
    $resolverArguments = @('--fixture', '180')
    if (-not $ImageStalls) { $resolverArguments += '--tunnel-outage' }
    $resolver = Launch (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') $resolverArguments 'resolver'
    Wait-Ready $resolver 'resolver'
    $server = Launch $Dispatcher @(
        ('"{0}"' -f $includes), '127.0.0.2', '127.0.0.2', '127.0.0.3', '127.0.0.3', $trace,
        ('"{0}"' -f (Join-Path $root 'dispatcher.log'))
    ) 'dispatcher'
    Wait-Ready $server 'dispatcher'
    $rule = Add-DnsClientNrptRule -Namespace ".$zone" -NameServers '127.0.0.1' -DisplayName "WgpsCapacity-$id" -PassThru
    if ($ImageStalls) { Test-ImageStalls $direct $stalledApps; return }
    $warm = Launch $direct @('warm', $zone, '5', '1') 'warm'
    Wait-Client $warm 'warm'
    $warmResults = Read-Text 'warm.out' | ConvertFrom-Json
    if ($warmResults.directAnswers -ne 5) { throw 'Direct fixture DNS failed before load.' }
    $server.Refresh()
    $before = [pscustomobject]@{ PrivateMiB = $server.PrivateMemorySize64 / 1MB; Threads = $server.Threads.Count }
    $cpuBefore = $server.TotalProcessorTime.TotalSeconds
    $sample = [Diagnostics.Stopwatch]::StartNew()
    $flood = Launch $selected @('selected', $zone, '100', '12') 'selected'
    $ordinary = Launch $direct @('direct', $zone, '20', '12') 'direct'
    Wait-Client $flood 'selected'
    Wait-Client $ordinary 'direct'
    $sample.Stop()
    $server.Refresh()
    $cpuOneCorePercent = 100 * ($server.TotalProcessorTime.TotalSeconds - $cpuBefore) / $sample.Elapsed.TotalSeconds
    $after = [pscustomobject]@{ PrivateMiB = $server.PrivateMemorySize64 / 1MB; Threads = $server.Threads.Count }
    $selectedResults = Read-Text 'selected.out' | ConvertFrom-Json
    $directResults = Read-Text 'direct.out' | ConvertFrom-Json
    if ($selectedResults.started / $selectedResults.launch_seconds -lt 80) {
        throw 'The offered selected load was too slow to test capacity isolation.'
    }
    if ($selectedResults.directAnswers) { throw 'A selected query was answered by the direct resolver.' }
    $protected = $directResults.successes -ge $directResults.started * 0.99 -and $directResults.p99_ms -le 1000
    if ($ExpectStarvation -and $protected) { throw 'Pre-fix baseline did not expose the intended starvation regression.' }
    if (-not $ExpectStarvation -and -not $protected) { throw 'Direct DNS was disrupted by the selected tunnel outage.' }
    $logTimer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $log = Read-Text 'dispatcher.log'
        $resolverLog = Read-Text 'resolver.out'
        $decisions = [regex]::Matches($log, '(?m)^DNS direct-[^\r\n]* -> DIRECT').Count
        $received = [regex]::Matches($resolverLog, '(?m)^DIRECT direct-').Count
        if ($decisions -ge $directResults.successes -and $received -ge $directResults.successes) { break }
        Start-Sleep -Milliseconds 50
    } while ($logTimer.Elapsed.TotalSeconds -lt 3)
    if ($decisions -lt $directResults.successes -or $received -lt $directResults.successes) {
        throw 'The fixture did not drain its positive query evidence.'
    }
    if (-not $ExpectStarvation -and $log -notmatch '\(tunnel lane full\)') {
        throw 'No tunnel-capacity refusal was observed; the test did not exercise the limit.'
    }
    if (-not $ExpectStarvation -and $log -match '(?m)^WORKERS EXHAUSTED') {
        throw 'Selected upstream requests exhausted global worker admission despite the lane cap.'
    }
    if (-not $ExpectStarvation -and $log -match '(?m)^LOG QUEUE DROPPED') {
        throw 'Capacity fixture diagnostic evidence was dropped.'
    }
    if ($log -match '(?m)^DNS selected-[^\r\n]* -> DIRECT') { throw 'Selected attribution crossed to the direct lane.' }
    # Let the remaining four-second upstream exchanges finish, then resume the
    # same tunnel resolver. The dispatcher and its attribution stay in place.
    Start-Sleep -Seconds 5
    $recovery = Launch $probe @('system-dns', "resume.$zone") 'recovery'
    Wait-Client $recovery 'recovery'
    if ((Read-Text 'recovery.out') -notmatch 'ANSWER 192\.0\.2\.1') { throw 'Tunnel DNS did not recover.' }
    $recovered = Launch $selected @('recovered', $zone, '50', '2') 'recovered'
    Wait-Client $recovered 'recovered'
    $healthy = Read-Text 'recovered.out' | ConvertFrom-Json
    if ($healthy.tunnelAnswers -lt $healthy.started * 0.99 -or $healthy.directAnswers) {
        throw 'Healthy selected DNS did not sustain load after recovery.'
    }
    if ((Read-Text 'resolver.out') -match '(?m)^DIRECT (selected-|recovered-)') {
        throw 'A selected query reached the direct resolver, even if its answer was withheld.'
    }
    Write-Output ("OBSERVED: baseline=$ExpectStarvation selected=$($selectedResults|ConvertTo-Json -Compress) " +
        "direct=$($directResults|ConvertTo-Json -Compress); selected never reached direct, tunnel recovered under the same dispatcher.")
    Write-Output ("OBSERVED: dispatcher-only outage-load sample before=$($before|ConvertTo-Json -Compress) " +
        "after=$($after|ConvertTo-Json -Compress) one-core-percent=$cpuOneCorePercent seconds=$($sample.Elapsed.TotalSeconds); " +
        'excludes external processes and system-wide driver/DPC/interrupt work.')
    Write-Output 'PASS: tunnel outage capacity regression and resolver recovery.'
} catch {
    foreach ($file in Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue) {
        if ($file.Extension -in '.out', '.err', '.log') { Get-Content -LiteralPath $file.FullName -Tail 12 }
    }
    throw
} finally {
    $failures = [Collections.Generic.List[string]]::new()
    try { if ($rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force } } catch { $failures.Add([string]$_) }
    foreach ($child in $children) {
        try {
            if (-not $child.HasExited) { $child.Kill() }
            if (-not $child.WaitForExit(10000)) { throw 'A fixture child failed to stop.' }
        } catch { $failures.Add([string]$_) } finally { $child.Dispose() }
    }
    try { & logman.exe stop $trace -ets 2>$null | Out-Null } catch { $failures.Add([string]$_) }
    if ($failures.Count) { throw "Capacity fixture cleanup failed: $($failures -join ' | ')" }
}
