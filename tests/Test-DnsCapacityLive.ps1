# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only. This fixture owns loopback port 53 and a unique NRPT namespace.
param(
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [Parameter(Mandatory)] [string] $Dispatcher,
    [switch] $ExpectStarvation
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
try {
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $selected = Join-Path $root 'selected.exe'
    $direct = Join-Path $root 'direct.exe'
    Copy-Item (Join-Path $RepositoryRoot 'build\test-dns-load.exe') $selected
    Copy-Item (Join-Path $RepositoryRoot 'build\test-dns-load.exe') $direct
    $probe = Join-Path $root 'selected-probe.exe'
    Copy-Item (Join-Path $RepositoryRoot 'build\test-net-probe.exe') $probe
    $includes = Join-Path $root 'included.txt'
    [IO.File]::WriteAllText($includes, "$selected`r`n$probe`r`n", [Text.UTF8Encoding]::new($false))
    $resolver = Launch (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') @('--fixture', '180', '--tunnel-outage') 'resolver'
    Wait-Ready $resolver 'resolver'
    $server = Launch $Dispatcher @(
        ('"{0}"' -f $includes), '127.0.0.2', '127.0.0.2', '127.0.0.3', '127.0.0.3', $trace,
        ('"{0}"' -f (Join-Path $root 'dispatcher.log'))
    ) 'dispatcher'
    Wait-Ready $server 'dispatcher'
    $rule = Add-DnsClientNrptRule -Namespace ".$zone" -NameServers '127.0.0.1' -DisplayName "WgpsCapacity-$id" -PassThru
    $warm = Launch $direct @('warm', $zone, '5', '1') 'warm'
    Wait-Client $warm 'warm'
    $warmResults = Read-Text 'warm.out' | ConvertFrom-Json
    if ($warmResults.directAnswers -ne 5) { throw 'Direct fixture DNS failed before load.' }
    $flood = Launch $selected @('selected', $zone, '100', '12') 'selected'
    $ordinary = Launch $direct @('direct', $zone, '20', '12') 'direct'
    Wait-Client $flood 'selected'
    Wait-Client $ordinary 'direct'
    $selectedResults = Read-Text 'selected.out' | ConvertFrom-Json
    $directResults = Read-Text 'direct.out' | ConvertFrom-Json
    if ($selectedResults.started / $selectedResults.launch_seconds -lt 80) {
        throw 'The offered selected load was too slow to test capacity isolation.'
    }
    if ($selectedResults.directAnswers) { throw 'A selected query was answered by the direct resolver.' }
    $protected = $directResults.successes -ge $directResults.started * 0.99 -and $directResults.p99_ms -le 1000
    if ($ExpectStarvation -and $protected) { throw 'Pre-fix baseline did not expose the intended starvation regression.' }
    if (-not $ExpectStarvation -and -not $protected) { throw 'Direct DNS was disrupted by the selected tunnel outage.' }
    $log = Read-Text 'dispatcher.log'
    if (-not $ExpectStarvation -and $log -notmatch '\(tunnel lane full\)') {
        throw 'No tunnel-capacity refusal was observed; the test did not exercise the limit.'
    }
    if ($log -match '(?m)^DNS selected-[^\r\n]* -> DIRECT') { throw 'Selected attribution crossed to the direct lane.' }
    # Let the remaining four-second upstream exchanges finish, then resume the
    # same tunnel resolver. The dispatcher and its attribution stay in place.
    Start-Sleep -Seconds 5
    $recovery = Launch $probe @('system-dns', "resume.$zone") 'recovery'
    Wait-Client $recovery 'recovery'
    if ((Read-Text 'recovery.out') -notmatch 'ANSWER 192\.0\.2\.1') { throw 'Tunnel DNS did not recover.' }
    Write-Output ("OBSERVED: baseline=$ExpectStarvation selected=$($selectedResults|ConvertTo-Json -Compress) " +
        "direct=$($directResults|ConvertTo-Json -Compress); selected never reached direct, tunnel recovered under the same dispatcher.")
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
