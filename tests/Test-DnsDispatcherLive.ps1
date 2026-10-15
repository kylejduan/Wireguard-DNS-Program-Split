# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only: real DNS Client/ETW/NRPT path, using two loopback resolvers.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$addresses = @('0.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4')
$existingService = Get-Service -Name WireGuardProgramSplitController -ErrorAction SilentlyContinue
$udp = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -in $addresses })
$tcp = @(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -in $addresses })
if ($existingService -or $udp.Count -or $tcp.Count) {
    $existingService | Format-Table Name, Status
    $udp | Format-Table LocalAddress, LocalPort, OwningProcess
    $tcp | Format-Table LocalAddress, LocalPort, OwningProcess
    throw 'DNS integration test requires a disposable host without the project or a conflicting loopback DNS listener.'
}
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $RepositoryRoot "local\test-temp\dns live $id"
$zone = "wgps-$id.invalid"
$trace = "WireGuardProgramSplitDnsEtw-$id"
$children = [Collections.Generic.List[object]]::new()
$rule = $null
$blackHole = $null
function Read-SharedText([string] $Path) {
    try { $stream = [IO.FileStream]::new($Path, 'Open', 'Read', 'ReadWrite, Delete') }
    catch [IO.FileNotFoundException] { return '' } # Rotation may be between rename and reopen.
    try {
        $reader = [IO.StreamReader]::new($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
function Launch([string] $Exe, [string[]] $Arguments, [string] $Label) {
    $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $root "$Label.out") -RedirectStandardError (Join-Path $root "$Label.err")
    $null = $p.Handle
    $children.Add($p)
    return $p
}
function Wait-Ready($Process, [string] $Label) {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ($Process.HasExited) { throw "$Label exited: $([IO.File]::ReadAllText((Join-Path $root "$Label.err")))" }
        if ((Read-SharedText (Join-Path $root "$Label.out")) -match 'READY') { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Label did not become ready."
}
try {
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $selected = Join-Path $root 'selected.exe'
    $direct = Join-Path $root 'direct.exe'
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination $selected
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination $direct
    # Copies of the lane probe, which prints the address that answered: each resolver lane has its own.
    $selectedLane = Join-Path $root 'selected lane.exe'
    $directLane = Join-Path $root 'direct lane.exe'
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination $selectedLane
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination $directLane
    $includes = Join-Path $root 'included apps.txt'
    [IO.File]::WriteAllText($includes, "$selected`r`n$selectedLane`r`n", [Text.UTF8Encoding]::new($false))
    $resolver = Launch (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') @('--fixture', 300) 'resolver'
    Wait-Ready $resolver 'resolver'
    # The first physical resolver is a black hole: it takes datagrams and never answers. Unlisted DNS must
    # still be answered, by the second resolver, without the tunnel lane being affected.
    $blackHole = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse('127.0.0.4'), 53))
    $dispatcher = Launch (Join-Path $RepositoryRoot 'build\dns-dispatcher.exe') @(
        ('"{0}"' -f $includes), '127.0.0.2', '127.0.0.4,127.0.0.2', '127.0.0.3', '127.0.0.3', $trace,
        ('"{0}"' -f (Join-Path $root 'dispatcher.log'))
    ) 'dispatcher'
    Wait-Ready $dispatcher 'dispatcher'
    if ((Read-SharedText (Join-Path $root 'dispatcher.out')) -notmatch 'etw-filter=query-event') {
        throw 'The DNS Client provider did not accept the query-event ETW filter.'
    }
    $rule = Add-DnsClientNrptRule -Namespace ".$zone" -NameServers '127.0.0.1' -DisplayName "WgpsTest-$id" -PassThru
    foreach ($index in 1..10) {
        foreach ($lane in @('selected', 'direct')) {
            $exe = if ($lane -eq 'selected') { $selected } else { $direct }
            $probe = Launch $exe @('--system', "$lane-$index.$zone", '3') "$lane-$index"
            if (-not $probe.WaitForExit(10000)) { throw 'DNS integration probe timed out.' }
            if ($probe.ExitCode -ne 0) {
                throw "DNS integration probe failed: $([IO.File]::ReadAllText((Join-Path $root "$lane-$index.err")))"
            }
        }
    }
    $observed = (Read-SharedText (Join-Path $root 'resolver.out'))
    foreach ($index in 1..10) {
        if ($observed -notmatch "TUNNEL selected-$index\.$zone" -or $observed -notmatch "DIRECT direct-$index\.$zone") {
            throw "Missing selected/direct forwarding proof for pair $index."
        }
    }
    if ($observed -match 'DIRECT selected-' -or $observed -match 'TUNNEL direct-') { throw 'DNS crossed resolver lanes.' }
    $failoverLog = Read-SharedText (Join-Path $root 'dispatcher.log')
    $viaSecond = [regex]::Matches($failoverLog, '(?m)^DNS direct-\d+\.\S+ type=\d+ -> DIRECT[^\r\n]*\(resolver 2\)').Count
    $tunnelViaSecond = [regex]::Matches($failoverLog, '(?m)^DNS selected-[^\r\n]*\(resolver').Count
    Write-Output "OBSERVED: with a black-hole first resolver ($($blackHole.Available) bytes waiting at it), $viaSecond unlisted answers came from the second resolver and every unlisted lookup succeeded."
    if (-not $viaSecond -or -not $blackHole.Available -or $tunnelViaSecond) { throw 'Unlisted DNS did not fail over from the black-hole resolver, or the tunnel lane used the direct resolvers.' }

    # The same name from a selected and an unlisted application at once, in either order. The tunnel lane
    # answers 192.0.2.1 and the direct lane 192.0.2.2, so the answer proves the lane each one took.
    $rounds = 60
    $selectedLanes = @{}
    $directLanes = @{}
    foreach ($index in 1..$rounds) {
        $name = "pair-$index.$zone"
        $order = if ($index % 2) { @('selected', 'direct') } else { @('direct', 'selected') }
        $pair = foreach ($lane in $order) {
            $exe = if ($lane -eq 'selected') { $selectedLane } else { $directLane }
            [pscustomobject]@{ Lane = $lane; Process = (Launch $exe @('system-dns', $name) "$lane-pair-$index") }
        }
        foreach ($probe in $pair) {
            if (-not $probe.Process.WaitForExit(15000)) { throw 'A concurrent lane probe timed out.' }
            $text = Read-SharedText (Join-Path $root "$($probe.Lane)-pair-$index.out")
            $answer = if ($text -match 'ANSWER (\S+)') { $Matches[1] } else { 'failed' }
            $counts = if ($probe.Lane -eq 'selected') { $selectedLanes } else { $directLanes }
            $counts[$answer] = 1 + [int]$counts[$answer]
            if ($probe.Lane -eq 'selected' -and $answer -eq '192.0.2.2') { throw "Selected DNS took the direct lane for $name." }
        }
    }
    $describe = { param($Counts) ($Counts.Keys | Sort-Object | ForEach-Object { "$_ x$($Counts[$_])" }) -join ', ' }
    Write-Output "OBSERVED: $rounds concurrent same-name pairs; selected answers $(& $describe $selectedLanes); unlisted answers $(& $describe $directLanes)."
    if ([int]$selectedLanes['192.0.2.1'] -lt $rounds * 0.9) { throw 'Too few selected lookups were answered in the tunnel lane.' }

    # Truncated UDP answers while unlisted lookups of the same name keep raising events. For "tc-" names the
    # dispatcher completes the answer over TCP on the route it chose and returns it over UDP, so the client
    # never falls back; "tcbig-" answers are too large for UDP, so the client falls back to TCP, which raises
    # no new event. The proof is the dispatcher's routing: within the reuse window after the selected
    # application's event, no query for the name goes direct. The answer the selected application receives
    # is reported: the DNS Client service can hand it another process's answer for the same name.
    $truncatedRounds = 20
    $window = 3 * [Diagnostics.Stopwatch]::Frequency
    foreach ($prefix in @('tc', 'tcbig')) {
        $truncatedSelected = @{}
        foreach ($index in 1..$truncatedRounds) {
            $name = "$prefix-$index.$zone"
            $flood = foreach ($copy in 1..4) { Launch $directLane @('system-dns', $name, 5) "$prefix-direct-$index-$copy" }
            Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 40)
            $selectedProbe = Launch $selectedLane @('system-dns', $name) "$prefix-selected-$index"
            foreach ($process in @($flood) + $selectedProbe) {
                if (-not $process.WaitForExit(20000)) { throw 'A truncation probe timed out.' }
            }
            $text = Read-SharedText (Join-Path $root "$prefix-selected-$index.out")
            $answer = if ($text -match 'ANSWER (\S+)') { $Matches[1] } else { 'failed' }
            $truncatedSelected[$answer] = 1 + [int]$truncatedSelected[$answer]
        }
        $log = Read-SharedText (Join-Path $root 'dispatcher.log')
        $completed = 0
        $fallbacks = 0
        $withheld = 0
        $unseen = 0
        foreach ($index in 1..$truncatedRounds) {
            $name = [regex]::Escape("$prefix-$index.$zone")
            $withheld += [regex]::Matches($log, "(?m)^DNS $name type=1 -> DIRECT[^\r\n]*WITHHELD").Count
            $answerText = Read-SharedText (Join-Path $root "$prefix-selected-$index.out")
            if ($answerText -match 'ANSWER 192\.0\.2\.2') {
                Write-Output "DETAIL: $prefix-$index selected copy: $($answerText.Trim())"
                [regex]::Matches($log, "(?m)^(HINT|DNS) $name [^\r\n]*") | ForEach-Object { Write-Output "DETAIL:   $($_.Value)" }
            }
            $selectedEvents = @([regex]::Matches($log, "(?m)^HINT $name type=1 .*?selected=1 .*?event-qpc=(\d+)") | ForEach-Object { [int64]$_.Groups[1].Value })
            if (-not $selectedEvents.Count) { $unseen++; continue }
            $start = ($selectedEvents | Measure-Object -Minimum).Minimum
            foreach ($decision in [regex]::Matches($log, "(?m)^DNS $name type=1 -> (TUNNEL|DIRECT)([^\r\n]*?) classify=\S+ query-qpc=(\d+)")) {
                $arrival = [int64]$decision.Groups[3].Value
                if ($arrival -lt $start -or $arrival -gt $start + $window) { continue }
                if ($decision.Groups[1].Value -eq 'DIRECT') { throw "A query for $prefix-$index went direct after the selected application's event: $($decision.Value)" }
                if ($decision.Groups[2].Value -match 'completed over TCP') { $completed++ }
                if ($decision.Groups[2].Value -match '\(TCP\)') { $fallbacks++ }
            }
        }
        Write-Output ("OBSERVED: $truncatedRounds '$prefix' truncated selected lookups beside unlisted ones: no direct routing after the " +
            "selected event; $completed completed over TCP by the dispatcher, $fallbacks client TCP fallbacks, $withheld direct answers " +
            "withheld; $unseen selected lookups raised no query event; answers the selected copy received: $(& $describe $truncatedSelected).")
        Write-Output "OBSERVED: ETW loss and barrier failures so far: $([regex]::Matches($log, '(?m)^(ETW LOST|BARRIER INCOMPLETE)[^\r\n]*').Count)."
        # Completed answers never reach the client truncated, and a direct answer a selected lookup was merged
        # into is withheld, so no selected copy receives the direct lane's answer. Oversized answers remain
        # the documented limitation: they are only reported.
        if ($prefix -eq 'tc' -and ($completed -lt $truncatedRounds -or $truncatedSelected['192.0.2.2'])) {
            throw 'A completable truncated answer reached a selected copy from the direct lane, or was not completed.'
        }
        if ($prefix -eq 'tcbig' -and -not $fallbacks) { throw 'No oversized answer led to a tunnel-lane TCP fallback.' }
    }

    # Ordering, measured: every forwarded query has a query event for its name logged before its packet
    # arrived, on the same QPC clock. The dispatcher's barrier relies on this.
    $log = Read-SharedText (Join-Path $root 'dispatcher.log')
    $events = @{}
    foreach ($match in [regex]::Matches($log, '(?m)^HINT (\S+) type=1 .*?event-qpc=(\d+)')) {
        $key = $match.Groups[1].Value
        if (-not $events.ContainsKey($key)) { $events[$key] = [Collections.Generic.List[int64]]::new() }
        $events[$key].Add([int64]$match.Groups[2].Value)
    }
    $frequency = [Diagnostics.Stopwatch]::Frequency
    $margins = [Collections.Generic.List[double]]::new()
    $late = [Collections.Generic.List[string]]::new()
    $classify = @{ TUNNEL = [Collections.Generic.List[double]]::new(); DIRECT = [Collections.Generic.List[double]]::new() }
    foreach ($match in [regex]::Matches($log, '(?m)^DNS (\S+) type=1 -> (TUNNEL|DIRECT)((?: \(TCP\))?(?: \(reused\))?)[^\r\n]*? classify=(\d+)us query-qpc=(\d+)')) {
        $name = $match.Groups[1].Value.ToLowerInvariant().TrimEnd('.')
        $arrival = [int64]$match.Groups[5].Value
        $reusedRoute = $match.Groups[3].Value -match 'reused'
        if (-not $reusedRoute) { $classify[$match.Groups[2].Value].Add([double]$match.Groups[4].Value / 1000) }
        $before = @($events[$name] | Where-Object { $_ -lt $arrival })
        if ($before.Count) { $margins.Add(($arrival - ($before | Measure-Object -Maximum).Maximum) * 1000.0 / $frequency) }
        elseif (-not $reusedRoute) { $late.Add($name) }
    }
    $percentile = { param($Values, [double] $P)
        $sorted = @($Values | Sort-Object)
        if (-not $sorted.Count) { return 'n/a' }
        $sorted[[Math]::Min($sorted.Count - 1, [int][Math]::Ceiling($P * $sorted.Count) - 1)].ToString('0.00')
    }
    Write-Output ("OBSERVED: $($margins.Count) forwarded queries had their query event logged first, by at least " +
        "$(($margins | Measure-Object -Minimum).Minimum.ToString('0.000')) ms (median $(& $percentile $margins 0.5) ms); $($late.Count) did not.")
    Write-Output ("OBSERVED: classify time with the ordering barrier: DIRECT p50 $(& $percentile $classify.DIRECT 0.5) ms, " +
        "p99 $(& $percentile $classify.DIRECT 0.99) ms over $($classify.DIRECT.Count); TUNNEL p50 $(& $percentile $classify.TUNNEL 0.5) ms, " +
        "p99 $(& $percentile $classify.TUNNEL 0.99) ms over $($classify.TUNNEL.Count).")
    if ($late.Count) { throw "Forwarded queries without an earlier query event: $($late -join ', ')" }
    # Events whose process could not be identified make their name unsafe for direct routing for ten seconds.
    Write-Output ("OBSERVED: $([regex]::Matches($log, '(?m)^HINT [^\r\n]* path=\r?$').Count) of " +
        "$([regex]::Matches($log, '(?m)^HINT ').Count) query events had an unidentified process; " +
        "$([regex]::Matches($log, '(?m)^DNS [^\r\n]*BLOCKED').Count) queries were refused.")
    Write-Output 'PASS: real Windows DNS Client queries followed ETW-selected/direct resolver paths, including concurrent same-name pairs.'
} catch {
    foreach ($file in Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in '.log', '.out', '.err' }) {
        Write-Output "Diagnostic $($file.Name):"
        Get-Content -LiteralPath $file.FullName -Tail 30
    }
    throw
} finally {
    $failures = [Collections.Generic.List[string]]::new()
    try { if ($rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force } } catch { $failures.Add([string]$_) }
    if ($blackHole) { $blackHole.Dispose() }
    try { & logman.exe stop $trace -ets 2>$null | Out-Null } catch { $failures.Add([string]$_) }
    foreach ($child in $children) {
        try {
            if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force }
            if (-not $child.WaitForExit(10000)) { throw 'Test child did not stop.' }
        } catch { $failures.Add([string]$_) }
        finally { $child.Dispose() }
    }
    if ($failures.Count) { throw "DNS fixture cleanup failed: $($failures -join ' | ')" }
    # Retain bounded diagnostics under ignored local/ for failure attribution.
}
