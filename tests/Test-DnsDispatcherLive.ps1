# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only: real DNS Client/ETW/NRPT path, using two loopback resolvers.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$addresses = @('0.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3')
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
    $includes = Join-Path $root 'included apps.txt'
    [IO.File]::WriteAllText($includes, $selected, [Text.UTF8Encoding]::new($false))
    $resolver = Launch (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') @('--fixture') 'resolver'
    Wait-Ready $resolver 'resolver'
    $dispatcher = Launch (Join-Path $RepositoryRoot 'build\dns-dispatcher.exe') @(
        ('"{0}"' -f $includes), '127.0.0.2', '127.0.0.2', '127.0.0.3', '127.0.0.3', $trace,
        ('"{0}"' -f (Join-Path $root 'dispatcher.log'))
    ) 'dispatcher'
    Wait-Ready $dispatcher 'dispatcher'
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
    Write-Output 'PASS: 20 real Windows DNS Client queries followed ETW-selected/direct resolver paths.'
} catch {
    foreach ($file in Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in '.log', '.out', '.err' }) {
        Write-Output "Diagnostic $($file.Name):"
        Get-Content -LiteralPath $file.FullName -Tail 30
    }
    throw
} finally {
    $failures = [Collections.Generic.List[string]]::new()
    try { if ($rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force } } catch { $failures.Add([string]$_) }
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
