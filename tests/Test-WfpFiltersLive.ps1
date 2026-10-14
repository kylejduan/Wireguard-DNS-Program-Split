# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable Windows CI only: persistent WFP filters against the real Base Filtering Engine, for throwaway
# executables and a TEST-NET tunnel address. Needs elevation and outbound IPv4, not the PIA driver: without
# it the redirect callouts are unregistered, which is the state the driver-independent blocks must cover.
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$probe = Join-Path $RepositoryRoot 'build\wfp-probe.exe'
function Invoke-Probe([string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($probe, ($Arguments -join ' '))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); throw "wfp-probe.exe $($Arguments[0]) timed out." }
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode; Output = $output.Result.Trim(); Error = $errors.Result.Trim()
            Milliseconds = $timer.ElapsedMilliseconds
        }
    } finally { $process.Dispose() }
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The WFP integration test requires an elevated session.'
}
# The provider key is fixed, so this test would replace and then remove a real installation's filters.
$initial = Invoke-Probe @('status')
if ((Get-Service -Name WireGuardProgramSplitController -ErrorAction SilentlyContinue) -or
    $initial.ExitCode -ne 0 -or $initial.Output -notmatch '^ABSENT:') {
    throw "WFP integration test requires a disposable host without the project or its filters: $($initial.Output) $($initial.Error)"
}
$piaDriver = [bool](Get-Service -Name PiaWFPCallout -ErrorAction SilentlyContinue)
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $RepositoryRoot "local\test-temp\wfp live $id"
$observer = $null
$oneAppState = 'PRESENT: 10 filter(s) including 4 boot-time, 1 provider context(s), 2 callout(s), 1 sublayer(s), provider.'
# The second copy's name has uppercase non-ASCII letters, so it gets a second, fully lowercased identifier.
$twoAppState = 'PRESENT: 30 filter(s) including 12 boot-time, 1 provider context(s), 2 callout(s), 1 sublayer(s), provider.'
$blocksOnlyState = 'PRESENT: 8 filter(s) including 4 boot-time, 1 provider context(s), 0 callout(s), 1 sublayer(s), provider.'
$holder = $null
$script:substDrive = $null
$dnsChildren = [Collections.Generic.List[object]]::new()
$dnsRule = $null
$dnsTrace = $null
function Assert-Verified([string] $List, [string] $Address, [string] $Message) {
    $result = Invoke-Probe @('verify', ('"{0}"' -f $List), $Address)
    # Without the PIA driver the objects can match while the callouts stay unregistered.
    $expected = if ($piaDriver) { @(0) } else { @(4) }
    Assert-True ($result.ExitCode -in $expected) "$Message (exit $($result.ExitCode): $($result.Output) $($result.Error))"
    if (-not $piaDriver) { Assert-True ($result.Error -match 'not registered') 'verification reports unregistered callouts' }
}
function Assert-Rejected([string] $List, [string] $Address, [string] $Message) {
    $result = Invoke-Probe @('verify', ('"{0}"' -f $List), $Address)
    Assert-True ($result.ExitCode -eq 1 -and $result.Error -match 'do not match') "$Message (exit $($result.ExitCode): $($result.Error))"
}
function Invoke-NetProbe([string] $Exe, [string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($Exe, ($Arguments -join ' '))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw "net-probe $($Arguments -join ' ') timed out." }
        $process.WaitForExit()
        $text = $output.Result.Trim()
        $code = if ($text -match 'error (\d+)') { [int]$Matches[1] } else { 0 }
        [pscustomobject]@{ Passed = $process.ExitCode -eq 0; Error = $code; Text = $text }
    } finally { $process.Dispose() }
}
try {
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $selectedOne = Join-Path $root 'selected one.exe'
    # Uppercase non-ASCII in a name with spaces: WFP lowercases application identifiers' ASCII only.
    $selectedTwo = Join-Path $root "Selected $([char]0x00C9) Two.exe"
    $direct = Join-Path $root 'direct.exe'
    foreach ($path in @($selectedOne, $selectedTwo, $direct)) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination $path
    }
    $oneApp = Join-Path $root 'one app.txt'
    $twoApps = Join-Path $root 'two apps.txt'
    [IO.File]::WriteAllText($oneApp, $selectedOne, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllLines($twoApps, @($selectedOne, $selectedTwo), [Text.UTF8Encoding]::new($false))

    # A public resolver that answers both TCP and UDP from this host before any filter exists.
    $external = $null
    foreach ($candidate in @('1.1.1.1', '9.9.9.9', '8.8.8.8')) {
        if ((Invoke-NetProbe $selectedOne @('tcp', $candidate, 443, 3000)).Passed -and
            (Invoke-NetProbe $selectedOne @('udp-dns', $candidate, 3000)).Passed) { $external = $candidate; break }
    }
    if (-not $external) { throw 'No public resolver answered TCP 443 and UDP 53; the traffic proof needs outbound IPv4.' }
    # A neighbor that does not exist on a link-local subnet: the route exists, so authorization runs.
    $linkLocal = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -like 'fe80*' -and $_.AddressState -eq 'Preferred' } | Select-Object -First 1
    $ipv6Target = if ($linkLocal) { "fe80::5e1:abcd:1234:5678%$($linkLocal.InterfaceIndex)" } else { $null }

    # Handoff from an earlier release: its filter host's dynamic session holds the PIA callout keys. Install
    # commits the blocks first and says so; once the host has gone, a repeat installs the whole set.
    $holderOut = Join-Path $root 'holder.out'
    $holder = Start-Process -FilePath (Join-Path $RepositoryRoot 'build\test-wfp-callout-holder.exe') -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $holderOut -RedirectStandardError (Join-Path $root 'holder.err')
    $null = $holder.Handle
    $wait = [Diagnostics.Stopwatch]::StartNew()
    # An empty file yields no value at all, which -notmatch would treat as a match; compare a string.
    while ([string](Get-Content -LiteralPath $holderOut -Raw -ErrorAction SilentlyContinue) -notmatch 'READY') {
        if ($holder.HasExited -or $wait.Elapsed.TotalSeconds -gt 10) { throw 'The callout holder did not become ready.' }
        Start-Sleep -Milliseconds 100
    }
    $install = Invoke-Probe @('install', ('"{0}"' -f $oneApp), '192.0.2.1')
    Assert-True ($install.ExitCode -eq 3 -and $install.Error -match 'without the redirect') `
        "install under a foreign callout owner commits the blocks and reports it: $($install.ExitCode) $($install.Error)"
    $status = Invoke-Probe @('status')
    Assert-True ($status.Output -eq $blocksOnlyState) "the blocks are in place while the old host runs: $($status.Output)"
    Assert-Rejected $oneApp '192.0.2.1' 'a set without the redirect does not verify'
    $holder.Kill()
    $null = $holder.WaitForExit(10000)
    $holder.Dispose()
    $holder = $null
    $wait = [Diagnostics.Stopwatch]::StartNew()
    do {
        # BFE ends the killed host's session asynchronously.
        $install = Invoke-Probe @('install', ('"{0}"' -f $oneApp), '192.0.2.1')
        if ($install.ExitCode -ne 3) { break }
        Start-Sleep -Milliseconds 250
    } while ($wait.Elapsed.TotalSeconds -lt 10)
    # Filters that name callouts are accepted while no driver has registered them.
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match '^READY:') "install succeeds: $($install.Error)"
    if (-not $piaDriver) {
        Assert-True ($install.Output -match 'not registered') 'install succeeds before any driver registers the PIA callouts'
    }
    $status = Invoke-Probe @('status')
    Assert-True ($status.Output -eq $oneAppState) "install creates exactly the persistent set: $($status.Output)"
    $verify = Invoke-Probe @('verify', ('"{0}"' -f $oneApp), '192.0.2.1')
    Write-Output ("OBSERVED: install {0} ms, verify {1} ms, status {2} ms against this host's filter engine." -f
        $install.Milliseconds, $verify.Milliseconds, $status.Milliseconds)
    Assert-Verified $oneApp '192.0.2.1' 'verification accepts the installed set'
    Assert-Rejected $oneApp '192.0.2.2' 'verification rejects another tunnel address'
    Assert-Rejected $twoApps '192.0.2.1' 'verification rejects another application list'

    # End to end in the driver-unregistered state: the listed copy cannot leave, the unlisted copy can. A
    # refused TCP connect reports WSAEACCES. A blocked UDP send reports nothing, and traffic to this host's own
    # addresses counts as loopback, so the UDP proof is the filter engine's audit record of the block.
    $auditCategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'  # Filtering Platform Connection
    $auditBefore = (& auditpol.exe /get /subcategory:$auditCategory /r | Where-Object { $_ } | ConvertFrom-Csv).'Inclusion Setting'
    $auditStarted = Get-Date
    & auditpol.exe /set /subcategory:$auditCategory /failure:enable | Out-Null
    try {
        foreach ($check in @(@('tcp', $external, 443, 3000), @('udp-dns', $external, 3000))) {
            $unlisted = Invoke-NetProbe $direct $check
            Assert-True $unlisted.Passed "an unlisted copy is unaffected: $($check -join ' '): $($unlisted.Text)"
            $listed = Invoke-NetProbe $selectedOne $check
            Assert-True (-not $listed.Passed) "the listed copy cannot reach $($check -join ' ') off the tunnel address: $($listed.Text)"
            if ($check[0] -eq 'tcp') {
                Assert-True ($listed.Error -eq 10013) "the listed copy's TCP connect is refused with WSAEACCES: $($listed.Text)"
            }
            Write-Output "OBSERVED: listed copy $($check -join ' '): $($listed.Text)"
        }
        $blocked = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $auditStarted } -ErrorAction SilentlyContinue |
            ForEach-Object {
                $fields = @{}
                foreach ($field in ([xml]$_.ToXml()).Event.EventData.Data) { $fields[$field.Name] = [string]$field.'#text' }
                [pscustomobject]$fields
            } | Where-Object { $_.DestAddress -eq $external -and $_.Protocol -eq '17' -and $_.DestPort -eq '53' })
        Assert-True (@($blocked | Where-Object { $_.Application -like '*\selected one.exe' }).Count -gt 0) `
            "the filter engine records blocking the listed copy's UDP datagram to $external`:53"
        Assert-True (@($blocked | Where-Object { $_.Application -like '*\direct.exe' }).Count -eq 0) `
            'no block is recorded for the unlisted copy'
        Write-Output "OBSERVED: the filter engine recorded $(@($blocked).Count) blocked UDP datagram(s) from the listed copy to $external`:53."
    } finally {
        $restore = if ($auditBefore -match 'Failure') { '/failure:enable' } else { '/failure:disable' }
        & auditpol.exe /set /subcategory:$auditCategory $restore | Out-Null
    }
    # The redirect filters carry no loopback exemption, so IPv4 loopback shows what they do on their own
    # while the PIA driver has not registered its callouts; the IPv4 blocks spare loopback.
    $redirectOnly = Invoke-NetProbe $selectedOne @('loopback', '127.0.0.1')
    Write-Output "OBSERVED: with only the unregistered redirect callouts in its path (driver present: $piaDriver), the listed copy's IPv4 loopback connection: $($redirectOnly.Text)"
    if ($redirectOnly.Passed) {
        Write-Output 'OBSERVED: the unregistered redirect callouts let traffic through; the refusals above came from the authorization blocks.'
    }
    $ipv6Loopback = Invoke-NetProbe $selectedOne @('loopback', '::1')
    Assert-True $ipv6Loopback.Passed "the listed copy keeps IPv6 loopback: $($ipv6Loopback.Text)"
    if ($ipv6Target) {
        $unlisted = Invoke-NetProbe $direct @('tcp', $ipv6Target, 443, 1500)
        Assert-True ($unlisted.Error -ne 10013) "an unlisted copy's IPv6 reaches authorization and is not refused: $($unlisted.Text)"
        $listed = Invoke-NetProbe $selectedOne @('tcp', $ipv6Target, 443, 1500)
        Assert-True (-not $listed.Passed -and $listed.Error -eq 10013) "the listed copy's IPv6 is refused: $($listed.Text)"
    } else { Write-Output 'OBSERVED: no preferred IPv6 link-local address; the IPv6 traffic proof was skipped.' }

    # Replacement is atomic: a concurrent reader sees one complete set or the other, never a gap.
    $observations = Join-Path $root 'observations.txt'
    $stopObserving = Join-Path $root 'stop-observing'
    $observer = Start-Job -ScriptBlock {
        param($Probe, $Observations, $StopFile)
        while (-not (Test-Path -LiteralPath $StopFile)) { Add-Content -LiteralPath $Observations -Value (& $Probe status) }
    } -ArgumentList $probe, $observations, $stopObserving
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $observations) -and $wait.Elapsed.TotalSeconds -lt 60) { Start-Sleep -Milliseconds 100 }
    foreach ($index in 1..12) {
        $target = if ($index % 2) { @($twoApps, '192.0.2.2') } else { @($oneApp, '192.0.2.1') }
        $replace = Invoke-Probe @('install', ('"{0}"' -f $target[0]), $target[1])
        Assert-True ($replace.ExitCode -eq 0) "replacement $index succeeds: $($replace.Error)"
    }
    [IO.File]::WriteAllText($stopObserving, 'stop')
    $null = Wait-Job -Job $observer -Timeout 60
    $seen = @(Get-Content -LiteralPath $observations | Where-Object { $_ })
    $unexpected = @($seen | Where-Object { $_ -ne $oneAppState -and $_ -ne $twoAppState })
    Assert-True ($seen.Count -gt 0 -and $unexpected.Count -eq 0) `
        "a concurrent reader never sees a partial or empty set during replacement ($($seen.Count) reads): $($unexpected -join ' | ')"
    Write-Output "OBSERVED: $($seen.Count) concurrent reads during 12 replacements all saw a complete set."

    # A run killed at any point leaves the previous complete set or the new one, which install then replaces.
    $random = [Random]::new()
    foreach ($index in 1..20) {
        $target = if ($index % 2) { @($twoApps, '192.0.2.2') } else { @($oneApp, '192.0.2.1') }
        $killed = Start-Process -FilePath $probe -ArgumentList @('install', ('"{0}"' -f $target[0]), $target[1]) `
            -PassThru -WindowStyle Hidden
        $null = $killed.Handle
        Start-Sleep -Milliseconds ($random.Next(0, 40))
        try { if (-not $killed.HasExited) { $killed.Kill() } } catch [InvalidOperationException] { }
        $null = $killed.WaitForExit(10000)
        $killed.Dispose()
        $state = (Invoke-Probe @('status')).Output
        Assert-True ($state -eq $oneAppState -or $state -eq $twoAppState) "a killed install leaves a complete set: $state"
        # The filters commit first and the identity record follows; a run ended between the two leaves a record
        # that verification rejects, so the controller reinstalls. Either way the set is never partial.
        $target = if ($state -eq $oneAppState) { @($oneApp, '192.0.2.1') } else { @($twoApps, '192.0.2.2') }
        $verify = Invoke-Probe @('verify', ('"{0}"' -f $target[0]), $target[1])
        Assert-True ($verify.ExitCode -eq $(if ($piaDriver) { 0 } else { 4 }) -or $verify.Error -match 'identities changed or were not recorded') `
            "the set left by a killed install is intact: $($verify.ExitCode) $($verify.Error)"
    }
    $install = Invoke-Probe @('install', ('"{0}"' -f $twoApps), '192.0.2.3')
    Assert-True ($install.ExitCode -eq 0) "install replaces a set left by killed runs: $($install.Error)"
    # An uninstalled or temporarily replaced executable keeps its filters, keyed by the identifier derived
    # from its path, so a restored copy is covered before any reconcile.
    $parked = Join-Path $root 'parked.exe'
    Move-Item -LiteralPath $selectedOne -Destination $parked
    $verify = Invoke-Probe @('verify', ('"{0}"' -f $twoApps), '192.0.2.3')
    Assert-True ($verify.Output -match 'WARNING: listed executable is absent; its filters stay in place') `
        "an absent executable is a warning: $($verify.Output) $($verify.Error)"
    Assert-Verified $twoApps '192.0.2.3' 'the set verifies while one executable is absent'
    $install = Invoke-Probe @('install', ('"{0}"' -f $twoApps), '192.0.2.3')
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'WARNING: listed executable is absent; its filters stay in place') `
        "install keeps the absent executable's filters: $($install.Output) $($install.Error)"
    Assert-True ((Invoke-Probe @('status')).Output -eq $twoAppState) 'every listed path keeps its filters'
    Move-Item -LiteralPath $parked -Destination $selectedOne
    $restored = Invoke-NetProbe $selectedOne @('tcp', $external, 443, 3000)
    Assert-True (-not $restored.Passed -and $restored.Error -eq 10013) `
        "a restored executable is refused at once, before any reinstall: $($restored.Text)"
    Assert-Verified $twoApps '192.0.2.3' 'the derived identifier equals the filter engine''s for the restored file'
    # The management API lowercases ASCII only, the kernel every letter; the fully lowercased identifier is
    # the one a running image with uppercase non-ASCII letters in its name matches.
    $nonAscii = Invoke-NetProbe $selectedTwo @('tcp', $external, 443, 3000)
    Assert-True (-not $nonAscii.Passed -and $nonAscii.Error -eq 10013) `
        "a listed executable with uppercase non-ASCII letters in its name is refused: $($nonAscii.Text)"
    Assert-Verified $twoApps '192.0.2.3' 'the replacement matches the new list and address'
    Assert-Rejected $twoApps '192.0.2.2' 'no object of the replaced set remains'
    Assert-True ((Invoke-Probe @('status')).Output -eq $twoAppState) 'replacement leaves exactly one set'

    # Identity through a junction: the alias names the resolved file whether or not it exists.
    $real = Join-Path $root 'real'
    $alias = Join-Path $root 'alias'
    [IO.Directory]::CreateDirectory($real) | Out-Null
    New-Item -ItemType Junction -Path $alias -Target $real | Out-Null
    $realApp = Join-Path $real 'junction app.exe'
    $aliasApp = Join-Path $alias 'junction app.exe'
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination $realApp
    $junctionList = Join-Path $root 'junction.txt'
    [IO.File]::WriteAllText($junctionList, $aliasApp, [Text.UTF8Encoding]::new($false))
    $install = Invoke-Probe @('install', ('"{0}"' -f $junctionList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0 -and (Invoke-Probe @('status')).Output -eq $oneAppState) "a junction alias installs: $($install.Error)"
    foreach ($path in @($aliasApp, $realApp)) {
        $refused = Invoke-NetProbe $path @('tcp', $external, 443, 3000)
        Assert-True ($refused.Error -eq 10013) "a listed junction alias is refused through either path: $path $($refused.Text)"
    }
    Move-Item -LiteralPath $realApp -Destination $parked
    $install = Invoke-Probe @('install', ('"{0}"' -f $junctionList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'its filters stay in place') `
        "an absent alias is derived through the junction: $($install.Output) $($install.Error)"
    Move-Item -LiteralPath $parked -Destination $realApp
    $restored = Invoke-NetProbe $aliasApp @('tcp', $external, 443, 3000)
    Assert-True ($restored.Error -eq 10013) "an alias restored behind a junction is refused at once: $($restored.Text)"
    Assert-Verified $junctionList '192.0.2.4' 'the derived identity of an absent alias is the resolved file''s'

    # A link whose target is temporarily absent is not resolved through the link's own spelling: the entry
    # keeps its recorded identity, the target's, so the restored target is covered at once. The same holds
    # for a junction whose target directory is unavailable.
    $identityRecord = Join-Path $root 'resolved-identities.tsv'
    $linkTarget = Join-Path $root 'link target\real target.exe'
    $junctionTargetDirectory = Join-Path $root 'junction target'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $linkTarget)) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $root 'links')) | Out-Null
    [IO.Directory]::CreateDirectory($junctionTargetDirectory) | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination $linkTarget
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination (Join-Path $junctionTargetDirectory 'junction target app.exe')
    $link = Join-Path $root 'links\link app.exe'
    New-Item -ItemType SymbolicLink -Path $link -Target $linkTarget | Out-Null
    $goneJunction = Join-Path $root 'gone junction'
    New-Item -ItemType Junction -Path $goneJunction -Target $junctionTargetDirectory | Out-Null
    foreach ($case in @(
        @{ Name = 'a symbolic link whose target is absent'; App = $link
           Hide = { Move-Item -LiteralPath $linkTarget -Destination $parked }; Show = { Move-Item -LiteralPath $parked -Destination $linkTarget } },
        @{ Name = 'a junction whose target is unavailable'; App = (Join-Path $goneJunction 'junction target app.exe')
           Hide = { Rename-Item -LiteralPath $junctionTargetDirectory -NewName 'junction target away' }
           Show = { Rename-Item -LiteralPath (Join-Path $root 'junction target away') -NewName 'junction target' } }
    )) {
        $caseList = Join-Path $root 'reparse.txt'
        [IO.File]::WriteAllText($caseList, $case.App, [Text.UTF8Encoding]::new($false))
        $install = Invoke-Probe @('install', ('"{0}"' -f $caseList), '192.0.2.4')
        Assert-True ($install.ExitCode -eq 0 -and (Invoke-Probe @('status')).Output -eq $oneAppState) "$($case.Name): installs while present: $($install.Error)"
        $refused = Invoke-NetProbe $case.App @('tcp', $external, 443, 3000)
        Assert-True ($refused.Error -eq 10013) "$($case.Name): refused while present: $($refused.Text)"
        $recorded = [IO.File]::ReadAllText($identityRecord)
        & $case.Hide
        $install = Invoke-Probe @('install', ('"{0}"' -f $caseList), '192.0.2.4')
        Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'cannot be resolved; its recorded identity is kept' -and
            [IO.File]::ReadAllText($identityRecord) -ceq $recorded -and (Invoke-Probe @('status')).Output -eq $oneAppState) `
            "$($case.Name): keeps its recorded identity instead of the link's spelling: $($install.Output) $($install.Error)"
        & $case.Show
        $refused = Invoke-NetProbe $case.App @('tcp', $external, 443, 3000)
        Assert-True ($refused.Error -eq 10013) "$($case.Name): refused at once when the target returns: $($refused.Text)"
        Assert-Verified $caseList '192.0.2.4' "$($case.Name): the recorded identity is the target's"
    }

    # An alias retargeted from A to B, with the install stopped after committing B's filters but before
    # publishing the record (the record still names A), and the alias then unresolvable: the committed
    # filters' identity is kept along with the record's, so B stays protected.
    $retargetAlias = Join-Path $root 'retarget alias'
    $retargetApps = foreach ($side in @('A', 'B')) {
        $directory = Join-Path $root "retarget $side"
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination (Join-Path $directory 'retarget app.exe')
        Join-Path $directory 'retarget app.exe'
    }
    $retargetList = Join-Path $root 'retarget.txt'
    [IO.File]::WriteAllText($retargetList, (Join-Path $retargetAlias 'retarget app.exe'), [Text.UTF8Encoding]::new($false))
    New-Item -ItemType Junction -Path $retargetAlias -Target (Join-Path $root 'retarget A') | Out-Null
    $install = Invoke-Probe @('install', ('"{0}"' -f $retargetList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0) "the alias installs while it names A: $($install.Error)"
    $recordForA = [IO.File]::ReadAllText($identityRecord)
    [IO.Directory]::Delete($retargetAlias)
    New-Item -ItemType Junction -Path $retargetAlias -Target (Join-Path $root 'retarget B') | Out-Null
    $install = Invoke-Probe @('install', ('"{0}"' -f $retargetList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0) "the alias installs once it names B: $($install.Error)"
    [IO.File]::WriteAllText($identityRecord, $recordForA, [Text.UTF8Encoding]::new($false))
    Rename-Item -LiteralPath (Join-Path $root 'retarget B') -NewName 'retarget B away'
    $install = Invoke-Probe @('install', ('"{0}"' -f $retargetList), '192.0.2.4')
    Rename-Item -LiteralPath (Join-Path $root 'retarget B away') -NewName 'retarget B'
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'cannot be resolved') `
        "an unresolvable alias with a stale record installs: $($install.Output) $($install.Error)"
    foreach ($app in $retargetApps) {
        $refused = Invoke-NetProbe $app @('tcp', $external, 443, 3000)
        Assert-True ($refused.Error -eq 10013) "both the committed and the recorded identities stay protected: $app $($refused.Text)"
    }
    # Each identity keeps its own attribution path in the record, for the DNS lane below.
    $retargetRows = @([IO.File]::ReadAllLines($identityRecord) | Where-Object { $_ -match 'retarget app\.exe' })
    Assert-True ($retargetRows.Count -eq 2 -and ($retargetRows -match 'retarget a\\').Count -eq 1 -and ($retargetRows -match 'retarget b\\').Count -eq 1) `
        "both identities keep their attribution paths: $($retargetRows -join ' | ')"
    Write-Output 'OBSERVED: an install interrupted between committing B and publishing its record kept A and B protected and attributed once the alias stopped resolving.'

    # A path that cannot be resolved, such as on a removed substituted drive, keeps its installed filters.
    $letter = [char[]]'WVUTSRQPONMLKJ' | Where-Object { -not (Test-Path -LiteralPath "$($_):\") } | Select-Object -First 1
    $substDirectory = Join-Path $root 'subst target'
    [IO.Directory]::CreateDirectory($substDirectory) | Out-Null
    & subst.exe "$($letter):" $substDirectory
    $script:substDrive = "$($letter):"
    $substApp = "$($letter):\subst app.exe"
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination (Join-Path $substDirectory 'subst app.exe')
    $substList = Join-Path $root 'subst.txt'
    [IO.File]::WriteAllText($substList, $substApp, [Text.UTF8Encoding]::new($false))
    $install = Invoke-Probe @('install', ('"{0}"' -f $substList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0 -and (Invoke-Probe @('status')).Output -eq $oneAppState) "a substituted-drive path installs: $($install.Error)"
    & subst.exe $script:substDrive /d
    $install = Invoke-Probe @('install', ('"{0}"' -f $substList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'cannot be resolved; its recorded identity is kept' -and
        (Invoke-Probe @('status')).Output -eq $oneAppState) `
        "an unresolvable path keeps its filters through a replacement: $($install.Output) $($install.Error)"
    Assert-Verified $substList '192.0.2.4' 'a retained identity verifies'
    & subst.exe $script:substDrive $substDirectory
    $retained = Invoke-NetProbe $substApp @('tcp', $external, 443, 3000)
    Assert-True ($retained.Error -eq 10013) "the retained filters still cover the executable when its drive returns: $($retained.Text)"
    # The dispatcher attributes by the same record. Started while the drive is gone, it still holds the
    # resolved path, so after the drive returns the selected copy's ordinary DNS goes to the tunnel lane.
    $substDns = "$($letter):\subst dns.exe"
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination (Join-Path $substDirectory 'subst dns.exe')
    $directDns = Join-Path $root 'direct dns.exe'
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\dns-probe.exe') -Destination $directDns
    $substDnsList = Join-Path $root 'subst dns.txt'
    [IO.File]::WriteAllText($substDnsList, $substDns, [Text.UTF8Encoding]::new($false))
    $install = Invoke-Probe @('install', ('"{0}"' -f $substDnsList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0) "the DNS lane's copy installs: $($install.Error)"
    & subst.exe $script:substDrive /d
    $install = Invoke-Probe @('install', ('"{0}"' -f $substDnsList), '192.0.2.4')
    Assert-True ($install.ExitCode -eq 0 -and $install.Output -match 'recorded identity is kept') "the absent drive keeps the record: $($install.Output)"
    # The dispatcher also gets the retarget entry's two rows, so both of its identities are attributed.
    $dispatcherIdentities = Join-Path $root 'dispatcher identities.tsv'
    [IO.File]::WriteAllText($dispatcherIdentities, [IO.File]::ReadAllText($identityRecord) + (($retargetRows | ForEach-Object { "$_`n" }) -join ''),
        [Text.UTF8Encoding]::new($false))
    $zone = "wgps-$([guid]::NewGuid().ToString('N')).invalid"
    $dnsTrace = "WireGuardProgramSplitDnsEtw-$([guid]::NewGuid().ToString('N'))"
    $responder = Start-Process -FilePath (Join-Path $RepositoryRoot 'build\test-dns-responder.exe') -ArgumentList @('--fixture') -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'dns responder.out') -RedirectStandardError (Join-Path $root 'dns responder.err')
    $null = $responder.Handle
    $dnsChildren.Add($responder)
    $dnsDispatcher = Start-Process -FilePath (Join-Path $RepositoryRoot 'build\dns-dispatcher.exe') -ArgumentList @(
        ('"{0}"' -f $dispatcherIdentities), '127.0.0.2', '127.0.0.2', '127.0.0.3', '127.0.0.3', $dnsTrace,
        ('"{0}"' -f (Join-Path $root 'dns dispatcher.log'))) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $root 'dns dispatcher.out') -RedirectStandardError (Join-Path $root 'dns dispatcher.err')
    $null = $dnsDispatcher.Handle
    $dnsChildren.Add($dnsDispatcher)
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while ([string](Get-Content -LiteralPath (Join-Path $root 'dns responder.out') -Raw -ErrorAction SilentlyContinue) -notmatch 'READY' -or
           [string](Get-Content -LiteralPath (Join-Path $root 'dns dispatcher.out') -Raw -ErrorAction SilentlyContinue) -notmatch 'READY') {
        if ($responder.HasExited -or $dnsDispatcher.HasExited -or $wait.Elapsed.TotalSeconds -gt 15) { throw 'The DNS fixture did not become ready.' }
        Start-Sleep -Milliseconds 100
    }
    $dnsRule = Add-DnsClientNrptRule -Namespace ".$zone" -NameServers '127.0.0.1' -DisplayName "WgpsTest-$zone" -PassThru
    & subst.exe $script:substDrive $substDirectory
    foreach ($index in 1..3) {
        foreach ($lane in @(@('selected', $substDns), @('direct', $directDns))) {
            $lookup = Start-Process -FilePath $lane[1] -ArgumentList @('--system', "$($lane[0])-$index.$zone", '3') -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $root "lookup $($lane[0]) $index.out") -RedirectStandardError (Join-Path $root "lookup $($lane[0]) $index.err")
            $null = $lookup.Handle
            Assert-True ($lookup.WaitForExit(15000)) 'the DNS lookup finishes'
            $lookup.WaitForExit()
            Assert-True ($lookup.ExitCode -eq 0) "the $($lane[0]) lookup resolves: $([IO.File]::ReadAllText((Join-Path $root "lookup $($lane[0]) $index.err")))"
            $lookup.Dispose()
        }
    }
    $observed = [string](Get-Content -LiteralPath (Join-Path $root 'dns responder.out') -Raw)
    Assert-True ($observed -match "TUNNEL selected-1\.$zone" -and $observed -notmatch 'DIRECT selected-' -and
        $observed -match "DIRECT direct-1\.$zone" -and $observed -notmatch 'TUNNEL direct-') `
        "a dispatcher started while the drive was gone keeps the selected copy's DNS in the tunnel lane: $observed"
    Write-Output 'OBSERVED: ordinary DNS of a listed executable on a substituted drive that was absent when the dispatcher started went to the tunnel lane.'
    foreach ($index in 0..1) {
        $side = @('a', 'b')[$index]
        $lookup = Invoke-NetProbe $retargetApps[$index] @('system-dns', "retarget-$side.$zone")
        Assert-True ($lookup.Text -match 'ANSWER 192\.0\.2\.1') "ordinary DNS from retained identity $side goes to the tunnel lane: $($lookup.Text)"
    }
    Write-Output 'OBSERVED: ordinary DNS from both retained identities of the interrupted alias went to the tunnel lane.'
    & subst.exe $script:substDrive /d
    $script:substDrive = $null
    $install = Invoke-Probe @('install', ('"{0}"' -f $twoApps), '192.0.2.3')
    Assert-True ($install.ExitCode -eq 0) "the two-application set is restored: $($install.Error)"

    $remove = Invoke-Probe @('remove')
    Assert-True ($remove.ExitCode -eq 0 -and $remove.Output -match '^REMOVED: 30 filter') "remove deletes every owned object: $($remove.Output) $($remove.Error)"
    Assert-True ((Invoke-Probe @('status')).Output -match '^ABSENT:') 'nothing owned remains after removal'
    $again = Invoke-Probe @('remove')
    Assert-True ($again.ExitCode -eq 0 -and $again.Output -match '^REMOVED: 0 filter') 'removal is idempotent'
    Assert-Rejected $oneApp '192.0.2.1' 'verification fails once the filters are removed'
    foreach ($check in @(@('tcp', $external, 443, 3000), @('udp-dns', $external, 3000))) {
        $after = Invoke-NetProbe $selectedOne $check
        Assert-True $after.Passed "a formerly listed copy reaches $($check -join ' ') again after removal: $($after.Text)"
    }
    Write-Output 'PASS: persistent WFP filters install, block listed IPv4 off the tunnel and IPv6 without the PIA driver, replace atomically, survive killed runs and remove against the real filter engine.'
} catch {
    foreach ($file in @(Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.out', '.err', '.txt' })) {
        Write-Output "Diagnostic $($file.Name):"
        Get-Content -LiteralPath $file.FullName -Tail 30
    }
    throw
} finally {
    $failures = [Collections.Generic.List[string]]::new()
    if ($script:substDrive) { & subst.exe $script:substDrive /d }
    foreach ($child in $dnsChildren) {
        try { if (-not $child.HasExited) { $child.Kill() }; $null = $child.WaitForExit(10000) } catch { $failures.Add([string]$_) }
        $child.Dispose()
    }
    if ($dnsRule) { try { Remove-DnsClientNrptRule -Name $dnsRule.Name -Force } catch { $failures.Add([string]$_) } }
    if ($dnsTrace) { & logman.exe stop $dnsTrace -ets 2>$null | Out-Null }
    if ($holder) {
        try { if (-not $holder.HasExited) { $holder.Kill() }; $null = $holder.WaitForExit(10000) } catch { $failures.Add([string]$_) }
        $holder.Dispose()
    }
    if ($observer) {
        try { [IO.File]::WriteAllText((Join-Path $root 'stop-observing'), 'stop') } catch { }
        $null = Wait-Job -Job $observer -Timeout 30
        Remove-Job -Job $observer -Force
    }
    $cleanup = Invoke-Probe @('remove')
    if ($cleanup.ExitCode -ne 0) { $failures.Add("WFP cleanup failed: $($cleanup.Error)") }
    if ($failures.Count) { throw "WFP fixture cleanup failed: $($failures -join ' | ')" }
}
