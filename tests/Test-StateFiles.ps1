# SPDX-License-Identifier: GPL-3.0-or-later
# State files are read and written as UTF-8; the installer never leaves its private key readable outside a
# protected directory; and cleanup never follows a link or deletes a directory it cannot prove it owns.
param([Parameter(Mandatory)] [string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

# The include list and other state files are UTF-8 without a BOM; Windows PowerShell's Get-Content reads such a
# file as ANSI, so a non-ASCII path would be corrupted on read and the corruption saved by the next change.
$encodingRoot = Join-Path ([IO.Path]::GetTempPath()) ("wgps-encoding-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($encodingRoot) | Out-Null
try {
    $definitions = @{}
    foreach ($entry in @(@('Tray.ps1', 'Get-IncludedApps'), @('Tray.ps1', 'Save-IncludedApps'), @('Invoke-WfpFilters.ps1', 'Get-IncludedPaths'))) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot "src\powershell\$($entry[0])"), [ref]$tokens, [ref]$errors)
        $found = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $entry[1] }, $true))
        Assert-True ($found.Count -eq 1) "$($entry[0]) defines $($entry[1])"
        $definitions[$entry[1]] = $found[0].Extent.Text
    }
    foreach ($definition in $definitions.Values) { . ([scriptblock]::Create($definition)) }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    # Percent-encoded UTF-8: Windows PowerShell reads this file as ANSI.
    $accented = [Uri]::UnescapeDataString('C:\Apps\Jos%C3%A9\App.exe')
    $wide = [Uri]::UnescapeDataString('C:\Tools\%E6%BC%A2%E5%AD%97\Tool.exe')
    $includeFile = Join-Path $encodingRoot 'included-apps.txt'
    $reloadFile = Join-Path $encodingRoot 'reload.request'
    [IO.File]::WriteAllLines($includeFile, [string[]]@('# selected', 'C:\Program Files\App\app.exe', $accented), $utf8)
    Assert-True (@(Get-IncludedApps) -ccontains $accented) 'the tray reads a non-ASCII included path intact'
    Save-IncludedApps (@(Get-IncludedApps) + $wide)
    $saved = $utf8.GetString([IO.File]::ReadAllBytes($includeFile))
    Assert-True ($saved.Contains($accented) -and $saved.Contains($wide) -and $saved[0] -ne [char]0xFEFF) 'an added app keeps the non-ASCII paths, in UTF-8 without a BOM'
    Save-IncludedApps @(Get-IncludedApps | Where-Object { $_ -cne $wide })
    $roundTrip = @([IO.File]::ReadAllLines($includeFile, $utf8))
    Assert-True (($roundTrip -join '|') -ceq ((@('C:\Program Files\App\app.exe', $accented) | Sort-Object) -join '|')) 'a removal round trip leaves the other non-ASCII path intact'
    $exe = $includeFile
    $IncludedAppsFile = $includeFile
    Assert-True (@(Get-IncludedPaths) -ccontains $accented) 'the WFP component reads a non-ASCII included path intact'
} finally {
    Remove-Item -LiteralPath $encodingRoot -Recurse -Force -ErrorAction SilentlyContinue
}
# The prepared profile holds the private key. Validation writes nothing; a prepared file is protected when it
# is created; installer staging is a protected directory, and staging an interrupted run left is removed.
$stagingRoot = Join-Path ([IO.Path]::GetTempPath()) ("wgps-staging-test-{0}" -f [guid]::NewGuid())
[IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
try {
    . (Join-Path $RepositoryRoot 'src\powershell\Common.ps1')
    $prepare = Join-Path $RepositoryRoot 'src\powershell\Prepare-Profile.ps1'
    $keyBytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
    $privateKey = [Convert]::ToBase64String($keyBytes)
    $source = Join-Path $stagingRoot 'source.conf'
    [IO.File]::WriteAllText($source, "[Interface]`r`nPrivateKey = $privateKey`r`nAddress = 192.0.2.2/32`r`nDNS = 203.0.113.53`r`n[Peer]`r`nPublicKey = $privateKey`r`nAllowedIPs = 0.0.0.0/0`r`nEndpoint = 198.51.100.10:51820`r`n")
    $validated = & $prepare -InputPath $source -ValidateOnly
    Assert-True ($validated.TunnelAddress -eq '192.0.2.2' -and $validated.TunnelDns -eq '203.0.113.53' -and
        @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -Force).Count -eq 1) 'profile validation derives the settings and writes nothing'

    # Only an elevated run, as on CI and in the installer, can create and use a directory that grants SYSTEM and
    # Administrators alone; an unelevated one could not even remove it again.
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated) {
        $staging = New-ProgramSplitPrivateDirectory -Path (Join-Path $stagingRoot ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid()))
        $refused = $false
        try { New-ProgramSplitPrivateDirectory -Path $staging | Out-Null } catch { $refused = $true }
        Assert-True ($refused -and (Test-ProgramSplitPrivateAcl -Path $staging)) 'installer staging is created protected and never adopted when it exists'
        $null = & $prepare -InputPath $source -OutputPath (Join-Path $staging 'WireGuardSplit.conf') -SettingsPath (Join-Path $staging 'settings.json') -SkipAcl
        Assert-True (Test-ProgramSplitPrivateTree -Path $staging) 'prepared files in staging carry only the SYSTEM and Administrators access they inherit'
        # Without a protected directory, a prepared file is protected itself when it is created.
        $standalone = Join-Path $stagingRoot 'standalone'
        $null = & $prepare -InputPath $source -OutputPath (Join-Path $standalone 'WireGuardSplit.conf') -SettingsPath (Join-Path $standalone 'settings.json')
        foreach ($file in @(Get-ChildItem -LiteralPath $standalone -Force -File)) {
            $acl = Get-Acl -LiteralPath $file.FullName
            $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
            Assert-True ($acl.AreAccessRulesProtected -and ($sids -join ',') -eq 'S-1-5-18,S-1-5-32-544') "a prepared file grants only SYSTEM and Administrators: $($file.Name)"
        }
        Remove-ProgramSplitTree -Path $standalone
        Assert-True ((@(Get-ChildItem -LiteralPath $staging -Force -File | ForEach-Object { $_.Name } | Sort-Object) -join ',') -eq 'settings.json,WireGuardSplit.conf') `
            'preparation leaves no temporary copy beside the profile'
        # An interrupted run leaves only this protected directory; the next installation removes it.
        $nearMatch = Join-Path $stagingRoot 'WireGuardProgramSplit-install-not-owned'
        [IO.Directory]::CreateDirectory($nearMatch) | Out-Null
        Remove-ProgramSplitStaleStaging -Parents @($stagingRoot)
        Assert-True (-not (Test-Path -LiteralPath $staging) -and (Test-Path -LiteralPath $nearMatch)) 'stale exact-owned staging is removed and a near match is kept'
    } else {
        Write-Output 'SKIPPED: protected installer staging needs an elevated run (CI runs it elevated).'
    }

    # Cleanup never follows a link: a file symbolic link or a junction inside a staging directory is deleted
    # itself, and the file outside keeps its contents.
    $outside = Join-Path $stagingRoot 'outside'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    $victim = Join-Path $outside 'victim.txt'
    [IO.File]::WriteAllText($victim, 'unrelated contents')
    $newLinkedStaging = {
        param($Directory)
        New-Item -ItemType Junction -Path (Join-Path $Directory 'junction') -Target $outside | Out-Null
        $linked = $false
        try { New-Item -ItemType SymbolicLink -Path (Join-Path $Directory 'link.conf') -Target $victim -ErrorAction Stop | Out-Null; $linked = $true } catch { }
        [IO.File]::WriteAllText((Join-Path $Directory 'WireGuardSplit.conf'), 'staged')
        $linked
    }
    $plain = Join-Path $stagingRoot 'plain-linked'
    [IO.Directory]::CreateDirectory($plain) | Out-Null
    $fileLinked = & $newLinkedStaging $plain
    # A hard link shares the outside file's contents; removal deletes only this name.
    New-Item -ItemType HardLink -Path (Join-Path $plain 'alias.conf') -Target $victim | Out-Null
    Remove-ProgramSplitTree -Path $plain
    Assert-True (-not (Test-Path -LiteralPath $plain) -and [IO.File]::ReadAllText($victim) -eq 'unrelated contents' -and (Test-Path -LiteralPath $victim)) `
        'removal deletes symbolic links, junctions and hard-link names themselves and leaves their targets and contents untouched'
    if (-not $fileLinked) { Write-Output 'SKIPPED: creating a file symbolic link needs elevation or Developer Mode; the junction case ran.' }
    # A matching directory that the installer did not create protected is skipped, not opened.
    $foreign = Join-Path $stagingRoot ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid())
    [IO.Directory]::CreateDirectory($foreign) | Out-Null
    $null = & $newLinkedStaging $foreign
    $warnings = @(Remove-ProgramSplitStaleStaging -Parents @($stagingRoot) 3>&1 | ForEach-Object { [string]$_ })
    Assert-True ((Test-Path -LiteralPath (Join-Path $foreign 'WireGuardSplit.conf')) -and [IO.File]::ReadAllText((Join-Path $foreign 'WireGuardSplit.conf')) -eq 'staged' -and
        [IO.File]::ReadAllText($victim) -eq 'unrelated contents' -and @($warnings -match 'left in place').Count -eq 1) `
        'stale cleanup skips and reports a matching directory it cannot prove the installer owns'
    Remove-ProgramSplitTree -Path $foreign
    if ($elevated) {
        # Owned staging holding a link is not the installer's tree: it is skipped whole.
        $owned = New-ProgramSplitPrivateDirectory -Path (Join-Path $stagingRoot ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid()))
        $null = & $newLinkedStaging $owned
        New-Item -ItemType HardLink -Path (Join-Path $owned 'alias.conf') -Target $victim | Out-Null
        $warnings = @(Remove-ProgramSplitStaleStaging -Parents @($stagingRoot) 3>&1 | ForEach-Object { [string]$_ })
        Assert-True ((Test-Path -LiteralPath (Join-Path $owned 'WireGuardSplit.conf')) -and [IO.File]::ReadAllText($victim) -eq 'unrelated contents' -and
            @($warnings -match 'left in place').Count -eq 1) 'owned staging holding a link or a foreign-protected file is skipped whole'
        Remove-ProgramSplitTree -Path $owned
        # A descendant with an extra writable ACE: skipped whole as well.
        $loosened = New-ProgramSplitPrivateDirectory -Path (Join-Path $stagingRoot ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid()))
        $loose = Join-Path $loosened 'WireGuardSplit.conf'
        [IO.File]::WriteAllText($loose, 'staged')
        $looseAcl = Get-Acl -LiteralPath $loose
        $looseAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Modify', 'Allow'))
        [IO.File]::SetAccessControl($loose, $looseAcl)
        $warnings = @(Remove-ProgramSplitStaleStaging -Parents @($stagingRoot) 3>&1 | ForEach-Object { [string]$_ })
        Assert-True ((Test-Path -LiteralPath $loose) -and @($warnings -match 'left in place').Count -eq 1) 'staging with a user-writable descendant is skipped whole'
        Remove-ProgramSplitTree -Path $loosened
        # The installer's own tree, files inheriting the directory's descriptor, is accepted and removed.
        $clean = New-ProgramSplitPrivateDirectory -Path (Join-Path $stagingRoot ("WireGuardProgramSplit-install-{0}" -f [guid]::NewGuid()))
        [IO.Directory]::CreateDirectory((Join-Path $clean 'sub')) | Out-Null
        [IO.File]::WriteAllText((Join-Path $clean 'sub\settings.json'), '{}')
        $null = & $prepare -InputPath $source -OutputPath (Join-Path $clean 'WireGuardSplit.conf') -SettingsPath (Join-Path $clean 'settings.json') -SkipAcl
        Assert-True (Test-ProgramSplitPrivateTree -Path $clean) 'files and subdirectories the installer writes into its staging inherit exactly its descriptor'
        Remove-ProgramSplitStaleStaging -Parents @($stagingRoot)
        Assert-True (-not (Test-Path -LiteralPath $clean) -and [IO.File]::ReadAllText($victim) -eq 'unrelated contents') 'stale staging with exactly the installer descriptor is removed'
    }
    $installSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'Install.ps1'))
    $prepareSource = [IO.File]::ReadAllText($prepare)
    Assert-True ($installSource -notmatch 'GetTempPath' -and $installSource.IndexOf('-ValidateOnly') -lt $installSource.IndexOf('if ($PlanOnly) { return $plan }') -and
        $installSource.IndexOf('if ($PlanOnly) { return $plan }') -lt $installSource.IndexOf('New-ProgramSplitPrivateDirectory') -and
        $installSource.IndexOf('New-ProgramSplitPrivateDirectory') -lt $installSource.IndexOf('-OutputPath $stagedProfile')) `
        'the installer plans without staging and stages only into a directory protected first'
    Assert-True ($prepareSource -notmatch 'Set-Acl' -and $prepareSource -notmatch 'GetCurrent\(\)\.User') 'profile files are never written first and protected afterwards, nor granted to the current user'
    foreach ($name in @('Install.ps1', 'Uninstall.ps1', 'Migrate-Installation.ps1')) {
        Assert-True ([IO.File]::ReadAllText((Join-Path $RepositoryRoot $name)) -notmatch 'Remove-Item[^\r\n]*-Recurse') "$name removes trees only without following links"
    }
    foreach ($script in @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1' -File)) {
        Assert-True ([IO.File]::ReadAllText($script.FullName) -notmatch 'Remove-Item[^\r\n]*-Recurse') "$($script.Name) removes trees only without following links"
    }
} finally {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$productScripts = @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1' -File) +
    @('Install.ps1', 'Uninstall.ps1', 'Migrate-Installation.ps1' | ForEach-Object { Get-Item -LiteralPath (Join-Path $RepositoryRoot $_) })
foreach ($script in $productScripts) {
    $ansiReads = @([IO.File]::ReadAllLines($script.FullName) | Where-Object { $_ -match 'Get-Content' -and $_ -notmatch '-Encoding' })
    Assert-True (-not $ansiReads.Count) "$($script.Name) reads state as ANSI with Get-Content: $($ansiReads -join ' | ')"
}

Write-Output "PASS: state files round-trip as UTF-8, installer staging stays protected, and cleanup never follows links."
