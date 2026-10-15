# SPDX-License-Identifier: GPL-3.0-or-later
Set-StrictMode -Version Latest

function Assert-ProgramSplit64BitPowerShell {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'WireGuard Program Split requires 64-bit Windows PowerShell for process ownership checks.'
    }
}

function Test-ProgramSplitProcessPath {
    param([int] $ProcessId, [Parameter(Mandatory)] [string] $ExpectedPath)

    if ($ProcessId -le 0) { return $false }
    if (-not ('WireGuardProgramSplit.ProcessIdentity' -as [type])) {
        # Process.MainModule enumerates modules. This read-only check needs only the
        # image name; pin the process handle while querying it, without caching PIDs.
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace WireGuardProgramSplit {
    public static class ProcessIdentity {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags,
            StringBuilder path, ref int size);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        public static bool Matches(int pid, string expected) {
            IntPtr process = OpenProcess(0x1000, false, pid); // QUERY_LIMITED_INFORMATION
            if (process == IntPtr.Zero) return false;
            try {
                uint code;
                if (!GetExitCodeProcess(process, out code) || code != 259) return false;
                int size = 32768;
                var path = new StringBuilder(size);
                return QueryFullProcessImageName(process, 0, path, ref size) &&
                    String.Equals(path.ToString(), expected, StringComparison.OrdinalIgnoreCase);
            } finally { CloseHandle(process); }
        }
    }
}
'@
    }
    return [WireGuardProgramSplit.ProcessIdentity]::Matches($ProcessId, $ExpectedPath)
}

function Get-ProgramSplitOwnedTraceNames {
    param(
        [AllowNull()] [string] $StateValue,
        [AllowEmptyCollection()] [string[]] $CommandLines = @()
    )

    $pattern = 'WireGuardProgramSplitDnsEtw-[0-9a-f]{32}'
    $names = [Collections.Generic.List[string]]::new()
    if ($StateValue -and $StateValue.Trim() -match "^$pattern$") { $names.Add($Matches[0]) }
    foreach ($commandLine in $CommandLines) {
        foreach ($match in [regex]::Matches([string]$commandLine, $pattern)) { $names.Add($match.Value) }
    }
    @($names | Sort-Object -Unique)
}

function Get-ProgramSplitTaskArguments {
    param([Parameter(Mandatory)] [string] $ScriptPath)

    return '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $ScriptPath
}

function Test-ProgramSplitTaskOwnership {
    param(
        [Parameter(Mandatory)] $Task,
        [Parameter(Mandatory)] [string] $PowerShellPath,
        [Parameter(Mandatory)] [string] $ScriptPath
    )

    $actions = @($Task.Actions)
    if ($actions.Count -ne 1) { return $false }
    $execute = $actions[0].PSObject.Properties['Execute']
    $arguments = $actions[0].PSObject.Properties['Arguments']
    if ($null -eq $execute -or $null -eq $arguments) { return $false }
    $actualExecutable = [Environment]::ExpandEnvironmentVariables([string] $execute.Value)
    $expectedExecutable = [Environment]::ExpandEnvironmentVariables($PowerShellPath)
    return $actualExecutable -eq $expectedExecutable -and
        [string] $arguments.Value -eq (Get-ProgramSplitTaskArguments -ScriptPath $ScriptPath)
}

function Get-ProgramSplitServiceCommand {
    param(
        [Parameter(Mandatory)] [string] $HostPath,
        [Parameter(Mandatory)] [string] $ArgumentPath
    )

    return '"{0}" /service "{1}"' -f $HostPath, $ArgumentPath
}

function Test-ProgramSplitServiceOwnership {
    param(
        [Parameter(Mandatory)] $Service,
        [Parameter(Mandatory)] [string] $HostPath,
        [Parameter(Mandatory)] [string] $ArgumentPath
    )

    if ([string] $Service.PathName -eq (Get-ProgramSplitServiceCommand -HostPath $HostPath `
            -ArgumentPath $ArgumentPath)) { return $true }
    # Existing installations used unquoted commands only under paths without whitespace.
    return $HostPath -notmatch '\s' -and $ArgumentPath -notmatch '\s' -and
        [string] $Service.PathName -eq ('{0} /service {1}' -f $HostPath, $ArgumentPath)
}

function Test-ProgramSplitNrptRuleOwnership {
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] [string] $DisplayName
    )

    $namespaces = @($Rule.Namespace)
    $nameServers = @($Rule.NameServers)
    return [string] $Rule.DisplayName -eq $DisplayName -and
        $namespaces.Count -eq 1 -and [string] $namespaces[0] -eq '.' -and
        $nameServers.Count -eq 1 -and [string] $nameServers[0] -eq '127.0.0.1' -and
        [string] $Rule.Comment -eq 'Owned by WireGuardProgramSplit; safe to remove on recovery.'
}

function Get-ProgramSplitLocalNrptRules {
    # The local rules Get-DnsClientNrptRule reports, read from the keys it reads. Under a tenth of the CIM query's
    # cost, so the controller's two-second pass uses it; validation keeps the CIM and effective-policy checks.
    param(
        [Microsoft.Win32.RegistryKey] $Hive = [Microsoft.Win32.Registry]::LocalMachine,
        [string] $Path = 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
    )

    $key = $Hive.OpenSubKey($Path)
    if (-not $key) { return }
    try {
        foreach ($name in $key.GetSubKeyNames()) {
            $rule = $key.OpenSubKey($name)
            if (-not $rule) { continue }
            try {
                [pscustomobject]@{
                    Name = $name
                    DisplayName = [string] $rule.GetValue('DisplayName', '')
                    Namespace = @($rule.GetValue('Name', @()))
                    NameServers = @(([string] $rule.GetValue('GenericDNSServers', '')) -split ';' |
                        ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    Comment = [string] $rule.GetValue('Comment', '')
                }
            } finally { $rule.Dispose() }
        }
    } finally { $key.Dispose() }
}

function Assert-ProgramSplitNrptRulesCompatible {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [Parameter(Mandatory)] [string] $DisplayName,
        [switch] $RequireOwned
    )

    $owned = @($Rules | Where-Object {
        Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $DisplayName
    })
    if ($Rules | Where-Object { $_.DisplayName -eq $DisplayName -and $_ -notin $owned }) {
        throw 'A foreign NRPT rule uses the WireGuard Program Split display name.'
    }
    if ($Rules | Where-Object { $_.Namespace -contains '.' -and $_ -notin $owned }) {
        throw 'Another catch-all NRPT rule is active.'
    }
    if ($RequireOwned -and $owned.Count -ne 1) {
        throw 'The owned local split-DNS NRPT rule is missing or duplicated.'
    }
}

function Assert-ProgramSplitEffectiveNrptPolicy {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies)

    $catchAll = @($Policies | Where-Object { $_.Namespace -contains '.' })
    if ($catchAll.Count -ne 1) { throw 'Effective NRPT must contain exactly one catch-all policy.' }
    $servers = @($catchAll[0].NameServers | ForEach-Object {
        if ($_ -is [Net.IPAddress]) { $_.IPAddressToString } else { [string]$_ }
    })
    if ($servers.Count -ne 1 -or $servers[0] -ne '127.0.0.1') {
        throw 'Effective catch-all NRPT policy does not use the owned loopback dispatcher.'
    }
}

function Get-ProgramSplitForeignNrptNamespaces {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
        [Parameter(Mandatory)] [string] $DisplayName
    )

    # A narrower namespace rule wins over the owned catch-all, so Windows sends those names to the servers
    # the rule names for selected and unlisted applications alike. Reported, not treated as a failure.
    $namespaces = @($Rules | Where-Object { -not (Test-ProgramSplitNrptRuleOwnership -Rule $_ -DisplayName $DisplayName) } |
        ForEach-Object { @($_.Namespace) }) + @($Policies | ForEach-Object { @($_.Namespace) })
    @($namespaces | ForEach-Object { [string] $_ } | Where-Object { $_ -and $_ -ne '.' } | Sort-Object -Unique)
}

# NRPT changes by the controller, the components and the dispatcher supervisor in controller-service.exe
# are serialized by this lock. Invariant: while the stack is enabled the owned rule names a ready owned
# dispatcher, except for at most about 15 seconds after the dispatcher ends, when the supervisor suspends
# it; nothing but disable, service stop or uninstall removes it otherwise.
function Use-ProgramSplitNrptLock {
    param([Parameter(Mandatory)] [scriptblock] $Action)

    $lock = [Threading.Mutex]::new($false, 'Global\WireGuardProgramSplitNrptComponent')
    $held = $false
    try {
        try { $held = $lock.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Timed out waiting for the NRPT component lock.' }
        & $Action
    } finally {
        if ($held) { $lock.ReleaseMutex() }
        $lock.Dispose()
    }
}

function Test-ProgramSplitDispatcherAnswers {
    # The liveness query controller-service.exe's supervisor sends: the dispatcher's receive loop answers it
    # itself, without attribution or an upstream, so a hung or suspended dispatcher does not.
    param([ValidateRange(50, 5000)] [int] $TimeoutMilliseconds = 1000)

    $client = [Net.Sockets.UdpClient]::new()
    try {
        $client.Client.ReceiveTimeout = $TimeoutMilliseconds
        $client.Connect([Net.IPAddress]::Loopback, 53)
        $id = Get-Random -Maximum 65536
        $query = [Collections.Generic.List[byte]]::new()
        $query.AddRange([byte[]]@(($id -shr 8), ($id -band 0xff), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        foreach ($label in @('liveness', 'wireguard-program-split', 'invalid')) {
            $query.Add([byte]$label.Length)
            $query.AddRange([Text.Encoding]::ASCII.GetBytes($label))
        }
        $query.AddRange([byte[]]@(0, 0, 1, 0, 1))
        $null = $client.Send($query.ToArray(), $query.Count)
        $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        $reply = $client.Receive([ref]$remote)
        return $reply.Length -ge 12 -and $reply[0] -eq ($id -shr 8) -and $reply[1] -eq ($id -band 0xff) -and
            [bool]($reply[2] -band 0x80)
    } catch { return $false } finally { $client.Dispose() }
}

function Test-ProgramSplitDispatcherReady {
    # A ready owned dispatcher: the managed process, with its exact image, listening on 127.0.0.1:53 and
    # answering the liveness query.
    param([Parameter(Mandatory)] [string] $Root)

    $managedPid = 0
    try { $pidText = [IO.File]::ReadAllText((Join-Path $Root 'state\dns-dispatcher.pid')) } catch { return $false }
    if (-not [int]::TryParse($pidText, [ref]$managedPid)) { return $false }
    if (-not (Test-ProgramSplitProcessPath -ProcessId $managedPid -ExpectedPath (Join-Path $Root 'bin\dns-dispatcher.exe'))) {
        return $false
    }
    if (-not (Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $managedPid })) { return $false }
    return Test-ProgramSplitDispatcherAnswers
}

function Wait-ProgramSplitProbe {
    param(
        [Parameter(Mandatory)] [scriptblock] $Probe,
        [ValidateRange(0, 60000)] [int] $TimeoutMilliseconds = 8000,
        [ValidateRange(0, 5000)] [int] $RetryMilliseconds = 250,
        [Threading.WaitHandle] $StopEvent
    )

    # Monotonic: a wall-clock correction must neither cut the wait short nor extend it.
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try { & $Probe; return }
        catch { $lastError = $_ }
        if ($timer.ElapsedMilliseconds -ge $TimeoutMilliseconds) { throw $lastError }
        # A stop request ends the wait at once instead of finishing a start that is about to be torn down.
        if ($StopEvent) {
            if ($StopEvent.WaitOne($RetryMilliseconds)) { throw 'Readiness wait abandoned: a stop was requested.' }
        } elseif ($RetryMilliseconds) { Start-Sleep -Milliseconds $RetryMilliseconds }
    }
}

function Test-ProgramSplitEndpointRouteOwnership {
    param(
        [Parameter(Mandatory)] $Route,
        [Parameter(Mandatory)] $State
    )

    return [string] $Route.DestinationPrefix -eq [string] $State.DestinationPrefix -and
        [uint32] $Route.InterfaceIndex -eq [uint32] $State.InterfaceIndex -and
        [string] $Route.NextHop -eq [string] $State.NextHop -and
        [uint16] $Route.RouteMetric -eq [uint16] $State.RouteMetric
}

function Get-ProgramSplitMigrationMismatches {
    # Migration replaces only the scripts it names. Every other installed script and project binary must
    # already be this release's, or the relocated controller would run against components it does not match.
    param(
        [Parameter(Mandatory)] [string] $InstalledRoot,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [string] $BuildDirectory,
        [Parameter(Mandatory)] [string[]] $ReplacedScripts,
        [Parameter(Mandatory)] [string[]] $Executables
    )

    $mismatches = [Collections.Generic.List[string]]::new()
    foreach ($script in @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1' -File)) {
        if ($script.Name -in $ReplacedScripts) { continue }
        $installed = Join-Path $InstalledRoot "src\$($script.Name)"
        # Line endings depend on the checkout, not the release.
        if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or
            [IO.File]::ReadAllText($installed).Replace("`r`n", "`n") -cne
                [IO.File]::ReadAllText($script.FullName).Replace("`r`n", "`n")) {
            $mismatches.Add("src\$($script.Name)")
        }
    }
    foreach ($name in $Executables) {
        $built = Join-Path $BuildDirectory $name
        $installed = Join-Path $InstalledRoot "bin\$name"
        if (-not (Test-Path -LiteralPath $built -PathType Leaf) -or -not (Test-Path -LiteralPath $installed -PathType Leaf) -or
            (Get-FileHash -LiteralPath $built).Hash -ne (Get-FileHash -LiteralPath $installed).Hash) {
            $mismatches.Add("bin\$name")
        }
    }
    @($mismatches)
}

function Assert-ProgramSplitInstallNamesAvailable {
    param($Tasks, $Services)

    if (@($Tasks | Where-Object { $null -ne $_ }).Count -gt 0 -or
        @($Services | Where-Object { $null -ne $_ }).Count -gt 0) {
        throw 'A scheduled task or service already uses a WireGuard Program Split resource name.'
    }
}

function Clear-ProgramSplitStoppedMarker {
    param([Parameter(Mandatory)] [string] $Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $Path) {
        throw 'The stale controller stopped acknowledgement could not be cleared.'
    }
}

# Installer staging holds the prepared profile and its private key. It is created protected (SYSTEM and
# Administrators, nothing inherited) under %ProgramData%, before any key byte is written into it.
$script:ProgramSplitStagingPattern = '^WireGuardProgramSplit-install-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

function Get-ProgramSplitAclShape {
    # One item's security descriptor, normalized: owner, whether the DACL is protected, and each ACE as
    # type|SID|rights|inherited|inheritance flags|propagation flags, sorted.
    param([Parameter(Mandatory)] [string] $Path)

    $acl = Get-Acl -LiteralPath $Path
    [pscustomobject]@{
        Owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
        Protected = $acl.AreAccessRulesProtected
        Aces = (@($acl.Access | ForEach-Object {
            '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.AccessControlType, $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value,
                $_.FileSystemRights, $_.IsInherited, $_.InheritanceFlags, $_.PropagationFlags
        } | Sort-Object) -join ';')
    }
}

function Test-ProgramSplitPrivateAcl {
    # Exactly the descriptor the installer gives its private directories: a real directory (not a link),
    # owned by SYSTEM or Administrators, with a protected DACL holding only explicit SYSTEM and Administrators
    # full control that every file and subdirectory inherits.
    param([Parameter(Mandatory)] [string] $Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
        $shape = Get-ProgramSplitAclShape -Path $Path
        $shape.Owner -in @('S-1-5-18', 'S-1-5-32-544') -and $shape.Protected -and $shape.Aces -ceq
            'Allow|S-1-5-18|FullControl|False|ContainerInherit, ObjectInherit|None;Allow|S-1-5-32-544|FullControl|False|ContainerInherit, ObjectInherit|None'
    } catch { $false }
}

function Test-ProgramSplitPrivateTree {
    # The private directory and every descendant: no link anywhere, each owned by SYSTEM or Administrators,
    # and each holding only the SYSTEM and Administrators full control inherited from the directory. Since
    # then only SYSTEM and Administrators can change anything inside, nobody else can swap in a link between
    # this check and the deletion that follows.
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-ProgramSplitPrivateAcl -Path $Path)) { return $false }
    try {
        $pending = [Collections.Generic.Stack[string]]::new()
        $pending.Push($Path)
        while ($pending.Count) {
            foreach ($child in @([IO.DirectoryInfo]::new($pending.Pop()).EnumerateFileSystemInfos())) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
                $directory = [bool]($child.Attributes -band [IO.FileAttributes]::Directory)
                $flags = if ($directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
                $shape = Get-ProgramSplitAclShape -Path $child.FullName
                if ($shape.Owner -notin @('S-1-5-18', 'S-1-5-32-544') -or $shape.Protected -or $shape.Aces -cne
                        "Allow|S-1-5-18|FullControl|True|$flags|None;Allow|S-1-5-32-544|FullControl|True|$flags|None") { return $false }
                if ($directory) { $pending.Push($child.FullName) }
            }
        }
        $true
    } catch { $false }
}

function New-ProgramSplitPrivateDirectory {
    param([Parameter(Mandatory)] [string] $Path)

    # CreateDirectory applies the descriptor only to a directory it creates, so an existing one is refused.
    if (Test-Path -LiteralPath $Path) { throw "A private directory already exists: $Path" }
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    if (-not (Test-ProgramSplitPrivateAcl -Path $Path)) { throw "The private directory is not protected: $Path" }
    $Path
}

function Get-ProgramSplitStagingParents {
    # Staging now lives under %ProgramData%; releases before 0.3.2 staged under %TEMP%.
    @($env:ProgramData, [IO.Path]::GetTempPath()) | Where-Object { $_ }
}

function Remove-ProgramSplitStaleStaging {
    # Staging left by an interrupted installation. The name alone proves nothing: a directory is removed only
    # when it and everything in it carry exactly the descriptor the installer sets. Anything else is skipped
    # and reported, and nothing in it is deleted.
    param([Parameter(Mandatory)] [string[]] $Parents)

    foreach ($parent in $Parents) {
        foreach ($directory in @(Get-ChildItem -LiteralPath $parent -Directory -Filter 'WireGuardProgramSplit-install-*' -Force -ErrorAction Stop |
                Where-Object { $_.Name -match $script:ProgramSplitStagingPattern })) {
            try { Remove-ProgramSplitStagingDirectory -Path $directory.FullName }
            catch { Write-Warning $_.Exception.Message }
        }
    }
}

# Files are deleted, never overwritten first. On SSDs and NTFS an overwrite does not reliably remove the old
# data (wear levelling, the journal), and writing through a name can change a hard-linked file elsewhere, so
# confidentiality rests on the ACL while the data exists and on deletion afterwards.
function Remove-ProgramSplitTree {
    # Removes a file or directory tree without ever following a link: a symbolic link or junction (any
    # reparse point) is deleted itself, never entered, so its target is untouched. A hard link loses only
    # this name.
    param([Parameter(Mandatory)] [string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if ($item.PSIsContainer) { [IO.Directory]::Delete($item.FullName, $false) } else { [IO.File]::Delete($item.FullName) }
        return
    }
    if ($item.PSIsContainer) {
        foreach ($child in @([IO.DirectoryInfo]::new($item.FullName).EnumerateFileSystemInfos())) {
            Remove-ProgramSplitTree -Path $child.FullName
        }
        [IO.Directory]::Delete($item.FullName, $false)
        return
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($item.FullName, 'Normal') }
    [IO.File]::Delete($item.FullName)
}

function Remove-ProgramSplitStagingDirectory {
    # Installer staging is deleted only when it and every descendant carry exactly the installer's
    # descriptor; otherwise it is left in place, untouched, and reported.
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-ProgramSplitPrivateTree -Path $Path)) {
        throw "Installer staging was left in place: it or something in it is not protected as the installer creates it: $Path"
    }
    try { Remove-ProgramSplitTree -Path $Path }
    catch { throw "Sensitive installer staging could not be removed: $Path. $($_.Exception.Message)" }
    if (Test-Path -LiteralPath $Path) {
        throw "Sensitive installer staging could not be removed: $Path."
    }
}

function Close-ProgramSplitInstallScope {
    param(
        [AllowNull()] [string] $StagingPath,
        [Parameter(Mandatory)] [Threading.Mutex] $Mutex,
        [Parameter(Mandatory)] [bool] $MutexHeld
    )

    try {
        if ($StagingPath) { Remove-ProgramSplitStagingDirectory -Path $StagingPath }
    } finally {
        try {
            if ($MutexHeld) { $Mutex.ReleaseMutex() }
        } finally { $Mutex.Dispose() }
    }
}

function Install-ProgramSplitProfilePair {
    param(
        [Parameter(Mandatory)] [string] $ActiveProfile,
        [Parameter(Mandatory)] [string] $ActiveSettings,
        [Parameter(Mandatory)] [string] $PreparedProfile,
        [Parameter(Mandatory)] [string] $PreparedSettings
    )

    $profileBackup = "$ActiveProfile.previous"
    $settingsBackup = "$ActiveSettings.previous"
    if ((Test-Path -LiteralPath $profileBackup) -or (Test-Path -LiteralPath $settingsBackup)) {
        throw 'A preserved profile recovery backup already exists; recover it before importing again.'
    }
    $backupsComplete = $false
    $replacementStarted = $false
    $discardBackups = $false
    $rolledBack = $false
    try {
        Copy-Item -LiteralPath $ActiveProfile -Destination $profileBackup -Force
        Copy-Item -LiteralPath $ActiveSettings -Destination $settingsBackup -Force
        $backupsComplete = $true
        $replacementStarted = $true
        Move-Item -LiteralPath $PreparedProfile -Destination $ActiveProfile -Force
        Move-Item -LiteralPath $PreparedSettings -Destination $ActiveSettings -Force
    } catch {
        $failure = $_
        if ($backupsComplete -and $replacementStarted) {
            $rollbackErrors = [Collections.Generic.List[string]]::new()
            foreach ($pair in @(
                @($profileBackup, $ActiveProfile),
                @($settingsBackup, $ActiveSettings)
            )) {
                try { Copy-Item -LiteralPath $pair[0] -Destination $pair[1] -Force }
                catch { $rollbackErrors.Add($_.Exception.Message) }
            }
            if ($rollbackErrors.Count) {
                throw "$($failure.Exception.Message) Rollback also failed: $($rollbackErrors -join '; ')"
            }
            $rolledBack = $true
        } else {
            $discardBackups = $true
        }
        throw $failure
    } finally {
        Remove-Item -LiteralPath $PreparedProfile, $PreparedSettings -Force -ErrorAction SilentlyContinue
        if ($discardBackups -or $rolledBack) {
            Remove-Item -LiteralPath $profileBackup, $settingsBackup -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{ Profile = $profileBackup; Settings = $settingsBackup }
}

function Restore-ProgramSplitProfilePair {
    param(
        [Parameter(Mandatory)] [string] $ActiveProfile,
        [Parameter(Mandatory)] [string] $ActiveSettings,
        [Parameter(Mandatory)] [string] $StoppedMarker,
        [ValidateRange(0, 300)] [int] $TimeoutSeconds = 20
    )

    $profileBackup = "$ActiveProfile.previous"
    $settingsBackup = "$ActiveSettings.previous"
    if (-not (Test-Path -LiteralPath $profileBackup -PathType Leaf) -and
        -not (Test-Path -LiteralPath $settingsBackup -PathType Leaf)) { return }

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $StoppedMarker -PathType Leaf)) {
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            throw 'The controller did not confirm that the managed stack stopped; backups were preserved.'
        }
        Start-Sleep -Milliseconds 250
    }

    $restored = $false
    try {
        if (Test-Path -LiteralPath $profileBackup -PathType Leaf) {
            Copy-Item -LiteralPath $profileBackup -Destination $ActiveProfile -Force
        }
        if (Test-Path -LiteralPath $settingsBackup -PathType Leaf) {
            Copy-Item -LiteralPath $settingsBackup -Destination $ActiveSettings -Force
        }
        $restored = $true
    } finally {
        if ($restored) {
            Remove-Item -LiteralPath $profileBackup, $settingsBackup -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ProgramSplitConfiguration {
    param([Parameter(Mandatory)] [string] $Root)

    $settingsPath = Join-Path $Root 'config\settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
        throw "Missing local settings: $settingsPath"
    }
    $settings = [IO.File]::ReadAllText($settingsPath) | ConvertFrom-Json
    foreach ($name in @('TunnelAddress', 'TunnelDns')) {
        $value = [string] $settings.$name
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($value, [ref] $parsed) -or
            $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Local setting $name must be one IPv4 address."
        }
    }

    [pscustomobject]@{
        Root = $Root
        AdapterName = 'WireGuardSplit'
        ServiceName = 'WireGuardTunnel$WireGuardSplit'
        ControllerServiceName = 'WireGuardProgramSplitController'
        TrayTask = 'WireGuard Program Split Tray'
        NrptDisplayName = 'WireGuard Program Split local dispatcher'
        ProfilePath = Join-Path $Root 'profiles\WireGuardSplit.conf'
        SettingsPath = $settingsPath
        TunnelAddress = [string] $settings.TunnelAddress
        TunnelDns = [string] $settings.TunnelDns
        TunnelDefaultMetric = 9999
    }
}

function Get-ProgramSplitPhysicalDefault {
    param([Parameter(Mandatory)] [string] $AdapterName)

    $candidates = foreach ($route in Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
        -PolicyStore ActiveStore -ErrorAction Stop) {
        $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction SilentlyContinue
        if ($interface -and $route.InterfaceAlias -ne $AdapterName) {
            [pscustomobject]@{
                Route = $route
                EffectiveMetric = [int64] $route.RouteMetric + [int64] $interface.InterfaceMetric
            }
        }
    }
    $winner = $candidates | Sort-Object EffectiveMetric | Select-Object -First 1
    if (-not $winner) { throw 'No physical IPv4 default gateway found.' }
    return $winner.Route
}

function Test-ProgramSplitPhysicalInputs {
    # True while the host still has the physical default route, source address and
    # pre-dispatch resolver the dispatcher needs. A transport failure without them is an
    # uplink outage, not a fault in this stack: restarting the stack would remove the
    # NRPT rule and dispatcher while the tunnel cannot work anyway, which sends selected
    # applications' DNS to the physical resolver for nothing.
    param([Parameter(Mandatory)] [string] $AdapterName, [string] $TunnelDns)

    try {
        $physical = Get-ProgramSplitPhysicalDefault -AdapterName $AdapterName
        $source = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $physical.InterfaceIndex -ErrorAction Stop |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1 -ExpandProperty IPAddress
        $resolvers = @(Get-ProgramSplitPhysicalResolvers -AdapterName $AdapterName -TunnelDns $TunnelDns `
            -InterfaceIndex $physical.InterfaceIndex)
        return [bool] ($source -and $resolvers.Count)
    } catch { return $false }
}

function Get-ProgramSplitPhysicalResolvers {
    # The resolvers the dispatcher forwards unlisted names to, in the order the physical interface lists
    # them: at most three, each neither the loopback dispatcher nor the tunnel resolver. The dispatcher
    # passes over one that stops answering, so a dead primary with a live secondary is not an outage. A caller
    # that has already chosen the physical interface passes its index, so the source address and resolvers
    # come from one interface even during a handoff, and the routes are not enumerated twice.
    param([Parameter(Mandatory)] [string] $AdapterName, [string] $TunnelDns, [uint32] $InterfaceIndex)

    try {
        if (-not $InterfaceIndex) { $InterfaceIndex = (Get-ProgramSplitPhysicalDefault -AdapterName $AdapterName).InterfaceIndex }
        $parsed = $null
        return @((Get-DnsClientServerAddress -AddressFamily IPv4 `
            -InterfaceIndex $InterfaceIndex -ErrorAction Stop).ServerAddresses |
            Where-Object { $_ -notin @('127.0.0.1', $TunnelDns) -and [Net.IPAddress]::TryParse($_, [ref]$parsed) -and
                $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -Unique | Select-Object -First 3)
    } catch { return @() }
}

function Get-ProgramSplitPhysicalResolver {
    # The first physical resolver, or $null when the host has none.
    param([Parameter(Mandatory)] [string] $AdapterName, [string] $TunnelDns)

    @(Get-ProgramSplitPhysicalResolvers -AdapterName $AdapterName -TunnelDns $TunnelDns) | Select-Object -First 1
}

# The bounded runner: controller-service.exe --run, beside these scripts in an installation. Tests set it first.
if (-not (Get-Variable -Name ProgramSplitRunner -Scope Script -ErrorAction SilentlyContinue)) {
    $script:ProgramSplitRunner = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\controller-service.exe'
}

function ConvertTo-ProgramSplitArgument([string] $Value) {
    # One argument quoted for CommandLineToArgvW and the C runtime: quotes around anything empty or holding
    # whitespace or a quote, embedded quotes escaped, and backslashes doubled only before a quote.
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $quoted = [Text.StringBuilder]::new('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') { $null = $quoted.Append([char]'\', 2 * $backslashes + 1).Append('"') }
        else { $null = $quoted.Append([char]'\', $backslashes).Append($character) }
        $backslashes = 0
    }
    $null = $quoted.Append([char]'\', 2 * $backslashes).Append('"')
    $quoted.ToString()
}

function Start-ProgramSplitProcess {
    # Starts a program through the bounded runner: suspended in its own job, contained before it runs, ended
    # with its descendants at its deadline counted from now, both pipes drained with bounded retention. Output
    # comes back through pipes rather than files, so a log another process holds open cannot fail the run.
    # Encoding states what the program writes: Utf8 for this project's native tools, Oem for Windows
    # PowerShell and other console programs writing to a redirected stream. Each argument is passed as it
    # is, quoted here as needed; callers never quote.
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [Parameter(Mandatory)] [ValidateRange(1, 600000)] [int] $TimeoutMilliseconds,
        [ValidateSet('Utf8', 'Oem')] [string] $Encoding = 'Utf8'
    )

    # The program path is quoted plainly: a path holds no quotes, and argv[0] is not parsed for escapes.
    $commandLine = (@('"' + $FilePath + '"') + @($ArgumentList | ForEach-Object { ConvertTo-ProgramSplitArgument ([string]$_) })) -join ' '
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commandLine))
    $start = [Diagnostics.ProcessStartInfo]::new($script:ProgramSplitRunner, "--run $TimeoutMilliseconds $encoded")
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $runner = [Diagnostics.Process]::Start($start)
    # The runner's frame is bounded and it always ends by the deadline plus a small margin, so reading each
    # stream to its end is safe and starts at once, whenever the result is collected.
    [pscustomobject]@{
        Runner = $runner; Frame = $runner.StandardOutput.ReadToEndAsync(); RunnerError = $runner.StandardError.ReadToEndAsync()
        TimeoutMilliseconds = $TimeoutMilliseconds; Encoding = $Encoding
    }
}

function Complete-ProgramSplitProcess {
    # Collects a started program's result. The runner enforced its deadline; the wait here is only a backstop
    # against a broken runner. Logs are a best-effort copy afterwards.
    param(
        [Parameter(Mandatory)] $Started,
        [string] $OutputLog,
        [string] $ErrorLog
    )

    try {
        if (-not $Started.Runner.WaitForExit($Started.TimeoutMilliseconds + 20000)) {
            try { $Started.Runner.Kill() } catch { }
            throw 'The bounded runner did not finish.'
        }
        $Started.Runner.WaitForExit()
        $fields = @{}
        foreach ($line in ($Started.Frame.Result -split "`r?`n")) {
            $pair = $line -split '=', 2
            if ($pair.Count -eq 2) { $fields[$pair[0]] = $pair[1] }
        }
        if (-not $Started.Frame.Result.StartsWith('WGPS-RUN 1')) { throw "The bounded runner failed: $($Started.RunnerError.Result)" }
        if ($fields.ContainsKey('error')) { throw "Could not run the program: $($fields['error'])" }
        $encoding = if ($Started.Encoding -eq 'Oem') {
            [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        } else { [Text.UTF8Encoding]::new($false) }
        $output = $encoding.GetString([Convert]::FromBase64String($fields['stdout']))
        $errors = $encoding.GetString([Convert]::FromBase64String($fields['stderr']))
        foreach ($log in @(@($OutputLog, $output), @($ErrorLog, $errors))) {
            if ($log[0]) { try { [IO.File]::WriteAllText($log[0], $log[1]) } catch { } }
        }
        # The runner writes the exit code as the unsigned value Windows keeps; it is read back as the signed
        # code a program exits with, so exit -1 and an NTSTATUS crash such as 0xC0000005 keep their value.
        $exitCode = $null
        if ($fields['exit']) {
            $unsigned = [uint32]0
            if (-not [uint32]::TryParse($fields['exit'], [ref]$unsigned)) { throw "The bounded runner reported a malformed exit code: $($fields['exit'])" }
            $exitCode = [BitConverter]::ToInt32([BitConverter]::GetBytes($unsigned), 0)
        }
        [pscustomobject]@{
            ExitCode = $exitCode
            TimedOut = $fields['timedout'] -eq '1'
            OutputTruncated = $fields['stdout-truncated'] -eq '1'
            ErrorTruncated = $fields['stderr-truncated'] -eq '1'
            Output = @($output -split "\r?\n" | Where-Object { $_ })
            Error = @($errors -split "\r?\n" | Where-Object { $_ })
            # The program's own runtime: a parallel start completes components in turn, so the time until
            # this call would include the wait for the others.
            Milliseconds = [long]$fields['runtime']
        }
    } finally { $Started.Runner.Dispose() }
}

function Invoke-ProgramSplitProcess {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [Parameter(Mandatory)] [int] $TimeoutMilliseconds,
        [string] $OutputLog,
        [string] $ErrorLog,
        [ValidateSet('Utf8', 'Oem')] [string] $Encoding = 'Utf8'
    )

    Complete-ProgramSplitProcess -Started (Start-ProgramSplitProcess -FilePath $FilePath -ArgumentList $ArgumentList `
        -TimeoutMilliseconds $TimeoutMilliseconds -Encoding $Encoding) -OutputLog $OutputLog -ErrorLog $ErrorLog
}
