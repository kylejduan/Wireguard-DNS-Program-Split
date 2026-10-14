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

function Remove-ProgramSplitStagingDirectory {
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
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
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
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
        $resolver = Get-ProgramSplitPhysicalResolver -AdapterName $AdapterName -TunnelDns $TunnelDns
        return [bool] ($source -and $resolver)
    } catch { return $false }
}

function Get-ProgramSplitPhysicalResolver {
    # The resolver the dispatcher forwards unlisted names to: the first address on the
    # physical interface that is neither the loopback dispatcher nor the tunnel resolver.
    # Returns $null when the host has no such address.
    param([Parameter(Mandatory)] [string] $AdapterName, [string] $TunnelDns)

    try {
        $physical = Get-ProgramSplitPhysicalDefault -AdapterName $AdapterName
        return (Get-DnsClientServerAddress -AddressFamily IPv4 `
            -InterfaceIndex $physical.InterfaceIndex -ErrorAction Stop).ServerAddresses |
            Where-Object { $_ -notin @('127.0.0.1', $TunnelDns) } | Select-Object -First 1
    } catch { return $null }
}
