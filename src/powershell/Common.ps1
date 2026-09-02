Set-StrictMode -Version Latest

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

function Test-ProgramSplitServiceOwnership {
    param(
        [Parameter(Mandatory)] $Service,
        [Parameter(Mandatory)] [string] $HostPath,
        [Parameter(Mandatory)] [string] $ProfilePath
    )

    return [string] $Service.PathName -eq ('{0} /service {1}' -f $HostPath, $ProfilePath)
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

function Assert-ProgramSplitInstallNamesAvailable {
    param($Tasks, $Service)

    if (@($Tasks).Count -gt 0 -or $null -ne $Service) {
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

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not (Test-Path -LiteralPath $StoppedMarker -PathType Leaf)) {
        if ([DateTime]::UtcNow -ge $deadline) {
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
        ControllerTask = 'WireGuard Program Split Controller'
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
