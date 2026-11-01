# SPDX-License-Identifier: GPL-3.0-or-later
# Opt-in physical recovery. A DNS timeout, dead router, unplugged cable or
# disconnected radio is never sufficient evidence for an adapter reset.

function Get-ProgramSplitRecoveryPolicy([string] $Root) {
    $path = Join-Path $Root 'config\network-recovery.json'
    if (-not [IO.File]::Exists($path)) { return $null }
    if ((Get-Item -LiteralPath $path).Length -gt 16384) { throw 'Recovery policy is too large.' }
    $policy = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($policy.Schema -ne 1 -or $policy.Enabled -isnot [bool]) { throw 'Invalid recovery policy.' }
    $restartOption=$policy.PSObject.Properties['AllowAdapterRestart']
    if($restartOption -and $restartOption.Value -isnot [bool]){throw 'Invalid adapter restart permission.'}
    if (-not $policy.Enabled) { return $null }
    $entries = @($policy.Adapters)
    if ($entries.Count -eq 0 -or $entries.Count -gt 8) { throw 'Recovery requires one to eight explicitly enrolled adapters.' }
    $seen = @{}
    foreach ($entry in $entries) {
        $guid = [guid]$entry.Guid
        if ($guid -eq [guid]::Empty -or $seen.ContainsKey($guid.ToString()) -or $entry.Type -notin @(6, 71)) {
            throw 'Recovery adapter identities must be unique physical Ethernet or Wi-Fi GUIDs.'
        }
        $seen[$guid.ToString()] = $true
        if ($entry.Type -eq 71 -and ($entry.WifiProfile -isnot [string] -or
            $entry.WifiProfile.Length -eq 0 -or $entry.WifiProfile.Length -gt 255 -or $entry.WifiProfile.Contains([char]0))) {
            throw 'Wi-Fi recovery requires an explicitly enrolled saved profile.'
        }
    }
    return $policy
}

function Test-ProgramSplitAdapterRestartAllowed($Policy) {
    $option=$Policy.PSObject.Properties['AllowAdapterRestart']
    return ($null -ne $option -and $option.Value -is [bool] -and $option.Value)
}

function Get-ProgramSplitWifiIntent([guid] $Guid, [datetime] $Now) {
    # Only a recent failed connection request creates recovery intent. A newer
    # disconnect, successful connection, or request for another profile cancels it.
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
        Id = @(8000, 8001, 8002, 8003); StartTime = $Now.AddSeconds(-120)
    } -MaxEvents 32 -ErrorAction SilentlyContinue)
    foreach ($event in $events) {
      try {
        $xml = [xml]$event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[[string]$item.Name] = [string]$item.InnerText }
        if (-not $data.ContainsKey('InterfaceGuid') -or [guid]$data.InterfaceGuid -ne $Guid) { continue }
        $reason = if ($data.ContainsKey('ReasonCode')) { [int]$data.ReasonCode } else { 0 }
        return [pscustomobject]@{
            Id = [int]$event.Id; RecordId = [long]$event.RecordId
            Profile = [string]$data.ProfileName; Reason = $reason; Time = $event.TimeCreated.ToUniversalTime()
        }
      } catch { continue }
    }
    return $null
}

function Get-ProgramSplitRecoveryBudget([string] $Root) {
    $path = Join-Path $Root 'state\network-recovery-budget.json'
    if (-not [IO.File]::Exists($path)) { throw 'Recovery budget is missing; explicitly enroll again after inspection.' }
    if ((Get-Item -LiteralPath $path).Length -gt 16384) { throw 'Recovery budget is too large.' }
    $saved = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($saved.Schema -ne 1 -or @($saved.Adapters).Count -gt 64) { throw 'Invalid recovery budget; manual inspection is required.' }
    $result = @{}
    foreach ($entry in @($saved.Adapters)) {
        $key = ([guid]$entry.Guid).ToString()
        if ([guid]$key -eq [guid]::Empty -or $result.ContainsKey($key) -or $entry.Resets -isnot [int] -or
            $entry.Resets -lt 0 -or $entry.Resets -gt 2 -or $entry.RefreshRecord -lt 0) { throw 'Invalid recovery budget.' }
        foreach ($field in @('WindowUtc','ResetUtc','SequenceUtc')) { $null = [datetime]::Parse($entry.$field).ToUniversalTime() }
        $result[$key] = $entry
    }
    return $result
}

function Get-ProgramSplitRecentNetworkEvents([datetime] $Now) {
    # Only collected when recovery is already justified. Keep enough pre-reset
    # context for driver/power-transition diagnosis without starting a packet trace.
    try {
        Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$Now.AddMinutes(-5)} -MaxEvents 128 -ErrorAction Stop |
            Where-Object {$_.ProviderName -match 'NDIS|Kernel-PnP|Kernel-Power|Netwtw|aqnic|Aquantia|Marvell'} |
            Select-Object -First 24 | ForEach-Object {
                [pscustomobject]@{Utc=$_.TimeCreated.ToUniversalTime().ToString('o');Provider=$_.ProviderName;Id=$_.Id;Level=$_.Level}
            }
    } catch { }
}

function Get-ProgramSplitRecoveryAction {
    param($Entry, $Snapshot, $Wireless, $Intent, $Budget, [int] $PauseSamples,
        [datetime] $Now, [double] $UptimeSeconds, [bool] $AllowAdapterRestart = $false,
        [double] $FailureSeconds = 0)
    if ($UptimeSeconds -lt 90 -or -not $Snapshot.Hardware -or -not $Snapshot.AdminUp -or
        $Snapshot.LowPower -or [guid]$Snapshot.Guid -ne [guid]$Entry.Guid -or $Snapshot.Type -ne $Entry.Type) { return '' }
    if ($Budget) {
        $resetAge = ($Now - [datetime]::Parse($Budget.ResetUtc).ToUniversalTime()).TotalSeconds
        $windowAge = ($Now - [datetime]::Parse($Budget.WindowUtc).ToUniversalTime()).TotalSeconds
        if ($resetAge -lt 600 -or $windowAge -lt 0 -or ($windowAge -lt 3600 -and $Budget.Resets -ge 2)) { return '' }
    }
    if ($AllowAdapterRestart -and $FailureSeconds -ge 300 -and $Entry.Type -eq 6 -and $Snapshot.Paused -and $Snapshot.LinkUp -and $PauseSamples -ge 3) {
        return 'ResetPaused'
    }
    if ($Entry.Type -ne 71 -or -not $Wireless -or $Wireless.State -ne 4 -or -not $Wireless.RadioOn -or
        -not $Intent -or $Intent.Id -ne 8002 -or $Intent.Reason -ne 163851 -or
        $Intent.Profile -cne $Entry.WifiProfile -or ($Now - $Intent.Time).TotalSeconds -lt 60 -or
        ($Now - $Intent.Time).TotalSeconds -gt 120 -or $FailureSeconds -lt 60) { return '' }
    # Refresh the scan and retry a requested profile before considering a reset.
    if (-not $Budget) { return 'ReconnectWifi' }
    $sequenceAge = ($Now - [datetime]::Parse($Budget.SequenceUtc).ToUniversalTime()).TotalSeconds
    if ($sequenceAge -lt 0) { return '' }
    if ($AllowAdapterRestart -and $FailureSeconds -ge 300 -and $sequenceAge -lt 600 -and $Budget.RefreshRecord -gt 0 -and $Intent.RecordId -gt $Budget.RefreshRecord -and
        $Wireless.Visible -and $Wireless.Signal -ge 25) { return 'ResetWifi' }
    if ($sequenceAge -ge 600) { return 'ReconnectWifi' }
    return ''
}

function Invoke-ProgramSplitPhysicalRecovery {
    param([string] $Root, [guid] $Guid, [string] $Action, [int] $PauseSamples = 0,
        [Nullable[UInt64]] $PausedSentBytes = $null, [Nullable[UInt64]] $FailureStartedTick = $null,
        [Nullable[UInt64]] $PausedReceivedBytes = $null)
    $lease=$null
    try {
        try {$lease=[IO.File]::Open((Join-Path $Root 'state\network-recovery.lock'),'OpenOrCreate','ReadWrite','None')}
        catch [IO.IOException] {return 'DEFER: another physical recovery is running.'}
        $policy = Get-ProgramSplitRecoveryPolicy $Root
        if (-not $policy -or -not [IO.File]::Exists((Join-Path $Root 'state\enabled'))) { return 'DEFER: recovery is disabled.' }
        $entry = @($policy.Adapters | Where-Object { [guid]$_.Guid -eq $Guid })
        if ($entry.Count -ne 1) { throw 'Adapter is not explicitly enrolled.' }
        $entry = $entry[0]
        . (Join-Path $PSScriptRoot 'PhysicalNetwork.ps1')
        $snapshot = [ProgramSplit.PhysicalNetwork]::Read($Guid)
        $now = [datetime]::UtcNow
        $wireless = if ($entry.Type -eq 71) { [ProgramSplit.PhysicalNetwork]::ReadWireless($Guid, $entry.WifiProfile) }
        $intent = if ($entry.Type -eq 71) { Get-ProgramSplitWifiIntent $Guid $now }
        $budgets = Get-ProgramSplitRecoveryBudget $Root
        $key = $Guid.ToString()
        $budget = $budgets[$key]
        $tick = [ProgramSplit.PhysicalNetwork]::GetTickCount64()
        $uptime = $tick / 1000.0
        $failureSeconds=if($null -ne $FailureStartedTick -and $tick -ge $FailureStartedTick){($tick-$FailureStartedTick)/1000.0}else{0}
        $allowed = Get-ProgramSplitRecoveryAction $entry $snapshot $wireless $intent $budget $PauseSamples $now $uptime `
            (Test-ProgramSplitAdapterRestartAllowed $policy) $failureSeconds
        if ($allowed -ne $Action) { return 'DEFER: fresh evidence no longer authorizes recovery.' }
        if($Action -ne 'ReconnectWifi') {
            try {
                $settings=Get-ProgramSplitConfiguration -Root $Root
                $route=Get-ProgramSplitPhysicalDefault -AdapterName $settings.AdapterName
                if($route.InterfaceIndex -ne $snapshot.Index){return 'DEFER: another physical adapter carries the default route.'}
            } catch {return 'DEFER: active physical adapter could not be confirmed.'}
        }
        # Validate the actual persistent filters, not just their on-disk marker.
        $proof = & (Join-Path $PSScriptRoot 'Invoke-WfpFilters.ps1') -Action Validate 2>&1
        if ($LASTEXITCODE -ne 0 -or ($proof -join ' ') -notmatch '^PASS:') { throw 'Persistent payload protection could not be verified.' }
        $service = Get-Service WireGuardProgramSplitController -ErrorAction Stop
        if ($service.Status -ne 'Running' -or -not [IO.File]::Exists((Join-Path $Root 'state\enabled'))) {
            return 'DEFER: controller is stopping or disabled.'
        }
        if (-not $budget) {
            $budget = [pscustomobject]@{Guid=$key; WindowUtc=$now.ToString('o'); ResetUtc=[datetime]::MinValue.ToString('o');
                SequenceUtc=[datetime]::MinValue.ToString('o'); Resets=0; RefreshRecord=0}
        }
        if (($now - [datetime]::Parse($budget.WindowUtc).ToUniversalTime()).TotalSeconds -ge 3600) {
            $budget.WindowUtc=$now.ToString('o');$budget.Resets=0
        }
        if ($Action -eq 'ReconnectWifi') { $budget.SequenceUtc=$now.ToString('o');$budget.RefreshRecord=0 }
        else { $budget.Resets++;$budget.ResetUtc=$now.ToString('o');$budget.RefreshRecord=0 }
        $budgets[$key]=$budget
        # Reserve before the action. A crash or timeout still consumes the attempt.
        $budgetPath=Join-Path $Root 'state\network-recovery-budget.json'
        $temporary="$budgetPath.$PID.tmp"
        [IO.File]::WriteAllText($temporary, (@{Schema=1;Adapters=@($budgets.Values)} | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
        try { [ProgramSplit.PhysicalNetwork]::AtomicMove($temporary,$budgetPath) }
        finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        $evidence=Join-Path $Root 'logs\network-recovery'
        [IO.Directory]::CreateDirectory($evidence) | Out-Null
        if ((Get-Item -LiteralPath $evidence).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Recovery evidence must not be a reparse point.' }
        $record=[ordered]@{Utc=$now.ToString('o');Action=$Action;Before=$snapshot;Wireless=$wireless;Intent=$intent;
            Budget=$budget;RecentSystemEvents=@(Get-ProgramSplitRecentNetworkEvents $now);Outcome='started'}
        $recordPath=Join-Path $evidence ($now.ToString('yyyyMMdd-HHmmss-fff')+'.json')
        [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
        try {
            $adapter=$null
            if($Action -ne 'ReconnectWifi') {
                $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {[guid]$_.InterfaceGuid -eq $Guid})
                if($adapters.Count -ne 1){throw 'Physical adapter identity is no longer unique.'}
                $adapter=$adapters[0]
            }
            $fresh=[ProgramSplit.PhysicalNetwork]::Read($Guid)
            if($fresh.Guid -ne $Guid -or -not $fresh.Hardware -or -not $fresh.AdminUp -or $fresh.LowPower -or $fresh.Type -ne $entry.Type -or
                -not [IO.File]::Exists((Join-Path $Root 'state\enabled'))) {
                $record.Outcome='cancelled';return 'DEFER: adapter state changed before recovery.'
            }
            if($Action -eq 'ResetPaused' -and (-not $fresh.Paused -or -not $fresh.LinkUp -or
                $fresh.SentBytes -ne $snapshot.SentBytes -or $fresh.ReceivedBytes -ne $snapshot.ReceivedBytes -or
                ($null -ne $PausedSentBytes -and $fresh.SentBytes -ne $PausedSentBytes) -or
                ($null -ne $PausedReceivedBytes -and $fresh.ReceivedBytes -ne $PausedReceivedBytes))) {
                $record.Outcome='cancelled';return 'DEFER: pause resolved before recovery.'
            }
            if($Action -in @('ReconnectWifi','ResetWifi')) {
                $freshIntent=Get-ProgramSplitWifiIntent $Guid ([datetime]::UtcNow)
                $freshWifi=[ProgramSplit.PhysicalNetwork]::ReadWireless($Guid,$entry.WifiProfile)
                if($freshWifi.State -ne 4 -or -not $freshWifi.RadioOn -or -not $freshIntent -or
                    $freshIntent.RecordId -ne $intent.RecordId -or
                    ($Action -eq 'ResetWifi' -and (-not $freshWifi.Visible -or $freshWifi.Signal -lt 25))) {
                    $record.Outcome='cancelled';return 'DEFER: wireless intent or connectivity changed.'
                }
            }
            if ($Action -ne 'ReconnectWifi') {
                if ($adapter.ifIndex -ne $fresh.Index -or -not $adapter.HardwareInterface -or $adapter.AdminStatus -ne 'Up') {
                    throw 'Adapter identity or administrative state changed before recovery.'
                }
                $deviceId=[string]$adapter.PnPDeviceID
                if($deviceId -notmatch '^(PCI|USB|ACPI)\\.+$'){throw 'Physical device instance could not be verified.'}
                # Ask PnP to restart the exact device in one OS-managed operation.
                # A killed disable/enable script can leave an adapter administratively off.
                $restart=Invoke-ProgramSplitProcess -FilePath "$env:SystemRoot\System32\pnputil.exe" `
                    -ArgumentList @('/restart-device',$deviceId) -TimeoutMilliseconds 15000 -Encoding Oem
                $record.RestartExitCode=$restart.ExitCode
                $record.RestartTimedOut=$restart.TimedOut
                if($restart.TimedOut -or $restart.ExitCode -ne 0){throw 'Device restart did not complete; inspect the adapter before retrying.'}
            }
            if ($entry.Type -eq 71) {
                $ready=[Diagnostics.Stopwatch]::StartNew()
                do {
                    try {$radio=[ProgramSplit.PhysicalNetwork]::ReadWireless($Guid,$entry.WifiProfile);if($radio.RadioOn){break}}catch{}
                    if($ready.Elapsed.TotalSeconds -ge 8){throw 'Wireless radio did not become ready after recovery.'}
                    Start-Sleep -Milliseconds 200
                } while($true)
                [ProgramSplit.PhysicalNetwork]::Scan($Guid)
                # WlanScan is asynchronous. Allow the scan cache to refresh before
                # retrying; a user request or radio change during the wait wins.
                Start-Sleep -Seconds 2
                $latestIntent=Get-ProgramSplitWifiIntent $Guid ([datetime]::UtcNow)
                $radio=[ProgramSplit.PhysicalNetwork]::ReadWireless($Guid,$entry.WifiProfile)
                if(-not $radio.RadioOn -or $radio.State -ne 4 -or -not $radio.Visible -or
                    -not $latestIntent -or $latestIntent.RecordId -ne $intent.RecordId) {
                    $record.Outcome='cancelled';return 'DEFER: Wi-Fi request or state changed during scan.'
                }
                [ProgramSplit.PhysicalNetwork]::Connect($Guid, $entry.WifiProfile)
                if($Action -eq 'ReconnectWifi') {
                    $budget.RefreshRecord=$intent.RecordId
                    [IO.File]::WriteAllText($temporary,(@{Schema=1;Adapters=@($budgets.Values)}|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
                    try{[ProgramSplit.PhysicalNetwork]::AtomicMove($temporary,$budgetPath)}
                    finally{Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
                }
            }
            $record.Outcome='requested'; 'PASS: '+$Action+' requested for enrolled physical adapter '+$Guid
        } catch { $record.Outcome='failed';$record.Error=$_.Exception.Message;throw }
        finally {
            try { $record.After=[ProgramSplit.PhysicalNetwork]::Read($Guid) } catch { }
            [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
            Get-ChildItem -LiteralPath $evidence -File -Filter '*.json' | Sort-Object Name -Descending |
                Select-Object -Skip 10 | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
        }
    } finally {if($lease){$lease.Dispose()}}
}

function Test-ProgramSplitPhysicalRecovery {
    param([string] $Root)
    if(-not [IO.File]::Exists((Join-Path $Root 'config\network-recovery.json'))){return}
    try {
        if(-not ('ProgramSplit.PhysicalNetwork' -as [type])){. (Join-Path $PSScriptRoot 'PhysicalNetwork.ps1')}
        $nowTick=[ProgramSplit.PhysicalNetwork]::GetTickCount64()/1000.0
    } catch { return } # Native observation failure must never take down the VPN controller.
    if (-not (Get-Variable physicalRecoveryNext -Scope Script -ErrorAction SilentlyContinue)) {
        $script:physicalRecoveryNext=0.0;$script:physicalPauseSamples=@{};$script:physicalRecoveryError=''
        $script:physicalFirstSent=@{};$script:physicalFirstReceived=@{};$script:physicalFaultSince=@{};$script:wirelessFaultSince=@{}
        $script:physicalAdapterErrors=@{};$script:physicalNextAttempt=@{};$script:physicalGraceUntil=$nowTick+90
    }
    if($nowTick -lt $script:physicalRecoveryNext){return}
    # Sleep/resume or a long blocked pass breaks consecutive confirmation.
    if($nowTick -gt $script:physicalRecoveryNext+15){$script:physicalPauseSamples=@{};$script:physicalFaultSince=@{};$script:wirelessFaultSince=@{};$script:physicalGraceUntil=$nowTick+90}
    $script:physicalRecoveryNext=$nowTick+30
    try {
        $policy=Get-ProgramSplitRecoveryPolicy $Root
        if(-not $policy){$script:physicalPauseSamples=@{};$script:physicalFaultSince=@{};$script:wirelessFaultSince=@{};return}
        $budgets=Get-ProgramSplitRecoveryBudget $Root
        foreach($entry in @($policy.Adapters)) {
            $guid=[guid]$entry.Guid;$key=$guid.ToString()
          try {
            $snapshot=[ProgramSplit.PhysicalNetwork]::Read($guid)
            $validPause=$snapshot.Paused -and $snapshot.Hardware -and $snapshot.AdminUp -and $snapshot.LinkUp -and -not $snapshot.LowPower
            if(-not $validPause){$script:physicalPauseSamples[$key]=0}
            if(-not $script:physicalPauseSamples[$key] -or $script:physicalFirstSent[$key] -ne $snapshot.SentBytes -or $script:physicalFirstReceived[$key] -ne $snapshot.ReceivedBytes){
                $script:physicalFirstSent[$key]=$snapshot.SentBytes;$script:physicalFirstReceived[$key]=$snapshot.ReceivedBytes;$script:physicalPauseSamples[$key]=0;$script:physicalFaultSince[$key]=$nowTick
            }
            $samples=if($validPause){[Math]::Min(3,1+[int]$script:physicalPauseSamples[$key])}else{0}
            $script:physicalPauseSamples[$key]=$samples
            $now=[datetime]::UtcNow
            $wireless=if($entry.Type -eq 71){[ProgramSplit.PhysicalNetwork]::ReadWireless($guid,$entry.WifiProfile)}
            $intent=if($entry.Type -eq 71 -and $wireless.State -eq 4){Get-ProgramSplitWifiIntent $guid $now}
            $failureSeconds=if($validPause){$nowTick-$script:physicalFaultSince[$key]}else{0}
            if($entry.Type -eq 71){
                if($wireless.State -eq 4 -and $wireless.RadioOn -and $intent -and $intent.Id -eq 8002 -and
                    $intent.Reason -eq 163851 -and $intent.Profile -ceq $entry.WifiProfile -and
                    ($now-$intent.Time).TotalSeconds -ge 0 -and ($now-$intent.Time).TotalSeconds -le 120){
                    if(-not $script:wirelessFaultSince.ContainsKey($key)){$script:wirelessFaultSince[$key]=$nowTick}
                    $failureSeconds=$nowTick-$script:wirelessFaultSince[$key]
                }else{$script:wirelessFaultSince.Remove($key)}
            }
            $action=Get-ProgramSplitRecoveryAction $entry $snapshot $wireless $intent $budgets[$key] $samples $now ([ProgramSplit.PhysicalNetwork]::GetTickCount64()/1000.0) `
                (Test-ProgramSplitAdapterRestartAllowed $policy) $failureSeconds
            if($action -and $nowTick -ge $script:physicalGraceUntil -and $nowTick -ge $script:physicalNextAttempt[$key]){
                $script:physicalNextAttempt[$key]=$nowTick+120
                try {Invoke-Component 'Invoke-NetworkRecovery.ps1' 'Recover' @('-InterfaceGuid',$key,'-RecoveryAction',$action,'-PauseSamples',[string]$samples,'-PausedSentBytes',[string]$script:physicalFirstSent[$key],'-FailureStartedTick',[string][UInt64](($nowTick-$failureSeconds)*1000),'-PausedReceivedBytes',[string]$script:physicalFirstReceived[$key])}
                finally{$script:physicalPauseSamples[$key]=0}
            }
            $script:physicalAdapterErrors.Remove($key)
          } catch {
            $script:physicalPauseSamples[$key]=0
            $script:physicalFaultSince.Remove($key);$script:wirelessFaultSince.Remove($key)
            if($script:physicalAdapterErrors[$key] -ne $_.Exception.Message){Write-ControllerLog ('Physical recovery observation deferred for '+$key+': '+$_.Exception.Message)}
            $script:physicalAdapterErrors[$key]=$_.Exception.Message
          }
        }
        $script:physicalRecoveryError=''
    } catch {
        if($script:physicalRecoveryError -ne $_.Exception.Message){
            Write-ControllerLog ('Physical recovery deferred: '+$_.Exception.Message)
            $script:physicalRecoveryError=$_.Exception.Message
        }
    }
}
