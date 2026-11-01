# SPDX-License-Identifier: GPL-3.0-or-later
# Failed health probes are observations, not permission to interrupt a live tunnel.
function Clear-ProgramSplitRepairBudgetSafely([string] $Root) {
    try {Clear-ProgramSplitRepairBudget $Root}
    catch {Write-ControllerLog 'Repair ledger cleanup deferred; health passed and running components are preserved.'}
}

function Clear-ProgramSplitSoftFailure {
    $script:pendingSoftFailure=$null
}

function Test-ProgramSplitSoftFailureReady([string] $Kind, [double] $Now) {
    $seen=Get-Variable pendingSoftFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if(-not $seen -or $seen.Kind -cne $Kind -or $Now -lt $seen.Last -or $Now-$seen.Last -gt 75) {
        $script:pendingSoftFailure=[pscustomobject]@{Kind=$Kind;First=$Now;Last=$Now;Samples=1}
        return $false
    }
    if($Now-$seen.Last -ge 20){$seen.Samples++;$seen.Last=$Now}
    return ($seen.Samples -ge 3 -and $Now-$seen.First -ge 60)
}

function Test-ProgramSplitTunnelTrafficProgress([string] $AdapterName) {
    # Positive receives protect a working tunnel when only its DNS server fails.
    # Unknown identity/counters also defer a destructive action.
    try {
        if(-not ('ProgramSplit.PhysicalNetwork' -as [type])){. (Join-Path $PSScriptRoot 'PhysicalNetwork.ps1')}
        $adapters=@(Get-NetAdapter -Name $AdapterName -ErrorAction Stop)
        if($adapters.Count -ne 1 -or $adapters[0].Status -ne 'Up'){return $true}
        $current=[ProgramSplit.PhysicalNetwork]::Read([guid]$adapters[0].InterfaceGuid)
        $previous=Get-Variable tunnelTrafficObservation -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $script:tunnelTrafficObservation=[pscustomobject]@{Guid=$current.Guid;ReceivedBytes=$current.ReceivedBytes}
        return (-not $previous -or $previous.Guid -ne $current.Guid -or $previous.ReceivedBytes -ne $current.ReceivedBytes)
    } catch {return $true}
}
