# SPDX-License-Identifier: GPL-3.0-or-later
# Bound repeated failed repairs independently of process restarts. This never
# removes traffic protection. A successful health check or explicit disable
# clears the budget; otherwise a fresh attempt is allowed after fifteen minutes.
function Get-ProgramSplitRepairBudget([string] $Root) {
    $path=Join-Path $Root 'state\repair-budget.json'
    if(-not [IO.File]::Exists($path)){return $null}
    if((Get-Item -LiteralPath $path).Length -gt 4096){throw 'Invalid repair budget.'}
    $budget=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    if($budget.Schema -ne 1 -or $budget.Count -isnot [int] -or $budget.Count -lt 1 -or
        $budget.Count -gt 3 -or $budget.Reason -isnot [string] -or $budget.Reason.Length -gt 2048){throw 'Invalid repair budget.'}
    $null=[datetime]::Parse($budget.WindowUtc).ToUniversalTime()
    return $budget
}
function Test-ProgramSplitRepairBudget([string] $Root) {
    try {
        $budget=Get-ProgramSplitRepairBudget $Root
        if(-not $budget){return $true}
        $age=([datetime]::UtcNow-[datetime]::Parse($budget.WindowUtc).ToUniversalTime()).TotalSeconds
        return ($age -ge 0 -and ($budget.Count -lt 3 -or $age -ge 900))
    } catch {return $false}
}
function Add-ProgramSplitRepairAttempt([string] $Root, [string] $Reason) {
    try {
        $now=[datetime]::UtcNow
        $budget=Get-ProgramSplitRepairBudget $Root
        $age=if($budget){($now-[datetime]::Parse($budget.WindowUtc).ToUniversalTime()).TotalSeconds}else{900}
        if($age -lt 0 -or ($budget -and $budget.Count -ge 3 -and $age -lt 900)){return $false}
        $count=if($budget -and $age -lt 900){$budget.Count+1}else{1}
        $window=if($budget -and $age -lt 900){$budget.WindowUtc}else{$now.ToString('o')}
        if($Reason.Length -gt 2048){$Reason=$Reason.Substring(0,2048)}
        $path=Join-Path $Root 'state\repair-budget.json';$temp="$path.$PID.tmp"
        . (Join-Path $PSScriptRoot 'PhysicalNetwork.ps1')
        try {
            [IO.File]::WriteAllText($temp,(@{Schema=1;Count=$count;WindowUtc=$window;Reason=$Reason}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
            [ProgramSplit.PhysicalNetwork]::AtomicMove($temp,$path)
        }finally{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
        return $true
    } catch {return $false}
}
function Clear-ProgramSplitRepairBudget([string] $Root) {
    Remove-Item -LiteralPath (Join-Path $Root 'state\repair-budget.json') -Force -ErrorAction SilentlyContinue
}
