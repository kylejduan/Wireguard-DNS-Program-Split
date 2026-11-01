# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\RepairPolicy.ps1')
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw "ASSERTION FAILED: $Message"}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('wgps-repair-test-'+[guid]::NewGuid())
try {
    [IO.Directory]::CreateDirectory((Join-Path $root 'state'))|Out-Null
    Assert-True (Test-ProgramSplitRepairBudget $root) 'first recovery is allowed'
    foreach($attempt in 1..3){Assert-True (Add-ProgramSplitRepairAttempt $root 'fixture failure') "attempt $attempt is reserved"}
    Assert-True (-not (Test-ProgramSplitRepairBudget $root)) 'three failures open the circuit'
    Assert-True (-not (Add-ProgramSplitRepairAttempt $root 'different failure')) 'a changed message cannot evade the rate bound'
    . (Join-Path $RepositoryRoot 'src\powershell\RepairPolicy.ps1')
    Assert-True (-not (Test-ProgramSplitRepairBudget $root)) 'process/function reload does not reset the durable budget'
    $path=Join-Path $root 'state\repair-budget.json'
    $budget=Get-ProgramSplitRepairBudget $root
    $budget.WindowUtc=[datetime]::UtcNow.AddMinutes(-16).ToString('o')
    [IO.File]::WriteAllText($path,($budget|ConvertTo-Json))
    Assert-True (Test-ProgramSplitRepairBudget $root) 'a later probe can retry after the cooldown'
    Assert-True (Add-ProgramSplitRepairAttempt $root 'later failure') 'later attempt starts a new bounded window'
    Assert-True ((Get-ProgramSplitRepairBudget $root).Count -eq 1) 'expired budget resets to one reserved attempt'
    $budget=Get-ProgramSplitRepairBudget $root;$budget.WindowUtc=[datetime]::UtcNow.AddMinutes(5).ToString('o')
    [IO.File]::WriteAllText($path,($budget|ConvertTo-Json))
    Assert-True (-not (Test-ProgramSplitRepairBudget $root)) 'backward clock movement cannot unlock a retry'
    [IO.File]::WriteAllText($path,'corrupt')
    Assert-True (-not (Test-ProgramSplitRepairBudget $root)) 'corrupt budget defers repairs'
    Clear-ProgramSplitRepairBudget $root
    Assert-True (Test-ProgramSplitRepairBudget $root) 'successful health or explicit disable clears the circuit'
    $destination=Join-Path $root 'atomic.txt';$source=Join-Path $root 'atomic-new.txt'
    [IO.File]::WriteAllText($destination,'old');[IO.File]::WriteAllText($source,'new')
    $locked=[IO.File]::Open($destination,'Open','Read','Read')
    try {
        $failed=$false;try{[ProgramSplit.PhysicalNetwork]::AtomicMove($source,$destination)}catch{$failed=$true}
        Assert-True ($failed -and [IO.File]::ReadAllText($destination) -eq 'old' -and [IO.File]::Exists($source)) 'a blocked atomic replacement preserves the old ledger'
    }finally{$locked.Dispose()}
    [ProgramSplit.PhysicalNetwork]::AtomicMove($source,$destination)
    Assert-True ([IO.File]::ReadAllText($destination) -eq 'new' -and -not [IO.File]::Exists($source)) 'an atomic replacement commits once sharing permits it'
    Write-Output 'PASS: repair burst limit, persistence, cooldown, clock rollback and corrupt-state handling.'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
