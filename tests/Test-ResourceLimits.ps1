# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$path = Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
foreach ($name in @('Write-ControllerLog', 'Save-HealthFailureEvidence')) {
    $function = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    Assert-True ($function.Count -eq 1) "exactly one $name implementation"
    . ([scriptblock]::Create($function[0].Extent.Text))
}
$temporary = Join-Path $RepositoryRoot ("local\test-temp\limits-{0}" -f [guid]::NewGuid())
try {
    $logs = Join-Path $temporary 'logs'
    $logFile = Join-Path $logs 'controller.log'
    Write-ControllerLog 'first event'
    foreach ($index in 1..6) {
        $file = [IO.File]::OpenWrite($logFile)
        try { $file.SetLength(8MB) } finally { $file.Dispose() }
        Write-ControllerLog "rotation $index"
        Assert-True (([IO.File]::ReadAllText($logFile)) -match "rotation $index") 'newest event survives rotation'
    }
    Assert-True (@(Get-ChildItem -LiteralPath $logs -File).Count -eq 4) 'only current log and three archives retained'
    Write-ControllerLog ('x' * 1000000)
    Assert-True ((Get-Item -LiteralPath $logFile).Length -lt 64KB) 'oversized log messages are bounded'
    $reader = [IO.FileStream]::new($logFile, 'Open', 'ReadWrite', 'Read')
    try {
        $reader.SetLength(8MB)
        Write-ControllerLog 'rotation blocked by a reader'
        Assert-True ($reader.Length -eq 8MB) 'failed rotation never appends beyond the cap'
    } finally { $reader.Dispose() }
    Write-ControllerLog 'recovered after reader closed'
    Assert-True ([IO.File]::ReadAllText($logFile) -match 'recovered') 'logging resumes after a temporary file lock'
    # Active log writers cannot extend the snapshot beyond its finite initial tail.
    $growing = Join-Path $logs 'dns-dispatcher.log'
    $writer = [IO.FileStream]::new($growing, 'Create', 'Write', 'ReadWrite, Delete')
    try {
        $writer.SetLength(3MB)
        Save-HealthFailureEvidence -Reason 'bounded snapshot'
        $snapshot = Get-ChildItem -LiteralPath (Join-Path $logs 'health-failures') -Directory | Select-Object -First 1
        Assert-True ((Get-Item -LiteralPath (Join-Path $snapshot.FullName 'dns-dispatcher.log')).Length -eq 2MB) `
            'an open large diagnostic log produces exactly a 2 MiB snapshot'
    } finally { $writer.Dispose() }
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output 'PASS: bounded controller logging, locked-file recovery, and finite evidence snapshots.'
