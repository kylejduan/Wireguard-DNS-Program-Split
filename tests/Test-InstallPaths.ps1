# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $RepositoryRoot 'src\powershell\Common.ps1')
function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
$hostPath = 'C:\Program Files\WireGuardProgramSplit\bin\controller-service.exe'
$scriptPath = 'C:\Program Files\WireGuardProgramSplit\src\Controller.ps1'
$command = Get-ProgramSplitServiceCommand -HostPath $hostPath -ArgumentPath $scriptPath
Assert-True ($command -ceq ('"' + $hostPath + '" /service "' + $scriptPath + '"')) `
    'both service paths are quoted'
Assert-True (Test-ProgramSplitServiceOwnership -Service ([pscustomobject]@{ PathName = $command }) `
    -HostPath $hostPath -ArgumentPath $scriptPath) 'quoted Program Files service is owned'
foreach ($foreignCommand in @("$hostPath /service $scriptPath", "$command extra", ('"C:\Other.exe" /service "' + $scriptPath + '"'))) {
    Assert-True (-not (Test-ProgramSplitServiceOwnership -Service ([pscustomobject]@{ PathName = $foreignCommand }) `
        -HostPath $hostPath -ArgumentPath $scriptPath)) 'ambiguous or foreign service command is rejected'
}
$oldHost = 'C:\ProgramData\WireGuardProgramSplit\bin\controller-service.exe'
$oldScript = 'C:\ProgramData\WireGuardProgramSplit\src\Controller.ps1'
Assert-True (Test-ProgramSplitServiceOwnership -Service ([pscustomobject]@{ PathName = "$oldHost /service $oldScript" }) `
    -HostPath $oldHost -ArgumentPath $oldScript) 'legacy service remains recognizable for migration and uninstall'

# Execute the actual controller launcher from a fixture root containing spaces.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Controller.ps1'), [ref]$tokens, [ref]$errors)
$launcher = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Start-Component', 'Complete-Component')
}, $true))
Assert-True ($launcher.Count -eq 2) 'controller component launcher is available'
$commonAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Common.ps1'), [ref]$tokens, [ref]$errors)
$capture = @($commonAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('ConvertTo-ProgramSplitArgument', 'Start-ProgramSplitProcess', 'Complete-ProgramSplitProcess')
}, $true))
Assert-True ($capture.Count -eq 3) 'process capture helpers are available'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('WireGuard path test ' + [guid]::NewGuid())
try {
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    [IO.File]::WriteAllText((Join-Path $temporary 'sample child.ps1'), 'param([string] $Action) Write-Output "child received: $Action"')
    [IO.File]::WriteAllText((Join-Path $temporary 'launch.ps1'), (@(
        '$logs = $PSScriptRoot', '$script:logged = [Collections.Generic.List[string]]::new()',
        ("`$script:ProgramSplitRunner = '{0}'" -f (Join-Path $RepositoryRoot 'build\controller-service.exe')),
        'function Write-ControllerLog([string] $message) { $script:logged.Add($message) }') +
        @($capture | ForEach-Object { $_.Extent.Text }) + @($launcher | ForEach-Object { $_.Extent.Text }) +
        @('Complete-Component (Start-Component "sample child.ps1" "Validate")', '$script:logged') -join "`n"))
    $logged = @(& (Join-Path $temporary 'launch.ps1'))
    Assert-True (($logged -join ' ') -match 'child received: Validate' -and ($logged -join ' ') -match 'completed in') `
        "child receives the requested action from a path containing spaces and completes: $($logged -join ' ')"
    Assert-True ((Get-Content -LiteralPath (Join-Path $temporary 'sample child-output.log') -Raw).Trim() -eq 'child received: Validate') `
        'component output is also kept in its log'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
# Migration swaps three scripts, so it must refuse an installation whose other components are another release's.
$legacy = Join-Path ([IO.Path]::GetTempPath()) ('WireGuard legacy layout ' + [guid]::NewGuid())
try {
    $installed = Join-Path $legacy 'installed'
    $build = Join-Path $legacy 'build'
    foreach ($directory in @((Join-Path $installed 'src'), (Join-Path $installed 'bin'), $build)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $replaced = @('Common.ps1', 'Controller.ps1', 'Invoke-Tunnel.ps1')
    $executables = @('controller-service.exe', 'wfp-probe.exe')
    foreach ($script in Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1') {
        # Line endings differ between checkouts without changing the release.
        [IO.File]::WriteAllText((Join-Path $installed "src\$($script.Name)"),
            [IO.File]::ReadAllText($script.FullName).Replace("`r`n", "`n").Replace("`n", "`r`n"))
    }
    [IO.File]::WriteAllText((Join-Path $installed 'src\Controller.ps1'), '# an older controller, replaced by the migration')
    foreach ($name in $executables) {
        [IO.File]::WriteAllText((Join-Path $build $name), "current $name")
        [IO.File]::WriteAllText((Join-Path $installed "bin\$name"), "current $name")
    }
    $mismatches = @(Get-ProgramSplitMigrationMismatches -InstalledRoot $installed -RepositoryRoot $RepositoryRoot `
        -BuildDirectory $build -ReplacedScripts $replaced -Executables $executables)
    Assert-True ($mismatches.Count -eq 0) "an installation of this release migrates: $($mismatches -join ', ')"
    # The layout before persistent filters: a dynamic-session wrapper and host, and no validation worker.
    [IO.File]::WriteAllText((Join-Path $installed 'src\Invoke-WfpFilters.ps1'), "param([ValidateSet('Start', 'Stop', 'Status')] [string] `$Action)")
    Remove-Item -LiteralPath (Join-Path $installed 'src\ValidationWorker.ps1')
    [IO.File]::WriteAllText((Join-Path $installed 'bin\wfp-probe.exe'), 'dynamic session host')
    $mismatches = @(Get-ProgramSplitMigrationMismatches -InstalledRoot $installed -RepositoryRoot $RepositoryRoot `
        -BuildDirectory $build -ReplacedScripts $replaced -Executables $executables)
    Assert-True ((($mismatches | Sort-Object) -join ',') -eq 'bin\wfp-probe.exe,src\Invoke-WfpFilters.ps1,src\ValidationWorker.ps1') `
        "a legacy layout is refused with every differing component named: $($mismatches -join ', ')"
    Remove-Item -LiteralPath (Join-Path $build 'controller-service.exe')
    Assert-True (@(Get-ProgramSplitMigrationMismatches -InstalledRoot $installed -RepositoryRoot $RepositoryRoot `
        -BuildDirectory $build -ReplacedScripts $replaced -Executables $executables) -contains 'bin\controller-service.exe') `
        'a missing build output is a mismatch, not a pass'
} finally { Remove-Item -LiteralPath $legacy -Recurse -Force -ErrorAction SilentlyContinue }
$migrationSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'Migrate-Installation.ps1'))
Assert-True ($migrationSource.IndexOf('Get-ProgramSplitMigrationMismatches') -gt 0 -and
    $migrationSource.IndexOf('Get-ProgramSplitMigrationMismatches') -lt $migrationSource.IndexOf('if ($PlanOnly) { return $plan }') -and
    $migrationSource.IndexOf('if ($mismatches.Count)') -lt $migrationSource.IndexOf('$stopped = $true')) `
    'migration refuses another release before planning or stopping anything'

$removal = & (Join-Path $RepositoryRoot 'Uninstall.ps1') -PlanOnly
Assert-True ($removal.DestinationRoot -eq (Join-Path $env:ProgramFiles 'WireGuardProgramSplit')) `
    'uninstall defaults to Program Files'
Write-Output 'PASS: Program Files service ownership and real child-script launch with spaces.'
