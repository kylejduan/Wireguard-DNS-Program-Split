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
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-Component'
}, $true))
Assert-True ($launcher.Count -eq 1) 'controller component launcher is available'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('WireGuard path test ' + [guid]::NewGuid())
$process = $null
try {
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    [IO.File]::WriteAllText((Join-Path $temporary 'sample child.ps1'), 'param([string] $Action) Write-Output "child received: $Action"')
    [IO.File]::WriteAllText((Join-Path $temporary 'launch.ps1'),
        '$logs = $PSScriptRoot' + "`n" + $launcher[0].Extent.Text + "`n" + 'Start-Component "sample child.ps1" "Validate"')
    $component = & (Join-Path $temporary 'launch.ps1')
    $process = $component.Process
    Assert-True ($process.WaitForExit(10000)) 'component exits within its deadline'
    $process.WaitForExit()
    Assert-True ($process.ExitCode -eq 0) 'component path with spaces executes successfully'
    Assert-True ((Get-Content -LiteralPath $component.Stdout -Raw).Trim() -eq 'child received: Validate') `
        'child receives the requested action from a path containing spaces'
} finally {
    if ($process) {
        if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
$removal = & (Join-Path $RepositoryRoot 'Uninstall.ps1') -PlanOnly
Assert-True ($removal.DestinationRoot -eq (Join-Path $env:ProgramFiles 'WireGuardProgramSplit')) `
    'uninstall defaults to Program Files'
Write-Output 'PASS: Program Files service ownership and real child-script launch with spaces.'
