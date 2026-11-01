# SPDX-License-Identifier: GPL-3.0-or-later
param([Parameter(Mandatory)] [string] $RepositoryRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'src\powershell\Common.ps1'), [ref] $tokens, [ref] $errors)
$function = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-ProgramSplitOwnedTcpListener'
}, $true)
Assert-True ($errors.Count -eq 0 -and $null -ne $function) 'listener probe parses'
Invoke-Expression $function.Extent.Text

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    Assert-True (Test-ProgramSplitOwnedTcpListener -ProcessId $PID -Port $port) 'real owned listener accepts connections'
    Assert-True (-not (Test-ProgramSplitOwnedTcpListener -ProcessId 0 -Port $port)) 'foreign listener is rejected'
    $listener.Stop()
    Assert-True (-not (Test-ProgramSplitOwnedTcpListener -ProcessId $PID -Port $port)) 'closed listener is rejected'

    # Reproduce State=0 metadata independently of the host build. An owned endpoint
    # without a listener still must fail, so metadata alone can never pass the probe.
    $listener.Start()
    $script:testListenerPort = $listener.LocalEndpoint.Port
    function Get-NetTCPConnection {
        param($LocalAddress, $LocalPort, $ErrorAction)
        [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = $LocalPort; OwningProcess = $PID; State = 0; RemoteAddress='0.0.0.0'; RemotePort=0 }
    }
    Assert-True (Test-ProgramSplitOwnedTcpListener -ProcessId $PID -Port $script:testListenerPort) 'unknown state does not reject a working owned listener'
    Assert-True (-not (Test-ProgramSplitOwnedTcpListener -ProcessId 0 -Port $script:testListenerPort)) 'unknown state still requires the right process'
    $listener.Stop()
    Assert-True (-not (Test-ProgramSplitOwnedTcpListener -ProcessId $PID -Port $script:testListenerPort)) 'stale owned metadata cannot pass after listener closes'
    Remove-Item Function:\Get-NetTCPConnection
    Write-Output 'PASS: owned TCP listener, foreign owner, closed socket, unknown state and stale metadata.'
} finally { $listener.Stop() }
