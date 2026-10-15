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

# Component and probe output comes back through pipes; a log another process holds open with read-only
# sharing neither fails the run nor changes its result, and capture is bounded.
$commonPath = Join-Path $RepositoryRoot 'src\powershell\Common.ps1'
$commonAst = [Management.Automation.Language.Parser]::ParseFile($commonPath, [ref]$tokens, [ref]$errors)
# The bounded runner is controller-service.exe --run from the build.
$ProgramSplitRunner = Join-Path $RepositoryRoot 'build\controller-service.exe'
foreach ($name in @('ConvertTo-ProgramSplitArgument', 'Start-ProgramSplitProcess', 'Complete-ProgramSplitProcess', 'Invoke-ProgramSplitProcess')) {
    $function = @($commonAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    Assert-True ($function.Count -eq 1) "exactly one $name implementation"
    . ([scriptblock]::Create($function[0].Extent.Text))
}
foreach ($name in @('Start-Component', 'Complete-Component', 'Invoke-Component')) {
    $function = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true))
    Assert-True ($function.Count -eq 1) "exactly one $name implementation"
    # The component directory is the fixture's rather than this script's.
    . ([scriptblock]::Create($function[0].Extent.Text.Replace('$PSScriptRoot', '$componentRoot')))
}
$temporary = Join-Path $RepositoryRoot ("local\test-temp\capture-{0}" -f [guid]::NewGuid())
try {
    $logs = Join-Path $temporary 'logs'
    $logFile = Join-Path $logs 'controller.log'
    [IO.Directory]::CreateDirectory($logs) | Out-Null
    $cmd = "$env:SystemRoot\System32\cmd.exe"
    $lockedOutput = Join-Path $logs 'probe.log'
    [IO.File]::WriteAllText($lockedOutput, 'before')
    $reader = [IO.FileStream]::new($lockedOutput, 'Open', 'Read', 'Read')
    try {
        $result = Invoke-ProgramSplitProcess -FilePath $cmd -ArgumentList @('/d', '/c', 'echo PASS: answered& exit 0') `
            -TimeoutMilliseconds 10000 -OutputLog $lockedOutput -ErrorLog (Join-Path $logs 'probe-error.log') -Encoding Oem
        Assert-True ($result.ExitCode -eq 0 -and -not $result.TimedOut -and ($result.Output -match '^PASS: answered')) `
            "a probe whose log is held open read-only still runs and is judged from its pipes: $($result.Output)"
        $failed = Invoke-ProgramSplitProcess -FilePath $cmd -ArgumentList @('/d', '/c', 'echo broken 1>&2& exit 3') `
            -TimeoutMilliseconds 10000 -OutputLog $lockedOutput
        Assert-True ($failed.ExitCode -eq 3 -and ($failed.Error -match 'broken')) 'a failing probe is still reported as failing'
    } finally { $reader.Dispose() }
    Assert-True ([IO.File]::ReadAllText($lockedOutput) -eq 'before') 'a locked log is left as it was rather than failing the run'
    $free = Join-Path $logs 'free.log'
    $null = Invoke-ProgramSplitProcess -FilePath $cmd -ArgumentList @('/d', '/c', 'echo written') -TimeoutMilliseconds 10000 -OutputLog $free
    Assert-True ([IO.File]::ReadAllText($free) -match 'written') 'an unlocked log still receives the output'
    $large = Invoke-ProgramSplitProcess -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoProfile', '-Command', '[Console]::Out.Write((''x'' * 1048576)); exit 0') -TimeoutMilliseconds 60000
    Assert-True ($large.ExitCode -eq 0 -and ($large.Output -join '').Length -le 65536) `
        "capture keeps at most 64 KiB of a large output and still drains it: $(($large.Output -join '').Length)"
    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $slow = Invoke-ProgramSplitProcess -FilePath $powerShell `
        -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutMilliseconds 2000 -Encoding Oem
    Assert-True ($slow.TimedOut -and $null -eq $slow.ExitCode -and $slow.Milliseconds -lt 15000) 'a probe past its deadline is ended and reported'
    # A program that writes without end is still ended at its deadline.
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $flood = Invoke-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-Command',
        'while ($true) { [Console]::Out.Write((''x'' * 4096)) }') -TimeoutMilliseconds 3000
    Assert-True ($flood.TimedOut -and $timer.Elapsed.TotalSeconds -lt 15) "a program writing without end is ended at its deadline ($($timer.Elapsed.TotalSeconds) s)"
    # Descendants end with the program: on its timeout, and when it exits leaving one behind.
    foreach ($case in @(@{ Name = 'timed out'; Tail = 'Start-Sleep -Seconds 120'; Timeout = 8000 }, @{ Name = 'exited'; Tail = 'exit 0'; Timeout = 30000 })) {
        $script = ('$child = Start-Process -FilePath ''{0}'' -ArgumentList ''-NoProfile'',''-Command'',''Start-Sleep -Seconds 120'' -PassThru -WindowStyle Hidden; ' +
            '[Console]::Out.WriteLine($child.Id); [Console]::Out.Flush(); {1}') -f $powerShell, $case.Tail
        $parent = Invoke-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-EncodedCommand',
            [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))) -TimeoutMilliseconds $case.Timeout
        $grandchild = [int]@($parent.Output | Where-Object { $_ -match '^\d+$' })[0]
        $wait = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-Process -Id $grandchild -ErrorAction SilentlyContinue) -and $wait.Elapsed.TotalSeconds -lt 5) { Start-Sleep -Milliseconds 100 }
        $survivor = Get-Process -Id $grandchild -ErrorAction SilentlyContinue
        if ($survivor) { Stop-Process -Id $grandchild -Force -ErrorAction SilentlyContinue }
        Assert-True ($grandchild -gt 0 -and -not $survivor) "a descendant of a $($case.Name) program is ended with it"
    }
    # Results collected in any order keep each program's own deadline: a fast program collected after a slow
    # one that timed out is not reported as timed out.
    $fast = Start-ProgramSplitProcess -FilePath $cmd -ArgumentList @('/d', '/c', 'echo PASS: fast') -TimeoutMilliseconds 4000 -Encoding Oem
    $sluggish = Start-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -TimeoutMilliseconds 4000
    $sluggishResult = Complete-ProgramSplitProcess -Started $sluggish
    $fastResult = Complete-ProgramSplitProcess -Started $fast
    Assert-True ($sluggishResult.TimedOut -and -not $fastResult.TimedOut -and $fastResult.ExitCode -eq 0 -and ($fastResult.Output -match 'PASS: fast')) `
        'a fast program collected after a slow one keeps its own result'
    # A program that overruns its deadline is timed out at the deadline even if it would have finished
    # before its result is collected, and one still running is not left to run past it.
    $late = Start-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 4') -TimeoutMilliseconds 1500
    Start-Sleep -Seconds 7
    $lateResult = Complete-ProgramSplitProcess -Started $late
    Assert-True ($lateResult.TimedOut -and $null -eq $lateResult.ExitCode) 'a program past its deadline is timed out at the deadline, whenever it is collected'
    # Output encoding is the producer's: UTF-8 from a native-style writer is decoded as UTF-8.
    $utf8 = Invoke-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-Command',
        '$b = [Text.Encoding]::UTF8.GetBytes([string][char]0x00E9 + [char]0x4E2D); [Console]::OpenStandardOutput().Write($b, 0, $b.Length)') -TimeoutMilliseconds 30000
    Assert-True (($utf8.Output -join '') -ceq ([string][char]0x00E9 + [char]0x4E2D)) "UTF-8 output is decoded as UTF-8: $($utf8.Output)"
    $missing = $null
    try { $null = Invoke-ProgramSplitProcess -FilePath (Join-Path $temporary 'absent.exe') -TimeoutMilliseconds 5000 } catch { $missing = $_.Exception.Message }
    Assert-True ($missing -match 'Could not run the program: cannot start the program') "a program that cannot start is reported, not run: $missing"
    Assert-True ($large.OutputTruncated) 'truncated output is flagged'
    # Exit codes keep their signed value, including NTSTATUS crash codes.
    foreach ($code in @(-1, -1073741819, 3)) {
        $exited = Invoke-ProgramSplitProcess -FilePath $cmd -ArgumentList @('/d', '/c', "exit $code") -TimeoutMilliseconds 10000 -Encoding Oem
        Assert-True ($exited.ExitCode -eq $code) "exit code $code is reported exactly: $($exited.ExitCode)"
    }
    # Every argument arrives as given, with no quoting by the caller: spaces, embedded quotes, trailing
    # backslashes, empty values and backslashes before quotes.
    $values = @('plain', 'with space', 'quote"inside', 'trailing\', 'C:\Path With Spaces\x\', '', 'back\\"quote', 'tab	and space ')
    $echo = Invoke-ProgramSplitProcess -FilePath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') `
        -ArgumentList (@('echo-args') + $values) -TimeoutMilliseconds 10000
    $echoed = @($echo.Output | Where-Object { $_ -like 'ARG*' } | ForEach-Object { $_.Substring(4).TrimEnd(']').TrimStart('[') })
    Assert-True ($echoed.Count -eq $values.Count -and -not (Compare-Object -SyncWindow 0 -CaseSensitive $echoed $values)) `
        "arguments arrive exactly as given: $($echo.Output -join ' | ')"
    # The program is in the runner's job from creation: if the runner itself dies, the program ends with it,
    # and collecting that run reports a failure rather than a result.
    $orphanable = Start-ProgramSplitProcess -FilePath $powerShell -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 60') -TimeoutMilliseconds 60000
    $wait = [Diagnostics.Stopwatch]::StartNew()
    $program = $null
    while (-not $program -and $wait.Elapsed.TotalSeconds -lt 10) {
        $program = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($orphanable.Runner.Id)" | Select-Object -First 1
        if (-not $program) { Start-Sleep -Milliseconds 100 }
    }
    $orphanable.Runner.Kill()
    $wait.Restart()
    while ((Get-Process -Id $program.ProcessId -ErrorAction SilentlyContinue) -and $wait.Elapsed.TotalSeconds -lt 5) { Start-Sleep -Milliseconds 100 }
    $orphan = Get-Process -Id $program.ProcessId -ErrorAction SilentlyContinue
    if ($orphan) { Stop-Process -Id $program.ProcessId -Force -ErrorAction SilentlyContinue }
    $collected = $null
    try { $null = Complete-ProgramSplitProcess -Started $orphanable } catch { $collected = $_.Exception.Message }
    Assert-True ($program -and -not $orphan -and $collected -match 'bounded runner failed') "a program ends with its runner, and that run is a failure: $collected"
    $spaced = Join-Path $temporary 'dir with space'
    [IO.Directory]::CreateDirectory($spaced) | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'build\test-net-probe.exe') -Destination (Join-Path $spaced 'echo probe.exe')
    $fromSpaced = Invoke-ProgramSplitProcess -FilePath (Join-Path $spaced 'echo probe.exe') -ArgumentList @('echo-args', 'x') -TimeoutMilliseconds 10000
    Assert-True ($fromSpaced.ExitCode -eq 0 -and ($fromSpaced.Output -contains 'ARG [x]')) 'a program path with spaces starts'

    # A controller component whose output and error logs are both held open read-only still completes.
    $componentRoot = Join-Path $temporary 'src'
    [IO.Directory]::CreateDirectory($componentRoot) | Out-Null
    [IO.File]::WriteAllText((Join-Path $componentRoot 'Invoke-Fixture.ps1'), "param([string] `$Action) Write-Output `"fixture `$Action done`"")
    foreach ($suffix in 'output', 'error') { [IO.File]::WriteAllText((Join-Path $logs "Invoke-Fixture-$suffix.log"), 'held') }
    $held = @(foreach ($suffix in 'output', 'error') { [IO.FileStream]::new((Join-Path $logs "Invoke-Fixture-$suffix.log"), 'Open', 'Read', 'Read') })
    try {
        $threw = $null
        try { Invoke-Component 'Invoke-Fixture.ps1' 'Validate' } catch { $threw = $_.Exception.Message }
        Assert-True (-not $threw) "a component with its logs held open completes: $threw"
        Assert-True (([IO.File]::ReadAllText($logFile)) -match 'fixture Validate done') 'the component output reaches the controller log'
    } finally { foreach ($stream in $held) { $stream.Dispose() } }
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($script in Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src\powershell') -Filter '*.ps1') {
    Assert-True (([IO.File]::ReadAllText($script.FullName)) -notmatch 'RedirectStandardOutput \$') `
        "$($script.Name) redirects no process output to a file"
}
Write-Output 'PASS: bounded controller logging, locked-file recovery, finite evidence snapshots, and log locks that cannot fail a run.'
