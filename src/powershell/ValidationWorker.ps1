# SPDX-License-Identifier: GPL-3.0-or-later
param([switch] $Serve)

# Anonymous pipes expose no named endpoint. The parent owns a kill-on-close job
# containing this worker and its probes; a timed-out request cannot outlive it.
if ($Serve) {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    # .NET Framework initializes redirected stdin using the parent console
    # encoding and can emit a UTF-8 preamble during Process.Start itself.
    $inputReader = [IO.StreamReader]::new([Console]::OpenStandardInput(), [Text.UTF8Encoding]::new($false, $true), $true)
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    while ($null -ne ($request = $inputReader.ReadLine())) {
        if ($request -notin @('Invoke-LocalNrpt.ps1', 'Invoke-DnsDispatcher.ps1')) { exit 2 }
        try {
            # Invocation (not dot sourcing) gives each request a fresh script scope.
            # The scripts reload configuration and observe live state on every call.
            $LASTEXITCODE = 0
            $output = @(& (Join-Path $PSScriptRoot $request) -Action Validate *>&1)
            if ($LASTEXITCODE -ne 0) { throw "Validation exited with code $LASTEXITCODE." }
            $message = $output -join ' '
            if ($message.Length -gt 16384) { throw 'Validation output exceeded its limit.' }
            $reply = @{ Ok = $true; Message = $message }
        } catch {
            $message = [string]$_.Exception.Message
            if ($message.Length -gt 16384) { $message = $message.Substring(0, 16384) }
            $reply = @{ Ok = $false; Message = $message }
        }
        [Console]::WriteLine(($reply | ConvertTo-Json -Compress))
    }
    exit 0
}

if (-not ('ProgramSplit.ValidationWorker' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
namespace ProgramSplit {
    public sealed class ValidationWorker : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
            public long ProcessTime, JobTime;
            public uint Flags;
            public UIntPtr MinWorkingSet, MaxWorkingSet;
            public uint ActiveProcesses;
            public UIntPtr Affinity;
            public uint Priority, Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct JobLimits {
            public BasicLimits Basic;
            public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeWaitHandle CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool SetInformationJobObject(SafeWaitHandle job, int kind, ref JobLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool AssignProcessToJobObject(SafeWaitHandle job, IntPtr process);
        SafeWaitHandle job;
        Process child;
        public int ProcessId { get { return child.Id; } }
        public ValidationWorker(string script) {
            try {
                job = CreateJobObject(IntPtr.Zero, null);
                var limits = new JobLimits();
                limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                if (job.IsInvalid || !SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)))
                    throw new InvalidOperationException("Cannot supervise validation worker.");
                var start = new ProcessStartInfo(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                 @"WindowsPowerShell\v1.0\powershell.exe"),
                    "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\" -Serve");
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                start.RedirectStandardInput = true;
                start.RedirectStandardOutput = true;
                start.StandardOutputEncoding = new UTF8Encoding(false);
                child = Process.Start(start);
                if (!AssignProcessToJobObject(job, child.Handle))
                    throw new InvalidOperationException("Cannot contain validation worker.");
            } catch { Dispose(); throw; }
        }
        public string Validate(string name, int timeoutMilliseconds) {
            if (name != "Invoke-LocalNrpt.ps1" && name != "Invoke-DnsDispatcher.ps1")
                throw new ArgumentException("Unsupported validation.");
            try {
                // StreamWriter may emit a BOM when the supervisor console is
                // UTF-8 (including CI). Requests are fixed ASCII, with no BOM.
                byte[] request = Encoding.ASCII.GetBytes(name + "\n");
                child.StandardInput.BaseStream.Write(request, 0, request.Length);
                child.StandardInput.BaseStream.Flush();
                var read = Task.Run(() => {
                    var line = new StringBuilder();
                    for (;;) {
                        int value = child.StandardOutput.Read();
                        if (value < 0) throw new IOException("Validation worker exited without a result.");
                        if (value == '\n') return line.ToString();
                        if (line.Length >= 65536) throw new IOException("Validation response exceeded its limit.");
                        line.Append((char)value);
                    }
                });
                try {
                    if (!read.Wait(timeoutMilliseconds)) throw new TimeoutException("Validation worker timed out.");
                    return read.Result;
                } catch (AggregateException error) { throw error.GetBaseException(); }
            } catch { Dispose(); throw; }
        }
        public void Dispose() {
            if (job != null) { job.Dispose(); job = null; }
            if (child != null) {
                try { if (!child.HasExited) child.Kill(); child.WaitForExit(5000); } catch (InvalidOperationException) { }
                child.Dispose(); child = null;
            }
        }
    }
}
'@
}
$script:validationWorker = $null

function Stop-ValidationWorker {
    if ($script:validationWorker) {
        $script:validationWorker.Dispose()
        $script:validationWorker = $null
    }
}

function Invoke-Validation([string] $Name) {
    try {
        if (-not $script:validationWorker) {
            $script:validationWorker = [ProgramSplit.ValidationWorker]::new($PSCommandPath)
        }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $reply = $script:validationWorker.Validate($Name, 45000) | ConvertFrom-Json
        if ($reply.Ok -isnot [bool] -or -not $reply.Ok) { throw "$Name Validate failed: $($reply.Message)" }
        Write-ControllerLog ([string]$reply.Message)
        Write-ControllerLog "$Name Validate completed in $($timer.ElapsedMilliseconds) ms."
    } catch {
        Stop-ValidationWorker
        throw
    }
}
