#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Linux fixtures stay in the checkout. Windows junction/ACL fixtures need NTFS;
# WSL's Linux filesystem cannot implement those Windows filesystem operations.
mkdir -p "$repo_root/local/test-temp"
export TMPDIR="$repo_root/local/test-temp"
windows_test_temp=$(powershell.exe -NoLogo -NoProfile -NonInteractive -Command '
  $base = [Environment]::ExpandEnvironmentVariables([Environment]::GetEnvironmentVariable("TEMP", "User"))
  if (-not $base -or $base.StartsWith("\\")) { throw "A local Windows TEMP directory is required." }
  $path = Join-Path $base ("wgps-tests-" + [guid]::NewGuid().ToString())
  [IO.Directory]::CreateDirectory($path) | Out-Null
  [Console]::WriteLine($path)
' | tr -d '\r')
windows_test_temp_wsl=$(wslpath -u "$windows_test_temp")
cleanup_windows_fixtures() {
  if [[ -n "$windows_test_temp_wsl" && -d "$windows_test_temp_wsl" ]]; then
    rm -rf -- "$windows_test_temp_wsl"
  fi
}
trap cleanup_windows_fixtures EXIT
export TEMP="$windows_test_temp_wsl" TMP="$windows_test_temp_wsl"
export WSLENV="${WSLENV:+$WSLENV:}TEMP/p:TMP/p"
"$repo_root/scripts/build-wsl.sh"
compiler=${CXX:-x86_64-w64-mingw32-g++}
"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static \
  "$repo_root/tests/native/net-probe.cpp" -o "$repo_root/build/test-net-probe.exe" -lws2_32 -ldnsapi

"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
  "$repo_root/tests/native/tray-action.cpp" -o "$repo_root/build/test-tray-action.exe" -lcrypt32

"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
  "$repo_root/tests/native/tray-dialog.cpp" -o "$repo_root/build/test-tray-dialog.exe" -lcrypt32

"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
  "$repo_root/tests/native/tray-session.cpp" -o "$repo_root/build/test-tray-session.exe" -lshell32 -lcomdlg32 -luser32 -lcrypt32 -lole32
"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
  "$repo_root/tests/native/tray-stub.cpp" -o "$repo_root/build/test-tray-stub.exe"

"$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
  "$repo_root/tests/native/tray-backstop.cpp" -o "$repo_root/build/test-tray-backstop.exe" -lcrypt32

for executable in controller-service dns-dispatcher dns-probe wfp-probe tray; do
  "$repo_root/build/$executable.exe" --self-test
done

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-PowerShell.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-TcpListener.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-NetworkRecovery.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-NetworkRecoveryExecution.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-RepairPolicy.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-TunnelRecovery.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-RecoveryStability.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-ControllerHealth.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-InstallLayout.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-InstallPaths.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-ProcessIdentity.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-AdapterMaintenance.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-TunnelPreflight.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-StateFiles.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-ResourceLimits.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-ValidationWorker.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-Tray.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-TrayMaintenance.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

"$repo_root/tests/check-public-tree.sh"

# Opt-in: exercise tunnel recovery against the real Service Control Manager. Prompts for elevation and
# creates, hangs and removes a throwaway service; it never touches the installed tunnel.
if [[ "${1:-}" == "--live" ]]; then
  compiler=${CXX:-x86_64-w64-mingw32-g++}
  "$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
    "$repo_root/tests/native/pending-service.cpp" -o "$repo_root/build/test-pending-service.exe"
  stage="$windows_test_temp_wsl/live"
  mkdir -p "$stage"
  cp "$repo_root/src/powershell/Invoke-Tunnel.ps1" "$repo_root/tests/Test-TunnelRecoveryLive.ps1" \
    "$repo_root/build/test-pending-service.exe" "$stage/"
  cat > "$stage/run-live.ps1" <<'POWERSHELL'
$ErrorActionPreference='Stop'
$result=Join-Path $PSScriptRoot 'result.txt'
try {
  & (Join-Path $PSScriptRoot 'Test-TunnelRecoveryLive.ps1') `
    -TunnelScript (Join-Path $PSScriptRoot 'Invoke-Tunnel.ps1') `
    -StubService (Join-Path $PSScriptRoot 'test-pending-service.exe') *>&1 |
    Out-File -LiteralPath $result -Encoding utf8
} catch { $_ | Out-String | Out-File -LiteralPath $result -Encoding utf8 -Append; exit 1 }
POWERSHELL
  cat > "$stage/elevate-live.ps1" <<'POWERSHELL'
$run=Join-Path $PSScriptRoot 'run-live.ps1'
$arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$run`""
$process=Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList $arguments -PassThru
exit $process.ExitCode
POWERSHELL
  powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(wslpath -w "$stage/elevate-live.ps1")" || true
  result=$(tr -d '\r' < "$stage/result.txt" 2>/dev/null || true)
  rm -r -- "$stage"
  printf '%s\n' "$result"
  grep -q 'PASS: tunnel recovery works against the real Service Control Manager' <<< "$result"
fi
