#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
"$repo_root/scripts/build-wsl.sh"

for executable in controller-service dns-dispatcher dns-probe wfp-probe; do
  "$repo_root/build/$executable.exe" --self-test
done

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-PowerShell.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-TunnelRecovery.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-ControllerHealth.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
  -File "$(wslpath -w "$repo_root/tests/Test-InstallLayout.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

"$repo_root/tests/check-public-tree.sh"

# Opt-in: exercise tunnel recovery against the real Service Control Manager. Prompts for elevation and
# creates, hangs and removes a throwaway service; it never touches the installed tunnel.
if [[ "${1:-}" == "--live" ]]; then
  compiler=${CXX:-x86_64-w64-mingw32-g++}
  "$compiler" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode \
    "$repo_root/tests/native/pending-service.cpp" -o "$repo_root/build/test-pending-service.exe"
  stage=$(wslpath -u "$(powershell.exe -NoProfile -Command '[IO.Path]::GetTempPath()' | tr -d '\r')")wgps-live-$$
  mkdir -p "$stage"
  cp "$repo_root/src/powershell/Invoke-Tunnel.ps1" "$repo_root/tests/Test-TunnelRecoveryLive.ps1" \
    "$repo_root/build/test-pending-service.exe" "$stage/"
  stage_windows=$(wslpath -w "$stage")
  powershell.exe -NoLogo -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',\"& '$stage_windows\\Test-TunnelRecoveryLive.ps1' -TunnelScript '$stage_windows\\Invoke-Tunnel.ps1' -StubService '$stage_windows\\test-pending-service.exe' *>&1 | Out-File -FilePath '$stage_windows\\result.txt' -Encoding utf8\""
  result=$(tr -d '\r' < "$stage/result.txt" 2>/dev/null || true)
  rm -rf "$stage"
  printf '%s\n' "$result"
  grep -q 'PASS: tunnel recovery works against the real Service Control Manager' <<< "$result"
fi
