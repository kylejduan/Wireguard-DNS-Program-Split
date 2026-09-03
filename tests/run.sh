#!/usr/bin/env bash
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
  -File "$(wslpath -w "$repo_root/tests/Test-InstallLayout.ps1")" \
  -RepositoryRoot "$(wslpath -w "$repo_root")"

"$repo_root/tests/check-public-tree.sh"
