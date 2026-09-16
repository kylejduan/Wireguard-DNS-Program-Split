#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

mapfile -d '' files < <(git ls-files -co --exclude-standard -z)
if ((${#files[@]} == 0)); then
  echo 'FAIL: no public files found.' >&2
  exit 1
fi

for path in "${files[@]}"; do
  case "${path,,}" in
    *.conf|*.dll|*.exe|*.sys|*.cat|*.zip|*.dpapi|*.pyc|*.pyo|*.pyz|*.o|*.pcap|*.pcapng)
      echo "FAIL: private or binary artifact is public: $path" >&2
      exit 1
      ;;
  esac
done

if grep -nIE 'PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{40,}=' "${files[@]}"; then
  echo 'FAIL: a WireGuard private key appears in the public tree.' >&2
  exit 1
fi
if grep -nIE '[A-Za-z]:\\Users\\[^%<]' "${files[@]}"; then
  echo 'FAIL: a literal Windows user profile appears in the public tree.' >&2
  exit 1
fi

while IFS= read -r -d '' path; do
  lines=$(wc -l < "$path")
  if ((lines > 1000)); then
    echo "FAIL: source file exceeds 1000 lines: $path ($lines)" >&2
    exit 1
  fi
done < <(find src tests -type f \( -name '*.cpp' -o -name '*.ps1' -o -name '*.py' -o -name '*.c' -o -name '*.h' \) -print0)

echo 'PASS: public tree contains no private artifacts, literal user paths, or oversized sources.'
