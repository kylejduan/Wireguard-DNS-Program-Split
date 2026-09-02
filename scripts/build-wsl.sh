#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compiler=${CXX:-x86_64-w64-mingw32-g++}
output="$repo_root/build"
common=(-std=c++20 -O2 -Wall -Wextra -Werror -static)

mkdir -p "$output"
"$compiler" "${common[@]}" -municode "$repo_root/src/native/dns-dispatcher.cpp" \
  -o "$output/dns-dispatcher.exe" -lws2_32 -ltdh
"$compiler" "${common[@]}" "$repo_root/src/native/dns-probe.cpp" \
  -o "$output/dns-probe.exe" -lws2_32 -ldnsapi
"$compiler" "${common[@]}" -municode "$repo_root/src/native/tunnel-host.cpp" \
  -o "$output/tunnel-host.exe"
"$compiler" "${common[@]}" -municode "$repo_root/src/native/wfp-probe.cpp" \
  -o "$output/wfp-probe.exe" -lfwpuclnt -lrpcrt4 -lole32 -lws2_32
