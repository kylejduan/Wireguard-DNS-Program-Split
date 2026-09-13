#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output="$repo/build/linux"
mkdir -p "$output"
cc -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
    "$repo/tests/linux/probe_socket.c" -o "$output/probe_socket"
if [[ ${1:-} == --fixture-only ]]; then exit 0; fi
if [[ ${WG_CLASSIFIER_DISPOSABLE_VM:-} != 1 ]] ||
   [[ $(uname -r) == *microsoft* ]] || [[ $(hostname) == TV ]]; then
    echo 'BPF build requires WG_CLASSIFIER_DISPOSABLE_VM=1 on the disposable native VM.' >&2
    exit 1
fi
for tool in bpftool clang c++ pkg-config; do command -v "$tool" >/dev/null; done
test -r /sys/kernel/btf/vmlinux
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
case "$(uname -m)" in
    x86_64) arch=x86 ;;
    aarch64) arch=arm64 ;;
    *) echo 'Unsupported BPF build architecture' >&2; exit 1 ;;
esac
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$output/vmlinux.h.new"
mv "$output/vmlinux.h.new" "$output/vmlinux.h"
clang -O2 -g -target bpf -D"__TARGET_ARCH_$arch" -Wall -Wextra -Werror \
    -I"$output" $(pkg-config --cflags libbpf) \
    -c "$repo/src/linux/bpf/classifier.bpf.c" -o "$output/classifier.bpf.o"
c++ -O2 -g -std=c++17 -Wall -Wextra -Werror \
    "$repo/src/linux/native/bpf-loader.cpp" -o "$output/bpf-loader" \
    $(pkg-config --cflags --libs libbpf)
printf 'Built for kernel %s; libbpf %s. No attachment performed.\n' \
    "$(uname -r)" "$(pkg-config --modversion libbpf)"
