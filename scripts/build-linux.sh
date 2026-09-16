#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output="$repo/build/linux"
mkdir -p "$output"
cc -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
    "$repo/tests/linux/probe_socket.c" -o "$output/probe_socket"
if [[ ${1:-} == --fixture-only ]]; then exit 0; fi
if [[ ${1:-} != --package-only ]]; then
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
fi
python3 - "$repo" "$output" <<'PY'
from pathlib import Path
import shutil
import sys
import zipfile

repo, output = map(Path, sys.argv[1:])
with zipfile.ZipFile(output / 'wg-program-split.pyz.new', 'w',
                     compression=zipfile.ZIP_DEFLATED) as archive:
    def add(name, data):
        # Fixed timestamps and mode: the same sources give the same archive bytes.
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, data)
    for source in sorted((repo / 'src/linux/wg_program_split').glob('*.py')):
        add('wg_program_split/' + source.name, source.read_bytes())
    add('__main__.py', 'from wg_program_split.cli import main\nraise SystemExit(main())\n')
(output / 'wg-program-split.pyz.new').replace(output / 'wg-program-split.pyz')
for unit in ('wg-program-split-guard.service', 'wg-program-split.service'):
    shutil.copyfile(repo / 'src/linux/systemd' / unit, output / unit)
print('Packaged isolated Python CLI and service units. No installation performed.')
PY
