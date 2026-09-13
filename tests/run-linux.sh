#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$repo/src/linux"
case "${1:-}" in
    '')
        python3 -m unittest discover -s tests/linux -p 'test_*.py'
        tests/linux/test_classifier.sh baseline
        tests/linux/test_classifier.sh native
        python3 tests/linux/test_resolver_ipc.py --native
        python3 tests/linux/test_policy_bulk.py --native
        python3 tests/linux/test_boot.py --native
        bash -n scripts/build-linux.sh scripts/wg-program-split tests/run-linux.sh
        tests/check-public-tree.sh
        ;;
    --vm)
        if [[ ${WG_CLASSIFIER_DISPOSABLE_VM:-} != 1 || $EUID != 0 ]] ||
           [[ ! -f /var/lib/wgps-vm-provisioned || $(hostname) == TV ]] ||
           [[ $(uname -r) == *microsoft* ]]; then
            echo 'FAIL: privileged checks require the explicitly marked disposable native VM.' >&2
            exit 1
        fi
        if [[ -z ${SUDO_USER:-} || $SUDO_USER == root ]]; then
            echo 'FAIL: invoke via sudo from a non-root account with a systemd user manager.' >&2
            exit 1
        fi
        validation_uid=$(id -u "$SUDO_USER")
        if ! runuser -u "$SUDO_USER" -- env "XDG_RUNTIME_DIR=/run/user/$validation_uid" \
             timeout 5 systemctl --user show-environment >/dev/null; then
            echo 'FAIL: the invoking account needs a working systemd user manager.' >&2
            exit 1
        fi
        scripts/build-linux.sh
        tests/linux/test_classifier.sh vm
        python3 tests/linux/test_resolver_ipc.py --vm
        python3 tests/linux/test_policy_bulk.py --vm
        python3 tests/linux/test_dns_paths.py --vm
        python3 tests/linux/test_resolver_integration.py --vm
        python3 tests/linux/test_network_vm.py --vm
        python3 tests/linux/test_packet_paths.py --vm
        python3 tests/linux/test_acceptance.py --vm
        ;;
    --performance)
        python3 tests/linux/test_dns_performance.py --vm
        ;;
    *) echo 'Usage: tests/run-linux.sh [--vm|--performance]' >&2; exit 2 ;;
esac
