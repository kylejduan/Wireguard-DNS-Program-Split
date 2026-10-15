#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A failed early guard is retried without an operator; disposable VM only.

The runtime directory is a small tmpfs that is filled, so every journal or
birth-record write fails with ENOSPC, as on a host whose /run is briefly full.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import test_acceptance as acc

REPO = Path(__file__).resolve().parents[2]
CONTROLLER, GUARD = acc.UNITS[1], acc.UNITS[0]


def run(*args, okay=True, timeout=90):
    return acc.execute(*args, okay=okay, timeout=timeout, env=acc.ENV)


def substate(name):
    return run('systemctl', 'show', name, '-p', 'SubState', '--value').stdout.strip()


def unit(name):
    result = run('systemctl', 'show', name, '-p', 'ActiveState', '-p', 'NRestarts', '-p', 'MainPID')
    return {key: value for key, value in (line.split('=', 1) for line in result.stdout.splitlines())}


def status():
    result = run(acc.CLI, 'status', okay=False)
    return json.loads(result.stdout).get('state') if result.returncode == 0 else None


class Runtime:
    """A full /run/wg-program-split; remount() is the empty /run of a new boot."""

    def __init__(self):
        self.filler = acc.STATE / 'filler'

    def mount(self):
        acc.STATE.mkdir(mode=0o700, exist_ok=True)
        run('mount', '-t', 'tmpfs', '-o', 'size=64k,mode=0700', 'wgps-retry', acc.STATE)
        with open(self.filler, 'wb', buffering=0) as output:
            try:
                while output.write(b'\0' * 4096):
                    pass
            except OSError:
                pass
        probe = acc.STATE / 'probe'
        try:
            probe.write_text('x' * 4096)
            raise AssertionError('runtime directory still has space')
        except OSError:
            probe.unlink(missing_ok=True)

    def unmount(self):
        if os.path.ismount(acc.STATE):
            run('umount', acc.STATE)


def observe(seconds, samples):
    """Sample until SECONDS pass: never ready, nothing networked, any pins blocked."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        state = unit(CONTROLLER)
        samples.append((time.monotonic(), int(state['NRestarts'])))
        assert status() != 'ready', 'ready while the guard could not be recorded'
        assert run('ip', 'link', 'show', 'wgps0', okay=False).returncode != 0, 'network prepared without a guard'
        if acc.PINS.exists():
            snapshot = json.loads(run(acc.ARTIFACTS / 'bpf-loader', 'snapshot', acc.PINS).stdout)
            assert not snapshot['ready'], 'guard pins are not blocking'
        time.sleep(0.5)


def restart_times(samples):
    times, last = [], samples[0][1]
    for moment, count in samples:
        if count != last:
            times.append(moment)
            last = count
    return times


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vm', action='store_true', required=True)
    parser.parse_args()
    acc.require_vm()
    sys.path.insert(0, str(REPO / 'src/linux'))
    os.environ['PYTHONPATH'] = str(REPO / 'src/linux')
    from fixtures import vpn_fixture
    acc.pristine()
    baseline = acc.snapshot()
    evidence = REPO / 'local/validation' / ('guard-retry-' + uuid.uuid4().hex[:10])
    evidence.mkdir(parents=True, mode=0o700)
    run('cc', '-O2', '-std=c11', '-pthread', REPO / 'tests/linux/probe_socket.c', '-o', evidence / 'selected-ip')
    build = REPO / 'build/linux'
    runtime, results = Runtime(), {}
    with vpn_fixture(owned_host=False) as peer:
        profile, settings = evidence / 'profile.conf', evidence / 'settings.json'
        profile.write_text('[Interface]\nPrivateKey = ' + (peer / 'host.key').read_text().strip() +
                           '\nAddress = 10.200.0.1/32\nDNS = 10.200.0.2\n[Peer]\nPublicKey = ' +
                           (peer / 'peer.pub').read_text().strip() +
                           '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.2:51822\n')
        settings.write_text(json.dumps({'schema_version': 1, 'included_executables': [str(evidence / 'selected-ip')]}))
        profile.chmod(0o600); settings.chmod(0o600)
        run('/usr/bin/python3', '-I', build / 'wg-program-split.pyz', 'install', '--profile', profile,
            '--settings', settings, '--artifacts', build)
        try:
            # A persistent failure: the controller starts anyway and retries,
            # backing off, and an explicit disable ends the retries.
            runtime.mount()
            run('systemctl', 'start', '--no-block', CONTROLLER)  # Pulls in the early guard first.
            samples = []
            observe(75, samples)
            assert unit(GUARD)['ActiveState'] == 'failed', unit(GUARD)
            times = restart_times(samples)
            gaps = [round(b - a, 1) for a, b in zip(times, times[1:])]
            results['persistent_restart_gaps_seconds'] = gaps
            assert 3 <= len(times) <= 6 and gaps[-1] >= 2 * gaps[0], (times, gaps)
            print('PASS a failed early guard still starts the controller, which retries with backoff', gaps, flush=True)
            disabled = run(acc.CLI, 'disable', okay=False)
            results['disable_exit_under_enospc'] = disabled.returncode
            frozen = unit(CONTROLLER)
            assert frozen['ActiveState'] in ('inactive', 'failed') and frozen['MainPID'] == '0', frozen
            time.sleep(20)
            assert unit(CONTROLLER)['NRestarts'] == frozen['NRestarts'], 'retries continued after disable'
            assert unit(CONTROLLER)['ActiveState'] in ('inactive', 'failed')
            print('PASS explicit disable stops the retries', flush=True)

            # A transient failure at boot: once space returns, the next retry
            # loads the guard, then networking, with no operator step.
            runtime.unmount()
            runtime.mount()
            run('systemctl', 'reset-failed', *acc.UNITS, okay=False)  # Exits 1 for a unit not failed.
            run('systemctl', 'enable', *acc.UNITS)
            run('systemctl', 'start', '--no-block', CONTROLLER)
            samples = []
            observe(15, samples)
            assert restart_times(samples), 'no failed startup was retried'
            # Free the space while a retry is pending (the restart delay is at
            # least five seconds), not while its transaction runs: the guard
            # unit then sees the space too and ends active. If the fault cleared
            # between the guard and controller of one retry, the controller
            # would load the guard itself and the unit would stay failed.
            acc.wait_for(lambda: substate(CONTROLLER) == 'auto-restart', 'a pending controller retry', timeout=60)
            runtime.filler.unlink()
            freed = time.monotonic()
            acc.wait_for(lambda: status() == 'ready', 'automatic recovery to ready', timeout=120)
            results['recovery_after_space_returned_seconds'] = round(time.monotonic() - freed, 1)
            results['guard_unit_after_recovery'] = unit(GUARD)['ActiveState']
            # Each retry pulled the early guard in again, ordered before the controller.
            assert results['guard_unit_after_recovery'] == 'active'
            snapshot = json.loads(run(acc.ARTIFACTS / 'bpf-loader', 'snapshot', acc.PINS).stdout)
            assert snapshot['ready']
            probe = run(evidence / 'selected-ip', 'identity').stdout
            assert f"mark=0x{snapshot['mark']:08x}" in probe, probe
            print('PASS a transient early-guard failure recovers to ready without an operator', flush=True)
            disabled = json.loads(run(acc.CLI, 'disable').stdout)
            assert disabled['state'] == 'disabled' and not acc.PINS.exists()
            assert all(unit(name)['ActiveState'] in ('inactive', 'failed') for name in acc.UNITS)
            print('PASS disable after recovery releases the guard and network', flush=True)
        finally:
            run(acc.CLI, 'disable', okay=False)
            run(acc.CLI, 'uninstall', okay=False)
            runtime.unmount()
            shutil.rmtree(acc.STATE, ignore_errors=True)
            for name in ('profile.conf', 'settings.json', 'installation.json'):
                (acc.CONFIG / name).unlink(missing_ok=True)
            for directory in (acc.CONFIG, acc.ARTIFACTS):  # Uninstall keeps directories.
                if directory.exists():
                    directory.rmdir()
            run('systemctl', 'daemon-reload')
            for name in acc.UNITS:
                run('systemctl', 'reset-failed', name, okay=False)
            for path in (profile, settings):
                path.unlink(missing_ok=True)
    (evidence / 'results.json').write_text(json.dumps(results, indent=2))
    assert acc.snapshot() == baseline, 'baseline routes, resolver, BPF or listeners changed'
    acc.pristine()
    print('PASS fixture removed; baseline restored. Evidence:', evidence, json.dumps(results), flush=True)


if __name__ == '__main__':
    main()
