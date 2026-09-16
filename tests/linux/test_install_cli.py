# SPDX-License-Identifier: GPL-3.0-or-later
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import zipfile
from unittest import mock

from wg_program_split.install import ALLOWED, LAYOUT, InstallError, install, uninstall, verify_units


class InstallTests(unittest.TestCase):
    def setUp(self):
        build = Path(__file__).resolve().parents[2] / 'build/linux'
        build.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='install-test-', dir=build)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o700)
        self.artifacts = self.base / 'artifacts'
        self.artifacts.mkdir()
        for name in LAYOUT:
            (self.artifacts / name).write_bytes(b'fixture-build-artifact\n')
        key = base64.b64encode(bytes(range(1, 33))).decode()
        self.profile = f'[Interface]\nPrivateKey={key}\nAddress=10.200.0.1/32\nDNS=10.200.0.2\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.2:51822\nAllowedIPs=0.0.0.0/0\n'
        self.settings = '{"schema_version":1,"included_executables":[]}'

    def deploy(self):
        return install(self.artifacts, self.profile, self.settings, root=self.root)

    def test_install_is_inactive_and_remove_retains_private_configuration(self):
        result = self.deploy()
        self.assertFalse(result['activated'])
        self.assertEqual(set(result['installed']), ALLOWED)
        self.assertEqual((self.root / 'etc/wg-program-split/profile.conf').stat().st_mode & 0o777, 0o600)
        result = uninstall(root=self.root)
        self.assertFalse(result['retained'])
        self.assertEqual(set(result['removed']), ALLOWED)
        self.assertEqual((self.root / 'etc/wg-program-split/profile.conf').read_text(), self.profile)

    def test_include_list_reads_stored_keys_inactive_without_runtime_side_effects(self):
        from wg_program_split import cli
        from wg_program_split.controller import Controller, Paths
        self.deploy()
        config = self.root / 'etc/wg-program-split'
        keys = ['/missing/program', '/raw-byte-\udcff']
        (config / 'settings.json').write_text(json.dumps({'schema_version': 1, 'included_executables': keys}))
        (config / 'profile.conf').unlink()  # Listing configured paths does not need a VPN profile.
        state = self.root / 'run/wg-program-split'
        controller = Controller(paths=Paths(config=config, state=state, pins=self.root / 'pins'),
                                owner_uid=os.getuid())
        before = {str(p): (p.lstat().st_ino, p.lstat().st_mtime_ns) for p in self.root.rglob('*')}
        with mock.patch('wg_program_split.controller.Controller', return_value=controller), \
                mock.patch.object(cli.subprocess, 'run', side_effect=AssertionError('listing must not launch services')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['include', 'list']), 0)
        self.assertEqual(json.loads(output.getvalue()), {'mode': 'include', 'source': 'configured',
            'live_enforcement': 'not_checked', 'included_executables': keys})
        self.assertEqual(before, {str(p): (p.lstat().st_ino, p.lstat().st_mtime_ns) for p in self.root.rglob('*')})
        self.assertFalse(state.exists())

    def test_include_list_rejects_untrusted_settings_without_creating_state(self):
        from wg_program_split.controller import Controller, Paths
        self.deploy()
        config, state = self.root / 'etc/wg-program-split', self.root / 'run/wg-program-split'
        controller = Controller(paths=Paths(config=config, state=state), owner_uid=os.getuid())
        settings = config / 'settings.json'
        settings.unlink()
        settings.symlink_to(config / 'profile.conf')
        with self.assertRaises(RuntimeError):
            controller.include_list()
        self.assertFalse(state.exists())

    def test_modified_and_replaced_files_are_retained(self):
        self.deploy()
        path = self.root / 'usr/lib/wg-program-split/bpf-loader'
        path.write_bytes(b'operator modification')
        result = uninstall(root=self.root)
        self.assertIn('usr/lib/wg-program-split/bpf-loader', result['retained'])
        self.assertEqual(path.read_bytes(), b'operator modification')
        self.assertTrue(result['removal_deferred'])
        self.assertTrue((self.root / 'usr/bin/wg-program-split').exists())
        self.assertEqual(len(verify_units(root=self.root)), 2)

    def test_uninstall_can_resume_after_operator_removes_retained_file(self):
        self.deploy()
        path = self.root / 'usr/lib/wg-program-split/bpf-loader'
        path.write_bytes(b'operator modification')
        self.assertTrue(uninstall(root=self.root)['retained'])
        path.unlink()
        self.assertFalse(uninstall(root=self.root)['retained'])
        self.assertFalse((self.root / 'etc/wg-program-split/installation.json').exists())

    def test_service_control_requires_both_exact_installed_units(self):
        self.deploy()
        self.assertEqual(len(verify_units(root=self.root)), 2)
        path = self.root / 'usr/lib/systemd/system/wg-program-split.service'
        path.write_bytes(b'foreign service replacement')
        with self.assertRaises(InstallError):
            verify_units(root=self.root)

    def test_cli_uninstall_retry_remains_callable_after_deferred_removal(self):
        from wg_program_split import cli
        self.deploy()
        changed = self.root / 'usr/lib/wg-program-split/bpf-loader'
        changed.write_bytes(b'operator modification')
        def command(argv, **kwargs):
            self.assertEqual(argv[0], '/usr/bin/systemctl')
            self.assertEqual(kwargs['env'], cli.SERVICE_ENV)
            output = ('FragmentPath=/usr/lib/systemd/system/' + argv[2] + '\nDropInPaths=\n'
                      if argv[1] == 'show' else '')
            return subprocess.CompletedProcess(argv, 0, stdout=output)
        with mock.patch('wg_program_split.controller.Controller') as controller, \
                mock.patch.object(cli, 'verify_units', side_effect=lambda: verify_units(root=self.root)), \
                mock.patch.object(cli, 'uninstall', side_effect=lambda: uninstall(root=self.root)), \
                mock.patch.object(cli.subprocess, 'run', side_effect=command):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['uninstall']), 0)
            self.assertTrue(json.loads(output.getvalue())['removal_deferred'])
            self.assertTrue((self.root / 'usr/bin/wg-program-split').exists())
            changed.unlink()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['uninstall']), 0)
            self.assertFalse(json.loads(output.getvalue())['removal_deferred'])
            self.assertEqual(controller.return_value.disable.call_count, 2)

    def test_activation_refuses_effective_service_override_before_networking(self):
        from wg_program_split import cli
        with mock.patch('wg_program_split.controller.Controller') as controller, \
                mock.patch.object(cli, '_service_units', side_effect=RuntimeError('foreign override')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['activate']), 1)
            controller.return_value.activate.assert_not_called()

    def test_failed_service_start_stops_management_and_restores_blocking(self):
        from wg_program_split import cli
        with mock.patch('wg_program_split.controller.Controller') as controller, \
                mock.patch.object(cli, '_service_units'), \
                mock.patch.object(cli, '_services', side_effect=[RuntimeError('start failed'), None]) as service, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['activate']), 1)
            controller.return_value.activate.assert_not_called()
            controller.return_value.guard.assert_called_once()
            self.assertEqual(service.call_args_list[-1], mock.call('stop'))

    def test_activate_observes_daemon_activation_before_competing_for_the_lock(self):
        from wg_program_split import cli
        with mock.patch('wg_program_split.controller.Controller') as controller, \
                mock.patch.object(cli, '_service_units'), mock.patch.object(cli, '_services'), \
                mock.patch.object(cli.time, 'sleep'):
            controller.return_value.peek_state.side_effect = ['inactive', 'preparing', 'ready']
            controller.return_value.status.return_value = {'state': 'ready'}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['activate']), 0)
            controller.return_value.activate.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['state'], 'ready')
            controller.return_value.peek_state.side_effect = ['loading', 'degraded']
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['activate']), 0)
            controller.return_value.activate.assert_called_once()

    def test_failure_during_copy_rolls_back_only_our_acquisitions(self):
        import wg_program_split.install as module
        original = module._create
        calls = 0
        def fail(path, content, mode):
            nonlocal calls
            calls += 1
            if calls == 5:
                raise OSError('injected disk failure')
            return original(path, content, mode)
        with mock.patch.object(module, '_create', side_effect=fail):
            with self.assertRaises(OSError):
                self.deploy()
        self.assertFalse(list(self.root.rglob('*')))

    def test_foreign_collision_and_symlink_ancestors_are_preserved(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.root / 'usr').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(InstallError):
            self.deploy()
        self.assertTrue((self.root / 'usr').is_symlink())
        self.assertFalse(list(outside.iterdir()))

    def test_manifest_cannot_name_an_unrelated_file(self):
        self.deploy()
        path = self.root / 'etc/wg-program-split/installation.json'
        manifest = json.loads(path.read_text())
        manifest['files']['etc/passwd'] = next(iter(manifest['files'].values()))
        path.write_text(json.dumps(manifest))
        with self.assertRaises(InstallError):
            uninstall(root=self.root)
        self.assertTrue((self.root / 'usr/lib/wg-program-split/bpf-loader').exists())

    def test_isolated_zipapp_ignores_caller_directory_and_pythonpath(self):
        package = Path(__file__).resolve().parents[2] / 'src/linux/wg_program_split'
        application = self.base / 'application.pyz'
        with zipfile.ZipFile(application, 'w') as archive:
            for source in package.glob('*.py'):
                archive.write(source, 'wg_program_split/' + source.name)
            archive.writestr('__main__.py', 'from wg_program_split.cli import main\nraise SystemExit(main())\n')
        attacker = self.base / 'caller'
        (attacker / 'wg_program_split').mkdir(parents=True)
        (attacker / 'wg_program_split/__init__.py').write_text('raise RuntimeError("caller code imported")')
        profile, settings = self.base / 'input.conf', self.base / 'input.json'
        profile.write_text(self.profile)
        settings.write_text(self.settings)
        result = subprocess.run(['/usr/bin/python3', '-I', str(application), 'validate',
                                 '--profile', str(profile), '--settings', str(settings)],
                                cwd=attacker, env={**os.environ, 'PYTHONPATH': str(attacker)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'valid': True, 'mode': 'include', 'included': 0})
        self.assertNotIn('PrivateKey', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
