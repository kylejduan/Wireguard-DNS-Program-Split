# SPDX-License-Identifier: GPL-3.0-or-later
"""Local disk recovery checks; systemd/network operations are replaced, never run."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_boot as boot


class BootRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='wgps-boot-recovery-', dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'wgps-boot-0123456789ab'
        self.patches = ExitStack(); self.addCleanup(self.patches.close)
        original_file, original_match = boot.file_id, boot.re.fullmatch
        def file_id(path):
            result = original_file(path); result[3] = 0; return result
        def directory_id(path):
            info = path.lstat()
            assert stat.S_ISDIR(info.st_mode)
            return info.st_dev, info.st_ino, 0, stat.S_IMODE(info.st_mode)
        self.patches.enter_context(patch.object(boot, 'file_id', side_effect=file_id))
        self.patches.enter_context(patch.object(boot, 'directory_identity', side_effect=directory_id))
        self.patches.enter_context(patch.object(boot.re, 'fullmatch', side_effect=lambda pattern, value:
            True if pattern.startswith('/var/lib/') and value == str(self.root) else original_match(pattern, value)))
        self.patches.enter_context(patch('sys.stdout', new=io.StringIO()))
        self.stage = boot.Stage(self.root)
        self.stage.publish()
        self.anchor = self.stage.before[-1]

    def test_lost_publish_output_accepts_only_known_hash_ancestor(self):
        self.stage.data['phase'] = 'prepared'
        with patch('builtins.print', side_effect=BrokenPipeError):
            self.stage.publish()
        resumed = boot.Stage(self.root, self.anchor)
        self.assertEqual(resumed.data['phase'], 'prepared')
        resumed.verify()
        with self.assertRaises(AssertionError):
            boot.Stage(self.root, '0' * 64)
        checkpoint = self.root / ('.checkpoint-' + self.anchor + '.json')
        checkpoint.write_text('{}')
        with self.assertRaises(AssertionError):
            boot.Stage(self.root, self.anchor)

    def test_cleanup_intent_recovers_deleted_dropin_after_reload_failure(self):
        state, config = self.base / 'state', self.base / 'config'
        state.mkdir(mode=0o700); config.mkdir(mode=0o700)
        dropdir = self.base / 'dropin'; dropdir.mkdir(mode=0o755)
        dropin = dropdir / 'owned.conf'; boot.create(dropin, b'owned', 0o644)
        self.stage.capture(dropin)
        self.stage.data.update(phase='negative', negative_boot=boot.boot_id(), dropin=str(dropin),
                              negative_runtime=list(boot.directory_identity(state)))
        self.stage.data['directories'][str(dropdir)] = list(boot.directory_identity(dropdir))
        self.stage.publish(); anchor = self.stage.before[-1]
        with patch.object(boot, 'STATE', state), patch.object(boot, 'CONFIG', config), \
                patch.object(boot, 'PINS', self.base / 'absent-pins'), \
                patch.object(boot.Stage, 'verify_links'), \
                patch.object(boot.Stage, 'control', side_effect=RuntimeError('injected reload failure')):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                boot.cleanup(self.stage)
            self.assertFalse(dropin.exists())
            resumed = boot.Stage(self.root, anchor)
            self.assertEqual(resumed.data['phase'], 'cleaning')
            resumed.verify()
            # Retry passes verification and reaches the next operation, rather
            # than failing because the exact journaled deletion already happened.
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                boot.cleanup(resumed)
            dropin.parent.mkdir(mode=0o700)
            boot.create(dropin.parent / 'replacement', b'foreign')
            with self.assertRaises(AssertionError): resumed.verify()

    def test_lost_final_response_reopens_public_archive_from_old_host_hash(self):
        self.stage.data['phase'] = 'complete'; self.stage.publish()
        repo = self.base / 'repo'
        archive = repo / 'local/validation' / self.root.name
        archive.parent.mkdir(parents=True); self.root.rename(archive)
        with patch.object(boot, 'REPO', repo):
            resumed = boot.Stage(self.root, self.anchor)
            self.assertTrue(resumed.archived)
            resumed.verify()

    def test_rename_intent_recovers_only_original_dropin_inode(self):
        source, target = self.root / 'staged.disabled', self.root / 'active.conf'
        boot.create(source, b'[Service]\nExecStartPre=/usr/bin/false\n')
        self.stage.capture(source)
        self.stage.data.update(phase='negative-arming', dropin_source=str(source), dropin=str(target))
        self.stage.publish(); anchor = self.stage.before[-1]
        source.rename(target)
        resumed = boot.Stage(self.root, anchor); resumed.verify()
        target.unlink(); boot.create(target, b'changed foreign override')
        with self.assertRaises(AssertionError): resumed.verify()


if __name__ == '__main__': unittest.main()
