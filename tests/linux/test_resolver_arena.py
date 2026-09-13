"""Runtime resolver sockets must not inherit the checkout's path length."""
import json
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_resolver_integration as integration


class ResolverArenaTests(unittest.TestCase):
    def test_short_runtime_archives_cache_and_socket_metadata_after_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='ri-', dir=Path.home()) as directory:
            base = Path(directory)
            evidence = base / ('long-checkout-' * 10) / 'evidence'
            evidence.mkdir(parents=True)
            with patch.object(integration, 'REPO', evidence.parent):
                with integration.runtime_arena(evidence, parent=base) as (work, complete):
                    self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                    endpoint = work / 'run/avahi-daemon/socket'
                    endpoint.parent.mkdir(parents=True)
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(str(endpoint))
                    (work / 'cache').mkdir()
                    (work / 'cache/hosts').write_bytes(b'cache-proof\0\xff')
                    complete()
            self.assertFalse(work.exists())
            self.assertEqual((evidence / 'cache/hosts').read_bytes(), b'cache-proof\0\xff')
            metadata = json.loads((evidence / 'runtime-metadata.json').read_text())
            entry = next(item for item in metadata['entries'] if item['path'] == 'run/avahi-daemon/socket')
            self.assertTrue(stat.S_ISSOCK(entry['mode']))

    def test_unconfirmed_cleanup_retains_original_paths_and_cache(self):
        with tempfile.TemporaryDirectory(prefix='ri-', dir=Path.home()) as directory:
            base = Path(directory)
            evidence = base / 'evidence'
            evidence.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'namespace survived'):
                with integration.runtime_arena(evidence, parent=base) as (work, _complete):
                    identity = work.stat().st_ino
                    (work / 'cache').write_bytes(b'live mapping')
                    raise RuntimeError('namespace survived')
            self.assertEqual(work.stat().st_ino, identity)
            self.assertEqual((work / 'cache').read_bytes(), b'live mapping')
            self.assertFalse((evidence / 'cache').exists())
            retained = json.loads((evidence / 'retained-runtime.json').read_text())
            self.assertEqual(retained['path'], str(work))

    def test_replaced_arena_is_never_adopted_for_retirement(self):
        with tempfile.TemporaryDirectory(prefix='ri-', dir=Path.home()) as directory:
            base = Path(directory)
            evidence = base / 'evidence'
            evidence.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                with integration.runtime_arena(evidence, parent=base) as (work, complete):
                    moved = base / 'original'
                    work.rename(moved)
                    work.mkdir(mode=0o700)
                    (work / 'foreign').write_text('retain')
                    complete()
            self.assertEqual((work / 'foreign').read_text(), 'retain')
            self.assertTrue(moved.is_dir())
            self.assertFalse((evidence / 'foreign').exists())


if __name__ == '__main__':
    unittest.main()
