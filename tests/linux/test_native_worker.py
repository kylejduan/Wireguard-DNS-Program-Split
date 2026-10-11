# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real anonymous pipes and child lifetime without kernel attachment."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wg_program_split.native_worker import NativeWorker
from wg_program_split.preflight import NativeGuard, ControllerError


class NativeWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.loader = Path(self.temp.name) / 'bpf-loader'
        self.worker = None
        self.addCleanup(lambda: self.worker.close() if self.worker else None)

    def script(self, body):
        self.loader.write_text('#!/usr/bin/python3\nimport os,sys,time,json\n' + body)
        self.loader.chmod(0o700)

    def start(self, body):
        self.script(body)
        self.worker = NativeWorker(self.loader, '/unused')
        return self.worker

    def test_reuses_process_and_observes_new_inputs(self):
        source = Path(self.temp.name) / 'state'
        source.write_text('one')
        worker = self.start(f'''for line in sys.stdin:
 print(json.dumps({{"pid":os.getpid(),"value":open({str(source)!r}).read(),"op":line.strip()}}),flush=True)
''')
        first = json.loads(worker.request('snapshot'))
        source.write_text('two')
        second = json.loads(worker.request('probe-dns'))
        self.assertEqual(first['pid'], second['pid'])
        self.assertEqual((first['value'], second['value']), ('one', 'two'))
        self.assertEqual(second['op'], 'probe-dns')
        process = worker.process
        worker.close()
        self.assertIsNotNone(process.poll())

    def test_timeout_kills_and_reaps_owned_process(self):
        worker = self.start('for line in sys.stdin: time.sleep(60)\n')
        process = worker.process
        with self.assertRaises(TimeoutError):
            worker.request('snapshot', timeout=0.1)
        self.assertIsNotNone(process.poll())
        self.assertIsNone(worker.process)

    def test_crash_and_partial_output_are_not_observations(self):
        worker = self.start("sys.stdin.readline(); print('{partial',end='',flush=True)\n")
        with self.assertRaises(OSError):
            worker.request('snapshot')
        self.assertIsNone(worker.process)

    def test_output_bound_applies_before_newline(self):
        worker = self.start("sys.stdin.readline(); sys.stdout.write('x'*1000000); sys.stdout.flush()\n")
        with self.assertRaises(ValueError):
            worker.request('snapshot', maximum=128)
        self.assertIsNone(worker.process)

    def test_fragmented_response(self):
        worker = self.start("sys.stdin.readline(); sys.stdout.write('{'); sys.stdout.flush(); time.sleep(.02); print('}',flush=True)\n")
        self.assertEqual(worker.request('snapshot'), '{}\n')

    def test_multiple_responses_rejected(self):
        worker = self.start("sys.stdin.readline(); os.write(1,b'{}\\n{}\\n')\n")
        with self.assertRaises(ValueError):
            worker.request('snapshot')

    def test_mutating_request_rejected(self):
        worker = self.start('for line in sys.stdin: print(line,flush=True)\n')
        with self.assertRaises(ValueError):
            worker.request('remove')

    def test_guard_replaces_worker_after_failure_and_artifact_replacement(self):
        self.script("for line in sys.stdin: print('{}',flush=True)\n")
        guard = NativeGuard(self.loader.parent, '/unused')
        guard.persistent = True
        self.addCleanup(guard.close)
        with patch('wg_program_split.preflight.verify_artifact'):
            guard._run('snapshot', guard.pins)
            old = guard._worker.process
            old.kill()
            old.wait()
            with self.assertRaises(ControllerError):
                guard._run('snapshot', guard.pins)
            self.assertIsNone(guard._worker)
            guard._run('snapshot', guard.pins)
            replacement = guard._worker.process
            new = self.loader.with_suffix('.new')
            new.write_bytes(self.loader.read_bytes())
            new.chmod(0o700)
            new.replace(self.loader)
            guard._run('snapshot', guard.pins)
            self.assertIsNotNone(replacement.poll())
            self.assertNotEqual(guard._worker.process.pid, replacement.pid)


if __name__ == '__main__':
    unittest.main()
