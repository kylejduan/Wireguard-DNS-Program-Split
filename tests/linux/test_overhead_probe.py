"""Real probe I/O: pacing must not depend on replies, and errors stay visible."""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import test_native_overhead as runner


class WorkloadSelectionTests(unittest.TestCase):
    def test_stream_changes_only_udp_pacing_and_keeps_rates_and_serial_mode(self):
        self.assertTrue(callable(getattr(runner, 'case_set', None)), 'UDP pacing selection is missing')
        serial, stream = runner.case_set('serial'), runner.case_set('stream')
        self.assertEqual(serial, runner.CASES)
        self.assertEqual(len(serial), len(stream))
        for original, changed in zip(serial, stream):
            if original[1] == 'udp':
                self.assertEqual(changed, (original[0] + '_stream', 'udp_stream', *original[2:]))
            else: self.assertEqual(changed, original)
        with self.assertRaises(ValueError): runner.case_set('unknown')


@unittest.skipUnless(shutil.which('cc'), 'native C compiler required')
class DatagramProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(dir=Path.home())
        cls.binary = Path(cls.directory.name) / 'probe'
        subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).with_name('overhead_probe.c')), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def exchange(self, mode='udp_stream', transform=None, milliseconds='128'):
        errors, packets = [], []
        done = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0)); peer.settimeout(.1)
            def serve():
                batch = []
                try:
                    while not done.is_set():
                        try: data, address = peer.recvfrom(2000)
                        except socket.timeout: continue
                        packets.append(data); batch.append((data, address))
                        # Withhold replies until eight requests are in flight.
                        if len(batch) == 8 or mode == 'udp':
                            for data, address in reversed(batch):
                                replies = transform(data) if transform else [data]
                                for reply in replies: peer.sendto(reply, address)
                            batch.clear()
                except BaseException as error: errors.append(error)
            thread = threading.Thread(target=serve); thread.start()
            child = subprocess.Popen([self.binary, 'client', mode, '127.0.0.1', '53',
                                      str(peer.getsockname()[1]), milliseconds, '1000', '0', '/dev/null'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready = child.stdout.readline()
                self.assertTrue(ready, 'probe rejected the requested workload')
                self.assertTrue(json.loads(ready)['ready'])
                output, stderr = child.communicate('go ' + str(time.monotonic_ns() + 50000000) + '\n', timeout=5)
                result = json.loads(output)
                return child.returncode, result, packets, stderr
            finally:
                if child.poll() is None:
                    child.terminate()
                child.communicate(timeout=2)
                done.set(); thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    def test_independent_sending_accepts_reordered_replies_without_losing_samples(self):
        code, row, packets, stderr = self.exchange()
        self.assertEqual(code, 0, stderr)
        self.assertEqual((row['planned'], len(row['samples']), len(packets)), (128, 128, 128))
        self.assertEqual(sorted(int.from_bytes(p[4:8], 'big') for p in packets), list(range(128)))
        self.assertGreaterEqual(row['inflight_max'], 8)
        self.assertTrue(all(latency > 0 and error == 0 and size == 1200
                            for latency, _, error, size in row['samples']))

    def test_corrupt_reply_is_a_failed_experiment(self):
        code, row, _, _ = self.exchange(transform=lambda data: [data[:-1] + bytes([data[-1] ^ 1])])
        self.assertNotEqual(code, 0)
        self.assertTrue(any(sample[2] for sample in row['samples']))

    def test_duplicates_and_missing_replies_are_errors(self):
        for transform in (lambda data: [data, data], lambda data: []):
            with self.subTest(transform=transform):
                code, row, _, _ = self.exchange(transform=transform)
                self.assertNotEqual(code, 0)
                self.assertTrue(any(sample[2] for sample in row['samples']))

    def test_window_exhaustion_fails_with_all_offered_samples_retained(self):
        code, row, packets, _ = self.exchange(transform=lambda data: [], milliseconds='384')
        self.assertNotEqual(code, 0)
        self.assertEqual((row['planned'], len(row['samples']), row['inflight_max']), (384, 384, 256))
        self.assertLess(len(packets), row['planned'])
        self.assertTrue(all(sample[2] for sample in row['samples']))

    def test_original_serial_workload_is_preserved(self):
        code, row, packets, stderr = self.exchange(mode='udp')
        self.assertEqual(code, 0, stderr)
        self.assertEqual((len(row['samples']), len(packets)), (128, 128))
        self.assertTrue(all(sample[2] == 0 for sample in row['samples']))


if __name__ == '__main__': unittest.main()
