"""Real probe I/O: pacing must not depend on replies, and errors stay visible."""
from errno import ECANCELED, ECONNREFUSED, ENOBUFS, EPROTO, ETIMEDOUT
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import test_native_overhead as runner

ROOM = 256 * 4608  # a whole stream window at twice the observed datagram truesize


def sequence(packet): return int.from_bytes(packet[4:8], 'big')


def stopped(process, seconds):
    os.kill(process.pid, signal.SIGSTOP)
    try: time.sleep(seconds)
    finally: os.kill(process.pid, signal.SIGCONT)


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

    def client(self, mode, port, milliseconds, during=None):
        child = subprocess.Popen([self.binary, 'client', mode, '127.0.0.1', '53', str(port), milliseconds,
                                  '1000', '0', '/dev/null'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready = child.stdout.readline()
            self.assertTrue(ready, 'probe rejected the requested workload')
            self.assertTrue(json.loads(ready)['ready'])
            start = time.monotonic_ns() + 50000000
            child.stdin.write('go %d\n' % start); child.stdin.flush()
            if during: during(start, child)
            output, stderr = child.communicate(timeout=5)
            return child.returncode, json.loads(output), stderr
        finally:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=2)

    def exchange(self, mode='udp_stream', transform=None, milliseconds='128', late=None):
        """Returns the client report and each request with its peer arrival time."""
        errors, packets = [], []
        done = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0)); peer.settimeout(.1)
            def serve():
                batch = []
                try:
                    while True:  # after the client exits, record what is already queued
                        try: data, address = peer.recvfrom(2000)
                        except socket.timeout:
                            if done.is_set(): break
                            continue
                        packets.append((time.monotonic_ns(), data)); batch.append((data, address))
                        # Withhold replies until eight requests are in flight.
                        if len(batch) == 8 or mode == 'udp':
                            for data, address in reversed(batch):
                                replies = transform(data) if transform else [data]
                                for reply in replies: peer.sendto(reply, address)
                            # One more datagram well after the final reply (sequence 120).
                            if late and len(packets) == int(milliseconds):
                                time.sleep(.02); peer.sendto(late(batch[0][0]), batch[0][1])
                            batch.clear()
                except BaseException as error: errors.append(error)
            thread = threading.Thread(target=serve); thread.start()
            try:
                code, row, stderr = self.client(mode, peer.getsockname()[1], milliseconds)
            finally:
                done.set(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            return code, row, packets, stderr

    def native(self, pause):
        """One second of udp_stream against the native peer; 200 ms after GO,
        pause(peer, client) stalls these owned children."""
        with subprocess.Popen([self.binary, 'peer', '127.0.0.1', '0', '0', '127.0.0.1'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as peer:
            try:
                ready = json.loads(peer.stdout.readline())
                self.assertGreaterEqual(ready['payload_rcvbuf'], ROOM)
                def during(start, child):
                    time.sleep(max(0, (start - time.monotonic_ns()) / 1e9 + .2))
                    pause(peer, child)
                code, row, stderr = self.client('udp_stream', ready['payload_port'], '1000', during)
                time.sleep(.05)  # the peer finishes serving its queue before counting
                peer.stdin.write('stats\n'); peer.stdin.flush()
                stats = json.loads(peer.stdout.readline())
                peer.stdin.write('quit\n'); peer.stdin.flush()
                self.assertEqual(peer.wait(timeout=5), 0)
            finally:
                if peer.poll() is None: peer.kill(); peer.wait(timeout=2)
        self.assertGreaterEqual(row['rcvbuf'], ROOM)
        # Neither fixture socket discarded anything, whatever the outcome.
        self.assertEqual((stats['payload_drops'], row['receive_drops']), (0, 0), stderr)
        return code, row, stats, stderr

    def test_independent_sending_accepts_reordered_replies_without_losing_samples(self):
        code, row, packets, stderr = self.exchange()
        self.assertEqual(code, 0, stderr)
        self.assertEqual((row['planned'], len(row['samples']), len(packets)), (128, 128, 128))
        self.assertEqual([sequence(p) for _, p in packets], list(range(128)))
        self.assertGreaterEqual(row['inflight_max'], 8)
        self.assertEqual((row['stream_errno'], row['receive_drops']), (0, 0))
        self.assertGreaterEqual(row['rcvbuf'], ROOM)
        self.assertTrue(all(latency > 0 and error == 0 and size == 1200
                            for latency, _, error, size in row['samples']))
        # Recorded lateness is the actual send time: never after the peer saw it.
        for arrived, packet in packets:
            index = sequence(packet)
            self.assertLessEqual(row['start_ns'] + index * row['period_ns'] + row['samples'][index][1], arrived)
        # Waiting for due times and replies sleeps in ppoll instead of spinning.
        self.assertLess(row['cpu_ns'], row['elapsed_ns'] / 4)

    def test_corrupt_reply_is_a_failed_experiment(self):
        code, row, _, _ = self.exchange(transform=lambda data: [data[:-1] + bytes([data[-1] ^ 1])])
        self.assertNotEqual(code, 0)
        # The first reply read (sequence 7) carries the cause; the rest were abandoned.
        errors = [sample[2] for sample in row['samples']]
        self.assertEqual(row['samples'][7], [0, row['samples'][7][1], EPROTO, 0])
        self.assertEqual(set(errors[:7] + errors[8:]), {ECANCELED})
        self.assertEqual(row['stream_errno'], EPROTO)
        # Replies whose sequence cannot be trusted fail on the first unanswered sample.
        for transform in (lambda data: [data + b'x'], lambda data: [data[:-1]],
                          lambda data: [data[:12] + bytes(b ^ 255 for b in data[12:16]) + data[16:]]):
            with self.subTest(transform=transform):
                code, row, _, _ = self.exchange(transform=transform)
                self.assertNotEqual(code, 0)
                errors = [sample[2] for sample in row['samples']]
                self.assertEqual((errors[0], set(errors[1:])), (EPROTO, {ECANCELED}))

    def test_duplicates_and_missing_replies_are_errors(self):
        code, row, _, _ = self.exchange(transform=lambda data: [data, data] if sequence(data) == 5 else [data])
        self.assertNotEqual(code, 0)
        # Sequence 5 keeps its valid reply and gains the duplicate failure.
        latency, _, error, size = row['samples'][5]
        self.assertEqual((error, size), (EPROTO, 1200)); self.assertGreater(latency, 0)
        self.assertEqual([sample[2:] for sample in row['samples'][6:8]], [[0, 1200]] * 2)
        errors = [sample[2] for sample in row['samples']]
        self.assertEqual(set(errors[:5] + errors[8:]), {ECANCELED})
        code, row, packets, _ = self.exchange(transform=lambda data: [])
        self.assertNotEqual(code, 0)
        self.assertEqual((len(packets), row['stream_errno']), (128, ETIMEDOUT))
        self.assertEqual({(sample[0], sample[2], sample[3]) for sample in row['samples']}, {(0, ETIMEDOUT, 0)})

    def test_late_datagram_after_the_last_reply_fails_the_run(self):
        for late, index in ((lambda data: data, 120), (lambda data: b'stray', 127)):
            with self.subTest(index=index):
                code, row, _, stderr = self.exchange(late=late)
                self.assertNotEqual(code, 0)
                self.assertEqual([i for i, sample in enumerate(row['samples']) if sample[2]], [index], stderr)
                self.assertEqual(row['samples'][index][2:], [EPROTO, 1200])

    def test_receive_error_keeps_the_kernel_errno_like_serial_mode(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as closed:
            closed.bind(('127.0.0.1', 0)); port = closed.getsockname()[1]
        code, row, _ = self.client('udp', port, '16')
        self.assertNotEqual(code, 0)
        self.assertEqual([sample[2] for sample in row['samples']], [ECONNREFUSED])
        code, row, _ = self.client('udp_stream', port, '16')
        self.assertNotEqual(code, 0)
        errors = [sample[2] for sample in row['samples']]
        self.assertEqual((len(errors), errors.count(ECONNREFUSED), row['stream_errno']), (16, 1, ECONNREFUSED))
        self.assertEqual(set(errors) - {ECONNREFUSED}, {ECANCELED})

    def test_stalled_peer_queues_every_request_the_window_allows(self):
        """The VM failure: a default peer queue (~90 datagrams) dropped requests
        sent while the peer was not scheduled."""
        code, row, stats, stderr = self.native(lambda peer, client: stopped(peer, .2))
        self.assertEqual(code, 0, stderr)
        self.assertGreaterEqual(row['inflight_max'], 150)
        self.assertEqual((stats['payload'], row['stream_errno']), (1000, 0))
        self.assertTrue(all(sample[2] == 0 and sample[3] == 1200 for sample in row['samples']))

    def test_stalled_client_queues_every_reply_the_window_allows(self):
        def pause(peer, client):
            os.kill(peer.pid, signal.SIGSTOP)
            try: time.sleep(.2); os.kill(client.pid, signal.SIGSTOP)
            finally: os.kill(peer.pid, signal.SIGCONT)
            try: time.sleep(.05)
            finally: os.kill(client.pid, signal.SIGCONT)
        code, row, stats, stderr = self.native(pause)
        self.assertEqual(code, 0, stderr)
        self.assertGreaterEqual(row['inflight_max'], 150)
        self.assertEqual((stats['payload'], row['stream_errno']), (1000, 0))
        self.assertTrue(all(sample[2] == 0 and sample[3] == 1200 for sample in row['samples']))

    def test_stall_beyond_the_window_is_reported_as_window_exhaustion(self):
        code, row, stats, _ = self.native(lambda peer, client: stopped(peer, .4))
        self.assertNotEqual(code, 0)
        errors = [sample[2] for sample in row['samples']]
        index = errors.index(ENOBUFS)
        self.assertEqual((row['inflight_max'], row['stream_errno'], errors.count(ENOBUFS)), (256, ENOBUFS, 1))
        self.assertEqual(set(errors[:index] + errors[index + 1:]), {0, ECANCELED})
        # Every request sent before exhaustion reached the peer.
        self.assertEqual(stats['payload'], index)

    def test_window_exhaustion_fails_with_all_offered_samples_retained(self):
        code, row, packets, _ = self.exchange(transform=lambda data: [], milliseconds='384')
        self.assertNotEqual(code, 0)
        self.assertEqual((row['planned'], len(row['samples']), row['inflight_max']), (384, 384, 256))
        self.assertEqual(len(packets), 256)
        errors = [sample[2] for sample in row['samples']]
        self.assertEqual(errors[256], ENOBUFS)
        self.assertEqual(set(errors[:256] + errors[257:]), {ECANCELED})

    def test_original_serial_workload_is_preserved(self):
        code, row, packets, stderr = self.exchange(mode='udp')
        self.assertEqual(code, 0, stderr)
        self.assertEqual((len(row['samples']), len(packets)), (128, 128))
        self.assertEqual([sequence(p) for _, p in packets], list(range(128)))
        self.assertEqual((row['inflight_max'], row['rcvbuf'], row['receive_drops'], row['stream_errno']),
                         (0, None, None, None))
        self.assertTrue(all(sample[2] == 0 and sample[3] == 1200 for sample in row['samples']))


if __name__ == '__main__': unittest.main()
