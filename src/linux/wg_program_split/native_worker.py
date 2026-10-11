# SPDX-License-Identifier: GPL-3.0-or-later
"""Private, bounded pipe transport for the controller's read-only native helper."""
import os
import selectors
import subprocess
import time


class NativeWorker:
    def __init__(self, loader, pins):
        self.process = subprocess.Popen(
            [str(loader), 'observe', str(pins)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})

    def request(self, operation, *, timeout=30, maximum=32 * 1024 * 1024):
        if operation not in ('snapshot', 'probe-dns'):
            raise ValueError('unsupported native observation')
        try:
            # One outstanding, fixed-size request; there is no externally reachable
            # socket or general command execution interface.
            self.process.stdin.write(operation.encode('ascii') + b'\n')
            deadline = time.monotonic() + timeout
            output = bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(self.process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        raise TimeoutError('native observation timed out')
                    chunk = os.read(self.process.stdout.fileno(), min(65536, maximum + 1 - len(output)))
                    if not chunk:
                        raise OSError('native observer exited without a result')
                    output.extend(chunk)
                    if len(output) > maximum:
                        raise ValueError('native observation exceeded its limit')
                    if b'\n' in chunk:
                        if output.count(b'\n') != 1 or output[-1] != 10:
                            raise ValueError('invalid native response framing')
                        return output.decode('utf-8')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is None:
            return
        process, self.process = self.process, None
        try:
            # No helper children or live kernel resources are owned by this process.
            # Killing it releases only transient descriptors and the current flock.
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        finally:
            process.stdin.close()
            process.stdout.close()
