# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded capture for fixed native commands; never publish private stderr."""
import os
import selectors
import subprocess
import time

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def capture(argv, *, input=None, timeout=30, maximum=32 * 1024 * 1024, stderr_maximum=1024 * 1024):
    """Reject excessive/incomplete output while reading, not after buffering it.

    Callers supply fixed tools that do not launch descendants. Multiplex input
    and both outputs so a large policy or error stream cannot deadlock a pipe.
    """
    payload = memoryview(input or b'')
    with subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=ENV) as process:
        try:
            deadline = time.monotonic() + timeout
            output, error_size, offset = bytearray(), 0, 0
            with selectors.DefaultSelector() as ready:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    ready.register(stream, selectors.EVENT_READ)
                if input is not None:
                    if payload:
                        os.set_blocking(process.stdin.fileno(), False)
                        ready.register(process.stdin, selectors.EVENT_WRITE)
                    else:
                        process.stdin.close()
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not (events := ready.select(remaining)):
                        raise subprocess.SubprocessError('native command timed out')
                    for key, _ in events:
                        stream = key.fileobj
                        if stream is process.stdin:
                            try:
                                offset += os.write(stream.fileno(), payload[offset:offset + 65536])
                            except BrokenPipeError:
                                offset = len(payload)
                            if offset == len(payload):
                                ready.unregister(stream)
                                stream.close()
                            continue
                        chunk = os.read(stream.fileno(), 65536)
                        if not chunk:
                            ready.unregister(stream)
                        elif stream is process.stdout:
                            if len(output) + len(chunk) > maximum:
                                raise subprocess.SubprocessError('native output exceeded its limit')
                            output.extend(chunk)
                        else:
                            error_size += len(chunk)
                            if error_size > stderr_maximum:
                                raise subprocess.SubprocessError('native error output exceeded its limit')
            process.wait(timeout=max(0, deadline - time.monotonic()))
            if process.returncode:
                raise subprocess.SubprocessError('native command failed')
            return output.decode('utf-8')
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
