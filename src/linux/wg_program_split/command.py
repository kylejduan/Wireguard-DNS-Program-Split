# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded capture for fixed native commands; never publish private stderr."""
import os
import selectors
import subprocess
import time

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def capture(argv, *, input=None, timeout=30, maximum=32 * 1024 * 1024, stderr_maximum=1024 * 1024):
    """Reject excessive/incomplete output while reading, not after buffering it."""
    output = bytearray()

    def collect(chunk):
        if len(output) + len(chunk) > maximum:
            raise subprocess.SubprocessError('native output exceeded its limit')
        output.extend(chunk)
    stream(argv, collect, input=input, timeout=timeout, stderr_maximum=stderr_maximum)
    return output.decode('utf-8')


def stream(argv, consume, *, input=None, timeout=30, stderr_maximum=1024 * 1024):
    """Pass standard output to consume() chunk by chunk under one overall deadline.

    Callers supply fixed tools that do not launch descendants. Multiplex input
    and both outputs so a large policy or error stream cannot deadlock a pipe.
    On a timeout, limit or consumer error the process is killed and reaped.
    """
    payload = memoryview(input or b'')
    with subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=ENV) as process:
        try:
            deadline = time.monotonic() + timeout
            error_size, offset = 0, 0
            with selectors.DefaultSelector() as ready:
                for pipe in (process.stdout, process.stderr):
                    os.set_blocking(pipe.fileno(), False)
                    ready.register(pipe, selectors.EVENT_READ)
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
                        pipe = key.fileobj
                        if pipe is process.stdin:
                            try:
                                offset += os.write(pipe.fileno(), payload[offset:offset + 65536])
                            except BrokenPipeError:
                                offset = len(payload)
                            if offset == len(payload):
                                ready.unregister(pipe)
                                pipe.close()
                            continue
                        chunk = os.read(pipe.fileno(), 65536)
                        if not chunk:
                            ready.unregister(pipe)
                        elif pipe is process.stdout:
                            consume(chunk)
                        else:
                            error_size += len(chunk)
                            if error_size > stderr_maximum:
                                raise subprocess.SubprocessError('native error output exceeded its limit')
            process.wait(timeout=max(0, deadline - time.monotonic()))
            if process.returncode:
                raise subprocess.SubprocessError('native command failed')
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
