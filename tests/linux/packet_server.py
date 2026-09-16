# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled peer echo and DNS servers; no external names or upstream DNS."""
import hashlib
import json
from pathlib import Path
import signal
import socket
import struct
import sys
import threading


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise EOFError()
        result.extend(data)
    return bytes(result)


def dns_reply(query, tcp):
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        if size > 63:
            raise ValueError('unsupported compressed fixture question')
        labels.append(query[offset + 1:offset + 1 + size].decode('ascii'))
        offset += 1 + size
    end = offset + 5
    name = '.'.join(labels)
    assert struct.unpack('!HH', query[offset + 1:end]) == (1, 1)
    assert struct.unpack('!HHHH', query[4:12]) == (1, 0, 0, 1)
    assert query[end:end + 3] == b'\x00\x00\x29'
    advertised = struct.unpack('!H', query[end + 3:end + 5])[0]
    assert advertised >= 4096
    opt = b'\x00' + struct.pack('!HHIH', 41, advertised, 0, 0)
    truncated = not tcp and name == 'fallback.test'
    if truncated:
        reply = query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 1) + query[12:end] + opt
    else:
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('198.51.100.7')
        padding = (bytes([250]) + b'x' * 250) * 12
        txt = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 60, len(padding)) + padding
        reply = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 2) + query[12:end] + answer + txt + opt
    return reply, {'name': name, 'edns_size': advertised, 'truncated': truncated}


class Servers:
    def __init__(self, payload_address, dns_address, payload_port, dns_port, ledger):
        self.ledger = Path(ledger)
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.sockets, self.threads, self.clients, self.errors = [], [], [], []
        try:
            self.payload_port = self._pair(payload_address, payload_port, 'payload')
            self.dns_port = self._pair(dns_address, dns_port, 'dns')
        except BaseException:
            self.close()
            raise

    def _thread(self, function, *args):
        def guarded():
            try:
                function(*args)
            except (OSError, EOFError, ValueError, AssertionError, IndexError, struct.error) as error:
                if not self.stop.is_set():
                    self.errors.append(repr(error))
        thread = threading.Thread(target=guarded, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _pair(self, address, port, kind):
        tcp = socket.socket()
        self.sockets.append(tcp)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((address, port))
        port = tcp.getsockname()[1]
        tcp.listen(16)
        tcp.settimeout(.2)
        udp = socket.socket(type=socket.SOCK_DGRAM)
        self.sockets.append(udp)
        if kind == 'dns':
            # Deliberately exercise EDNS replies larger than the WireGuard MTU.
            # Linux IP_MTU_DISCOVER=IP_PMTUDISC_DONT permits IPv4 fragmentation.
            udp.setsockopt(socket.IPPROTO_IP, 10, 0)
        udp.bind((address, port))
        udp.settimeout(.2)
        self._thread(self._accept, tcp, kind)
        self._thread(self._udp, udp, kind)
        return port

    def _record(self, value):
        with self.lock, self.ledger.open('a') as stream:
            stream.write(json.dumps(value) + '\n')

    def _accept(self, listener, kind):
        while not self.stop.is_set():
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                continue
            conn.settimeout(10)
            with self.lock:
                self.clients.append(conn)
            self._thread(self._tcp, conn, peer, kind)

    def _tcp(self, conn, peer, kind):
        with conn:
            if kind == 'dns':
                size = struct.unpack('!H', exact(conn, 2))[0]
                reply, meta = dns_reply(exact(conn, size), True)
                conn.sendall(struct.pack('!H', len(reply)) + reply)
                self._record({'kind': kind, 'protocol': 'tcp', 'peer': peer, 'bytes': len(reply), **meta})
                return
            seen, received, digest = 0, 0, hashlib.sha256()
            while not self.stop.is_set():
                header = exact(conn, 16)
                magic, sequence, count, size = struct.unpack('!4sIII', header)
                assert magic == b'WGPS' and sequence == seen and 0 < count <= 100000 and 0 < size <= 32768
                payload = exact(conn, size)
                digest.update(payload)
                conn.sendall(header + payload)
                seen, received = seen + 1, received + size
                if seen == count:
                    self._record({'kind': kind, 'protocol': 'tcp', 'peer': peer, 'operations': seen,
                                  'bytes': received, 'sha256': digest.hexdigest()})
                    return

    def _udp(self, listener, kind):
        sessions = {}
        while not self.stop.is_set():
            try:
                data, peer = listener.recvfrom(65535)
            except socket.timeout:
                continue
            if kind == 'dns':
                reply, meta = dns_reply(data, False)
                listener.sendto(reply, peer)
                self._record({'kind': kind, 'protocol': 'udp', 'peer': peer, 'bytes': len(reply), **meta})
                continue
            magic, sequence, count, size = struct.unpack('!4sIII', data[:16])
            assert magic == b'WGPS' and 0 < count <= 100000 and 0 < size <= 32768 and len(data) == 16 + size
            if sequence == 0:
                sessions[peer] = [0, 0, hashlib.sha256()]
            current = sessions[peer]
            assert sequence == current[0]
            current[0] += 1
            current[1] += size
            current[2].update(data[16:])
            listener.sendto(data, peer)
            if current[0] == count:
                self._record({'kind': kind, 'protocol': 'udp', 'peer': peer, 'operations': count,
                              'bytes': current[1], 'sha256': current[2].hexdigest()})
                del sessions[peer]

    def close(self):
        self.stop.set()
        for sock in self.sockets + self.clients:
            sock.close()
        for thread in self.threads:
            thread.join(3)
        if any(t.is_alive() for t in self.threads):
            raise RuntimeError('owned packet server thread did not stop')
        if self.errors:
            raise RuntimeError('packet responder failed: ' + '; '.join(self.errors))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


if __name__ == '__main__':
    if len(sys.argv) != 6:
        raise SystemExit('requires payload-address dns-address payload-port dns-port ledger')
    with Servers(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]) as server:
        signal.signal(signal.SIGTERM, lambda *_: server.stop.set())
        signal.signal(signal.SIGINT, lambda *_: server.stop.set())
        print(json.dumps({'ready': True}), flush=True)
        while not server.stop.wait(.2):
            if server.errors:
                raise RuntimeError('controlled packet server failed')
