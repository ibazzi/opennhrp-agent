#!/usr/bin/env python3
"""Local protocol regression: no external services or system config changes."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def exact(conn, size):
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        assert chunk, 'unexpected disconnect'
        data += chunk
    return data


def receive(conn):
    first, size = exact(conn, 2)
    assert first == 0x81 and size & 128
    size &= 127
    if size == 126:
        size = struct.unpack('!H', exact(conn, 2))[0]
    elif size == 127:
        size = struct.unpack('!Q', exact(conn, 8))[0]
    mask = exact(conn, 4)
    data = exact(conn, size)
    return json.loads(bytes(c ^ mask[i % 4] for i, c in enumerate(data)))


def send(conn, message):
    data = json.dumps(message).encode()
    header = bytes([0x81, len(data)]) if len(data) < 126 else b'\x81\x7e' + struct.pack('!H', len(data))
    conn.sendall(header + data)


def until(conn, predicate):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        message = receive(conn)
        if predicate(message):
            return message['payload']
    raise AssertionError('expected message not received')


def command(conn, target, args=(), text=''):
    ident = str(time.monotonic_ns())
    send(conn, dict(id=ident, type='command_request', payload=dict(
        target_socket=target, command=text, args=list(args))))
    return until(conn, lambda m: m['id'] == ident)


def handshake(listener, node_type):
    conn, _ = listener.accept()
    conn.settimeout(6)
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        data += exact(conn, 1)
    headers = {key.lower(): value for key, value in
               (line.split(': ', 1) for line in data.decode().split('\r\n')[1:] if ': ' in line)}
    assert headers['x-node-id'] == 'parity'
    assert headers['x-node-type'] == node_type
    assert headers['x-auth-token'] == 'test-token'
    accept = base64.b64encode(hashlib.sha1((headers['sec-websocket-key'] +
        '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    conn.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                  'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode())
    return conn


def run(binary, node_type):
    with tempfile.TemporaryDirectory(prefix='agent-parity-') as directory:
        root = Path(directory)
        delayed = threading.Event()
        sampling = threading.Event()
        stop = threading.Event()
        cluster = json.dumps(dict(cluster_id='cluster', local_member='parity', leader='parity',
            service_available=True, network_health='healthy', members=[], witness={}))
        peers = ''.join(f'Type: dynamic\nProtocol-Address: 10.0.0.{i}\n'
                        f'Registration-Mode: {mode}\n\n'
                        for i, mode in enumerate(('ha', 'legacy', 'invalid'), 1))
        sockets = []
        threads = []

        def serve(listener, ha):
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    request = b''
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        request += data
                    if delayed.is_set() and ((ha and node_type == 'hub') or
                                             (not ha and node_type == 'spoke')):
                        sampling.set()
                        stop.wait(1.5)
                    reply = cluster if ha else peers
                    try:
                        conn.sendall(reply.encode())
                    except BrokenPipeError:
                        pass

        for name, ha in [('core', False), ('ha', True)]:
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(root / name))
            listener.listen()
            listener.settimeout(.1)
            sockets.append(listener)
            thread = threading.Thread(target=serve, args=(listener, ha))
            thread.start()
            threads.append(thread)
        config = root / 'opennhrp.conf'
        config.write_text('old\n')
        config.chmod(0o600)
        ctl = root / 'test-ctl'
        ctl.write_text('#!/bin/sh\nif [ "$1" = ha ]; then printf key > "$4"; else exec /bin/sh "$@"; fi\n')
        ctl.chmod(0o700)
        env = dict(os.environ, OPENNHRP_SOCKET=str(root / 'core'),
                   OPENNHRP_HA_SOCKET=str(root / 'ha'), OPENNHRPCTL_PATH='test-ctl',
                   OPENNHRP_CONF_PATH=str(config), OPENNHRP_HA_STATE_DIR='/custom/ha',
                   PATH=directory + ':' + os.environ['PATH'])
        with socket.socket() as listener, (root / 'agent.log').open('w+') as log:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(8)
            process = subprocess.Popen([binary, '-server', f'ws://127.0.0.1:{listener.getsockname()[1]}/api/agent/ws',
                '--node-id', 'parity', '--node-type', node_type, '--token', 'test-token'], env=env, stderr=log)
            try:
                with handshake(listener, node_type) as conn:
                    field = 'spokes' if node_type == 'hub' else 'peers'
                    hb = until(conn, lambda m: m['type'] == 'heartbeat' and field in m['payload'])
                    assert [p.get('registration_mode') for p in hb[field]] == ['ha', 'legacy', None]
                    if node_type == 'hub':
                        assert hb['cluster_status']['state_dir'] == '/custom/ha'
                    assert command(conn, 'cli', ['-c', 'printf token; printf warning >&2'])['raw_text'] == 'token'
                    # Exceed pipe capacity on stderr to catch a sequential-read deadlock.
                    assert command(conn, 'cli', ['-c', 'head -c 131072 /dev/zero >&2; printf ok'])['raw_text'] == 'ok'
                    failure = command(conn, 'cli', ['-c', 'printf stdout-%s marker; printf failure >&2; exit 7'])
                    assert not failure['success'] and 'failure' in failure['error'] and 'stdout-marker' not in failure['error']
                    response = command(conn, 'cli-stdin', ['-c', 'cat; printf warning >&2'], 'input')
                    assert response['raw_text'] == 'input\nwarning'
                    assert command(conn, 'cli-export-key')['raw_text'] == 'key'
                    assert command(conn, 'fs', text='read-config')['raw_text'] == 'old\n'
                    assert command(conn, 'fs', ['new\n'], 'write-config')['success']
                    assert config.read_text() == 'new\n' and (root / 'opennhrp.conf.bak').read_text() == 'old\n'
                    assert config.stat().st_mode & 0o777 == 0o600
                    if node_type == 'spoke':
                        assert not command(conn, 'opennhrp-ha', text='show')['success']
                    delayed.set()
                    # Let the next heartbeat enter its deliberately slow socket read.
                    assert sampling.wait(4), 'heartbeat did not sample socket'
                    start = time.monotonic()
                    assert command(conn, 'fs', text='read-config')['success']
                    assert time.monotonic() - start < .8, 'heartbeat blocked command response'
                    delayed.clear()
                with handshake(listener, node_type) as conn:
                    assert command(conn, 'fs', text='read-config')['success']
                    until(conn, lambda m: m['type'] == 'heartbeat')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                finally:
                    stop.set()
                    for thread in threads:
                        thread.join(timeout=3)
                    for sock in sockets:
                        sock.close()
                if process.returncode:
                    log.seek(0)
                    raise AssertionError(log.read())
    print(f'parity ({node_type}): ok')


if __name__ == '__main__':
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/opennhrp-agent').resolve())
    for node_type in ('hub', 'spoke'):
        run(binary, node_type)
