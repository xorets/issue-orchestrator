"""Bounded Docker Engine HTTP operations; never put provider secrets in argv."""
from __future__ import annotations

import http.client
import json
import re
import socket
import threading
import time
from collections.abc import Callable


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class _ExecStream:
    def __init__(self, connection: _UnixConnection, response: http.client.HTTPResponse):
        self.connection = connection
        self.response = response

    def consume(self, consume: Callable[[bytes], None]) -> None:
        while True:
            header = self.response.read(8)
            if not header:
                break
            if len(header) != 8 or header[0] not in {1, 2} or header[1:4] != b"\0\0\0":
                raise ValueError("Invalid Docker output frame")
            remaining = int.from_bytes(header[4:], "big")
            while remaining:
                chunk = self.response.read(min(remaining, 65536))
                if not chunk:
                    raise ValueError("Truncated Docker output frame")
                consume(chunk)
                remaining -= len(chunk)

    def close(self) -> None:
        self.connection.close()


class DockerEngine:
    """Small adapter for identity, exec and complete-container termination."""
    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path

    def request(self, method: str, route: str, payload: dict | None = None) -> dict:
        connection = _UnixConnection(self.socket_path, 10)
        try:
            connection.request(method, "/v1.45" + route,
                body=None if payload is None else json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024 or response.status not in {200, 201, 204, 304}:
                raise ValueError(f"Docker operation refused: {method} {route} HTTP {response.status}")
            return {} if not body else json.loads(body)
        finally:
            connection.close()

    def inspect_exec(self, exec_id: str) -> dict:
        """Preserve only the exact exec inspection's 200 or 404 status."""
        if type(exec_id) is not str or re.fullmatch(r'[0-9a-f]{64}', exec_id) is None:
            raise ValueError('Docker exec identity is invalid')
        connection = _UnixConnection(self.socket_path, 10)
        try:
            connection.request('GET', f'/v1.45/exec/{exec_id}/json')
            response = connection.getresponse()
            if response.status == 404:
                return {'status':404}
            if response.status != 200:
                raise ValueError('Docker exec inspection refused')
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('Docker exec inspection exceeds bound')
            value = json.loads(raw)
            if type(value) is not dict:
                raise ValueError('Docker exec inspection is invalid')
            return {'status':200, 'value':value}
        finally:
            connection.close()

    def open_exec(self, exec_id: str, timeout: float) -> _ExecStream:
        """A bounded start acknowledgement, separate from its long-lived stream."""
        if timeout <= 0:
            raise ValueError('Docker exec start deadline exhausted')
        started = time.monotonic()
        limit = min(timeout, 10)
        connection = _UnixConnection(self.socket_path, limit)
        expired = threading.Event()
        def interrupt() -> None:
            expired.set()
            sock = connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()
        timer = threading.Timer(limit, interrupt)
        timer.daemon = True
        timer.start()
        try:
            connection.request("POST", f"/v1.45/exec/{exec_id}/start", body=b'{"Detach":false,"Tty":false}',
                headers={"Content-Type": "application/json"})
            sock = connection.sock
            response = connection.getresponse()
            elapsed = time.monotonic() - started
            if expired.is_set() or elapsed >= limit:
                raise TimeoutError('Docker exec start acknowledgement timed out')
            if response.status != 200:
                raise ValueError("Docker exec start refused")
            if sock is not None:
                sock.settimeout(max(0.001, timeout - elapsed))
            return _ExecStream(connection, response)
        except BaseException:
            connection.close()
            raise
        finally:
            timer.cancel()

    def start_exec(self, exec_id: str, consume: Callable[[bytes], None], timeout: float) -> None:
        """Read Docker's non-TTY multiplexed byte stream, bounded by its consumer."""
        stream = self.open_exec(exec_id, timeout)
        try:
            stream.consume(consume)
        finally:
            stream.close()

    def stop(self, container_id: str) -> None:
        self.request("POST", f"/containers/{container_id}/stop?t=2")
        waited = self.request("POST", f"/containers/{container_id}/wait?condition=not-running")
        if type(waited.get('StatusCode')) is not int or waited.get('Error'):
            raise ValueError('Docker container wait is unproven')
        if self.request("GET", f"/containers/{container_id}/json").get("State", {}).get("Running") is not False:
            raise ValueError("Docker container remains active after stop")
