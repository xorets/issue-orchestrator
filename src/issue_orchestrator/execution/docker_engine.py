"""Bounded Docker Engine HTTP operations; never put provider secrets in argv."""
from __future__ import annotations

import http.client
import json
import socket
from collections.abc import Callable


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


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

    def start_exec(self, exec_id: str, consume: Callable[[bytes], None], timeout: float) -> None:
        """Read Docker's non-TTY multiplexed byte stream, bounded by its consumer."""
        connection = _UnixConnection(self.socket_path, timeout)
        try:
            connection.request("POST", f"/v1.45/exec/{exec_id}/start", body=b'{"Detach":false,"Tty":false}',
                headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("Docker exec start refused")
            while True:
                header = response.read(8)
                if not header:
                    break
                if len(header) != 8 or header[0] not in {1, 2} or header[1:4] != b"\0\0\0":
                    raise ValueError("Invalid Docker output frame")
                remaining = int.from_bytes(header[4:], "big")
                while remaining:
                    chunk = response.read(min(remaining, 65536))
                    if not chunk:
                        raise ValueError("Truncated Docker output frame")
                    consume(chunk)
                    remaining -= len(chunk)
        finally:
            connection.close()

    def stop(self, container_id: str) -> None:
        self.request("POST", f"/containers/{container_id}/stop?t=2")
        self.request("POST", f"/containers/{container_id}/wait?condition=not-running")
        if self.request("GET", f"/containers/{container_id}/json")["State"]["Running"]:
            raise ValueError("Docker container remains active after stop")
