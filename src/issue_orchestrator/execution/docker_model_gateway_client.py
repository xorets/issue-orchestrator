"""Controller-only transport to the dispatcher's fixed private model gateway."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import stat
import socket as socket_module
import struct
import time
from collections.abc import AsyncGenerator, Mapping



def _socket_path(controller_home: str) -> Path:
    home = Path(controller_home)
    if not home.is_absolute() or home.resolve(strict=True) != home:
        raise ValueError('model gateway controller home differs')
    path = home / 'model-gateway.sock'
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('model gateway socket custody differs')
    return path


def _peer_identity() -> tuple[str, str]:
    pid_text = os.environ.get('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_PID', '')
    birth_text = os.environ.get('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_BIRTH', '')
    if not pid_text.isdecimal() or not birth_text.isdecimal() or int(pid_text) <= 0:
        raise ValueError('model gateway peer identity unavailable')
    return pid_text, birth_text


def _verify_peer(writer: asyncio.StreamWriter, pid_text: str, birth_text: str) -> None:
    peer = writer.get_extra_info('socket')
    if peer is None:
        raise ValueError('model gateway peer unavailable')
    pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket_module.SOL_SOCKET, socket_module.SO_PEERCRED, 12))
    raw = Path(f'/proc/{pid}/stat').read_text()
    birth = raw[raw.rindex(')') + 2:].split()[19]
    if pid != int(pid_text) or uid != os.getuid() or birth != birth_text:
        raise ValueError('model gateway peer identity differs')


def _verify_headers(head: bytes) -> None:
    lines = head[:-4].split(b'\r\n')
    if not re.fullmatch(rb'HTTP/1\.[01] 200(?: [^\r\n]*)?', lines[0]):
        raise ValueError('model gateway response refused')
    parsed = []
    for line in lines[1:]:
        if b':' not in line:
            raise ValueError('model gateway response headers invalid')
        name, value = line.split(b':', 1)
        parsed.append((name.strip().lower(), value.strip().lower()))
    if ([value.split(b';')[0].strip() for name, value in parsed if name == b'content-type'] != [b'text/event-stream'] or
            any(name in {b'transfer-encoding', b'content-length'} for name, _ in parsed)):
        raise ValueError('model gateway response framing refused')


async def forward_model_request(
                                *, controller_home: str, instance_token: str,
                                context: Mapping[str, object], request: dict,
                                provider_auth: str) -> AsyncGenerator[bytes, None]:
    """Forward one admitted request; the caller retains cancellation and deadline ownership."""
    if (not re.fullmatch(r'[0-9a-f]{64}', instance_token) or not isinstance(request, dict) or
            not isinstance(provider_auth, str) or not 0 < len(provider_auth.encode()) <= 65536):
        raise ValueError('model gateway input refused')
    socket = _socket_path(controller_home)
    deadline = context.get('deadline_unix_ns')
    output_limit = context.get('max_output_bytes')
    if type(deadline) is not int or type(output_limit) is not int or output_limit <= 0:
        raise ValueError('model gateway finite bounds unavailable')
    remaining = (deadline - time.time_ns()) / 1e9
    if remaining <= 0:
        raise ValueError('model gateway deadline expired')
    payload = json.dumps({'context': dict(context), 'request': request, 'provider_auth': provider_auth},
                         sort_keys=True, separators=(',', ':')).encode()
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError('model gateway request exceeds bound')
    pid_text, birth_text = _peer_identity()
    writer = None
    async with asyncio.timeout(remaining):
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket))
            _verify_peer(writer, pid_text, birth_text)
            headers = (b'POST /v1/responses HTTP/1.0\r\nHost: controller\r\nAuthorization: Bearer ' +
                       instance_token.encode() + b'\r\nContent-Type: application/json\r\nContent-Length: ' +
                       str(len(payload)).encode() + b'\r\nConnection: close\r\n\r\n')
            writer.write(headers + payload)
            await writer.drain()
            head = await reader.readuntil(b'\r\n\r\n')
            if len(head) > 16384:
                raise ValueError('model gateway response headers exceed bound')
            _verify_headers(head)
            total = 0
            while chunk := await reader.read(65536):
                total += len(chunk)
                if total > output_limit:
                    raise ValueError('model gateway response exceeds bound')
                yield chunk
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
