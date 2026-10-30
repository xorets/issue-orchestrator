"""Durable delivery-scoped reservations before Docker startup."""
import fcntl
import json
import os
from pathlib import Path
import stat

from .docker_launch_input import canonical, sealed_bytes
from .docker_output import private_directory


def _require_custody(packet: dict, template: Path, inner: dict, inner_path: Path) -> Path:
    root = inner_path.parent.parent
    parent = template.parent
    if (parent != root / 'launch-templates-docker-v1' or
            inner['execution']['docker_launch']['template_path'] != str(template)):
        raise ValueError('Docker startup allowance namespace differs from authority')
    private_directory(parent)
    for path in (parent, *parent.parents):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or
                (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError('Docker startup allowance ancestry is unsafe')
    for mount in packet['mounts']:
        if not mount['read_only']:
            for key in ('source', 'target'):
                path = Path(mount[key])
                if not path.is_absolute() or path.resolve() != path or parent.is_relative_to(path) or path.is_relative_to(parent):
                    raise ValueError('Docker startup allowance overlaps writable mount')
    return parent


def reserve_startup(packet: dict, template: Path | None) -> None:
    """Consume one authenticated delivery attempt without refunding failures."""
    if packet.get('worker_authority') is None:
        return
    if template is None:
        raise ValueError('Docker delivery template is unavailable')
    inner_path = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(sealed_bytes(inner_path, expected=packet['contract_sha256']))
    limit = inner.get('bounds', {}).get('transient_launch_max_attempts')
    if type(limit) is not int or limit <= 0:
        raise ValueError('Docker startup allowance is not a positive integer')
    parent = _require_custody(packet, template, inner, inner_path)
    name = 'startup-' + packet['builder_run_id']
    namespace = parent / name
    try:
        namespace.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)
    private_directory(namespace)
    directory = os.open(namespace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            info = os.fstat(lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Docker startup lock custody changed')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _consume(directory, namespace, packet, limit)
        finally:
            os.close(lock)
    finally:
        os.close(directory)


def _consume(directory: int, namespace: Path, packet: dict, limit: int) -> None:
    entries = os.listdir(directory)
    if len(entries) > 4097 or 'lock' not in entries:
        raise ValueError('Docker startup allowance audit capacity exceeded')
    records = [entry for entry in entries if entry != 'lock']
    subject = {'builder_run_id': packet['builder_run_id'], 'contract_sha256': packet['contract_sha256'], 'limit': limit}
    for index, entry in enumerate(sorted(records), 1):
        if entry != f'{index:08d}.json':
            raise ValueError('Docker startup allowance record sequence differs')
        raw = sealed_bytes(namespace / entry, limit=65536)
        if raw != canonical({**subject, 'attempt': index}):
            raise ValueError('Docker startup allowance record differs')
    if len(records) >= limit or len(records) >= 4096:
        raise ValueError('Docker startup allowance exhausted')
    raw = canonical({**subject, 'attempt': len(records) + 1})
    if len(raw) > 65536:
        raise ValueError('Docker startup allowance record exceeds audit capacity')
    fd = os.open(f'{len(records)+1:08d}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
