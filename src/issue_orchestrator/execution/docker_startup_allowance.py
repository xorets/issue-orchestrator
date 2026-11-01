"""Durable delivery-scoped reservations before Docker startup."""
from hashlib import sha256
import json
import os
import pwd
from pathlib import Path
import re
import stat

from .docker_launch_input import canonical, sealed_bytes, control_manifest_bytes
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
    import fcntl
    inner_path = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(sealed_bytes(inner_path, expected=packet['contract_sha256']))
    builder = packet.get('builder_run_id')
    engine_run = packet.get('run_id')
    if (type(builder) is not str or not re.fullmatch(r'run-[0-9a-f]{32}', builder) or
            type(engine_run) is not str or not re.fullmatch(r'[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}', engine_run) or
            inner.get('run_id') != builder or inner_path.parent.name != 'engine-contracts-docker-v1' or
            inner_path.name != builder + '.json'):
        raise ValueError('Docker startup allowance delivery identity differs')
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
            _consume(directory, namespace, packet, limit, require_bound=inner.get('role') == 'standard-implementation')
        finally:
            os.close(lock)
    finally:
        os.close(directory)


def _consume(directory: int, namespace: Path, packet: dict, limit: int, *, require_bound: bool) -> None:
    entries = os.listdir(directory)
    if len(entries) > 4097 or 'lock' not in entries:
        raise ValueError('Docker startup allowance audit capacity exceeded')
    records = [entry for entry in entries if entry != 'lock']
    subject = {'builder_run_id': packet['builder_run_id'], 'contract_sha256': packet['contract_sha256'], 'limit': limit}
    seen = set()
    for index, entry in enumerate(sorted(records), 1):
        if entry != f'{index:08d}.json':
            raise ValueError('Docker startup allowance record sequence differs')
        raw = sealed_bytes(namespace / entry, limit=65536)
        record = json.loads(raw)
        if (type(record) is not dict or set(record) != {*subject, 'attempt', 'engine_run_id', 'launch_sha256'} or
                type(record.get('attempt')) is not int or type(record.get('limit')) is not int or
                any(record.get(key) != value for key, value in {**subject, 'attempt': index}.items()) or
                type(record.get('engine_run_id')) is not str or
                not re.fullmatch(r'[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}', record['engine_run_id']) or
                type(record.get('launch_sha256')) is not str or
                not re.fullmatch(r'[0-9a-f]{64}', record['launch_sha256']) or
                record['engine_run_id'] in seen or raw != canonical(record)):
            raise ValueError('Docker startup allowance record differs')
        seen.add(record['engine_run_id'])
        if require_bound:
            _require_retained_binding(namespace.parent, record)
    if packet['run_id'] in seen:
        raise ValueError('Docker startup engine run already reserved')
    if len(records) >= limit or len(records) >= 4096:
        raise ValueError('Docker startup allowance exhausted')
    raw = canonical({**subject, 'attempt': len(records) + 1, 'engine_run_id':packet['run_id'],
        'launch_sha256':sha256(canonical(packet)).hexdigest()})
    if len(raw) > 65536:
        raise ValueError('Docker startup allowance record exceeds audit capacity')
    fd = os.open(f'{len(records)+1:08d}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _require_retained_binding(parent: Path, reservation: dict) -> None:
    """A prior unknown allocation may not be refunded by a new start grant."""
    path = parent / reservation['engine_run_id'] / 'docker-session.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 65536):
            raise ValueError('Docker prior original custody is unknown')
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        named = path.lstat()
        if (len(raw) != before.st_size or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino) or
                any(getattr(before, key) != getattr(after, key) for key in
                    ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))):
            raise ValueError('Docker prior original custody changed')
        value = json.loads(raw)
        if (type(value) is not dict or type(value.get('start_gate_version')) is not int or
                value['start_gate_version'] != 1 or value.get('original_binding') != 'bound' or
                value.get('run_id') != reservation['engine_run_id'] or
                value.get('launch_sha256') != reservation['launch_sha256'] or
                value.get('contract_sha256') != reservation['contract_sha256'] or
                type(value.get('original_fence')) is not str or
                re.fullmatch(r'[0-9a-f]{40}', value['original_fence']) is None):
            raise ValueError('Docker prior original custody requires reconciliation')
    finally:
        os.close(fd)


def seed_control_manifest(packet: dict, temporary: Path) -> None:
    """Use the pinned CLI cache path and the actual fetch time, never copy time."""
    if "control_manifest" not in packet:
        return
    raw = control_manifest_bytes(packet["control_manifest"])
    username = pwd.getpwuid(os.geteuid()).pw_name
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValueError("Docker CLI account name is unsafe")
    cache = private_directory(temporary / ("devcontainercli-" + username), create=True) / "control-manifest.json"
    descriptor = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(raw)
    fetched = packet["control_manifest"]["fetched_unix_ns"]
    os.utime(cache, ns=(fetched, fetched), follow_symlinks=False)
