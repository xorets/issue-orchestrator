"""Bounded provider status handoff from the selected Docker worker scratch."""
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat

from ..infra.provider_resilience import ProviderStatus, write_provider_status
from ..ports.provider_resilience import ProviderErrorType
from .docker_launch_input import sealed_bytes


ENV = 'ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR'


def allocate(packet: dict, root: Path) -> tuple[Path, int]:
    inner = json.loads(sealed_bytes(Path(packet['worker_authority']['engine_contract_path']), expected=packet['contract_sha256']))
    scratch = Path(inner['capabilities']['scratch'])
    if (inner['run_id'] != packet['builder_run_id'] or not scratch.is_absolute() or
            scratch == root or not scratch.is_relative_to(root) or scratch.resolve(strict=True) != scratch or
            {'source':str(scratch), 'target':str(scratch), 'read_only':False} not in packet['mounts']):
        raise ValueError('Docker provider scratch differs from admitted delivery')
    for mount in packet['mounts']:
        if mount == {'source':str(scratch), 'target':str(scratch), 'read_only':False}:
            continue
        for key in ('source', 'target'):
            path = Path(mount[key])
            if scratch.is_relative_to(path) or path.is_relative_to(scratch):
                raise ValueError('Docker provider scratch mount overlaps another mount')
    info = scratch.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Docker provider scratch custody differs')
    slot = scratch / ('provider-' + packet['run_id'])
    slot.mkdir(mode=0o700)
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return slot, descriptor


def worker_slot(value: str, run_dir: Path) -> Path:
    """Accept only the authenticated selected worker's exact run slot."""
    from .docker_worker_authority import MODEL_LAUNCH_ENV, _authority_environment, _model_authority
    raw = os.environ.get(MODEL_LAUNCH_ENV, '')
    if not 0 < len(raw.encode()) <= 65536:
        raise ValueError('Docker provider launch authority is unavailable')
    packet = json.loads(raw)
    environment = _authority_environment(packet)
    if not environment:
        raise ValueError('Docker provider launch authority is unavailable')
    outer, inner = _model_authority(packet, environment)
    scratch = Path(inner['capabilities']['scratch'])
    expected = scratch / ('provider-' + packet['run_id'])
    if (outer.get('schema_version') != 2 or inner['run_id'] != packet['builder_run_id'] or
            not scratch.is_absolute() or
            type(packet.get('run_id')) is not str or
            not re.fullmatch(r'[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}', packet['run_id']) or
            packet.get('engine_run_dir') != str(run_dir) or not run_dir.name.startswith(packet['run_id'] + '__') or
            {'source':str(scratch), 'target':str(scratch), 'read_only':False} not in packet['mounts'] or
            value != str(expected) or expected.resolve(strict=True) != expected):
        raise ValueError('Docker provider worker slot differs from delivery')
    info = expected.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Docker provider worker slot custody differs')
    return expected


def _read_status(directory: int, exit_code: int) -> ProviderStatus:
    try:
        fd = os.open('provider-status.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError as exc:
        raise ValueError('Docker provider status missing') from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                not 0 < info.st_size <= 4096):
            raise ValueError('Docker provider status custody differs')
        raw = os.read(fd, 4097)
        after = os.fstat(fd)
        named = os.stat('provider-status.json', dir_fd=directory, follow_symlinks=False)
        if ((named.st_dev, named.st_ino) != (info.st_dev, info.st_ino) or len(raw) != info.st_size or any(getattr(info, k) != getattr(after, k) for k in
                ('st_dev', 'st_ino', 'st_uid', 'st_nlink', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise ValueError('Docker provider status changed while reading')
    finally:
        os.close(fd)
    data = json.loads(raw)
    fields = {'provider', 'error_type', 'attempts', 'succeeded', 'exit_code', 'timed_out', 'last_error_summary',
        'last_attempt_at', 'quota_heals_on_timer'}
    if (type(data) is not dict or set(data) != fields or type(data['attempts']) is not int or data['attempts'] != 1 or
            type(data['succeeded']) is not bool or type(data['timed_out']) is not bool or
            type(data['quota_heals_on_timer']) is not bool or
            data['provider'] is not None and (type(data['provider']) is not str or len(data['provider']) > 128) or
            data['error_type'] is not None and data['error_type'] not in {x.value for x in ProviderErrorType} or
            data['last_error_summary'] is not None and (type(data['last_error_summary']) is not str or len(data['last_error_summary']) > 303) or
            type(data['last_attempt_at']) is not str or len(data['last_attempt_at']) > 64 or
            data['exit_code'] is not None and type(data['exit_code']) is not int or
            (data['exit_code'] if data['exit_code'] is not None else 124 if data['timed_out'] else 1) != exit_code):
        raise ValueError('Docker provider status shape or exec result differs')
    try:
        observed = datetime.fromisoformat(data['last_attempt_at'])
    except ValueError as exc:
        raise ValueError('Docker provider status timestamp differs') from exc
    if (type(exit_code) is not int or observed.utcoffset() is None or data['succeeded'] != (exit_code == 0) or
            data['succeeded'] and data['error_type'] is not None):
        raise ValueError('Docker provider status outcome differs')
    return ProviderStatus.from_dict(data)


def settle(slot: Path, descriptor: int, packet: dict, exit_code: int) -> None:
    info = os.fstat(descriptor)
    current = slot.lstat()
    if (slot.resolve(strict=True) != slot or not stat.S_ISDIR(current.st_mode) or
            (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino) or
            current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
        raise ValueError('Docker provider slot custody changed')
    status = _read_status(descriptor, exit_code)
    write_provider_status(Path(packet['engine_run_dir']), status)
