"""Bounded provider status handoff from the selected Docker worker scratch."""
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import shlex
import stat

from ..infra.provider_resilience import ProviderStatus, now_iso, write_provider_status
from .docker_launch_input import sealed_bytes


ENV = 'ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR'


class ProviderStatusWriteError(OSError):
    """A validated result was observed but its controller copy failed."""
    def __init__(self, value: ProviderStatus):
        super().__init__('Docker provider status recording failed')
        self.value = value


def allocate(packet: dict, root: Path, command: str) -> tuple[Path, int, str, bool]:
    inner = json.loads(sealed_bytes(Path(packet['worker_authority']['engine_contract_path']), expected=packet['contract_sha256']))
    words = shlex.split(command)
    module = 'issue_orchestrator.entrypoints.cli_tools.provider_runner'
    if words.count(module) != 1:
        raise ValueError('Docker provider command identity differs')
    args = words[words.index(module) + 1:]
    if args.count('--provider') != 1 or args.count('--quota-heals-on-timer') > 1:
        raise ValueError('Docker provider command lane differs')
    position = args.index('--provider')
    lane = args[position + 1] if position + 1 < len(args) else ''
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?', lane) or
            lane.partition(':')[0] != inner['execution']['provider']):
        raise ValueError('Docker provider command belongs to another provider')
    heals = '--quota-heals-on-timer' in args
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
    return slot, descriptor, lane, heals


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


def _read_status(directory: int, exit_code: int, lane: str, heals: bool) -> ProviderStatus:
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
    return ProviderStatus.from_worker_payload(json.loads(raw), exit_code, lane, heals)


def settle(slot: Path, descriptor: int, lane: str, heals: bool, packet: dict, exit_code: int) -> ProviderStatus:
    info = os.fstat(descriptor)
    current = slot.lstat()
    if (slot.resolve(strict=True) != slot or not stat.S_ISDIR(current.st_mode) or
            (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino) or
            current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
        raise ValueError('Docker provider slot custody changed')
    # Circuit chronology belongs to the controller, not the worker.
    observed_at = now_iso()
    status = _read_status(descriptor, exit_code, lane, heals)
    status = replace(status, last_attempt_at=observed_at)
    try:
        write_provider_status(Path(packet['engine_run_dir']), status)
    except OSError as exc:
        raise ProviderStatusWriteError(status) from exc
    return status
