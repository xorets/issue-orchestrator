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
    environment = _authority_environment(packet, worker=True)
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


def record_diagnostic(lock, record: dict, primary: dict | None = None, secondary: dict | None = None, *, child: dict | None = None) -> None:
    """Keep the first observed origin and a bounded list of subsequent failures."""
    with lock:
        diagnostic = record.setdefault('diagnostic', {'run_id':record['run_id'],
            'launch_sha256':record['launch_sha256'], 'primary':None, 'secondary':[]})
        if child is not None:
            diagnostic['child'] = child
        if primary is not None and diagnostic['primary'] is None:
            diagnostic['primary'] = primary
        if secondary is not None and secondary not in diagnostic['secondary'] and len(diagnostic['secondary']) < 4:
            diagnostic['secondary'].append(secondary)


def _child_value(value: object, run_id: str, launch_sha: str) -> bool:
    fields = {'schema_version', 'kind', 'run_id', 'launch_sha256', 'phase', 'reason', 'exit_code',
        'stderr_bytes', 'stderr_sha256', 'stderr_truncated', 'exception_type', 'elapsed_ms', 'remaining_ms', 'own_timer_fired', 'secondary'}
    if type(value) is not dict or set(value) != fields:
        return False
    reason, code = value['reason'], value['exit_code']
    count, digest, truncated = value['stderr_bytes'], value['stderr_sha256'], value['stderr_truncated']
    return (type(value['schema_version']) is int and value['schema_version'] == 1 and
        value['kind'] == 'builder-codex-child-diagnostic' and value['run_id'] == run_id and
        value['launch_sha256'] == launch_sha and value['phase'] == 'codex-child' and
        reason in {'nonzero', 'timeout', 'interrupted', 'spawn_failed'} and
        (code is None or type(code) is int and -255 <= code <= 255) and
        (reason != 'nonzero' or type(code) is int and code != 0) and
        (reason != 'spawn_failed' or code is None) and
        (value['exception_type'] is None or value['exception_type'] in {'TimeoutExpired', 'KeyboardInterrupt', 'InterruptedError', 'FileNotFoundError', 'PermissionError', 'OSError', 'SubprocessError'}) and
        (reason != 'nonzero' or value['exception_type'] is None) and
        ((count is None and digest is None and truncated is None) or
         (type(count) is int and 0 <= count <= 32768 and isinstance(digest, str) and
          re.fullmatch('[0-9a-f]{64}', digest) is not None and type(truncated) is bool)) and
        all(type(value[k]) is int and 0 <= value[k] <= 86400000 for k in ('elapsed_ms', 'remaining_ms')) and
        type(value['own_timer_fired']) is bool and value['own_timer_fired'] == (reason == 'timeout') and
        type(value['secondary']) is list and len(value['secondary']) <= 2 and
        all(item in {'record_failed', 'cleanup_failed'} for item in value['secondary']) and
        len(set(value['secondary'])) == len(value['secondary']))


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError('duplicate child diagnostic field')
    return value


def _child_marker(summary: str | None, run_id: str, launch_sha: str) -> dict | None:
    if not isinstance(summary, str):
        return None
    match = re.fullmatch(r'ACPCHILD1\|(nonzero|timeout|interrupted|spawn_failed)\|(n|0|-?[1-9][0-9]{0,2})\|(n|TimeoutExpired|KeyboardInterrupt|InterruptedError|FileNotFoundError|PermissionError|OSError|SubprocessError)\|(0|[1-9][0-9]{0,7})\|(0|[1-9][0-9]{0,7})\|([01])\|([01])', summary)
    if not match:
        return None
    reason, raw_exit, exception, elapsed, remaining, timer, cleanup = match.groups()
    value = {'schema_version':1, 'kind':'builder-codex-child-diagnostic', 'run_id':run_id,
        'launch_sha256':launch_sha, 'phase':'codex-child', 'reason':reason,
        'exit_code':None if raw_exit == 'n' else int(raw_exit), 'stderr_bytes':None,
        'stderr_sha256':None, 'stderr_truncated':None, 'exception_type':None if exception == 'n' else exception, 'elapsed_ms':int(elapsed),
        'remaining_ms':int(remaining), 'own_timer_fired':timer == '1',
        'secondary':['record_failed', *(['cleanup_failed'] if cleanup == '1' else [])]}
    return {**value, 'source':'marker'} if _child_value(value, run_id, launch_sha) else None


def read_child_diagnostic(directory: int, run_id: str, launch_sha: str,
                          status: ProviderStatus, exit_code: int) -> dict | None:
    """Read an untrusted observation only after the wrapper result is validated."""
    if exit_code != 78 or status.succeeded or status.exit_code != exit_code:
        return None
    try:
        fd = os.open('child-diagnostic.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return _child_marker(status.last_error_summary, run_id, launch_sha)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 4096):
            return None
        raw = os.read(fd, 4097)
        after = os.fstat(fd)
        named = os.stat('child-diagnostic.json', dir_fd=directory, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_nlink', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if ((named.st_dev, named.st_ino) != (before.st_dev, before.st_ino) or len(raw) != before.st_size or
                any(getattr(before, key) != getattr(after, key) for key in fields)):
            return None
        value = json.loads(raw, object_pairs_hook=_unique_object)
        return {**value, 'source':'slot'} if _child_value(value, run_id, launch_sha) else None
    except (OSError, ValueError, TypeError):
        return None
    finally:
        os.close(fd)


def valid_child_diagnostic(value: object, run_id: str, launch_sha: str) -> bool:
    if type(value) is not dict or type(value.get('source')) is not str or value['source'] not in {'slot', 'marker'}:
        return False
    inner = {key: item for key, item in value.items() if key != 'source'}
    try:
        if not _child_value(inner, run_id, launch_sha):
            return False
    except (TypeError, ValueError):
        return False
    if value['source'] == 'marker':
        return (inner['stderr_bytes'] is None and 'record_failed' in inner['secondary'])
    return True
