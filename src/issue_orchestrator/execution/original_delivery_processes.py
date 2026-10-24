"""Positive Linux observations for exact run processes and retained sessions."""
from __future__ import annotations

import os
from pathlib import Path
import socket

from ..domain.original_delivery import OriginalDelivery


def process_birth(pid: int) -> str | None:
    try:
        return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    except FileNotFoundError:
        return None


def engine_identity() -> tuple[str, int, str]:
    pid = os.getpid()
    birth = process_birth(pid)
    if birth is None:
        raise RuntimeError('Current engine process birth is unavailable')
    return socket.gethostname(), pid, birth


def capture_original_processes(owner: OriginalDelivery, *, include_workspace: bool = False) -> tuple[tuple[str, int, str, int, str], ...]:
    root = Path(owner.worktree).resolve(strict=True)
    run_dirs = {owner.run_dir, *(row[2] for row in owner.correction_runs)}
    found: list[tuple[str, int, str, int, str]] = []
    current_run = owner.correction_runs[-1][1] if owner.pending and owner.correction_runs else owner.run_id
    for proc in _user_processes():
        try:
            fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] == 'Z':
                continue  # An exited zombie cannot access files or run a child.
            if _owns_run(proc, root, run_dirs, include_workspace=include_workspace):
                if not include_workspace and not _descends_from_original_engine(proc, owner):
                    raise ValueError('Original worker is not owned by the current engine process tree')
                sid = int(fields[3])
                leader_birth = process_birth(sid)
                if leader_birth is None:
                    raise ValueError('Original worker session leader identity is unavailable')
                found.append((current_run, int(proc.name), fields[19], sid, leader_birth))
        except (FileNotFoundError, PermissionError):
            continue  # Retained exact PID/session proof is checked independently.
    return tuple(found)


def _descends_from_original_engine(proc: Path, owner: OriginalDelivery) -> bool:
    pid = int(proc.name)
    visited: set[int] = set()
    while pid > 1 and pid not in visited:
        visited.add(pid)
        fields = (Path('/proc')/str(pid)/'stat').read_text().rsplit(')', 1)[1].split()
        if pid == owner.engine_pid:
            return fields[19] == owner.engine_birth
        pid = int(fields[1])
    return False


def require_original_quiescent(owner: OriginalDelivery, *, offline: bool) -> None:
    if owner.engine_host != socket.gethostname():
        raise ValueError('Original owner is on another host')
    birth = process_birth(owner.engine_pid)
    if offline and birth == owner.engine_birth:
        raise ValueError('Original engine is still running')
    if not offline and engine_identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
        raise ValueError('Serving engine is not the original owner')
    _require_dead_roots(owner)
    if capture_original_processes(owner, include_workspace=True):
        raise ValueError('Original run process remains')
    retained = {(sid, sid_birth) for _, _, _, sid, sid_birth in owner.process_roots}
    for proc in _user_processes():
        try:
            fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] == 'Z':
                continue
            sid = int(fields[3])
            if _retained_session(sid, retained):
                raise ValueError('Original tracked descendant session remains')
        except FileNotFoundError:
            continue


def _retained_session(sid: int, retained: set[tuple[int, str]]) -> bool:
    if sid == os.getsid(0):
        return False  # The engine/transport's own shared session is not a worker.
    current = process_birth(sid)
    return any(original_sid == sid and (current is None or current == birth)
        for original_sid, birth in retained if birth)


def _user_processes():
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit() and int(proc.name) != os.getpid():
            try:
                if proc.stat().st_uid == os.getuid():
                    yield proc
            except FileNotFoundError:
                continue


def _owns_run(proc: Path, root: Path, run_dirs: set[str], *, include_workspace: bool) -> bool:
    cwd = (proc/'cwd').resolve(strict=True)
    if include_workspace and (cwd == root or root in cwd.parents):
        return True
    try:
        environment = (proc/'environ').read_bytes().split(b'\0')
    except PermissionError:
        # A readable cwd outside all owned roots supplies no ownership evidence.
        # Retained PID/birth + session checks cover supported children even when
        # their environment is protected or scrubbed after launch.
        return False
    return any(key == b'ISSUE_ORCHESTRATOR_RUN_DIR' and os.fsdecode(value) in run_dirs
        for key, _, value in (variable.partition(b'=') for variable in environment))


def _require_dead_roots(owner: OriginalDelivery) -> None:
    if not owner.process_roots:
        raise ValueError('Original worker root custody is unknown')
    for _, pid, original_birth, _, _ in owner.process_roots:
        if process_birth(pid) == original_birth:
            fields = (Path('/proc')/str(pid)/'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] != 'Z':
                raise ValueError('Original tracked worker remains')


def require_original_termination_scope(owner: OriginalDelivery, run_id: str) -> None:
    """A stale numeric registry target must never authorize killing a foreign PID."""
    if owner.engine_host != socket.gethostname():
        raise ValueError('Original termination belongs to another host')
    roots = [row for row in owner.process_roots if row[0] == run_id]
    if not roots:
        raise ValueError('Original native worker roots are unknown')
    for _, pid, birth, sid, sid_birth in roots:
        current = process_birth(pid)
        leader = process_birth(sid)
        if current is not None and current != birth or leader is not None and leader != sid_birth:
            raise ValueError('Original native worker numbers now belong to a foreign process')
