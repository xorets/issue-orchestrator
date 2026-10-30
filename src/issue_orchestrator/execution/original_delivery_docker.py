"""Docker custody for the original claim owner; no local PID can prove it."""
from __future__ import annotations

from ..domain.models import Session
from ..domain.original_delivery import DockerCustody, OriginalDelivery
from .terminal_docker import DockerPlugin, canonical, sealed_bytes
from .original_delivery_session import require_native_session_assets
from hashlib import sha256
import json
import os
import re
import stat
from pathlib import Path


class DockerOriginalCustody:
    def __init__(self, runner: DockerPlugin):
        self.runner = runner

    def first_model_snapshot(self, session: Session, contract_sha256: str, launch_sha256: str) -> dict:
        self.verify_session(session)
        identity = json.loads((session.run_assets.run_dir / "session-identity.json").read_bytes())
        if session.agent_config.provider != "codex" or identity.get("provider") != "codex":
            raise ValueError("Docker first-model provider differs from allocated session")
        return self.runner.first_model_snapshot(session.run_assets, session.terminal_id, contract_sha256, launch_sha256)

    def prestart_snapshot(self, session: Session) -> dict:
        self.verify_session(session)
        return self.runner.prestart_snapshot(session.run_assets, session.terminal_id)

    def model_gateway_snapshot(self, session: Session) -> dict:
        self.verify_session(session)
        identity = json.loads((session.run_assets.run_dir / "session-identity.json").read_bytes())
        if session.agent_config.provider != "codex" or identity.get("provider") != "codex":
            raise ValueError("Docker model gateway requires selected Codex session")
        return self.runner.model_gateway_snapshot(session.run_assets, session.terminal_id)

    def verify_review_parent(self, owner: OriginalDelivery, context: dict) -> None:
        parent, inner = context['review_parent'], context['original_inner']
        rows = [row for row in owner.docker_custody if row.run_id == parent['engine_run_id']]
        if len(rows) != 1:
            raise ValueError('Docker review parent original custody unavailable')
        template = Path(inner['execution']['docker_launch']['template_path'])
        packet = json.loads(sealed_bytes(template.parent / parent['engine_run_id'] / 'launch.json', expected=rows[0].launch_sha256))
        if (packet['run_id'] != owner.run_id or packet['builder_run_id'] != parent['builder_run_id'] or
                packet['contract_sha256'] != owner.contract_sha256 or packet['working_dir'] != owner.worktree or
                packet['daemon_id'] != rows[0].daemon_id or packet['controller_container_id'] != rows[0].controller_container_id):
            raise ValueError('Docker review parent protected launch changed')
        self.runner.verify_stopped_parent(packet, rows[0])

    def seal_first_model(self, session: Session, receipt: dict) -> dict:
        return self.runner.seal_first_model(session.run_assets, receipt)

    def capture(self, owner: OriginalDelivery) -> DockerCustody:
        name = owner.correction_runs[-1][3] if owner.pending and owner.correction_runs else owner.session_name
        run_id = owner.correction_runs[-1][1] if owner.pending and owner.correction_runs else owner.run_id
        if self.runner.template_path is not None:
            self.runner.select_run(run_id)
        receipt = self.runner.public_receipt(name)
        if (receipt["repository"], receipt["run_id"], receipt["contract_sha256"]) != (owner.repository, run_id, owner.contract_sha256):
            raise ValueError("Docker original claim does not match session custody")
        return self.runner.custody(name)

    def diagnostic(self, owner: OriginalDelivery) -> dict | None:
        """Read only the exact original's validated, non-authoritative diagnostics."""
        try:
            return self._diagnostic(owner)
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def _diagnostic(self, owner: OriginalDelivery) -> dict | None:
        from ..contracts.ui_openapi_models import ProviderDiagnosticPayload
        rows = [row for row in owner.docker_custody if row.run_id == owner.run_id]
        if len(rows) != 1 or self.runner.template_path is None:
            return None
        row = rows[0]
        self.runner.select_run(owner.run_id)
        assert self.runner.launch_path is not None
        packet = json.loads(sealed_bytes(self.runner.launch_path, expected=row.launch_sha256))
        if (packet['run_id'], packet['engine_run_dir'], packet['contract_sha256'], packet['working_dir'],
                packet['repository'], packet['session_name'], packet['daemon_id'], packet['controller_container_id']) != (
                owner.run_id, owner.run_dir, owner.contract_sha256, owner.worktree, owner.repository, owner.session_name,
                row.daemon_id, row.controller_container_id):
            return None
        pending = False
        try:
            record = json.loads(_private_diagnostic_bytes(self.runner.receipt_path(), 65536))
            if type(record) is not dict:
                raise ValueError('Docker receipt shape differs')
            diagnostic = record.get('diagnostic')
            pending = (record.get('run_id') == owner.run_id and record.get('launch_sha256') == row.launch_sha256
                and diagnostic is None)
            if (record.get('run_id') == owner.run_id and record.get('launch_sha256') == row.launch_sha256 and
                    diagnostic is not None):
                from .docker_provider_status import valid_child_diagnostic
                child = diagnostic.get('child') if type(diagnostic) is dict else None
                if child is not None and not valid_child_diagnostic(child, owner.run_id, row.launch_sha256):
                    diagnostic = {key: item for key, item in diagnostic.items() if key != 'child'}
                value = ProviderDiagnosticPayload.model_validate(diagnostic).model_dump(mode='json', exclude_unset=True)
                pairs = {('status', 'status_unavailable'), ('record', 'record_failed'),
                    ('record', 'record_unavailable'), ('stop', 'stop_unverified'),
                    ('output', 'output_failed'), ('transport', 'transport_failed')}
                if (value['run_id'] == owner.run_id and value['launch_sha256'] == row.launch_sha256 and
                        all((item['phase'], item['reason']) in pairs for item in value['secondary'])):
                    return value
        except (OSError, ValueError, TypeError, KeyError):
            pass
        fallback = self._diagnostic_from_status(owner, packet, row)
        if pending:
            return {**fallback, 'secondary':[]} if fallback['primary'] is not None else None
        return fallback

    def _diagnostic_from_status(self, owner: OriginalDelivery, packet: dict, row: DockerCustody) -> dict:
        from ..ports.provider_resilience import ProviderStatus
        result = {'run_id':owner.run_id, 'launch_sha256':row.launch_sha256, 'primary':None,
            'secondary':[{'phase':'record', 'reason':'record_unavailable'}]}
        path = Path(owner.run_dir)
        protected = Path(owner.worktree) / '.issue-orchestrator'
        try:
            overlays = [m for m in packet['mounts'] if m['target'] == str(protected)]
            if (path.resolve(strict=True) != path or not path.is_relative_to(protected) or len(overlays) != 1 or
                    overlays[0]['read_only'] is not True or
                    Path(overlays[0]['source']) not in {protected, Path('/srv/builder/tasks') / packet['builder_run_id'] / 'readonly-empty'} or
                    any(not m['read_only'] and Path(m['target']).is_relative_to(protected) for m in packet['mounts'])):
                raise ValueError('controller status custody unavailable')
            value = json.loads(_private_diagnostic_bytes(path / 'provider-status.json', 4096))
            if type(value) is not dict:
                raise ValueError('controller status shape differs')
        except (OSError, ValueError, TypeError, KeyError):
            result['secondary'].append({'phase':'status', 'reason':'status_unavailable'})
            return result
        try:
            info = self.runner.engine.request('GET', '/info')
            if info.get('ID') != row.daemon_id:
                return result
            actual = self.runner.engine.request('GET', f'/exec/{row.provider_exec_id}/json')
        except (OSError, ValueError, RuntimeError):
            result['secondary'].append({'phase':'transport', 'reason':'transport_failed'})
            return result
        if type(actual) is not dict:
            return result
        exit_code = actual.get('ExitCode')
        if (actual.get('ID') != row.provider_exec_id or actual.get('ContainerID') != row.container_id or
                actual.get('Running') is not False or type(exit_code) is not int):
            return result
        try:
            inner = json.loads(sealed_bytes(Path(packet['worker_authority']['engine_contract_path']),
                expected=owner.contract_sha256))
            lane = value.get('provider')
            if (not isinstance(lane, str) or lane.partition(':')[0] != inner['execution']['provider'] or
                    type(value.get('quota_heals_on_timer')) is not bool):
                raise ValueError('controller status provider differs')
            status = ProviderStatus.from_worker_payload(value, exit_code, lane, value['quota_heals_on_timer'])
        except (OSError, ValueError, TypeError, KeyError):
            result['secondary'].append({'phase':'status', 'reason':'status_unavailable'})
            return result
        result['primary'] = status.diagnostic()
        result.update(_fallback_child(inner, packet, owner, row, status, exit_code))
        return result

    def verify_session(self, session: Session) -> None:
        # The engine's typed run manifest/identity remain backend independent.
        require_native_session_assets(session)
        if self.runner.template_path is not None:
            self.runner.select_run(session.run_assets.run_id)
        receipt = self.runner.public_receipt(session.terminal_id)
        if receipt["run_id"] != session.run_assets.run_id:
            raise ValueError("Docker typed session run identity changed")

    def _container(self, custody: DockerCustody) -> dict:
        engine = self.runner.engine
        if engine.request("GET", "/info").get("ID") != custody.daemon_id:
            raise ValueError("Docker original daemon changed")
        actual = engine.request("GET", f"/containers/{custody.container_id}/json")
        if (actual.get("Id") != custody.container_id or
                actual.get("Config", {}).get("Labels", {}).get("io.builder.launch") != custody.launch_sha256):
            raise ValueError("Docker original worker identity changed")
        return actual

    def _worker(self, custody: DockerCustody) -> dict:
        actual = self._container(custody)
        provider = self.runner.engine.request("GET", f"/exec/{custody.provider_exec_id}/json")
        if provider.get("ID") != custody.provider_exec_id or provider.get("ContainerID") != custody.container_id:
            raise ValueError("Docker original exec identity changed")
        return actual

    def quiescent(self, owner: OriginalDelivery, *, offline: bool) -> None:
        if owner.execution_backend != "docker" or not owner.docker_custody:
            raise ValueError("Docker original custody is unknown")
        expected_runs = {owner.run_id, *(row[1] for row in owner.correction_runs)}
        if {row.run_id for row in owner.docker_custody} != expected_runs:
            raise ValueError("Docker original/correction run custody coverage is unknown")
        for custody in owner.docker_custody:
            actual = self._container(custody)
            if actual.get("State", {}).get("Running") is not False:
                raise ValueError("Docker original worker remains active")
            result = self.runner.engine.inspect_exec(custody.provider_exec_id)
            provider = result.get('value') if result.get('status') == 200 else None
            settled = (type(provider) is dict and provider.get('ID') == custody.provider_exec_id and
                provider.get('ContainerID') == custody.container_id and provider.get('Running') is False and
                type(provider.get('ExitCode')) is int)
            if not settled and self.never_started(owner, custody) is None:
                raise ValueError("Docker original provider settlement is unknown")
            if offline:
                controller = self.runner.engine.request("GET", f"/containers/{custody.controller_container_id}/json")
                if controller.get("Id") != custody.controller_container_id or controller.get("State", {}).get("Running") is not False:
                    raise ValueError("Docker original controller is active or unknown")

    def never_started(self, owner: OriginalDelivery, custody: DockerCustody | None = None) -> dict | None:
        """Return only a protected, identity-bound source-owned stop/wait proof."""
        try:
            rows = [row for row in owner.docker_custody if row.run_id == owner.run_id]
            if not owner.cancelled or len(rows) != 1 or custody is not None and custody != rows[0] or self.runner.template_path is None:
                return None
            row = rows[0]
            self.runner.select_run(row.run_id)
            path = self.runner.receipt_path()
            record = json.loads(_private_diagnostic_bytes(path, 65536, mode=0o600), object_pairs_hook=_unique_record)
            observation = {'running':False, 'pid':0, 'exit_code':None}
            missing = {'kind':'exact-exec-not-found', 'status':404}
            proof = record.get('never_started')
            after = proof.get('after') if type(proof) is dict else None
            expected = {'schema_version':1, 'kind':'docker-never-started', 'run_id':row.run_id,
                'contract_sha256':owner.contract_sha256, 'launch_sha256':row.launch_sha256,
                'daemon_id':row.daemon_id, 'controller_container_id':row.controller_container_id,
                'container_id':row.container_id, 'provider_exec_id':row.provider_exec_id,
                'disposition':'cancelled-before-exec-start', 'before':observation,
                'stop_wait':'completed', 'after':after}
            if (type(proof) is not dict or type(proof.get('schema_version')) is not int or
                    type(proof.get('before')) is not dict or proof['before'].get('running') is not False or
                    type(proof['before'].get('pid')) is not int or proof['before'].get('pid') != 0 or
                    proof['before'].get('exit_code', False) is not None or
                    not (after == missing and type(after.get('status')) is int or
                         type(after) is dict and set(after) == set(observation) and after.get('running') is False and
                         type(after.get('pid')) is int and after['pid'] == 0 and after.get('exit_code', False) is None)):
                return None
            if (record.get('state') != 'stopped' or type(record.get('start_gate_version')) is not int or
                    record['start_gate_version'] != 1 or record.get('start_intent') != 'cancelled-before-start' or
                    record.get('original_binding') != 'bound' or
                    not isinstance(record.get('original_fence'), str) or
                    re.fullmatch(r'[0-9a-f]{40}', record['original_fence']) is None or
                    proof != expected or
                    any(record.get(key) != expected[key] for key in ('run_id','contract_sha256','launch_sha256',
                        'daemon_id','controller_container_id','container_id','provider_exec_id'))):
                return None
            self.verify_contract(owner)
            actual = self._container(row)
            if actual.get('State', {}).get('Running') is not False:
                return None
            from .docker_never_started import after_stop
            if after_stop(self.runner.engine, self.runner.launch_path, record) != after:
                return None
            return expected
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def termination_scope(self, owner: OriginalDelivery, run_id: str) -> None:
        rows = [row for row in owner.docker_custody if row.run_id == run_id]
        if len(rows) != 1:
            raise ValueError("Docker original termination custody is unknown")
        self._worker(rows[0])

    def verify_contract(self, owner: OriginalDelivery) -> None:
        if self.runner.template_path is not None:
            self.runner.select_run(owner.run_id)
        if self.runner.launch_path is None:
            raise ValueError("Docker original launch binding is missing")
        packet = json.loads(sealed_bytes(self.runner.launch_path))
        if (packet["repository"], packet["run_id"], packet["session_name"], packet["contract_sha256"], packet["working_dir"]) != (
                owner.repository, owner.run_id, owner.session_name, owner.contract_sha256, owner.worktree):
            raise ValueError("Docker original launch binding changed")
        if owner.docker_custody and any(row.run_id == owner.run_id and row.launch_sha256 != sha256(canonical(packet)).hexdigest() for row in owner.docker_custody):
            raise ValueError("Docker original launch material changed")



def _fallback_child(inner, packet, owner, row, status, exit_code):
    from .docker_provider_status import read_child_diagnostic
    try:
        scratch = Path(inner['capabilities']['scratch'])
        slot = scratch / ('provider-' + owner.run_id)
        if (not scratch.is_absolute() or scratch.resolve(strict=True) != scratch or
                slot.resolve(strict=True) != slot or
                {'source':str(scratch), 'target':str(scratch), 'read_only':False} not in packet['mounts']):
            return {}
        parent = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent_info = os.fstat(parent)
            named_parent = scratch.lstat()
            if ((parent_info.st_dev, parent_info.st_ino) != (named_parent.st_dev, named_parent.st_ino) or
                    parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700):
                return {}
            fd = os.open(slot.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                current = os.fstat(fd)
                named = os.stat(slot.name, dir_fd=parent, follow_symlinks=False)
                if ((current.st_dev, current.st_ino) != (named.st_dev, named.st_ino) or
                        current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
                    return {}
                child = read_child_diagnostic(fd, owner.run_id, row.launch_sha256, status, exit_code)
                return {'child': child} if child is not None else {}
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    except (OSError, ValueError, TypeError, KeyError):
        return {}

def _private_diagnostic_bytes(path: Path, limit: int, *, mode: int | None = None) -> bytes:
    if path.resolve(strict=True) != path:
        raise ValueError('Docker diagnostic path is not canonical')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                mode is not None and stat.S_IMODE(before.st_mode) != mode or
                not 0 < before.st_size <= limit):
            raise ValueError('Docker diagnostic custody differs')
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        named = path.lstat()
        if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Docker diagnostic path changed while reading')
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in
                ('st_dev', 'st_ino', 'st_uid', 'st_nlink', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Docker diagnostic changed while reading')
        return raw
    finally:
        os.close(fd)


def _unique_record(pairs: list[tuple[str, object]]) -> dict:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError('duplicate Docker receipt field')
    return value
