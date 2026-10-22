"""Docker custody for the original claim owner; no local PID can prove it."""
from __future__ import annotations

from ..domain.models import Session
from ..domain.original_delivery import DockerCustody, OriginalDelivery
from .terminal_docker import DockerPlugin, canonical, sealed_bytes
from .original_delivery_session import require_native_session_assets
from hashlib import sha256
import json
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

    def verify_session(self, session: Session) -> None:
        # The engine's typed run manifest/identity remain backend independent.
        require_native_session_assets(session)
        if self.runner.template_path is not None:
            self.runner.select_run(session.run_assets.run_id)
        receipt = self.runner.public_receipt(session.terminal_id)
        if receipt["run_id"] != session.run_assets.run_id:
            raise ValueError("Docker typed session run identity changed")

    def _worker(self, custody: DockerCustody) -> dict:
        engine = self.runner.engine
        if engine.request("GET", "/info").get("ID") != custody.daemon_id:
            raise ValueError("Docker original daemon changed")
        actual = engine.request("GET", f"/containers/{custody.container_id}/json")
        if (actual.get("Id") != custody.container_id or
                actual.get("Config", {}).get("Labels", {}).get("io.builder.launch") != custody.launch_sha256):
            raise ValueError("Docker original worker identity changed")
        provider = engine.request("GET", f"/exec/{custody.provider_exec_id}/json")
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
            actual = self._worker(custody)
            if actual.get("State", {}).get("Running") is not False:
                raise ValueError("Docker original worker remains active")
            if offline:
                controller = self.runner.engine.request("GET", f"/containers/{custody.controller_container_id}/json")
                if controller.get("Id") != custody.controller_container_id or controller.get("State", {}).get("Running") is not False:
                    raise ValueError("Docker original controller is active or unknown")

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
