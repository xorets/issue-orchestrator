"""Docker custody for the original claim owner; no local PID can prove it."""
from __future__ import annotations

from ..domain.models import Session
from ..domain.original_delivery import DockerCustody, OriginalDelivery
from .terminal_docker import DockerPlugin, canonical, sealed_bytes
from .original_delivery_session import require_native_session_assets
from hashlib import sha256
import json


class DockerOriginalCustody:
    def __init__(self, runner: DockerPlugin):
        self.runner = runner

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
