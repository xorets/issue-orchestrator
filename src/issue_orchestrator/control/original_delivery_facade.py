"""Serialize original-owner commands through the existing typed owner and pause port."""
from __future__ import annotations

from typing import TYPE_CHECKING
from collections.abc import Callable
import threading
from ..domain.pause_state import PauseActor, PauseReason
from .original_delivery import DockerFirstModelCommand, OriginalDeliveryCommand, OriginalDeliveryOwner
from .pause_controller import PauseController

if TYPE_CHECKING:
    from .orchestrator_deps import OrchestratorDeps
    from ..domain.models import Session


def activate_docker_original(deps: OrchestratorDeps, session: Session, *, unavailable: Callable[[], bool]) -> None:
    """Register and recheck original custody before starting a prepared worker."""
    owner = deps.original_delivery_owner
    if unavailable() or owner is None or not deps.health_gate.check(paused=False).can_proceed:
        raise ValueError('Docker pre-start owner or engine health unavailable')
    fence = owner.register_prestart(session)
    if unavailable() or not deps.health_gate.check(paused=False).can_proceed:
        raise ValueError('Docker pre-start engine health changed')
    owner.require_prestart_current(session, fence)
    deps.runner.activate_session(session.run_assets, session.terminal_id, fence)


def original_delivery(owner: OriginalDeliveryOwner | None, issue_number: int,
                      command: OriginalDeliveryCommand | None, *, state_lock: threading.RLock) -> dict[str, object]:
    """Dispatch original commands under shared state custody."""
    with state_lock:
        if owner is None:
            raise ValueError("Original remote ownership is unavailable")
        return owner.observe(issue_number) if command is None else owner.execute(issue_number, command)


def docker_first_model(deps: OrchestratorDeps, controller: PauseController, capability: str,
                       command: DockerFirstModelCommand, *, shutdown_requested: Callable[[], bool], state_lock: threading.RLock) -> dict[str, object]:
    """Hold the authenticated allocation after preflight, before owner registration.

    The engine state lock covers the entire transaction.
    No failed admission may establish an operator hold or erase another cause.
    """
    with state_lock:
        run = deps.issue_run_ledger.run_for_capability(capability)
        owner = deps.original_delivery_owner
        if shutdown_requested() or owner is None or not deps.health_gate.check(paused=False).can_proceed:
            raise ValueError("Docker first-model owner or engine health unavailable")
        owner.first_model_preflight(run, command)
        if not controller.paused:
            controller.pause(reason=PauseReason.OPERATOR, actor=PauseActor.CONTROL_API,
                detail="Authenticated Docker model preflight for " + run.run_id)
        return owner.first_model(run, command)


def docker_model_gateway_context(deps: OrchestratorDeps, capability: str, previous: dict[str, object] | None = None, *, shutdown_requested: Callable[[], bool], state_lock: threading.RLock) -> dict[str, object]:
    """Resolve live ownership under the state lock; never hold it during forwarding."""
    with state_lock:
        run = deps.issue_run_ledger.run_for_capability(capability)
        owner = deps.original_delivery_owner
        if shutdown_requested() or owner is None or not deps.health_gate.check(paused=False).can_proceed:
            raise ValueError("Docker model gateway owner or engine health unavailable")
        return owner.model_gateway_context(run, previous)
