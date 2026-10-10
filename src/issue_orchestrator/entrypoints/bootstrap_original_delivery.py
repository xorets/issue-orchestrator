"""Compose the original delivery owner without launching an engine or planner."""
from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Iterator
from contextlib import contextmanager
from ..control.session_manager import SessionManager, SessionRef
from ..control.label_manager import LabelManager
from ..control.original_delivery import OriginalDeliveryOwner
from ..execution.original_delivery_adapter import original_delivery_ports
from ..execution.original_delivery_session import require_native_session_assets
from ..execution.original_delivery_contract import sealed_execution_contract
from ..execution.original_delivery_processes import capture_original_processes, engine_identity, require_original_quiescent, require_original_termination_scope
from ..ports.original_delivery import OriginalDeliveryClaims

if TYPE_CHECKING:
    from ..domain.models import OrchestratorState
    from ..infra.config import Config
    from ..ports.repository_host import RepositoryHost
    from ..ports.working_copy import WorkingCopy


def build_original_delivery_owner(config: Config, claims: object, repository: RepositoryHost,
                                  working_copy: WorkingCopy | None,
                                  state: OrchestratorState | None, session_manager: SessionManager | None = None) -> OriginalDeliveryOwner | None:
    if not isinstance(claims, OriginalDeliveryClaims):
        return None
    return OriginalDeliveryOwner(claims, repository, working_copy, config, state, engine_identity,
        lambda owner, offline: require_original_quiescent(owner, offline=offline),
        lambda owner: sealed_execution_contract(owner, config), capture_original_processes,
        LabelManager(config).extract_rework_cycle, require_native_session_assets, require_original_termination_scope,
        lambda session: session_manager is not None and session_manager.exists(SessionRef.from_name(session.terminal_id)))


@contextmanager
def build_offline_original_delivery_owner(config: Config) -> Iterator[OriginalDeliveryOwner]:
    from .bootstrap_claims import lease_config_from
    if not config.claims.enabled or not config.claims.claimant_id or not config.repo:
        raise ValueError("Original reconciliation requires its explicit original remote claimant/configuration")
    with original_delivery_ports(config, lease_config_from(config)) as (claims, repository):
        owner = build_original_delivery_owner(config, claims, repository, None, None)
        assert owner is not None
        yield owner
