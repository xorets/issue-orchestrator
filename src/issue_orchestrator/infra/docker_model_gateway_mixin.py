"""Controller methods for the selected Docker model gateway."""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Protocol, cast

from ..control.original_delivery_facade import docker_model_gateway_context

if TYPE_CHECKING:
    from ..control.orchestrator_deps import OrchestratorDeps
    from ..control.session_launcher import SessionLauncher


class _GatewayOwner(Protocol):
    deps: OrchestratorDeps
    state_lock: threading.RLock

    @property
    def shutdown_requested(self) -> bool: ...

    @property
    def session_launcher(self) -> SessionLauncher: ...


class DockerModelGatewayMixin:
    def docker_model_gateway_credentials(self) -> dict[str, str]:
        owner = cast(_GatewayOwner, self)
        return owner.session_launcher.docker_model_credentials()

    def docker_model_gateway_context(self, capability: str, previous: dict[str, object] | None = None) -> dict[str, object]:
        owner = cast(_GatewayOwner, self)
        return docker_model_gateway_context(owner.deps, capability, previous,
            shutdown_requested=lambda: owner.shutdown_requested, state_lock=owner.state_lock)
