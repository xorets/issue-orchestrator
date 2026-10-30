"""Route issue launch and original activation under shared state custody."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..control.original_delivery_facade import activate_docker_original
from ..control.session_routing import orchestrator_launch_session

if TYPE_CHECKING:
    from ..control.session_launch_types import LaunchStep
    from ..domain.tech_lead_session import TechLeadLaunchScope
    from ..ports.issue import Issue
    from .orchestrator import Orchestrator


def launch_issue(orchestrator: Orchestrator, issue: Issue, *, tech_lead_scope: TechLeadLaunchScope | None) -> LaunchStep:
    with orchestrator.state_lock:
        return orchestrator_launch_session(issue, orchestrator.state, orchestrator.session_launcher,
            orchestrator.deps.session_restorer, tech_lead_scope=tech_lead_scope,
            activate_original=lambda session: activate_docker_original(orchestrator.deps, session,
                unavailable=lambda: orchestrator.shutdown_requested or orchestrator.state.paused))
