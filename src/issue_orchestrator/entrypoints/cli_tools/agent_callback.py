"""How an agent subprocess calls back into the orchestrator.

The behaviour-level owner shared by every agent callback command —
``coding-done`` / ``reviewer-done`` (preflight-push, resume) and
``exchange-respond``. It answers two questions, and it is the only
place that answers them:

- **Where** to send the callback (:func:`resolve_control_api_port`).
- **How** to authenticate it (:class:`ApiRequestHeaders`).

Both rules previously lived in the resume-specific command module, so
generic callback behaviour depended on one particular command, and the
port rule had been copied into each caller. Copies drift: that is
exactly how the surfaces disagreed in #6913.
"""

from __future__ import annotations

import os
from ...infra.callback_address import validate_callback_origin
from collections.abc import MutableMapping
from dataclasses import dataclass

AGENT_CALLBACK_TOKEN_ENV_VAR = "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN"

# The port env vars an agent may carry, in precedence order. The
# prefixed one is set at session launch; the legacy unprefixed one is
# injected per review-exchange with the live bound port.
_PORT_ENV_VARS = ("ISSUE_ORCHESTRATOR_API_PORT", "ORCHESTRATOR_API_PORT")

# ``control_api_port: 0`` means "bind any free port". A literal "0" is
# therefore a *request*, never a reachable destination.
_AUTO_ASSIGN_SENTINEL = "0"


def callback_url(route: str, port: str, *, native_host: str = "localhost") -> str:
    """Use the launch-inherited origin for sibling workers; Native stays loopback."""
    origin = os.environ.get("ISSUE_ORCHESTRATOR_API_ORIGIN", f"http://{native_host}:{port}")
    if not route.startswith("/api/") or "?" in route or "#" in route:
        raise ValueError("invalid callback route")
    return validate_callback_origin(origin, int(port)) + route


@dataclass(frozen=True, slots=True)
class ApiHeader:
    """One HTTP header for an agent-scoped Control API callback."""

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class ApiRequestHeaders:
    """Typed HTTP headers for an agent-scoped Control API callback."""

    headers: tuple[ApiHeader, ...]

    @classmethod
    def from_agent_environment(cls) -> "ApiRequestHeaders":
        values = [ApiHeader("Content-Type", "application/json")]
        token = os.environ.get(AGENT_CALLBACK_TOKEN_ENV_VAR)
        if token:
            values.append(ApiHeader("Authorization", f"Bearer {token}"))
        return cls(headers=tuple(values))

    def to_mutable_mapping(self) -> MutableMapping[str, str]:
        """Project to the mutable mapping required by ``urllib``."""
        return {header.name: header.value for header in self.headers}


def api_request_headers() -> ApiRequestHeaders:
    """Build Control API request headers for agent-scoped callbacks."""
    return ApiRequestHeaders.from_agent_environment()


def resolve_control_api_port() -> str | None:
    """Resolve the port serving the Control API, or ``None`` if unset.

    The auto-assign sentinel is *truthy*, so a naive ``a or b`` chain
    returns ``"0"`` and shadows a live port supplied by a later
    variable. That is how every review-exchange verdict became
    undeliverable: agents dialled ``localhost:0`` (#6913, #6924).

    Returning ``None`` rather than a bogus port lets callers fail
    honestly. The orchestrator side must publish the *bound* port —
    see ``infra.agent_callback_endpoint``.
    """
    for name in _PORT_ENV_VARS:
        raw = os.environ.get(name)
        if raw is None:
            continue
        port = raw.strip()
        if port and port != _AUTO_ASSIGN_SENTINEL:
            return port
    return None
