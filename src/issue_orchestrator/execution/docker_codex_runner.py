"""Classify a Docker Codex result without treating child markers as provider errors."""
from .agent_runner_errors import classify_provider_error
from .agent_runner_types import AgentResult
from .docker_provider_status import _child_marker
from .subprocess_runner import SubprocessAgentRunner
from ..ports.provider_resilience import ProviderErrorType


class DockerCodexRunner(SubprocessAgentRunner):
    def _classify_result(self, result: AgentResult) -> ProviderErrorType | None:
        if (result.exit_code == 78 and not result.timed_out and
                _child_marker(result.stderr.removesuffix("\n"), "run", "launch") is not None):
            return classify_provider_error(stdout=result.stdout, stderr="",
                exit_code=result.exit_code, timed_out=result.timed_out)
        return super()._classify_result(result)
