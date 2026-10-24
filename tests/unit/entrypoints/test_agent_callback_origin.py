"""Native callback defaults and explicit sibling-container addressing."""
import pytest

from issue_orchestrator.entrypoints.cli_tools.agent_callback import callback_url


def test_callback_url_uses_explicit_trusted_origin(monkeypatch):
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_API_ORIGIN", "http://builder:19080")
    assert callback_url("/api/completion/submissions", "19080") == "http://builder:19080/api/completion/submissions"


@pytest.mark.parametrize("origin", ["https://other:19080", "http://user:pass@builder:19080", "http://builder:19080/path", "http://builder:19080?x=1", "http://builder:0", "http://builder:19081"])
def test_invalid_or_mismatched_origin_refuses(monkeypatch, origin):
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_API_ORIGIN", origin)
    with pytest.raises(ValueError, match="origin"):
        callback_url("/api/completion/submissions", "19080")


def test_native_default_is_loopback(monkeypatch):
    monkeypatch.delenv("ISSUE_ORCHESTRATOR_API_ORIGIN", raising=False)
    assert callback_url("/api/preflight-push", "19080") == "http://localhost:19080/api/preflight-push"


def test_session_exports_bound_sibling_origin():
    from issue_orchestrator.infra.agent_callback_endpoint import RuntimeAgentCallbackEndpoint
    from issue_orchestrator.control.session_env import api_port_export
    endpoint = RuntimeAgentCallbackEndpoint(advertised_host="builder")
    endpoint.publish_bound_port(19080)
    assert api_port_export(0, endpoint) == " ISSUE_ORCHESTRATOR_API_PORT='19080' ISSUE_ORCHESTRATOR_API_ORIGIN=http://builder:19080"
