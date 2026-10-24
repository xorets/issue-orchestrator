"""Sibling workers cannot ask the trusted service to execute arbitrary Git hooks."""
from fastapi.testclient import TestClient
import pytest

from issue_orchestrator.entrypoints.control_api import configure_api_token, control_app


@pytest.mark.parametrize("route", ["/api/preflight-push", "/api/review-exchange/respond", "/api/validated-work/intake", "/api/original-delivery/42/cancel"])
def test_docker_token_cannot_enter_host_git_exchange_or_operator_routes(route, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Untrusted worker reached host Git")
    monkeypatch.setattr("issue_orchestrator.execution.git_working_copy.GitWorkingCopy.push_preflight", forbidden)
    configure_api_token("admin", agent_callback="worker", agent_callback_scope="docker")
    try:
        response = TestClient(control_app).post(route, json={"worktree": str(tmp_path)}, headers={"Authorization": "Bearer worker"})
        assert response.status_code == 401
    finally:
        configure_api_token(None)


def test_docker_client_refuses_host_preflight_without_manufacturing_pass(monkeypatch, tmp_path):
    from issue_orchestrator.entrypoints.cli_tools.agent_done import run_preflight_push_check
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_CALLBACK_SCOPE", "docker")
    passed, error, _ = run_preflight_push_check(tmp_path)
    assert passed is False and "controller" in error


def test_docker_callback_authentication_cannot_be_disabled():
    with pytest.raises(ValueError, match="authenticated"):
        configure_api_token(None, agent_callback_scope="docker")
