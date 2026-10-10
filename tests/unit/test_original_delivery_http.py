"""The public route delegates original custody and fails closed on bad inputs."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, AsyncMock
from pathlib import Path

import pytest

from issue_orchestrator.entrypoints.web_operator_routes import web_operator_router
from issue_orchestrator.entrypoints.web_session_context import get_web_orchestrator
from issue_orchestrator.entrypoints.mcp_original_delivery import original_delivery_result
from issue_orchestrator.infra.orchestrator import Orchestrator
from issue_orchestrator.execution.orchestrator_http_api import OrchestratorAsyncHttpApi
from issue_orchestrator.domain.claim import ClaimFetchError


def test_original_delivery_route_does_not_authorize_an_absent_engine():
    app = FastAPI()
    app.include_router(web_operator_router)
    client = TestClient(app)
    response = client.get("/api/original-delivery/42")
    assert response.status_code == 503
    response = client.post("/api/original-delivery/42/correct", json={"lease_id": "foreign", "fence": "old"})
    assert response.status_code in (422, 503)


def observed_owner():
    return {'issue_number':42,'lease_id':'original','claimant':'engine','fence':'a'*40,
        'lease_current':True,'expires_at':'2026-10-10T19:00:00','owner':None,'remote_released':False}


def test_http_parses_fenced_command_once_and_refuses_unknown_or_unreadable_authority():
    app = FastAPI()
    app.include_router(web_operator_router)
    engine = MagicMock(spec=Orchestrator)
    app.dependency_overrides[get_web_orchestrator] = lambda: engine
    engine.original_delivery.return_value = observed_owner()
    client = TestClient(app)
    assert client.get('/api/original-delivery/42').json() == observed_owner()
    payload = {'lease_id':'original','fence':'a'*40,'run_id':'original',
        'contract_sha256':'b'*64,'request_id':'A','feedback':'Fix reviewed finding'}
    response = client.post('/api/original-delivery/42/correct',json=payload)
    assert response.status_code == 200
    issue, command = engine.original_delivery.call_args.args
    assert issue == 42 and command.operation == 'correct' and command.request_id == 'A'
    engine.original_delivery.reset_mock()
    assert client.post('/api/original-delivery/42/correct',json={**payload,'max_cycles':9}).status_code == 422
    engine.original_delivery.assert_not_called()
    engine.original_delivery.side_effect = ClaimFetchError('Remote claim unreadable')
    assert client.get('/api/original-delivery/42').status_code == 409


@pytest.mark.asyncio
async def test_typed_mcp_preserves_flat_observation_and_refuses_inactive_correction():
    api = MagicMock(spec=OrchestratorAsyncHttpApi)
    api.original_delivery = AsyncMock(return_value=observed_owner())
    result = await original_delivery_result(api,Path('/unused'),42,'observe',None,running=True)
    assert result.structuredContent == observed_owner() and not result.isError
    api.original_delivery.assert_awaited_once_with(42,'observe',None)
    result = await original_delivery_result(api,Path('/unused'),42,'correct',None,running=False)
    assert result.isError
    assert api.original_delivery.await_count == 1
