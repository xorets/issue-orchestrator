"""Real local UDS transport; upstream is a dummy server, no model call."""
import asyncio
import json
import os
import time
import pytest

@pytest.fixture
def gateway_dir():
    from pathlib import Path
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix='io-gateway-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.fixture(autouse=True)
def gateway_peer(monkeypatch):
    raw = open("/proc/self/stat").read()
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_MODEL_GATEWAY_PID", str(os.getpid()))
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_MODEL_GATEWAY_BIRTH", raw[raw.rindex(")") + 2:].split()[19])

from issue_orchestrator.execution.docker_model_gateway_client import forward_model_request


@pytest.mark.asyncio
async def test_private_uds_stream_and_request_scope(gateway_dir):
    seen=[]
    async def serve(reader, writer):
        head=await reader.readuntil(b'\r\n\r\n')
        length=next(int(line.split(b':',1)[1]) for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:'))
        body=await reader.readexactly(length)
        seen.append((head,json.loads(body)))
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: test\n\n')
        await writer.drain();writer.close();await writer.wait_closed()
    socket=gateway_dir/'model-gateway.sock'
    server=await asyncio.start_unix_server(serve,path=str(socket));os.chmod(socket,0o600)
    try:
        chunks=[x async for x in forward_model_request(controller_home=str(gateway_dir),instance_token='a'*64,
            context={'deadline_unix_ns':time.time_ns()+10_000_000_000,'max_output_bytes':100},
            request={'model':'test'},provider_auth='PRIVATE-DUMMY')]
    finally:
        server.close();await server.wait_closed()
    assert b''.join(chunks)==b'data: test\n\n'
    assert seen[0][0].startswith(b'POST /v1/responses HTTP/1.0')
    assert seen[0][1]['provider_auth']=='PRIVATE-DUMMY'
    assert seen[0][1]['request']=={'model':'test'}


@pytest.mark.asyncio
async def test_expired_deadline_refuses_before_connect(gateway_dir):
    socket=gateway_dir/'model-gateway.sock'
    server=await asyncio.start_unix_server(lambda *_:None,path=str(socket));os.chmod(socket,0o600)
    try:
        with pytest.raises(ValueError,match='deadline expired'):
            _=[x async for x in forward_model_request(controller_home=str(gateway_dir),instance_token='a'*64,
                context={'deadline_unix_ns':time.time_ns()-1,'max_output_bytes':100},request={},provider_auth='dummy')]
    finally:
        server.close();await server.wait_closed()


def test_actual_callback_router_to_private_uds(gateway_dir, monkeypatch, auth_enabled_control_client):
    import threading
    from http.server import BaseHTTPRequestHandler
    from socketserver import UnixStreamServer
    from types import SimpleNamespace
    from issue_orchestrator.entrypoints import control_api
    from issue_orchestrator.entrypoints.control_api_issue_support import ControlApiIssueDependencies, get_control_api_issue_dependencies
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            seen.append((self.path, self.headers.get('Authorization'), data))
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
            self.wfile.write(b'data: dummy\n\n')
        def log_message(self,*args): pass
    path=gateway_dir/'model-gateway.sock'; server=UnixStreamServer(str(path),Handler);os.chmod(path,0o600)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    context={'grant_kind':'builder-docker-container-model-authorization','controller_home':str(gateway_dir),'deadline_unix_ns':time.time_ns()+10_000_000_000,'max_output_bytes':1000}
    engine=SimpleNamespace(docker_model_gateway_context=lambda capability:context if capability=='cap' else (_ for _ in ()).throw(ValueError('denied')), docker_model_gateway_credentials=lambda:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY-PRIVATE'})
    deps=ControlApiIssueDependencies(get_orchestrator=lambda:engine,with_state_lock=lambda fn:fn())
    monkeypatch.setitem(control_api.control_app.dependency_overrides,get_control_api_issue_dependencies,lambda:deps)
    monkeypatch.setattr(KeyringProviderCredentials,'_read_secrets',staticmethod(lambda *_:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY-PRIVATE'}))
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN','a'*64)
    control_api.configure_api_token('admin',agent_callback='agent',agent_callback_scope='docker')
    try:
        response=auth_enabled_control_client.post('/api/docker/model-gateway/responses',json={'model':'selected'},headers={'Authorization':'Bearer agent','X-Completion-Capability':'cap'})
        assert response.status_code==200 and response.content==b'data: dummy\n\n'
        assert seen[0][0]=='/v1/responses' and seen[0][1]=='Bearer '+'a'*64
        assert seen[0][2]['provider_auth']=='DUMMY-PRIVATE'
        assert b'DUMMY-PRIVATE' not in response.content
        denied=auth_enabled_control_client.post('/api/docker/model-gateway/responses',json={},headers={'Authorization':'Bearer agent','X-Completion-Capability':'wrong'})
        assert denied.status_code==409 and len(seen)==1
    finally:
        control_api.configure_api_token(None);server.shutdown();server.server_close();thread.join(timeout=5)


@pytest.mark.asyncio
async def test_slow_body_expires_and_releases_allocation(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api,'verify_docker_callback_authorization',lambda _:True)
    deadline=time.time_ns()+80_000_000
    engine=SimpleNamespace(docker_model_gateway_context=lambda _: {'deadline_unix_ns':deadline})
    class Slow:
        async def stream(self):
            await asyncio.sleep(1)
            yield b'{}'
    with pytest.raises(HTTPException) as raised:
        await route.model_gateway(Slow(),SimpleNamespace(get_orchestrator=lambda:engine),authorization='x',x_completion_capability='slow-cap')
    assert raised.value.status_code==408
    assert not route._active  # noqa: SLF001 - verify release of the allocation guard


@pytest.mark.asyncio
async def test_changed_live_authority_refuses_before_credential_lookup(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api,'verify_docker_callback_authorization',lambda _:True)
    
    states=iter([{'deadline_unix_ns':time.time_ns()+1_000_000_000,'claim_ref_sha':'a'},
                 {'deadline_unix_ns':time.time_ns()+1_000_000_000,'engine_run_id':'foreign','claim_ref_sha':'b'}])
    engine=SimpleNamespace(docker_model_gateway_context=lambda _: next(states))
    class Body:
        async def stream(self): yield b'{"model":"test"}'
    with pytest.raises(HTTPException) as raised:
        await route.model_gateway(Body(),SimpleNamespace(get_orchestrator=lambda:engine),authorization='x',x_completion_capability='changed-cap')
    assert raised.value.status_code==409
    assert not route._active  # noqa: SLF001 - verify release of the allocation guard


@pytest.mark.asyncio
async def test_idle_stream_stops_when_owner_is_cancelled(monkeypatch):
    from types import SimpleNamespace
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api,'verify_docker_callback_authorization',lambda _:True)
    
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN','a'*64)
    context={'grant_kind':'builder-docker-container-model-authorization','deadline_unix_ns':time.time_ns()+5_000_000_000,'controller_home':'/unused','max_output_bytes':100}
    calls=[];closed=[]
    def current(_):
        calls.append(True)
        if len(calls)>2: raise ValueError('cancelled')
        return context
    async def idle(**kwargs):
        try:
            await asyncio.sleep(10)
            yield b'never'
        finally: closed.append(True)
    monkeypatch.setattr(route,'forward_model_request',idle)
    class Body:
        async def stream(self): yield b'{}'
    response=await route.model_gateway(Body(),SimpleNamespace(get_orchestrator=lambda:SimpleNamespace(docker_model_gateway_context=current, docker_model_gateway_credentials=lambda:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY'})),authorization='x',x_completion_capability='pending-cap')
    with pytest.raises(ValueError,match='cancelled'):
        await asyncio.wait_for(anext(response.body_iterator),timeout=2)
    assert closed==[True]
    assert not route._active  # noqa: SLF001 - verify release of the allocation guard


@pytest.mark.asyncio
async def test_oversized_body_refuses_before_credential_lookup(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api,'verify_docker_callback_authorization',lambda _:True)
    monkeypatch.setattr(route,'_MAX_REQUEST',4)
    
    engine=SimpleNamespace(docker_model_gateway_context=lambda _:{'deadline_unix_ns':time.time_ns()+1_000_000_000})
    class Body:
        async def stream(self): yield b'12345'
    with pytest.raises(HTTPException) as raised:
        await route.model_gateway(Body(),SimpleNamespace(get_orchestrator=lambda:engine),authorization='x',x_completion_capability='oversize-cap')
    assert raised.value.status_code==413
    assert not route._active  # noqa: SLF001 - verify release of the allocation guard


@pytest.mark.asyncio
async def test_wrong_peer_receives_no_auth_or_request(gateway_dir, monkeypatch):
    seen = []
    async def serve(reader, writer):
        seen.append(await reader.read())
        writer.close()
        await writer.wait_closed()
    path = gateway_dir / 'model-gateway.sock'
    server = await asyncio.start_unix_server(serve, path=str(path))
    os.chmod(path, 0o600)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_BIRTH', '0')
    try:
        with pytest.raises(ValueError, match='peer identity differs'):
            _ = [chunk async for chunk in forward_model_request(controller_home=str(gateway_dir),
                instance_token='a' * 64, context={'deadline_unix_ns':time.time_ns()+1_000_000_000,
                'max_output_bytes':100}, request={}, provider_auth='PRIVATE')]
        await asyncio.sleep(0.01)
        assert seen == [b'']
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_synthetic_route_uses_fixed_dummy_without_keyring(monkeypatch):
    from types import SimpleNamespace
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    from issue_orchestrator.execution.docker_worker_authority import SYNTHETIC_AUTH
    monkeypatch.setattr(control_api, 'verify_docker_callback_authorization', lambda _: True)
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    monkeypatch.setattr(KeyringProviderCredentials, '_read_secrets', staticmethod(lambda *_: pytest.fail('keyring touched')))
    monkeypatch.setattr('issue_orchestrator.execution.docker_worker_authority.docker_model_auth_requested', lambda: True)
    monkeypatch.setattr('issue_orchestrator.execution.docker_worker_authority.docker_container_grant_kind', lambda: 'builder-docker-container-synthetic-authorization')
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN', 'a' * 64)
    context = {'grant_kind': 'builder-docker-container-synthetic-authorization',
               'deadline_unix_ns': time.time_ns() + 5_000_000_000,
               'controller_home': '/unused', 'max_output_bytes': 100}
    received = []
    async def fake_forward(**kwargs):
        received.append(kwargs['provider_auth'])
        yield b'data: fixture\n\n'
    monkeypatch.setattr(route, 'forward_model_request', fake_forward)
    class Body:
        async def stream(self):
            yield b'{}'
    def current(_):
        return context
    engine = SimpleNamespace(docker_model_gateway_context=current, docker_model_gateway_credentials=lambda: KeyringProviderCredentials().session_env('codex', docker=True))
    response = await asyncio.wait_for(route.model_gateway(Body(), SimpleNamespace(get_orchestrator=lambda: engine),
                                         authorization='x', x_completion_capability='synthetic-cap'), timeout=1)
    async def collect():
        return [part async for part in response.body_iterator]
    assert await asyncio.wait_for(collect(), timeout=1) == [b'data: fixture\n\n']
    assert received == [SYNTHETIC_AUTH]


@pytest.mark.asyncio
async def test_actual_builder_listener_with_engine_client(gateway_dir, monkeypatch):
    """Actual listener and client; admission and upstream are explicitly substituted."""
    import sys
    from pathlib import Path
    from unittest.mock import patch
    builder_path = os.environ.get('BUILDER_GATEWAY_SOURCE')
    if not builder_path:
        pytest.skip('Builder gateway source not supplied')
    builder = Path(builder_path)
    monkeypatch.syspath_prepend(str(builder))
    import docker_model_gateway as gateway
    seen = []
    server = gateway.ModelGatewayServer(gateway_dir / 'model-gateway.sock', gateway_dir, gateway_dir, 'a' * 64,
                                        lambda pid, context: pid == os.getpid())
    def prepare(_state, _artifact, context, request, auth):
        seen.append((context, request, auth))
        return object(), 1, object()
    try:
        with patch.object(gateway, 'prepare_request', side_effect=prepare), \
             patch.object(gateway, 'stream_request', side_effect=lambda *args: args[-1](b'event: response.completed\n\n')):
            context = {'builder_run_id': 'run-fixture', 'grant_kind':'builder-docker-container-synthetic-authorization',
                       'deadline_unix_ns':time.time_ns()+5_000_000_000, 'max_output_bytes':1000}
            chunks = [part async for part in forward_model_request(controller_home=str(gateway_dir), instance_token='a'*64,
                      context=context, request={'input':[]}, provider_auth='dummy')]
        assert b''.join(chunks) == b'event: response.completed\n\n'
        assert seen == [(context, {'input': []}, 'dummy')]
    finally:
        server.close()


def test_renewed_claim_fence_keeps_only_same_allocation():
    from issue_orchestrator.entrypoints.docker_model_gateway_routes import _same_allocation
    old = {'claim_ref_sha': 'a' * 40, 'engine_run_id': 'same'}
    assert _same_allocation(old, {'claim_ref_sha': 'b' * 40, 'engine_run_id': 'same'})
    assert not _same_allocation(old, {'claim_ref_sha': 'b' * 40, 'engine_run_id': 'other'})
