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
    engine=SimpleNamespace(docker_model_gateway_context=lambda capability, previous=None:context if capability=='cap' else (_ for _ in ()).throw(ValueError('denied')), docker_model_gateway_credentials=lambda:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY-PRIVATE'})
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
    timeouts = []
    def controlled_timeout(_):
        timeout = asyncio.timeout(None)
        timeouts.append(timeout)
        return timeout
    monkeypatch.setattr(route, 'asyncio', SimpleNamespace(**{
        **vars(asyncio), 'timeout':controlled_timeout}))
    monkeypatch.setattr(route, 'time', SimpleNamespace(time_ns=lambda:0))
    engine=SimpleNamespace(docker_model_gateway_context=lambda _: {'deadline_unix_ns':10**12})
    body_started = asyncio.Event()
    body_closed = asyncio.Event()
    class Slow:
        async def stream(self):
            body_started.set()
            assert len(timeouts) == 2
            timeouts[-1].reschedule(asyncio.get_running_loop().time())
            try:
                await asyncio.Event().wait()
                yield b'{}'
            finally:
                body_closed.set()
    with pytest.raises(HTTPException) as raised:
        await route.model_gateway(Slow(),SimpleNamespace(get_orchestrator=lambda:engine),authorization='x',x_completion_capability='slow-cap')
    assert raised.value.status_code==408
    assert raised.value.detail == 'Docker model gateway deadline exhausted'
    assert body_started.is_set() and body_closed.is_set()
    assert not route._active  # noqa: SLF001 - verify release of the allocation guard


@pytest.mark.asyncio
async def test_changed_live_authority_refuses_before_credential_lookup(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api,'verify_docker_callback_authorization',lambda _:True)

    states=iter([{'grant_kind':'builder-docker-container-model-authorization','deadline_unix_ns':time.time_ns()+1_000_000_000,'claim_ref_sha':'a'},
                 {'deadline_unix_ns':time.time_ns()+1_000_000_000,'engine_run_id':'foreign','claim_ref_sha':'b'}])
    from issue_orchestrator.control.original_delivery import OriginalDeliveryOwner
    def current(_, previous=None):
        return OriginalDeliveryOwner.admit_model_gateway_context(next(states), previous)
    engine=SimpleNamespace(docker_model_gateway_context=current)
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
    clock = [0.0]
    entered = asyncio.Event()
    async def advance_to_poll(tasks, *, timeout):
        await entered.wait()
        clock[0] += timeout
        return set(), tasks
    monkeypatch.setattr(route, 'time', SimpleNamespace(time_ns=lambda:0, monotonic=lambda:clock[0]))
    monkeypatch.setattr(route, 'asyncio', SimpleNamespace(**{
        **vars(asyncio), 'wait':advance_to_poll, 'timeout':lambda _:asyncio.timeout(None)}))
    context={'grant_kind':'builder-docker-container-model-authorization','deadline_unix_ns':10**12,'controller_home':'/unused','max_output_bytes':100}
    calls=[];closed=[]
    def current(_, previous=None):
        calls.append(True)
        if len(calls)>2: raise ValueError('cancelled')
        return context
    async def idle(**kwargs):
        try:
            entered.set()
            await asyncio.Event().wait()
            yield b'never'
        finally: closed.append(True)
    monkeypatch.setattr(route,'forward_model_request',idle)
    class Body:
        async def stream(self): yield b'{}'
    response=await route.model_gateway(Body(),SimpleNamespace(get_orchestrator=lambda:SimpleNamespace(docker_model_gateway_context=current, docker_model_gateway_credentials=lambda:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY'})),authorization='x',x_completion_capability='pending-cap')
    with pytest.raises(ValueError,match='cancelled'):
        await anext(response.body_iterator)
    assert entered.is_set() and clock[0] == 0.5
    assert len(calls) == 3
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
    received = asyncio.Event()
    async def serve(reader, writer):
        seen.append(await reader.read())
        writer.close()
        await writer.wait_closed()
        received.set()
    path = gateway_dir / 'model-gateway.sock'
    server = await asyncio.start_unix_server(serve, path=str(path))
    os.chmod(path, 0o600)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_BIRTH', '0')
    try:
        with pytest.raises(ValueError, match='peer identity differs'):
            _ = [chunk async for chunk in forward_model_request(controller_home=str(gateway_dir),
                instance_token='a' * 64, context={'deadline_unix_ns':time.time_ns()+1_000_000_000,
                'max_output_bytes':100}, request={}, provider_auth='PRIVATE')]
        await received.wait()
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
    def current(_, previous=None):
        return context
    engine = SimpleNamespace(docker_model_gateway_context=current, docker_model_gateway_credentials=lambda: KeyringProviderCredentials().session_env('codex', docker=True))
    response = await route.model_gateway(Body(), SimpleNamespace(get_orchestrator=lambda: engine),
                                         authorization='x', x_completion_capability='synthetic-cap')
    async def collect():
        return [part async for part in response.body_iterator]
    assert await collect() == [b'data: fixture\n\n']
    assert received == [SYNTHETIC_AUTH]


@pytest.mark.builder_source
@pytest.mark.asyncio
async def test_actual_builder_listener_with_engine_client(gateway_dir, monkeypatch, builder_source):
    """Actual listener and client; admission and upstream are explicitly substituted."""
    from unittest.mock import patch
    monkeypatch.syspath_prepend(str(builder_source))
    import docker_model_gateway as gateway
    seen = []
    server = gateway.ModelGatewayServer(gateway_dir / 'model-gateway.sock', gateway_dir, gateway_dir, 'a' * 64,
                                        lambda pid, context: pid == os.getpid())
    def prepare(_state, _artifact, context, request, auth):
        seen.append((context, request, auth))
        return object(), 1, object()
    try:
        with patch.object(gateway, 'prepare_request', side_effect=prepare), \
             patch.object(gateway, 'stream_request', side_effect=lambda *args, **kwargs: args[-1](b'event: response.completed\n\n')):
            context = {'builder_run_id': 'run-fixture', 'grant_kind':'builder-docker-container-synthetic-authorization',
                       'deadline_unix_ns':time.time_ns()+5_000_000_000, 'max_output_bytes':1000}
            chunks = [part async for part in forward_model_request(controller_home=str(gateway_dir), instance_token='a'*64,
                      context=context, request={'input':[]}, provider_auth='dummy')]
        assert b''.join(chunks) == b'event: response.completed\n\n'
        assert seen == [(context, {'input': []}, 'dummy')]
    finally:
        server.close()


def test_owner_admits_only_same_allocation_and_supported_grant():
    from issue_orchestrator.control.original_delivery import OriginalDeliveryOwner
    admit = OriginalDeliveryOwner.admit_model_gateway_context
    old = {'claim_ref_sha': 'a' * 40, 'engine_run_id': 'same',
           'grant_kind': 'builder-docker-container-model-authorization'}
    renewed = {**old, 'claim_ref_sha': 'b' * 40}
    assert admit(renewed, old) == renewed
    with pytest.raises(ValueError, match='authority changed'):
        admit({**renewed, 'engine_run_id': 'other'}, old)
    with pytest.raises(ValueError, match='grant kind unavailable'):
        admit({**old, 'grant_kind': 'other'}, {**old, 'grant_kind': 'other'})



@pytest.mark.asyncio
async def test_continuous_stream_stops_after_authority_revoked(monkeypatch):
    from types import SimpleNamespace
    from issue_orchestrator.entrypoints import docker_model_gateway_routes as route

    clock = [0.0]
    monkeypatch.setattr(route, 'time', SimpleNamespace(time_ns=time.time_ns, monotonic=lambda: clock[0]))
    emitted = []
    async def forward(**kwargs):
        for i in range(100):
            clock[0] += 0.1
            emitted.append(i)
            yield b'data: fixture\n\n'
    monkeypatch.setattr(route, 'forward_model_request', forward)
    def current(_, previous=None):
        if len(emitted) >= 2:
            raise ValueError('revoked')
        return context
    context = {'controller_home': '/unused'}
    allocation = route._Allocation('continuous-test')
    stream = route._stream(SimpleNamespace(docker_model_gateway_context=current), 'cap', allocation,
                           context, time.time_ns() + 10_000_000_000, {}, 'dummy')
    with pytest.raises(ValueError, match='revoked'):
        _ = [chunk async for chunk in stream]
    assert 2 <= len(emitted) <= 7


@pytest.mark.asyncio
async def test_continuous_stream_accepts_renewed_fence(monkeypatch):
    from types import SimpleNamespace
    from issue_orchestrator.control.original_delivery import OriginalDeliveryOwner
    from issue_orchestrator.entrypoints import docker_model_gateway_routes as route

    clock = [0.0]
    monkeypatch.setattr(route, 'time', SimpleNamespace(time_ns=time.time_ns, monotonic=lambda: clock[0]))
    async def forward(**kwargs):
        for _ in range(20):
            clock[0] += 0.1
            yield b'data: fixture\n\n'
    monkeypatch.setattr(route, 'forward_model_request', forward)
    context = {'controller_home': '/unused', 'claim_ref_sha': 'old',
               'grant_kind': 'builder-docker-container-model-authorization'}
    checks = []
    def current(_, previous):
        checks.append(clock[0])
        return OriginalDeliveryOwner.admit_model_gateway_context({**context, 'claim_ref_sha': 'renewed'}, previous)
    allocation = route._Allocation('renewal-test')
    stream = route._stream(SimpleNamespace(docker_model_gateway_context=current), 'cap', allocation,
                           context, time.time_ns() + 10_000_000_000, {}, 'dummy')
    assert len([chunk async for chunk in stream]) == 20
    assert 2 <= len(checks) <= 4


@pytest.mark.asyncio
async def test_close_failure_releases_capability_for_next_request(monkeypatch):
    from types import SimpleNamespace
    from issue_orchestrator.entrypoints import control_api, docker_model_gateway_routes as route
    monkeypatch.setattr(control_api, 'verify_docker_callback_authorization', lambda _: True)
    monkeypatch.setattr(route, 'time', SimpleNamespace(time_ns=lambda:0, monotonic=lambda:0))
    context = {'grant_kind':'builder-docker-container-model-authorization', 'deadline_unix_ns':10**12,
        'controller_home':'/unused', 'max_output_bytes':100}
    engine = SimpleNamespace(docker_model_gateway_context=lambda *args:context,
        docker_model_gateway_credentials=lambda:{'XORETS_DOCKER_MODEL_AUTH_JSON':'DUMMY'})
    async def upstream(**kwargs):
        try:
            yield b'chunk'
        finally:
            raise ConnectionResetError('fixture close failed')
    monkeypatch.setattr(route, 'forward_model_request', upstream)
    class Body:
        async def stream(self): yield b'{}'
    for _ in range(2):
        response = await route.model_gateway(Body(), SimpleNamespace(get_orchestrator=lambda:engine),
            authorization='x', x_completion_capability='close-failure-cap')
        assert await anext(response.body_iterator) == b'chunk'
        with pytest.raises(ConnectionResetError, match='fixture close failed'):
            await response.body_iterator.aclose()
