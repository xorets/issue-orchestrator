"""Scoped worker model access through the trusted controller's private socket."""
from __future__ import annotations

import asyncio
from hashlib import sha256
import json
import os
import threading
import time

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from ..domain.completion_intake import IntakeUnauthorized
from ..execution.docker_model_gateway_client import forward_model_request
from ..execution.docker_worker_authority import MODEL_AUTH_ENV
from .control_api_issue_support import ControlApiIssueDependency

router = APIRouter()
_active: set[str] = set()
_lock = threading.Lock()
_MAX_REQUEST = 16 * 1024 * 1024


def _same_allocation(left: dict, right: dict) -> bool:
    """A renewed claim has a fresh fence but the same validated allocation."""
    return {k: v for k, v in left.items() if k != 'claim_ref_sha'} == {
        k: v for k, v in right.items() if k != 'claim_ref_sha'}


class _Allocation:
    def __init__(self, identity: str):
        self.identity = identity
        self.pending: set[asyncio.Task] = set()
        with _lock:
            if identity in _active:
                raise HTTPException(429, 'Docker model request already active')
            _active.add(identity)

    async def blocking(self, function, *args):
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)
        return await asyncio.shield(task)

    def release(self):
        if self.pending:
            for task in tuple(self.pending):
                task.add_done_callback(lambda _: self.release())
        else:
            with _lock:
                _active.discard(self.identity)


async def _initial_context(engine, capability, allocation):
    try:
        async with asyncio.timeout(10):
            context = await allocation.blocking(engine.docker_model_gateway_context, capability)
    except TimeoutError as error:
        raise HTTPException(408, 'Docker model gateway authority deadline exhausted') from error
    except IntakeUnauthorized as error:
        raise HTTPException(401, 'Invalid active run capability') from error
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise HTTPException(409, 'Docker model gateway authority unavailable') from error
    deadline = context.get('deadline_unix_ns')
    if type(deadline) is not int or deadline <= time.time_ns():
        raise HTTPException(409, 'Docker model gateway deadline unavailable')
    return context, deadline


async def _body(request):
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > _MAX_REQUEST - len(body):
            raise HTTPException(413, 'Docker model request exceeds bound')
        body.extend(chunk)
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise HTTPException(400, 'Docker model request is invalid') from error
    if type(value) is not dict:
        raise HTTPException(400, 'Docker model request is invalid')
    return value


async def _prepare(request, engine, capability, allocation, context, deadline):
    try:
        async with asyncio.timeout((deadline - time.time_ns()) / 1e9):
            value = await _body(request)
            try:
                fresh = await allocation.blocking(engine.docker_model_gateway_context, capability)
            except (IntakeUnauthorized, ValueError, OSError, KeyError, TypeError) as error:
                raise HTTPException(409, 'Docker model gateway authority changed') from error
            if not _same_allocation(fresh, context):
                raise HTTPException(409, 'Docker model gateway authority changed')
            if fresh.get('grant_kind') not in {'builder-docker-container-model-authorization',
                    'builder-docker-container-synthetic-authorization'}:
                raise HTTPException(409, 'Docker model grant kind unavailable')
            secret = await allocation.blocking(engine.docker_model_gateway_credentials)
            provider_auth = secret.get(MODEL_AUTH_ENV)
            if not isinstance(provider_auth, str):
                raise HTTPException(503, 'Docker model authentication unavailable')
            return fresh, value, provider_auth
    except TimeoutError as error:
        raise HTTPException(408, 'Docker model gateway deadline exhausted') from error


async def _next_with_owner(iterator, engine, capability, allocation, context):
    task = asyncio.ensure_future(anext(iterator))
    try:
        while not task.done():
            done, _ = await asyncio.wait({task}, timeout=0.5)
            if done:
                break
            fresh = await allocation.blocking(engine.docker_model_gateway_context, capability)
            if not _same_allocation(fresh, context):
                raise ValueError('Docker model gateway authority changed')
        return task.result()
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, StopAsyncIteration):
                pass


async def _stream(engine, capability, allocation, context, deadline, value, provider_auth):
    iterator = forward_model_request(controller_home=str(context['controller_home']),
        instance_token=os.environ.get('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN', ''),
        context=context, request=value, provider_auth=provider_auth)
    try:
        async with asyncio.timeout(max(0.0, (deadline - time.time_ns()) / 1e9)):
            while True:
                try:
                    yield await _next_with_owner(iterator, engine, capability, allocation, context)
                except StopAsyncIteration:
                    break
    finally:
        await iterator.aclose()
        allocation.release()


@router.post('/api/docker/model-gateway/responses')
async def model_gateway(request: Request, deps: ControlApiIssueDependency,
                        authorization: str = Header(...), x_completion_capability: str = Header(...)):
    from .control_api import verify_docker_callback_authorization
    if not verify_docker_callback_authorization(authorization):
        raise HTTPException(401, 'Docker callback authentication required')
    engine = deps.get_orchestrator()
    if engine is None:
        raise HTTPException(503, 'Docker model gateway unavailable')
    allocation = _Allocation(sha256(x_completion_capability.encode()).hexdigest())
    try:
        context, deadline = await _initial_context(engine, x_completion_capability, allocation)
        context, value, provider_auth = await _prepare(request, engine, x_completion_capability,
                                                        allocation, context, deadline)
        return StreamingResponse(_stream(engine, x_completion_capability, allocation, context,
                                         deadline, value, provider_auth), media_type='text/event-stream')
    except BaseException:
        allocation.release()
        raise
