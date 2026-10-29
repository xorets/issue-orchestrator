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


@router.post('/api/docker/model-gateway/responses')
async def model_gateway(  # noqa: C901, PLR0912 - bounded admission, cancellation and streaming share one allocation lifetime
                        request: Request, deps: ControlApiIssueDependency,
                        authorization: str = Header(...), x_completion_capability: str = Header(...)):
    from .control_api import verify_docker_callback_authorization
    if not verify_docker_callback_authorization(authorization):
        raise HTTPException(401, 'Docker callback authentication required')
    engine = deps.get_orchestrator()
    if engine is None:
        raise HTTPException(503, 'Docker model gateway unavailable')
    identity = sha256(x_completion_capability.encode()).hexdigest()
    with _lock:
        if identity in _active:
            raise HTTPException(429, 'Docker model request already active')
        _active.add(identity)
    transferred = False
    pending: set[asyncio.Task] = set()
    async def blocking(function, *args):
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        pending.add(task)
        task.add_done_callback(pending.discard)
        return await asyncio.shield(task)
    def release_when_settled():
        if pending:
            for task in tuple(pending):
                task.add_done_callback(lambda _: release_when_settled())
        else:
            with _lock:
                _active.discard(identity)
    try:
        # Validate ownership before reading a worker-controlled body or credentials.
        try:
            async with asyncio.timeout(10):
                context = await blocking(engine.docker_model_gateway_context, x_completion_capability)
        except TimeoutError as error:
            raise HTTPException(408, 'Docker model gateway authority deadline exhausted') from error
        except IntakeUnauthorized as error:
            raise HTTPException(401, 'Invalid active run capability') from error
        except (ValueError, OSError, KeyError, TypeError) as error:
            raise HTTPException(409, 'Docker model gateway authority unavailable') from error
        deadline = context.get('deadline_unix_ns')
        if type(deadline) is not int or deadline <= time.time_ns():
            raise HTTPException(409, 'Docker model gateway deadline unavailable')
        try:
            async with asyncio.timeout((deadline - time.time_ns()) / 1e9):
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
                try:
                    fresh = await blocking(engine.docker_model_gateway_context, x_completion_capability)
                except (IntakeUnauthorized, ValueError, OSError, KeyError, TypeError) as error:
                    raise HTTPException(409, 'Docker model gateway authority changed') from error
                if not _same_allocation(fresh, context):
                    raise HTTPException(409, 'Docker model gateway authority changed')
                context = fresh
                if context.get('grant_kind') not in {'builder-docker-container-model-authorization',
                        'builder-docker-container-synthetic-authorization'}:
                    raise HTTPException(409, 'Docker model grant kind unavailable')
                secret = await blocking(engine.docker_model_gateway_credentials)
                provider_auth = secret.get(MODEL_AUTH_ENV)
                instance_token = os.environ.get('ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN', '')
                if not isinstance(provider_auth, str):
                    raise HTTPException(503, 'Docker model authentication unavailable')
        except TimeoutError as error:
            raise HTTPException(408, 'Docker model gateway deadline exhausted') from error
        async def stream():
            iterator = forward_model_request(controller_home=str(context['controller_home']),
                instance_token=instance_token, context=context, request=value, provider_auth=provider_auth)
            next_chunk = None
            try:
                async with asyncio.timeout(max(0.0, (deadline - time.time_ns()) / 1e9)):
                    while True:
                        next_chunk = asyncio.ensure_future(anext(iterator))
                        while not next_chunk.done():
                            done, _ = await asyncio.wait({next_chunk}, timeout=0.5)
                            if done:
                                break
                            # Recheck live ownership even while upstream produces no bytes.
                            fresh = await blocking(engine.docker_model_gateway_context, x_completion_capability)
                            if not _same_allocation(fresh, context):
                                raise ValueError('Docker model gateway authority changed')
                        try:
                            chunk = next_chunk.result()
                        except StopAsyncIteration:
                            break
                        yield chunk
            finally:
                if next_chunk is not None and not next_chunk.done():
                    next_chunk.cancel()
                    try:
                        await next_chunk
                    except (asyncio.CancelledError, StopAsyncIteration):
                        pass
                await iterator.aclose()
                release_when_settled()
        response = StreamingResponse(stream(), media_type='text/event-stream')
        transferred = True
        return response
    finally:
        if not transferred:
            release_when_settled()
