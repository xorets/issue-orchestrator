"""Typed MCP encoding for the original owner's live and offline public boundary."""
import json
import logging
from pathlib import Path

from mcp.types import CallToolResult, TextContent

from ..contracts.original_delivery import OriginalDeliveryRequest
from ..contracts.ui_openapi_models import OriginalDeliveryPayload
from ..domain.claim import ClaimFetchError
from ..domain.original_delivery import OriginalDeliveryOperation
from ..execution.orchestrator_http_api import OrchestratorAsyncHttpApi
from ..infra.config import Config
from .bootstrap_original_delivery import build_offline_original_delivery_owner

logger = logging.getLogger(__name__)


async def original_delivery_result(api: OrchestratorAsyncHttpApi, config_path: Path,
                                   issue_number: int, operation: str,
                                   payload: OriginalDeliveryRequest | None, *, running: bool) -> CallToolResult:
    try:
        if type(issue_number) is not int or issue_number <= 0:
            raise ValueError("A positive original Issue is required")
        if operation != "observe":
            OriginalDeliveryOperation(operation)
        request = None if operation == "observe" else OriginalDeliveryRequest.model_validate(payload)
        if running:
            observed = await api.original_delivery(issue_number, operation,
                None if request is None else request.model_dump())
        else:
            if operation not in {"observe", "cancel", "reconcile"}:
                raise ValueError("An inactive engine permits only original terminal reconciliation")
            with build_offline_original_delivery_owner(Config.load(config_path)) as owner:
                observed = owner.observe(issue_number) if request is None else owner.execute(issue_number, request.command(operation))
        result = OriginalDeliveryPayload.model_validate(observed).model_dump(mode="json", exclude_unset=True)
    except (ValueError, ClaimFetchError, OSError, RuntimeError) as exc:
        logger.exception("MCP original delivery command refused")
        return CallToolResult(content=[TextContent(type="text", text=str(exc))], isError=True)
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))], structuredContent=result)


async def original_delivery_history_result(config_path: Path, request) -> CallToolResult:
    """Read selected claim history using the existing repository-scoped owner."""
    import asyncio
    from ..control.original_delivery_history import prove_history

    def read():
        with build_offline_original_delivery_owner(Config.load(config_path)) as owner:
            repository = owner.config.repo
            if not repository:
                raise ValueError('Original delivery repository is unavailable')
            return prove_history(owner.claims, repository, request.model_dump(mode='json'))

    try:
        result = await asyncio.to_thread(read)
    except (ValueError, ClaimFetchError, OSError, RuntimeError):
        logger.warning('MCP original delivery history refused')
        return CallToolResult(content=[TextContent(type='text', text='Original delivery history refused')], isError=True)
    return CallToolResult(content=[TextContent(type='text', text=json.dumps(result))], structuredContent=result)
