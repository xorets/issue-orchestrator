"""Typed MCP encoding for the original owner's live and offline public boundary."""
import json
import logging
from pathlib import Path

from mcp.types import CallToolResult, TextContent

from ..contracts.original_delivery import OriginalDeliveryRequest
from ..contracts.ui_openapi_models import OriginalDeliveryPayload
from ..domain.claim import ClaimFetchError
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
        request = None if operation == "observe" else OriginalDeliveryRequest.model_validate(payload)
        if running:
            observed = await api.original_delivery(issue_number, operation,
                None if request is None else request.model_dump())
        else:
            if operation not in {"observe", "cancel", "reconcile"}:
                raise ValueError("An inactive engine permits only original terminal reconciliation")
            with build_offline_original_delivery_owner(Config.load(config_path)) as owner:
                observed = owner.observe(issue_number) if request is None else owner.execute(issue_number, request.command(operation))
        result = OriginalDeliveryPayload.model_validate(observed).model_dump(mode="json")
    except (ValueError, ClaimFetchError, OSError, RuntimeError) as exc:
        logger.exception("MCP original delivery command refused")
        return CallToolResult(content=[TextContent(type="text", text=str(exc))], isError=True)
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))], structuredContent=result)
