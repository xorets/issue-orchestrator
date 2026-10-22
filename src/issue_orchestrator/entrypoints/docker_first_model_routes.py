"""Exact dual-auth Docker CODE first-model parent proof; no admin operations."""
from typing import Literal
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from ..contracts.ui_openapi_models import OriginalDeliveryPayload
from ..control.original_delivery import DockerFirstModelCommand
from ..domain.completion_intake import IntakeUnauthorized
from .control_api_issue_support import ControlApiIssueDependency

class FirstModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(pattern=r"^[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

class FirstModelWorker(BaseModel):
    model_config = ConfigDict(extra="forbid")
    daemon_id: str
    controller_container_id: str
    container_id: str
    provider_exec_id: str
    image_id: str
    running: Literal[True]
    paused: Literal[False]
    restarting: Literal[False]
    oom_killed: Literal[False]
    restart_count: Literal[0]
    provider_running: Literal[True]
    provider_exit_code: None

class FirstModelBarrier(BaseModel):
    model_config = ConfigDict(extra="forbid")
    paused: Literal[True]
    pause_reason: Literal["operator"]

class FirstModelReviewParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    kind: Literal['builder-docker-review-parent']
    subject_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    head_sha: str = Field(pattern=r'^[0-9a-f]{40}$')
    reviewer_authority_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_outer_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    original_inner_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    builder_run_id: str = Field(pattern=r'^run-[0-9a-f]{32}$')
    engine_run_id: str = Field(pattern=r'^[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}$')
    fence: str = Field(pattern=r'^[0-9a-f]{40}$')

class FirstModelReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    kind: Literal["builder-docker-first-model-receipt"]
    run_id: str
    builder_run_id: str
    contract_sha256: str
    outer_sha256: str
    launch_sha256: str
    projection_sha256: str
    observed_unix_ns: int
    original_delivery: OriginalDeliveryPayload
    claim_ref_sha: str
    worker: FirstModelWorker
    barrier: FirstModelBarrier
    review_parent: FirstModelReviewParent | None = None

class FirstModelEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    sha256: str

class FirstModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    kind: Literal["builder-docker-first-model"]
    receipt: FirstModelReceipt
    controller_evidence: FirstModelEvidence

docker_first_model_router = APIRouter()

@docker_first_model_router.post("/api/docker/first-model", response_model=FirstModelResponse, response_model_exclude_unset=True)
def first_model(body: FirstModelRequest, deps: ControlApiIssueDependency,
                authorization: str = Header(...), x_completion_capability: str = Header(...)) -> FirstModelResponse:
    from .control_api import verify_docker_callback_authorization
    if not verify_docker_callback_authorization(authorization):
        raise HTTPException(401, "Docker callback authentication required")
    engine = deps.get_orchestrator()
    if engine is None:
        raise HTTPException(503, "Docker first-model engine unavailable")
    try:
        result = engine.docker_first_model(x_completion_capability,
            DockerFirstModelCommand(body.run_id, body.contract_sha256, body.launch_sha256))
        return FirstModelResponse.model_validate(result)
    except IntakeUnauthorized as error:
        raise HTTPException(401, "Invalid active run capability") from error
    except (ValueError, OSError) as error:
        raise HTTPException(409, "Docker first-model original custody unavailable") from error
