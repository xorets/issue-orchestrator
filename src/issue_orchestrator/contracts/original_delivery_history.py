"""Bounded read-only proof input; all authority is independently revalidated."""
from pydantic import BaseModel, ConfigDict, Field


class Parent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    fence: str = Field(pattern=r'^[0-9a-f]{40}$')
    original_inner_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    engine_run_id: str = Field(pattern=r'^[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}$')
    head_sha: str = Field(pattern=r'^[0-9a-f]{40}$')


class Receipt(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    claim_ref_sha: str = Field(pattern=r'^[0-9a-f]{40}$')
    reserved_unix_ns: int = Field(gt=0)


class HistoryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    issue_number: int = Field(gt=0)
    parent: Parent
    expected_current_fence: str = Field(pattern=r'^[0-9a-f]{40}$')
    receipts: list[Receipt] = Field(max_length=256)
