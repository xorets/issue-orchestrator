"""Strict public original-owner commands; authority comes from engine observations."""
from pydantic import BaseModel, ConfigDict, Field
from ..control.original_delivery import OriginalDeliveryCommand


class OriginalDeliveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    lease_id: str = Field(min_length=1, max_length=256)
    fence: str = Field(min_length=1, max_length=256)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=256)
    session_name: str = Field(default="", max_length=256)
    started_at: str = Field(default="", max_length=256)
    pr_number: int = Field(default=0, ge=0)
    head_sha: str = Field(default="", max_length=40)
    base_sha: str = Field(default="", max_length=40)
    feedback: str = Field(default="", max_length=65536)

    def command(self, operation: str) -> OriginalDeliveryCommand:
        return OriginalDeliveryCommand(operation=operation, **self.model_dump())
