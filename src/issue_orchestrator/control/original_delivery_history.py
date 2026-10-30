"""Read-only renewal-history proof for a sealed original review parent."""
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import time
from typing import Any

from ..domain.claim import Claim
from ..ports.original_delivery import OriginalDeliveryClaimHistory


def require_expiry_only(anchor: Claim, candidate: Claim) -> None:
    if replace(candidate, expires_at=anchor.expires_at) != anchor or candidate.expires_at < anchor.expires_at:
        raise ValueError('Docker REVIEW permits only the selected lease expiry renewal')


def _unix_ns(value: datetime) -> int:
    """Claims use UTC; avoid float rounding at the reservation boundary."""
    utc = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    delta = utc - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def prove_history(claims: object, repository: str, request: dict[str, Any]) -> dict[str, str]:
    """Compare full historical claims and re-observe the selected current ref."""
    if not isinstance(claims, OriginalDeliveryClaimHistory):
        raise ValueError('Docker REVIEW requires authenticated selection-anchor history')
    issue = request['issue_number']
    parent = request['parent']
    current, fence = claims.original_claim(issue)
    if fence != request['expected_current_fence']:
        raise ValueError('Docker review current fence changed')
    anchor = claims.original_claim_at(issue, parent['fence'])
    require_expiry_only(anchor, current)
    owner = current.original
    if (owner is None or owner.execution_backend != 'docker' or owner.repository != repository or
            owner.contract_sha256 != parent['original_inner_sha256'] or owner.run_id != parent['engine_run_id'] or
            current.is_expired() or owner.cancelled or owner.released or owner.pending):
        raise ValueError('Docker review original parent changed')
    previous_expiry = anchor.expires_at
    previous_time = 0
    for receipt in request['receipts']:
        claim = claims.original_claim_at(issue, receipt['claim_ref_sha'])
        require_expiry_only(anchor, claim)
        reserved = receipt['reserved_unix_ns']
        if (reserved < previous_time or reserved < _unix_ns(claim.started_at) or reserved > time.time_ns() or
                claim.expires_at < previous_expiry or reserved >= _unix_ns(claim.expires_at)):
            raise ValueError('Docker review receipt chronology differs')
        previous_time, previous_expiry = reserved, claim.expires_at
    if current.expires_at < previous_expiry:
        raise ValueError('Docker review current lease predates receipt')
    final, final_fence = claims.original_claim(issue)
    if final_fence != fence or final != current or final.is_expired():
        raise ValueError('Docker review current fence changed')
    raw = (json.dumps(request, sort_keys=True, indent=2) + '\n').encode()
    return {'status': 'PASS', 'current_fence': fence, 'subject_sha256': sha256(raw).hexdigest()}
