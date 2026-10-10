"""Original remote claim custody and its one bounded correction budget."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import re


@dataclass(frozen=True, slots=True)
class OriginalDelivery:
    repository: str
    config_fingerprint: str
    contract_sha256: str
    run_id: str
    session_name: str
    native_phase_name: str
    logical_child: str
    started_at: str
    branch: str
    worktree: str
    run_dir: str
    agent: str
    engine_host: str
    engine_pid: int
    engine_birth: str
    max_cycles: int
    cycles: int = 0
    pr_number: int = 0
    base_sha: str = ""
    head_sha: str = ""
    correction_id: str = ""
    feedback: str = ""
    corrections: tuple[tuple[str, str, int], ...] = ()
    launches: tuple[str, ...] = ()
    correction_runs: tuple[tuple[str, str, str, str, str, str], ...] = ()
    engine_history: tuple[tuple[str, int, str], ...] = ()
    process_roots: tuple[tuple[str, int, str, int, str], ...] = ()
    pending: bool = False
    cancelled: bool = False
    released: bool = False

    def __post_init__(self) -> None:
        self._validate_identity()
        self._validate_history()
        for name in ("head_sha", "base_sha"):
            value = getattr(self, name)
            if type(value) is not str or value and not re.fullmatch(r"[0-9a-f]{40}", value):
                raise ValueError(f"published {name} is invalid")
        if type(self.feedback) is not str or type(self.correction_id) is not str:
            raise ValueError("original correction fields must be text")

    def _validate_identity(self) -> None:
        for name in ("repository", "config_fingerprint", "contract_sha256", "run_id", "session_name",
                     "native_phase_name", "logical_child", "started_at", "branch", "worktree", "run_dir", "agent", "engine_host", "engine_birth"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"original delivery requires {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", self.contract_sha256):
            raise ValueError("contract SHA256 is invalid")
        for name in ("engine_pid", "max_cycles", "cycles", "pr_number"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"original delivery {name} must be a non-negative integer")
        if self.engine_pid == 0 or self.cycles > self.max_cycles:
            raise ValueError("invalid original process or correction budget")
        if any(type(getattr(self, name)) is not bool for name in ("pending", "cancelled", "released")):
            raise ValueError("original delivery intent must be boolean")

    def _validate_history(self) -> None:
        _require_rows(self.process_roots, (str, int, str, int, str), "process roots")
        _require_rows(self.engine_history, (str, int, str), "engine history")
        _require_rows(self.corrections, (str, str, int), "corrections")
        _require_rows(self.correction_runs, (str, str, str, str, str, str), "correction runs")
        ids = tuple(item[0] for item in self.corrections)
        if len(ids) != self.cycles or len(set(ids)) != self.cycles:
            raise ValueError("original correction history does not match its budget")
        if tuple(item[2] for item in self.corrections) != tuple(range(1, self.cycles + 1)):
            raise ValueError("original correction cycles are invalid")
        if type(self.launches) is not tuple or any(type(item) is not str for item in self.launches):
            raise ValueError("original launches must be text")
        if len(set(self.launches)) != len(self.launches) or not set(self.launches) <= set(ids):
            raise ValueError("original launches do not match admitted requests")
        run_ids = tuple(item[0] for item in self.correction_runs)
        if len(set(run_ids)) != len(run_ids) or not set(run_ids) <= set(self.launches):
            raise ValueError("original correction runs do not match launch reservations")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> OriginalDelivery:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("original delivery field set is invalid")
        decoded = dict(value)
        for field in ("corrections", "correction_runs", "launches", "engine_history", "process_roots"):
            if type(decoded[field]) not in {list, tuple}:
                raise ValueError("original correction history must be a sequence")
            decoded[field] = tuple(decoded[field]) if field == "launches" else tuple(
                tuple(item) if type(item) in {list, tuple} else item for item in decoded[field])
        return cls(**decoded)


def _require_rows(value: object, types: tuple[type, ...], name: str) -> None:
    if type(value) is not tuple or any(type(row) is not tuple or len(row) != len(types) or
            any(type(item) is not kind for item, kind in zip(row, types, strict=True)) for row in value):
        raise ValueError(f"original {name} history is invalid")


def _correct(owner: OriginalDelivery, request_id: str, feedback: str) -> OriginalDelivery:
    for admitted_id, admitted_feedback, _ in owner.corrections:
        if admitted_id == request_id:
            if admitted_feedback != feedback:
                raise ValueError("correction request identity changed")
            return owner
    if owner.pending:
        raise ValueError("an original correction is pending handoff")
    if owner.cycles >= owner.max_cycles:
        raise ValueError("original correction budget exhausted")
    if not owner.pr_number or not owner.head_sha:
        raise ValueError("original published handoff is unknown")
    if type(feedback) is not str or not feedback.strip() or len(feedback.encode()) > 65536:
        raise ValueError("bounded correction findings are required")
    return replace(owner, cycles=owner.cycles + 1, correction_id=request_id, feedback=feedback,
        pending=True, corrections=(*owner.corrections, (request_id, feedback, owner.cycles + 1)))


def _handoff(owner: OriginalDelivery, pr_number: int, head_sha: str, base_sha: str) -> OriginalDelivery:
    if type(pr_number) is not int or pr_number <= 0 or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("an exact published PR/head is required")
    if owner.pending and owner.correction_id not in {row[0] for row in owner.correction_runs}:
        raise ValueError("original correction run handoff is unknown")
    return replace(owner, pr_number=pr_number, head_sha=head_sha, base_sha=base_sha, pending=False)


def transition(owner: OriginalDelivery, operation: str, *, request_id: str,
               pr_number: int = 0, head_sha: str = "", base_sha: str = "", feedback: str = "") -> OriginalDelivery:
    """Pure policy; the claim store commits this transition with its original fence."""
    if type(request_id) is not str or not request_id.strip() or len(request_id) > 256:
        raise ValueError("a bounded request id is required")
    if owner.released:
        if operation == "reconcile":
            return owner
        raise ValueError("original owner has been released")
    if operation in {"cancel", "reconcile"}:
        return replace(owner, **{ "cancelled" if operation == "cancel" else "released": True})
    if owner.cancelled:
        raise ValueError("original delivery is cancelled")
    if operation == "handoff":
        return _handoff(owner, pr_number, head_sha, base_sha)
    if operation == "correct":
        return _correct(owner, request_id, feedback)
    if operation == "launch" and owner.pending and request_id == owner.correction_id:
        return owner if request_id in owner.launches else replace(owner, launches=(*owner.launches, request_id))
    raise ValueError("unsupported original delivery operation")


def bind_correction_run(owner: OriginalDelivery, request_id: str, run_id: str, run_dir: str,
                        session_name: str, started_at: str, native_phase_name: str) -> OriginalDelivery:
    row = (request_id, run_id, run_dir, session_name, started_at, native_phase_name)
    if owner.cancelled or owner.released or not owner.pending or request_id != owner.correction_id:
        raise ValueError("original correction run binding refused")
    if request_id not in owner.launches or any(not value for value in row):
        raise ValueError("original launch reservation is unknown")
    existing = next((item for item in owner.correction_runs if item[0] == request_id), None)
    if existing is not None:
        if existing != row:
            raise ValueError("original correction run changed")
        return owner
    return replace(owner, correction_runs=(*owner.correction_runs, row))
