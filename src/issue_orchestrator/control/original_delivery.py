"""One original owner admits corrections and reconciles ended handoffs."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..domain.claim import Claim, ClaimFetchError
from ..domain.models import OrchestratorState, PendingRework, Session, SessionKind
from ..domain.original_delivery import OriginalDelivery
from ..ports.original_delivery import OriginalDeliveryClaims
from ..ports.repository_host import RepositoryHost
from ..ports.working_copy import WorkingCopy
from .issue_termination import IssueTerminationOutcome

if TYPE_CHECKING:
    from ..infra.config import Config


@dataclass(frozen=True)
class OriginalDeliveryCommand:
    operation: str
    lease_id: str
    fence: str
    contract_sha256: str
    run_id: str
    request_id: str
    session_name: str = ""
    started_at: str = ""
    pr_number: int = 0
    head_sha: str = ""
    base_sha: str = ""
    feedback: str = ""


@dataclass
class OriginalDeliveryOwner:
    claims: OriginalDeliveryClaims
    repository: RepositoryHost
    working_copy: WorkingCopy | None
    config: Config
    state: OrchestratorState | None
    identity: Callable[[], tuple[str, int, str]]
    quiescent: Callable[[OriginalDelivery, bool], None]
    verify_contract: Callable[[OriginalDelivery], None]
    capture_processes: Callable[[OriginalDelivery], tuple[tuple[str, int, str, int, str], ...]]
    cycle_from_labels: Callable[[list[str]], int | None]
    verify_session: Callable[[Session], None]
    termination_scope: Callable[[OriginalDelivery, str], None]
    current_session: Callable[[Session], bool]
    launch: Callable[[PendingRework], Session | None] | None = None
    terminate: Callable[[int], IssueTerminationOutcome] | None = None
    retained_issues: set[int] = field(default_factory=set)

    def observe(self, issue_number: int) -> dict[str, object]:
        claim, fence = self.claims.original_claim(issue_number)
        if claim.original is not None:
            self._require_scope(claim.original)
        return {"issue_number": issue_number, "lease_id": claim.lease_id, "claimant": claim.claimant,
                "fence": fence, "lease_current": not claim.is_expired(),
                "expires_at": claim.expires_at.isoformat(),
                "owner": None if claim.original is None else claim.original.to_dict(),
                "remote_released": claim.original is not None and claim.original.released}

    def execute(self, issue_number: int, command: OriginalDeliveryCommand) -> dict[str, object]:
        claim, fence = self.claims.original_claim(issue_number)
        if claim.lease_id != command.lease_id or fence != command.fence:
            raise ValueError("Original owner or fence changed; observe before retry")
        if command.operation == "register":
            return self._register(issue_number, command, claim)
        owner = self._owner(claim, command)
        claim, fence, owner = self._record_remote_cancel(issue_number, claim, fence, owner)
        if command.operation in {"cancel", "reconcile"}:
            return self._terminal(issue_number, command, owner, claim, fence)
        if command.operation == "resume":
            return self._resume(issue_number, command, claim, fence, owner)
        self._require_live(owner, claim)
        if command.operation == "track":
            return self._track(issue_number, command, owner)
        if command.operation == "launch" and command.request_id in owner.launches:
            if command.request_id != owner.correction_id:
                raise ValueError("Original correction request is historical")
            return self.observe(issue_number)
        self.quiescent(owner, False)
        self._require_handoff(owner, command)
        if command.operation == "launch":
            return self._launch(issue_number, command, owner)
        return self._mutate_handoff(issue_number, command, claim, fence)

    def _mutate_handoff(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim,
                        fence: str) -> dict[str, object]:
        if command.operation not in {"handoff", "correct"}:
            raise ValueError("Unsupported original operation")
        changed = self.claims.transition_original(issue_number, claim.lease_id, fence, command.operation,
            request_id=command.request_id, pr_number=command.pr_number, head_sha=command.head_sha,
            base_sha=command.base_sha, feedback=command.feedback)
        if changed is None:
            raise ValueError("Original fence changed before admission")
        return self.observe(issue_number)

    def _owner(self, claim: Claim, command: OriginalDeliveryCommand) -> OriginalDelivery:
        owner = claim.original
        if owner is None:
            raise ValueError("Original published owner is unknown")
        self._require_scope(owner)
        if (owner.run_id, owner.contract_sha256) != (command.run_id, command.contract_sha256):
            raise ValueError("Original run or contract changed")
        return owner

    def _record_remote_cancel(self, issue_number: int, claim: Claim, fence: str,
                              owner: OriginalDelivery) -> tuple[Claim, str, OriginalDelivery]:
        issue = self.repository.get_issue(issue_number)
        if issue is None:
            raise ClaimFetchError("Original Issue is unreadable")
        if "dispatch:cancel-requested" in issue.labels and not owner.cancelled:
            cancelled = self.claims.transition_original(issue_number, claim.lease_id, fence, "cancel", request_id="remote-cancellation-intent")
            if cancelled is None:
                raise ValueError("Original fence changed while recording cancellation")
            claim, fence = self.claims.original_claim(issue_number)
            assert claim.original is not None
            owner = claim.original
        return claim, fence, owner

    def _require_live(self, owner: OriginalDelivery, claim: Claim) -> None:
        if owner.cancelled or owner.released or claim.is_expired():
            raise ValueError("Original owner is cancelled, released or expired")
        if self.state is None or self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
            raise ValueError("Correction requires the current original engine; resume explicitly after restart")
        self.verify_contract(owner)

    def _launch(self, issue_number: int, command: OriginalDeliveryCommand, owner: OriginalDelivery) -> dict[str, object]:
        if owner.correction_id != command.request_id or not owner.pending or self.launch is None:
            raise ValueError("No current original correction admission")
        issue = self.repository.get_issue(issue_number)
        if issue is None or "dispatch:cancel-requested" in issue.labels:
            raise ValueError("Original correction cancelled or Issue unreadable before launch")
        session = self.launch(PendingRework(issue_key=issue.key, agent_type=owner.agent,
            issue_number=issue_number, pr_number=owner.pr_number, rework_cycle=owner.cycles,
            source="original-owner:" + owner.correction_id, feedback=owner.feedback))
        if session is None:
            raise ValueError("Admitted original correction did not launch; observe consumed reservation before retry")
        self.verify_session(session)
        claim, fence = self.claims.original_claim(issue_number)
        assert claim.original is not None
        roots = self.capture_processes(claim.original)
        if not roots or not self.claims.bind_original_processes(issue_number, claim.lease_id, fence, roots):
            raise ValueError("Correction process custody unproven; observe exact admitted run before retry")
        return self.observe(issue_number)

    def _track(self, issue_number: int, command: OriginalDeliveryCommand, owner: OriginalDelivery) -> dict[str, object]:
        if self.state is None:
            raise ValueError("Current native session is unavailable")
        sessions = [s for s in self.state.active_sessions if s.issue.number == issue_number]
        runs = {(row[1], row[3], row[4]) for row in owner.correction_runs if row[0] == command.request_id}
        if len(sessions) != 1 or (sessions[0].run_assets.run_id, sessions[0].terminal_id,
                sessions[0].run_assets.started_at) not in runs:
            raise ValueError("Current correction native run changed")
        self.verify_session(sessions[0])
        roots = self.capture_processes(owner)
        if not roots or not self.claims.bind_original_processes(issue_number, command.lease_id, command.fence, roots):
            raise ValueError("Current correction process fence changed")
        return self.observe(issue_number)

    def _register(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim) -> dict[str, object]:
        if self.state is None or not self.state.paused or str(self.state.pause_state.reason) != "operator":
            raise ValueError("Original engine requires current OPERATOR hold")
        sessions = [s for s in self.state.active_sessions if s.issue.number == issue_number]
        if len(sessions) != 1:
            raise ValueError("One current original session is required")
        session = sessions[0]
        if not self.current_session(session):
            raise ValueError("Current original native worker is not owned by the session runner")
        self.verify_session(session)
        run = session.run_assets
        if (run.run_id, session.terminal_id, run.started_at, session.lease_id) != (
                command.run_id, command.session_name, command.started_at, command.lease_id):
            raise ValueError("Original session identity changed")
        if session.key.kind is not SessionKind.CODE or session.rework_cycle:
            raise ValueError("Original session does not own initial implementation custody")
        if claim.is_expired():
            raise ValueError("Original lease is expired")
        if claim.original is not None:
            self._require_live(self._owner(claim, command), claim)
            self.retained_issues.add(issue_number)
            return self.observe(issue_number)
        self._require_unused_budget(issue_number)
        host, pid, birth = self.identity()
        owner = OriginalDelivery(repository=str(self.config.repo), config_fingerprint=self.config.config_fingerprint,
            contract_sha256=command.contract_sha256, run_id=run.run_id, session_name=session.terminal_id, native_phase_name=run.identity.session_name, logical_child=session.key.stable_id(),
            started_at=run.started_at, branch=session.branch_name, worktree=str(run.worktree_path),
            run_dir=str(run.run_dir), agent=session.agent_label or session.issue.agent_type or "", engine_host=host, engine_pid=pid,
            engine_birth=birth, max_cycles=self.config.max_rework_cycles)
        self.verify_contract(owner)
        roots = self.capture_processes(owner)
        if not roots:
            raise ValueError("Current original worker process custody is unavailable")
        owner = replace(owner, process_roots=roots)
        if not self.claims.bind_original(issue_number, claim.lease_id, command.fence, owner):
            raise ValueError("Original registration fence changed")
        self.retained_issues.add(issue_number)
        return self.observe(issue_number)

    def _require_unused_budget(self, issue_number: int) -> None:
        issue = self.repository.get_issue(issue_number)
        if issue is None or "dispatch:cancel-requested" in issue.labels:
            raise ValueError("Original registration cancelled or Issue unreadable")
        labels = [issue.labels, *(pr.labels for pr in self.repository.get_prs_for_issue(issue_number))]
        if any(self.cycle_from_labels(list(items)) for items in labels):
            raise ValueError("An existing rework budget cannot be reset by original registration")

    def _require_scope(self, owner: OriginalDelivery) -> None:
        if (owner.repository, owner.config_fingerprint) != (self.config.repo, self.config.config_fingerprint):
            raise ValueError("Original repository or configuration changed")

    def _require_handoff(self, owner: OriginalDelivery, command: OriginalDeliveryCommand) -> None:
        pr = self.repository.get_pr(command.pr_number)
        if pr is None or pr.state != "open" or pr.branch != owner.branch or pr.head_sha != command.head_sha:
            raise ValueError("Original published PR/head changed")
        if not command.base_sha or pr.base_sha != command.base_sha:
            raise ValueError("Original published base changed")
        if command.operation != "handoff" and owner.pr_number and (owner.pr_number, owner.head_sha, owner.base_sha) != (
                command.pr_number, command.head_sha, command.base_sha):
            raise ValueError("Current original handoff changed")
        if self.working_copy is None:
            raise ValueError("Original Git observation capability is unavailable")
        worktree = Path(owner.worktree)
        if self.working_copy.get_head_sha(worktree) != command.head_sha or self.working_copy.has_uncommitted_changes(worktree):
            raise ValueError("Original workspace contains unpublished work")

    def _resume(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim,
                fence: str, owner: OriginalDelivery) -> dict[str, object]:
        if self.state is None or owner.cancelled or owner.released:
            raise ValueError("Original restart custody is unavailable or cancelled")
        self.verify_contract(owner)
        if self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
            self.quiescent(owner, True)
            if not self.claims.resume_original(issue_number, claim.lease_id, fence, self.identity()):
                raise ValueError("Original restart fence changed")
        self.retained_issues.add(issue_number)
        return self.observe(issue_number)

    def _terminal(self, issue_number: int, command: OriginalDeliveryCommand, owner: OriginalDelivery,
                  claim: Claim, fence: str) -> dict[str, object]:
        if command.operation == "cancel" and not owner.cancelled:
            if self.claims.transition_original(issue_number, claim.lease_id, fence, "cancel", request_id=command.request_id) is None:
                raise ValueError("Original cancellation fence changed")
            claim, fence = self.claims.original_claim(issue_number)
            assert claim.original is not None
            owner = claim.original
        if self.state is not None and self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
            raise ValueError("Terminal reconciliation requires the original engine or offline custody proof")
        if self.state is not None and any(s.issue.number == issue_number for s in self.state.active_sessions):
            for session in self.state.active_sessions:
                if session.issue.number == issue_number:
                    self.verify_session(session)
                    self.termination_scope(owner, session.run_assets.run_id)
            if self.terminate is None:
                raise ValueError("Original termination capability is unavailable")
            if not self.terminate(issue_number).complete:
                raise ValueError("Original termination is incomplete; remote claim retained")
        self.quiescent(owner, self.state is None)
        if self.claims.transition_original(issue_number, claim.lease_id, fence, "reconcile", request_id=command.request_id) is None:
            raise ValueError("Original terminal fence changed")
        self.retained_issues.discard(issue_number)
        return self.observe(issue_number)

    def renew_retained(self) -> None:
        """Renew only this process's explicitly bound custody; the remote cell decides.

        The set is a transient enumeration cache, never authority or a budget.
        A restarted engine must publicly resume the exact original fence first.
        """
        for issue_number in tuple(self.retained_issues):
            claim, _ = self.claims.original_claim(issue_number)
            owner = claim.original
            if owner is None or owner.released or owner.cancelled:
                continue
            if (claim.expires_at - datetime.now()).total_seconds() > self.config.claims.lease_seconds / 2:
                continue
            if self.identity() == (owner.engine_host, owner.engine_pid, owner.engine_birth):
                if not self.claims.renew_claim(issue_number, claim.lease_id):
                    raise ClaimFetchError("Original retained lease renewal was not acknowledged")
