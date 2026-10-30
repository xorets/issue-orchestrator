"""One original owner admits corrections and reconciles ended handoffs."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..domain.claim import Claim, ClaimFetchError
from ..domain.models import OrchestratorState, PendingRework, Session
from ..domain.original_delivery import OriginalDelivery, OriginalDeliveryOperation
from ..infra.runtime_artifacts import builtin_cleanup_root
from ..ports.original_delivery import OriginalDeliveryClaims, OriginalDeliveryClaimHistory
from ..ports.original_docker_custody import OriginalDockerCustody
from ..ports.repository_host import RepositoryHost
from ..ports.working_copy import WorkingCopy
from ..domain.session_run import SessionRunAssets
from uuid import uuid4
import re
import time
from .original_delivery_history import require_expiry_only
from .issue_termination import IssueTerminationOutcome
from .pause_facade import require_model_preflight_barrier, require_operator_barrier

if TYPE_CHECKING:
    from ..infra.config import Config


class ModelGatewayGrantUnavailable(ValueError):
    """The active allocation does not carry a supported model grant."""


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

    def __post_init__(self) -> None:
        OriginalDeliveryOperation(self.operation)


@dataclass(frozen=True)
class DockerFirstModelCommand:
    run_id: str
    contract_sha256: str
    launch_sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}", self.run_id):
            raise ValueError("Docker first-model run is invalid")
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (self.contract_sha256, self.launch_sha256)):
            raise ValueError("Docker first-model digest is invalid")


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
    docker_custody: OriginalDockerCustody | None = None

    def first_model(self, run: SessionRunAssets, command: DockerFirstModelCommand) -> dict[str, object]:
        """Bind CODE or a distinct REVIEW allocation through its selected root authority."""
        require_operator_barrier(self.state)
        session,snapshot = self.first_model_preflight(run, command)
        reviewing = session.key.kind.capabilities.reports_verdict
        if reviewing:
            if snapshot.get('role') != 'standard-review':
                raise ValueError('Docker review requires separate reviewer authority')
            original = self._review_original(session, snapshot)
        else:
            if snapshot.get('role') != 'standard-implementation':
                raise ValueError('Docker CODE cannot reuse reviewer authority')
            original = self._first_model_original(session, command, snapshot)
        # Recheck the live daemon after registration and before producing evidence.
        if self.docker_custody.first_model_snapshot(session, command.contract_sha256, command.launch_sha256) != snapshot:
            raise ValueError("Docker first-model custody changed during registration")
        current = self._review_original(session, snapshot) if reviewing else self.observe(session.issue.number, include_diagnostic=False)
        if reviewing:
            original = current  # Both reads independently authenticated only expiry renewal from the anchor.
        elif current != original:
            raise ValueError("Docker first-model original fence changed during observation")
        receipt = {"schema_version": 1, "kind": "builder-docker-first-model-receipt", "run_id": run.run_id,
            "builder_run_id": snapshot["builder_run_id"], "contract_sha256": command.contract_sha256,
            "outer_sha256": snapshot["outer_sha256"], "launch_sha256": command.launch_sha256,
            "projection_sha256": snapshot["projection_sha256"], "observed_unix_ns": time.time_ns(),
            "original_delivery": original, "claim_ref_sha": original["fence"], "worker": snapshot["worker"],
            "barrier": {"paused": True, "pause_reason": "operator"}}
        if reviewing:
            receipt['review_parent'] = snapshot['review_parent']
        evidence = self.docker_custody.seal_first_model(session, receipt)
        return {"schema_version": 1, "kind": "builder-docker-first-model", "receipt": receipt, "controller_evidence": evidence}

    def model_gateway_context(self, run: SessionRunAssets, previous: dict[str, object] | None = None) -> dict[str, object]:
        """Bind a live allocated Docker request without creating or resuming a hold."""
        require_model_preflight_barrier(self.state)
        if self.docker_custody is None or self.config.terminal_adapter != "issue_orchestrator.execution.terminal_docker:DockerPlugin":
            raise ValueError("Docker model gateway custody unavailable")
        assert self.state is not None
        sessions = [session for session in self.state.active_sessions if session.run_assets == run]
        if len(sessions) != 1:
            raise ValueError("Docker model gateway allocation unavailable")
        session = sessions[0]
        snapshot = self.docker_custody.model_gateway_snapshot(session)
        if snapshot['engine_run_id'] != run.run_id:
            raise ValueError("Docker model gateway allocation changed")
        if session.key.kind.capabilities.reports_verdict:
            if snapshot['role'] != 'standard-review':
                raise ValueError("Docker model gateway review role differs")
            original = self._review_original(session, snapshot)
        else:
            if not session.key.kind.capabilities.open_pr_means_done or session.rework_cycle or snapshot['role'] != 'standard-implementation':
                raise ValueError("Docker model gateway role differs")
            original = self.observe(session.issue.number, include_diagnostic=False)
            owner = original['owner']
            if (not isinstance(owner, dict) or owner['run_id'] != run.run_id or
                    owner['contract_sha256'] != snapshot['contract_sha256'] or owner['cancelled'] or owner['released'] or
                    not original['lease_current'] or original['lease_id'] != session.lease_id or
                    tuple(owner['docker_custody']) != (snapshot['custody'],)):
                raise ValueError("Docker model gateway original claim or custody differs")
        if self.docker_custody.model_gateway_snapshot(session) != snapshot:
            raise ValueError("Docker model gateway custody changed during validation")
        again = self._review_original(session, snapshot) if session.key.kind.capabilities.reports_verdict else self.observe(session.issue.number, include_diagnostic=False)
        if again != original:
            raise ValueError("Docker model gateway claim changed during validation")
        worker = snapshot['worker']
        keys = ('engine_run_id','builder_run_id','role','model','contract_sha256','outer_sha256','launch_sha256',
                'projection_sha256','grant_sha256','grant_kind','deadline_unix_ns','max_model_requests','max_output_bytes',
                'outer_contract_path','inner_contract_path','launch_path','controller_home')
        context = {**{key:snapshot[key] for key in keys}, 'issue_number':session.issue.number,
                'claim_ref_sha':original['fence'], **{key:worker[key] for key in
                    ('daemon_id','container_id','provider_exec_id','image_id')}}
        return self.admit_model_gateway_context(context, previous)

    @staticmethod
    def admit_model_gateway_context(context: dict[str, object], previous: dict[str, object] | None) -> dict[str, object]:
        if previous is not None and {k: v for k, v in context.items() if k != 'claim_ref_sha'} != {
                k: v for k, v in previous.items() if k != 'claim_ref_sha'}:
            raise ValueError('Docker model gateway authority changed')
        if previous is not None and context.get('grant_kind') not in {'builder-docker-container-model-authorization',
                'builder-docker-container-synthetic-authorization'}:
            raise ModelGatewayGrantUnavailable('Docker model grant kind unavailable')
        return context

    def first_model_preflight(self, run: SessionRunAssets, command: DockerFirstModelCommand) -> tuple[Session, dict[str, Any]]:
        """Only the exact active admitted allocation may request its fixed planner barrier."""
        require_model_preflight_barrier(self.state)
        if self.docker_custody is None or self.config.terminal_adapter != "issue_orchestrator.execution.terminal_docker:DockerPlugin":
            raise ValueError("Docker first-model requires the selected custody adapter")
        assert self.state is not None
        sessions = [session for session in self.state.active_sessions if session.run_assets == run]
        if len(sessions) != 1 or run.run_id != command.run_id:
            raise ValueError("Docker first-model allocation is not the active original session")
        session = sessions[0]
        reviewing = session.key.kind.capabilities.reports_verdict
        if (not reviewing and not session.key.kind.capabilities.open_pr_means_done) or session.rework_cycle:
            raise ValueError("Docker first-model requires selected CODE or REVIEW authority")
        # Missing/stale/foreign runtime custody fails BEFORE original registration.
        snapshot = self.docker_custody.first_model_snapshot(session, command.contract_sha256, command.launch_sha256)
        if reviewing:
            if snapshot.get('role') != 'standard-review':
                raise ValueError('Docker review requires separate reviewer authority')
            self._review_original(session, snapshot)
        else:
            if snapshot.get('role') != 'standard-implementation':
                raise ValueError('Docker CODE cannot reuse reviewer authority')
            observed = self.observe(session.issue.number)
            owner = observed['owner']
            if observed['lease_id'] != session.lease_id or not observed['lease_current'] or owner is not None and (
                    not isinstance(owner, dict) or owner['run_id'] != run.run_id or owner['contract_sha256'] != command.contract_sha256 or
                    owner['cancelled'] or owner['released']):
                raise ValueError('Docker preflight original owner/fence unavailable')
        return session,snapshot

    def _first_model_original(self, session: Session, command: DockerFirstModelCommand, snapshot: dict[str, Any]) -> dict[str, object]:
        run = session.run_assets
        observed = self.observe(session.issue.number)
        if observed["owner"] is None:
            self.execute(session.issue.number, OriginalDeliveryCommand("register", str(observed["lease_id"]),
                str(observed["fence"]), command.contract_sha256, command.run_id,
                "docker-first-model-" + uuid4().hex, session_name=session.terminal_id, started_at=run.started_at))
        original = self.observe(session.issue.number, include_diagnostic=False)
        owner = original["owner"]
        if (not isinstance(owner, dict) or owner["run_id"] != run.run_id or
                owner["contract_sha256"] != command.contract_sha256 or owner["cancelled"] or owner["released"] or
                not original["lease_current"] or tuple(owner["docker_custody"]) != (snapshot["custody"],)):
            raise ValueError("Docker first-model original owner/fence changed")
        return original

    def _review_original(self, session: Session, snapshot: dict[str, Any]) -> dict[str, object]:
        """Observe a separate granted parent without current-config/engine substitution."""
        parent, inner = snapshot['review_parent'], snapshot['original_inner']
        if not isinstance(self.claims, OriginalDeliveryClaimHistory):
            raise ValueError('Docker REVIEW requires authenticated selection-anchor history')
        try:
            anchor = self.claims.original_claim_at(session.issue.number, parent['fence'])
        except ClaimFetchError as error:
            raise ValueError('Docker REVIEW selection anchor is unavailable') from error
        claim, fence = self.claims.original_claim(session.issue.number)
        require_expiry_only(anchor, claim)
        owner = claim.original
        if (owner is None or owner.execution_backend != 'docker' or owner.repository != self.config.repo or
                owner.contract_sha256 != parent['original_inner_sha256'] or owner.run_id != parent['engine_run_id'] or
                claim.is_expired() or owner.cancelled or owner.released or owner.pending or
                owner.worktree != inner['execution']['workspace'] or owner.branch != inner['branch']['name'] or
                owner.worktree == str(session.worktree_path) or owner.run_id == session.run_assets.run_id or
                any(row.container_id == snapshot['custody']['container_id'] or
                    row.provider_exec_id == snapshot['custody']['provider_exec_id'] for row in owner.docker_custody)):
            raise ValueError('Docker review original parent/fence/allocation changed')
        if self.working_copy is None or not self.working_copy.matches_exact_commit(session.worktree_path, parent['head_sha']):
            raise ValueError('Docker reviewer checkout differs from granted candidate')
        assert self.docker_custody is not None
        self.docker_custody.verify_review_parent(owner, snapshot)
        return {'issue_number':session.issue.number, 'lease_id':claim.lease_id, 'claimant':claim.claimant,
            'fence':fence, 'lease_current':True, 'expires_at':claim.expires_at.isoformat(),
            'owner':owner.to_dict(), 'remote_released':False}

    def _capture_custody(self, owner: OriginalDelivery) -> OriginalDelivery:
        if owner.execution_backend == "docker":
            if self.docker_custody is None:
                raise ValueError("Docker original custody adapter is unavailable")
            captured = self.docker_custody.capture(owner)
            previous = next((row for row in owner.docker_custody if row.run_id == captured.run_id), None)
            if previous is not None and previous != captured:
                raise ValueError("Docker original run custody changed")
            return replace(owner, docker_custody=tuple(dict.fromkeys((*owner.docker_custody, captured))))
        roots = self.capture_processes(owner)
        if not roots:
            raise ValueError("Current original worker process custody is unavailable")
        return replace(owner, process_roots=tuple(dict.fromkeys((*owner.process_roots, *roots))))

    def _bind_custody(self, issue_number: int, lease_id: str, fence: str, owner: OriginalDelivery) -> bool:
        captured = self._capture_custody(owner)
        if captured.execution_backend == "docker":
            from ..ports.original_delivery import DockerOriginalDeliveryClaims
            if not isinstance(self.claims, DockerOriginalDeliveryClaims):
                raise ValueError("Docker original claim storage is unavailable")
            return self.claims.bind_original_docker_custody(issue_number, lease_id, fence, captured.docker_custody)
        return self.claims.bind_original_processes(issue_number, lease_id, fence, captured.process_roots)

    def observe(self, issue_number: int, *, include_diagnostic: bool = True) -> dict[str, object]:
        claim, fence = self.claims.original_claim(issue_number)
        if claim.original is not None:
            self._require_scope(claim.original)
        result: dict[str, object] = {"issue_number": issue_number, "lease_id": claim.lease_id, "claimant": claim.claimant,
                "fence": fence, "lease_current": not claim.is_expired(),
                "expires_at": claim.expires_at.isoformat(),
                "owner": None if claim.original is None else claim.original.to_dict(),
                "remote_released": claim.original is not None and claim.original.released}
        if include_diagnostic and claim.original is not None and claim.original.execution_backend == "docker" and self.docker_custody is not None:
            result["diagnostic"] = self.docker_custody.diagnostic(claim.original)
            if claim.original.cancelled:
                proof = self.docker_custody.never_started(claim.original)
                if proof is not None:
                    result['never_started'] = proof
        return result

    def execute(self, issue_number: int, command: OriginalDeliveryCommand) -> dict[str, object]:
        claim, fence = self.claims.original_claim(issue_number)
        if claim.lease_id != command.lease_id or fence != command.fence:
            raise ValueError("Original owner or fence changed; observe before retry")
        if command.operation == "register":
            return self._register(issue_number, command, claim)
        owner = self._owner(claim, command)
        self._require_serving_custody(owner, command.operation)
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

    def _require_serving_custody(self, owner: OriginalDelivery, operation: str) -> None:
        if self.state is not None and self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
            if operation != "resume":
                raise ValueError("Operation requires the original engine; resume explicitly after restart")
            self.quiescent(owner, True)

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
        if not self._bind_custody(issue_number, claim.lease_id, fence, claim.original):
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
        if not self._bind_custody(issue_number, command.lease_id, command.fence, owner):
            raise ValueError("Current correction process fence changed")
        return self.observe(issue_number)

    def _register(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim) -> dict[str, object]:
        if self.state is None or not self.state.paused or str(self.state.pause_state.reason) != "operator":
            raise ValueError("Original engine requires current OPERATOR hold")
        return self._register_bound(issue_number, command, claim)

    def register_prestart(self, session: Session) -> str:
        """Bind the retained implementation allocation before its provider starts."""
        if self.state is None or self.docker_custody is None:
            raise ValueError('Docker original pre-start owner unavailable')
        if [s for s in self.state.active_sessions if s.issue.number == session.issue.number] != [session]:
            raise ValueError('Docker pre-start active session changed')
        snapshot = self.docker_custody.prestart_snapshot(session)
        claim, fence = self.claims.original_claim(session.issue.number)
        if claim.original is not None or claim.lease_id != session.lease_id or claim.is_expired():
            raise ValueError('Docker pre-start claim differs')
        run = session.run_assets
        command = OriginalDeliveryCommand('register', claim.lease_id, fence, snapshot['contract_sha256'],
            run.run_id, 'docker-prestart-' + uuid4().hex, session_name=session.terminal_id, started_at=run.started_at)
        self._register_bound(session.issue.number, command, claim)
        fresh, fence = self.claims.original_claim(session.issue.number)
        self.require_prestart_current(session, fence)
        return fence

    def require_prestart_current(self, session: Session, fence: str) -> None:
        if self.state is None or self.docker_custody is None:
            raise ValueError('Docker original pre-start owner unavailable')
        if [s for s in self.state.active_sessions if s.issue.number == session.issue.number] != [session]:
            raise ValueError('Docker pre-start active session changed')
        snapshot = self.docker_custody.prestart_snapshot(session)
        self._require_unused_budget(session.issue.number)
        fresh, current_fence = self.claims.original_claim(session.issue.number)
        owner = fresh.original
        if (current_fence != fence or fresh.lease_id != session.lease_id or fresh.is_expired() or owner is None or
                owner.cancelled or owner.released or owner.run_id != session.run_assets.run_id or
                owner.contract_sha256 != snapshot['contract_sha256'] or owner.docker_custody != (snapshot['custody'],) or
                self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth) or
                self.docker_custody.prestart_snapshot(session) != snapshot):
            raise ValueError('Docker pre-start owner or custody changed')
        self._require_scope(owner)
        self._require_live(owner, fresh)

    def _register_bound(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim) -> dict[str, object]:
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
        if not session.key.kind.capabilities.open_pr_means_done or session.rework_cycle:
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
            engine_birth=birth, max_cycles=self.config.max_rework_cycles,
            execution_backend="docker" if self.docker_custody is not None else "native")
        self.verify_contract(owner)
        owner = self._capture_custody(owner)
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
        if owner.execution_backend != ("docker" if self.docker_custody is not None else "native"):
            raise ValueError("Original execution backend changed")
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
        tracked = self.working_copy.list_dirty_files(worktree, "tracked")
        dirty = self.working_copy.list_dirty_files(worktree, "all")
        if (not self.working_copy.matches_exact_commit(worktree, command.head_sha) or tracked is None or dirty is None
                or tracked or any(builtin_cleanup_root(path) != ".issue-orchestrator/review-feedback" for path in dirty)):
            raise ValueError("Original workspace contains unpublished work")

    def _resume(self, issue_number: int, command: OriginalDeliveryCommand, claim: Claim,
                fence: str, owner: OriginalDelivery) -> dict[str, object]:
        if self.state is None or owner.cancelled or owner.released:
            raise ValueError("Original restart custody is unavailable or cancelled")
        self.verify_contract(owner)
        if self.identity() != (owner.engine_host, owner.engine_pid, owner.engine_birth):
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
