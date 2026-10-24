"""Unit tests for the GitHub ref-backed claim adapter."""

from __future__ import annotations

from datetime import datetime, timedelta

import httpx
import pytest

from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
from issue_orchestrator.adapters.github.ref_claim_adapter import (
    CLAIM_REF_PREFIX,
    GitHubRefClaimAdapter,
)
from issue_orchestrator.adapters.github.rate_limit import github_http_failure
from issue_orchestrator.domain.claim import Claim, ClaimFetchError, ClaimState
from issue_orchestrator.ports.repository_host import host_rate_limit_of
from issue_orchestrator.domain.lease_config import LeaseConfig

from .fake_git_data import FakeGitHubRefClient


def seed_claim_ref(
    client: FakeGitHubRefClient, issue_number: int, claim: Claim
) -> None:
    """Point an issue's claim ref at an existing claim."""
    client.seed_record(
        f"{CLAIM_REF_PREFIX}/issue-{issue_number}", format_claim_comment(claim)
    )


class FakeLabels:
    def __init__(self) -> None:
        self.added: list[tuple[int, str]] = []
        self.removed: list[tuple[int, str]] = []

    def add_label(self, issue_number: int, label: str) -> None:
        self.added.append((issue_number, label))

    def remove_label(self, issue_number: int, label: str) -> None:
        self.removed.append((issue_number, label))


def _adapter(
    client: FakeGitHubRefClient,
    labels: FakeLabels,
    claimant_id: str,
    *,
    lease_seconds: int = 30,
) -> GitHubRefClaimAdapter:
    return GitHubRefClaimAdapter(
        client=client,
        claimant_id=claimant_id,
        config=LeaseConfig(
            lease_seconds=lease_seconds,
            renew_interval_seconds=10,
            convergence_timeout_seconds=0.1,
            convergence_poll_min_ms=1,
            convergence_poll_max_ms=1,
        ),
        label_adapter=labels,
    )


def test_attempt_claim_creates_issue_ref_and_label() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")

    result = adapter.attempt_claim(issue_number=42)

    assert result.success is True
    assert result.state == ClaimState.CLAIMED
    assert result.lease_id is not None
    assert client.created_refs[0][0] == f"{CLAIM_REF_PREFIX}/issue-42"
    assert labels.added == [(42, "io:claimed")]
    assert adapter.run_convergence(42, result.lease_id) is True


def test_second_adapter_loses_to_active_ref_claim() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter_a = _adapter(client, labels, "orchestrator-a")
    adapter_b = _adapter(client, labels, "orchestrator-b")

    first = adapter_a.attempt_claim(issue_number=42)
    second = adapter_b.attempt_claim(issue_number=42)

    assert first.success is True
    assert second.success is False
    assert second.state == ClaimState.CLAIM_LOST
    assert second.competing_claims[0].claimant == "orchestrator-a"
    assert "already claimed" in str(second.error)
    assert labels.added == [(42, "io:claimed")]


def test_released_claim_can_be_taken_over_by_another_adapter() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter_a = _adapter(client, labels, "orchestrator-a")
    adapter_b = _adapter(client, labels, "orchestrator-b")

    first = adapter_a.attempt_claim(issue_number=42)
    assert first.lease_id is not None
    adapter_a.release_claim(issue_number=42, lease_id=first.lease_id)
    assert client.deleted_refs == [f"{CLAIM_REF_PREFIX}/issue-42"]
    assert client.get_git_ref(f"{CLAIM_REF_PREFIX}/issue-42") is None

    second = adapter_b.attempt_claim(issue_number=42)

    assert second.success is True
    current = adapter_b.get_current_claim(42)
    assert current is not None
    assert current.lease_id == second.lease_id
    assert current.claimant == "orchestrator-b"
    assert labels.removed == [(42, "io:claimed")]


def test_release_ignores_non_matching_lease() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")

    result = adapter.attempt_claim(issue_number=42)
    adapter.release_claim(issue_number=42, lease_id="someone-else")

    assert result.lease_id is not None
    assert client.deleted_refs == []
    current = adapter.get_current_claim(42)
    assert current is not None
    assert current.lease_id == result.lease_id
    assert labels.removed == []


def test_default_branch_is_cached_for_first_time_claims() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")

    first = adapter.attempt_claim(issue_number=42)
    second = adapter.attempt_claim(issue_number=43)

    assert first.success is True
    assert second.success is True
    assert client.default_branch_reads == 1


def test_renew_claim_moves_ref_with_non_force_update() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")

    result = adapter.attempt_claim(issue_number=42)
    assert result.lease_id is not None
    renewed = adapter.renew_claim(issue_number=42, lease_id=result.lease_id)

    assert renewed is True
    assert client.updated_refs[-1][0] == f"{CLAIM_REF_PREFIX}/issue-42"
    assert client.updated_refs[-1][2] is False
    current = adapter.get_current_claim(42)
    assert current is not None
    assert current.lease_id == result.lease_id


def test_renew_claim_returns_false_on_cas_conflict() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")

    result = adapter.attempt_claim(issue_number=42)
    assert result.lease_id is not None
    client.conflict_updates_remaining = 1

    assert adapter.renew_claim(issue_number=42, lease_id=result.lease_id) is False


def test_expired_claim_is_not_current() -> None:
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "orchestrator-a")
    expired_claim = Claim(
        lease_id="lease-expired",
        claimant="orchestrator-a",
        issue_number=42,
        started_at=datetime.now() - timedelta(seconds=10),
        expires_at=datetime.now() - timedelta(seconds=1),
        priority=1,
    )
    seed_claim_ref(client, 42, expired_claim)

    assert adapter.get_current_claim(42) is None


class RateLimitedRefClient(FakeGitHubRefClient):
    """GitHub refuses ref reads on a spent rate limit while ``limited`` is set.

    ``limit_next`` refuses only that many further reads, then answers again.
    """

    def __init__(self, *, limited: bool = True) -> None:
        super().__init__()
        self.limited = limited
        self.limit_next = 0
        self.limited_reads = 0

    def get_git_ref(self, ref: str) -> dict | None:
        if self.limited or self.limit_next:
            self.limit_next = max(0, self.limit_next - 1)
            self.limited_reads += 1
            raise github_http_failure(
                f"GitHub GET /git/{ref} failed: 403",
                status_code=403,
                headers=httpx.Headers({
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-reset": str(int(datetime.now().timestamp()) + 60),
                }),
                response_text='{"message": "API rate limit exceeded"}',
                method="GET",
                url=f"/git/{ref}",
            )
        return super().get_git_ref(ref)


def test_rate_limited_claim_read_reports_its_typed_limit() -> None:
    """#7297: the launch must be able to defer instead of counting a failure."""
    adapter = _adapter(RateLimitedRefClient(), FakeLabels(), "orchestrator-a")

    result = adapter.attempt_claim(issue_number=42)

    assert result.success is False
    assert result.host_rate_limit is not None
    assert result.host_rate_limit.kind == "primary"


def test_rate_limited_convergence_raises_instead_of_reporting_lost() -> None:
    """"Could not ask" must not read as "a peer won", which drops the work."""
    client = RateLimitedRefClient(limited=False)
    adapter = _adapter(client, FakeLabels(), "orchestrator-a")
    claimed = adapter.attempt_claim(issue_number=42)
    assert claimed.success and claimed.lease_id is not None
    client.limited = True

    with pytest.raises(ClaimFetchError) as caught:
        adapter.run_convergence(42, claimed.lease_id)

    assert host_rate_limit_of(caught.value) is not None
    assert client.limited_reads == 1, "no polling against a rate-limited host"


def test_original_owner_correction_and_terminal_release_share_remote_cas() -> None:
    from issue_orchestrator.domain.original_delivery import OriginalDelivery
    client = FakeGitHubRefClient()
    labels = FakeLabels()
    adapter = _adapter(client, labels, "original")
    acquired = adapter.attempt_claim(42)
    claim, fence = adapter.original_claim(42)
    assert claim.lease_id == acquired.lease_id
    delivery = OriginalDelivery(repository="local/one", config_fingerprint="config", contract_sha256="a" * 64,
        run_id="run", session_name="issue-42", native_phase_name="coding-1", logical_child="code:42", started_at="start", branch="delivery", worktree="/tmp/delivery",
        run_dir="/tmp/delivery/run", agent="agent:pilot", engine_host="host", engine_pid=12,
        engine_birth="34", max_cycles=1)
    assert adapter.bind_original(42, claim.lease_id, fence, delivery)
    bound, fence = adapter.original_claim(42)
    assert bound.original == delivery
    assert adapter.renew_claim(42, claim.lease_id)
    renewed, fence = adapter.original_claim(42)
    assert renewed.original == delivery
    published = adapter.transition_original(42, claim.lease_id, fence, "handoff", request_id="handoff",
        pr_number=101, head_sha="b" * 40)
    assert published.original.pr_number == 101
    _, fence = adapter.original_claim(42)
    assert adapter.transition_original(42, "foreign", fence, "cancel", request_id="cancel") is None
    cancelled = adapter.transition_original(42, claim.lease_id, fence, "cancel", request_id="cancel")
    assert cancelled.original.cancelled
    assert adapter.transition_original(42, claim.lease_id, fence, "reconcile", request_id="reconcile") is None
    _, fence = adapter.original_claim(42)
    terminal = adapter.transition_original(42, claim.lease_id, fence, "reconcile", request_id="reconcile")
    assert terminal.original.released
    assert client.deleted_refs == []
    assert adapter.get_current_claim(42) is None
    successor = _adapter(client, labels, "successor").attempt_claim(42)
    assert successor.success


def test_original_grant_survives_restart_and_lost_ack_without_relaunch(tmp_path) -> None:
    from issue_orchestrator.domain.original_delivery import OriginalDelivery
    from issue_orchestrator.domain.session_run import SessionRunAssets
    client = FakeGitHubRefClient()
    adapter = _adapter(client, FakeLabels(), 'original')
    assert adapter.attempt_claim(42).success
    claim, fence = adapter.original_claim(42)
    owner = OriginalDelivery(repository='test/repo', config_fingerprint='config', contract_sha256='a'*64,
        run_id='original', session_name='issue-42', native_phase_name='coding-1', logical_child='code:42', started_at='start', branch='delivery', worktree=str(tmp_path),
        run_dir=str(tmp_path/'original'), agent='agent:web', engine_host='host', engine_pid=1,
        engine_birth='birth', max_cycles=1)
    assert adapter.bind_original(42, claim.lease_id, fence, owner)
    _, fence = adapter.original_claim(42)
    assert adapter.transition_original(42, claim.lease_id, fence, 'handoff', request_id='handoff',
        pr_number=101, head_sha='a'*40, base_sha='b'*40)
    _, fence = adapter.original_claim(42)
    assert adapter.transition_original(42, claim.lease_id, fence, 'correct', request_id='A', feedback='Fix')
    assert adapter.reserve_original_launch(42, 'A')
    assert not adapter.reserve_original_launch(42, 'A')
    run_dir = tmp_path/'.issue-orchestrator'/'sessions'/'correction__rework-42'
    run = SessionRunAssets.from_paths(session_name='rework-42', run_id='correction', started_at='new-start',
        worktree_path=tmp_path, run_dir=run_dir, manifest_path=run_dir/'manifest.json', terminal_recording_path=run_dir/'log')
    assert adapter.bind_original_run(42, 'A', run, 'rework-42')
    restarted = _adapter(client, FakeLabels(), 'original')
    before, fence = restarted.original_claim(42)
    assert restarted.resume_original(42, before.lease_id, fence, ('host', 2, 'next-birth'))
    resumed, fence = restarted.original_claim(42)
    assert resumed.original.cycles == 1
    assert resumed.original.run_id == 'original'
    assert resumed.original.engine_history == (('host', 1, 'birth'),)
    assert resumed.original.correction_runs == (('A', 'correction', str(run_dir), 'rework-42', 'new-start', 'rework-42'),)
    assert not restarted.reserve_original_launch(42, 'A')
    foreign = _adapter(client, FakeLabels(), 'foreign')
    assert not foreign.renew_claim(42, before.lease_id)
    assert foreign.transition_original(42, before.lease_id, fence, 'cancel', request_id='foreign') is None
    assert foreign.original_claim(42) == restarted.original_claim(42)
    assert adapter.attempt_claim(43).success
    other = adapter.original_claim(43)
    assert restarted.transition_original(42, before.lease_id, fence, 'cancel', request_id='cancel')
    assert adapter.original_claim(43) == other
    with pytest.raises(ValueError, match='cancelled'):
        restarted.reserve_original_launch(42, 'B')
