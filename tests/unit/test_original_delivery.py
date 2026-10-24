"""Original custody uses one remote owner and one correction budget."""
from issue_orchestrator.domain.original_delivery import OriginalDelivery, transition


def custody():
    return OriginalDelivery(repository="local/one", config_fingerprint="config", contract_sha256="a" * 64,
        run_id="run-1", session_name="issue-42", native_phase_name="coding-1", logical_child="code:42", started_at="start-1", branch="delivery", worktree="/tmp/delivery",
        run_dir="/tmp/delivery/run", agent="agent:pilot", engine_host="host", engine_pid=12,
        engine_birth="34", max_cycles=1)


def test_correction_admission_is_bounded_cancel_aware_and_idempotent():
    original = custody()
    published = transition(original, "handoff", request_id="handoff-1", pr_number=101, head_sha="b" * 40)
    admitted = transition(published, "correct", request_id="correction-1", feedback="Fix finding")
    assert admitted.cycles == 1
    assert transition(admitted, "correct", request_id="correction-1", feedback="Fix finding") == admitted
    import pytest
    with pytest.raises(ValueError, match="pending|budget"):
        transition(admitted, "correct", request_id="correction-2", feedback="Again")
    cancelled = transition(admitted, "cancel", request_id="cancel-1")
    with pytest.raises(ValueError, match="cancel"):
        transition(cancelled, "correct", request_id="correction-1", feedback="Fix finding")
    released = transition(cancelled, "reconcile", request_id="settle-1")
    assert released.cancelled and released.released
    assert released.run_dir == original.run_dir


def test_replaying_an_older_correction_does_not_consume_another_cycle():
    from dataclasses import replace
    owner = replace(custody(), max_cycles=3)
    owner = transition(owner, "handoff", request_id="handoff", pr_number=101, head_sha="b" * 40)
    owner = transition(owner, "correct", request_id="A", feedback="First")
    owner = transition(owner, "launch", request_id="A")
    owner = replace(owner, correction_runs=(("A", "run2", "/tmp/run2", "rework-42", "start2", "coding-2"),))
    owner = transition(owner, "handoff", request_id="handoff2", pr_number=101, head_sha="c" * 40)
    owner = transition(owner, "correct", request_id="B", feedback="Second")
    replayed = transition(owner, "correct", request_id="A", feedback="First")
    assert replayed.cycles == 2
    assert replayed.correction_id == "B"


def test_grant_cannot_skip_launch_and_handoff():
    from dataclasses import replace
    import pytest
    owner = transition(replace(custody(), max_cycles=3), 'handoff', request_id='handoff', pr_number=1, head_sha='a'*40, base_sha='b'*40)
    owner = transition(owner, 'correct', request_id='A', feedback='Fix')
    with pytest.raises(ValueError, match='pending'):
        transition(owner, 'correct', request_id='B', feedback='More')


def test_launch_is_one_shot_and_duplicate_does_not_spawn():
    owner = transition(custody(), 'handoff', request_id='handoff', pr_number=1, head_sha='a'*40, base_sha='b'*40)
    owner = transition(owner, 'correct', request_id='A', feedback='Fix')
    launched = transition(owner, 'launch', request_id='A')
    assert launched.launches == ('A',)
    assert transition(launched, 'launch', request_id='A') == launched
