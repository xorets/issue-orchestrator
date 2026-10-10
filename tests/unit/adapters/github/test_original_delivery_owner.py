"""Original public control policies over genuine adapter CAS, with port fakes."""
from dataclasses import replace
from unittest.mock import MagicMock

import pytest

from issue_orchestrator.adapters.github.ref_claim_adapter import GitHubRefClaimAdapter
from issue_orchestrator.control.label_manager import LabelManager
from issue_orchestrator.control.original_delivery import OriginalDeliveryCommand, OriginalDeliveryOwner
from issue_orchestrator.domain.models import Issue, OrchestratorState, Session, SessionKey, SessionKind
from issue_orchestrator.domain.pause_state import PauseActor, PauseReason, PauseState
from issue_orchestrator.domain.session_run import SessionRunAssets
from issue_orchestrator.ports.pull_request_tracker import PRInfo
from issue_orchestrator.ports.repository_host import RepositoryHost
from issue_orchestrator.ports.working_copy import WorkingCopy

from .fake_git_data import FakeGitHubRefClient


@pytest.fixture
def original_owner(tmp_path, sample_config, sample_agent_config):
    sample_config.max_rework_cycles = 1
    sample_config.refresh_config_fingerprint()
    claims = GitHubRefClaimAdapter(FakeGitHubRefClient(), 'original')
    acquired = claims.attempt_claim(42)
    assert acquired.success
    issue = Issue(number=42, title='Chosen', labels=['agent:web'], repo=sample_config.repo)
    run_dir = tmp_path/'.issue-orchestrator'/'sessions'/'original__coding-1'
    run = SessionRunAssets.from_paths(session_name='coding-1', run_id='original', started_at='start',
        worktree_path=tmp_path, run_dir=run_dir, manifest_path=run_dir/'manifest.json', terminal_recording_path=run_dir/'log')
    session = Session(key=SessionKey(issue=issue.key, kind=SessionKind.CODE), issue=issue,
        agent_config=sample_agent_config, terminal_id='issue-42', worktree_path=tmp_path,
        branch_name='delivery', run_assets=run, agent_label='agent:web', lease_id=acquired.lease_id)
    state = OrchestratorState(active_sessions=[session], pause_state=PauseState.paused_now(
        reason=PauseReason.OPERATOR, actor=PauseActor.MCP))
    repository = MagicMock(spec=RepositoryHost)
    repository.get_issue.return_value = issue
    repository.get_prs_for_issue.return_value = []
    repository.get_pr.return_value = PRInfo(number=101,title='Draft',url='https://example/pull/101',
        branch='delivery',body='',state='open',labels=[],draft=True,head_sha='a'*40,base_sha='b'*40)
    git = MagicMock(spec=WorkingCopy)
    git.get_head_sha.return_value = 'a'*40
    git.has_uncommitted_changes.return_value = False
    quiescent = MagicMock()
    owner = OriginalDeliveryOwner(claims, repository, git, sample_config, state, lambda:('host',10,'birth'),
        quiescent, lambda _:None, lambda _:(('original',20,'child-birth',20,'child-birth'),),
        LabelManager(sample_config).extract_rework_cycle, lambda _:None, lambda _owner, _run:None, lambda _:True)
    return owner, session


def command(owner, operation, **changes):
    observed = owner.observe(42)
    fields = dict(operation=operation, lease_id=observed['lease_id'], fence=observed['fence'],
        run_id='original', contract_sha256='a'*64,request_id=operation,
        session_name='issue-42',started_at='start',pr_number=101,head_sha='a'*40,base_sha='b'*40)
    fields.update(changes)
    return OriginalDeliveryCommand(**fields)


def published(owner):
    owner.execute(42, command(owner,'register'))
    owner.state.active_sessions.clear()
    return owner.execute(42, command(owner,'handoff'))


def test_register_requires_current_terminal_phase_hold_and_original_budget(original_owner):
    owner, session = original_owner
    before = owner.observe(42)
    for changes in ({'lease_id':'foreign'}, {'fence':'stale'}, {'session_name':'coding-1'}, {'started_at':'old'}):
        with pytest.raises(ValueError):
            owner.execute(42, command(owner,'register',**changes))
        assert owner.observe(42) == before
    owner.current_session = lambda _:False
    with pytest.raises(ValueError,match="native worker"):
        owner.execute(42, command(owner,"register"))
    owner.current_session = lambda _:True
    session.rework_cycle = 1
    with pytest.raises(ValueError,match='initial'):
        owner.execute(42, command(owner,'register'))
    session.rework_cycle = None
    owner.repository.get_issue.return_value = replace(session.issue,labels=['rework-cycle-1'])
    with pytest.raises(ValueError,match='budget'):
        owner.execute(42, command(owner,'register'))
    owner.repository.get_issue.return_value = session.issue
    result = owner.execute(42, command(owner,'register'))
    assert result['owner']['session_name'] == 'issue-42'
    assert result['owner']['native_phase_name'] == 'coding-1'
    assert result['owner']['max_cycles'] == 1
    assert owner.execute(42, command(owner,'register')) == result


@pytest.mark.parametrize('kind', [SessionKind.REWORK, SessionKind.REVIEW,
    SessionKind.RETROSPECTIVE_REVIEW, SessionKind.TECH_LEAD, SessionKind.HISTORICAL])
def test_register_refuses_sessions_whose_existing_pr_is_not_their_original_output(original_owner, kind):
    owner, session = original_owner
    before = owner.observe(42)
    session.key = SessionKey(issue=session.issue.key, kind=kind)
    with pytest.raises(ValueError, match='initial implementation custody'):
        owner.execute(42, command(owner, 'register'))
    assert owner.observe(42) == before


def test_correction_is_atomic_one_shot_and_lost_ack_observable(original_owner):
    owner, original = original_owner
    published(owner)
    admitted = owner.execute(42, command(owner,'correct',request_id='A',feedback='Fix finding'))
    assert admitted['owner']['cycles'] == 1
    attempts = []
    def launch(rework):
        assert owner.claims.reserve_original_launch(42, rework.source.removeprefix('original-owner:'))
        attempts.append('native-launch')
        run_dir = original.run_assets.run_dir.parent/'correction__coding-2'
        run = SessionRunAssets.from_paths(session_name='coding-2',run_id='correction',started_at='start2',
            worktree_path=original.worktree_path,run_dir=run_dir,manifest_path=run_dir/'manifest.json',terminal_recording_path=run_dir/'log')
        assert owner.claims.bind_original_run(42,'A',run,'rework-42')
        session = replace(original,key=SessionKey(issue=original.issue.key,kind=SessionKind.REWORK),
            terminal_id='rework-42',run_assets=run,pr_number=101,rework_cycle=1)
        owner.state.active_sessions.append(session)
        return session
    owner.launch = launch
    result = owner.execute(42, command(owner,'launch',request_id='A'))
    assert result['owner']['correction_runs'][0] == ('A','correction',str(original.run_assets.run_dir.parent/'correction__coding-2'),'rework-42','start2','coding-2')
    owner.quiescent.reset_mock()
    assert owner.execute(42, command(owner,'launch',request_id='A')) == result
    owner.quiescent.assert_not_called()
    assert attempts == ['native-launch']
    owner.state.active_sessions.clear()
    owner.execute(42,command(owner,'handoff'))
    with pytest.raises(ValueError,match='budget'):
        owner.execute(42,command(owner,'correct',request_id='B',feedback='Another'))


def test_cancel_after_ended_handoff_releases_only_original_fenced_claim(original_owner):
    owner, original = original_owner
    published(owner)
    assert owner.claims.attempt_claim(43).success
    foreign = owner.claims.original_claim(43)
    owner.repository.get_issue.return_value = replace(original.issue,labels=['dispatch:cancel-requested'])
    with pytest.raises(ValueError,match='cancelled'):
        owner.execute(42,command(owner,'correct',request_id='A',feedback='Fix'))
    assert owner.observe(42)['owner']['cancelled']
    result = owner.execute(42,command(owner,'reconcile'))
    assert result['remote_released'] and result['owner']['cancelled']
    assert owner.claims.original_claim(43) == foreign
    assert owner.claims.attempt_claim(42).success


def test_restart_requires_positive_old_custody_and_preserves_budget(original_owner):
    owner, _ = original_owner
    published(owner)
    owner.execute(42,command(owner,'correct',request_id='A',feedback='Fix'))
    owner.identity = lambda:('host',11,'restart-birth')
    with pytest.raises(ValueError,match='resume'):
        owner.execute(42,command(owner,'launch',request_id='A'))
    resumed = owner.execute(42,command(owner,'resume'))
    assert resumed['owner']['cycles'] == 1
    assert resumed['owner']['engine_history'] == (('host',10,'birth'),)
    assert resumed['owner']['run_id'] == 'original'
    assert owner.quiescent.call_args.args[1] is True


def test_foreign_serving_engine_cannot_terminate_original_session(original_owner):
    owner, _ = original_owner
    owner.execute(42, command(owner, 'register'))
    owner.identity = lambda: ('host', 11, 'foreign-birth')
    owner.terminate = MagicMock()
    with pytest.raises(ValueError, match='original engine'):
        owner.execute(42, command(owner, 'reconcile'))
    owner.terminate.assert_not_called()
