"""Original public control policies over genuine adapter CAS, with port fakes."""
from dataclasses import replace
import subprocess
from unittest.mock import MagicMock

import pytest

from issue_orchestrator.adapters.github.ref_claim_adapter import GitHubRefClaimAdapter
from issue_orchestrator.control.label_manager import LabelManager
from issue_orchestrator.control.original_delivery import OriginalDeliveryCommand, OriginalDeliveryOwner
from issue_orchestrator.domain.models import Issue, OrchestratorState, Session, SessionKey, SessionKind
from issue_orchestrator.domain.pause_state import PauseActor, PauseReason, PauseState
from issue_orchestrator.domain.session_run import SessionRunAssets
from issue_orchestrator.execution.git_working_copy import GitWorkingCopy
from issue_orchestrator.execution.command_runner import LocalCommandRunner
from issue_orchestrator.adapters.git.git_cli import GitCLI
from issue_orchestrator.ports.git import Git, GitError, GitResult
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
    git.matches_exact_commit.return_value = True
    git.has_uncommitted_changes.return_value = False
    git.list_dirty_files.return_value = []
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


def git_command(root, *args):
    return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def real_git_owner(original_owner):
    owner, session = original_owner
    root = session.worktree_path
    git_command(root, 'init', '-b', 'delivery')
    git_command(root, 'config', 'user.email', 'fixture@example.invalid')
    git_command(root, 'config', 'user.name', 'Fixture')
    (root/'source.txt').write_bytes(b'Published source\n')
    git_command(root, 'add', 'source.txt', 'prompt.txt')
    git_command(root, 'commit', '-m', 'Published source')
    head = git_command(root, 'rev-parse', 'HEAD')
    owner.repository.get_pr.return_value = replace(owner.repository.get_pr.return_value, head_sha=head)
    owner.working_copy = GitWorkingCopy()
    owner.execute(42, command(owner, 'register'))
    owner.state.active_sessions.clear()
    feedback = root/'.issue-orchestrator/review-feedback/cycle-1.md'
    feedback.parent.mkdir(parents=True)
    feedback.write_bytes(b'Independent finding: preserve this feedback.\n')
    feedback.chmod(0o400)
    return owner, root, head, feedback


def test_original_handoff_and_correction_preserve_retained_feedback(real_git_owner):
    owner, root, head, feedback = real_git_owner
    before = (feedback.read_bytes(), feedback.stat().st_mode, git_command(root, 'status', '--porcelain'))
    owner.execute(42, command(owner, 'handoff', head_sha=head))
    admitted = owner.execute(42, command(owner, 'correct', head_sha=head, request_id='A', feedback='Fix finding'))
    assert admitted['owner']['cycles'] == 1
    assert (feedback.read_bytes(), feedback.stat().st_mode, git_command(root, 'status', '--porcelain')) == before


@pytest.mark.parametrize('flag', ['--assume-unchanged', '--skip-worktree'])
def test_original_correction_refuses_hidden_tracked_work_before_admission(real_git_owner, flag):
    owner, root, head, feedback = real_git_owner
    owner.execute(42, command(owner, 'handoff', head_sha=head))
    source = root/'source.txt'
    source.write_bytes(b'Unpublished operator changes\n')
    git_command(root, 'update-index', flag, 'source.txt')
    assert 'source.txt' not in git_command(root, 'status', '--porcelain')
    assert git_command(root, 'show', 'HEAD:source.txt').encode() != source.read_bytes().strip()
    before = (source.read_bytes(), (root/'.git/index').read_bytes(), feedback.read_bytes(), owner.observe(42))
    with pytest.raises(ValueError, match='unpublished work'):
        owner.execute(42, command(owner, 'correct', head_sha=head, request_id='A', feedback='Fix finding'))
    assert (source.read_bytes(), (root/'.git/index').read_bytes(), feedback.read_bytes(), owner.observe(42)) == before


@pytest.mark.parametrize('path,staged', [('source.txt', False), ('source.txt', True),
    ('unpublished.txt', False), ('unpublished\nfile.txt', False),
    ('.issue-orchestrator/review-feedback-other/notes.md', False),
    ('.issue-orchestrator/operator-notes.md', False),
    ('.issue-orchestrator/review-feedback/cycle-1.md', True)])
def test_original_handoff_refuses_unpublished_work_beside_feedback(real_git_owner, path, staged):
    owner, root, head, feedback = real_git_owner
    target = root/path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.chmod(0o600)
    target.write_bytes(b'Unpublished work\n')
    if staged:
        git_command(root, 'add', '--', path)
    before = (target.read_bytes(), feedback.read_bytes(), git_command(root, 'status', '--porcelain'), owner.observe(42))
    with pytest.raises(ValueError, match='unpublished work'):
        owner.execute(42, command(owner, 'handoff', head_sha=head))
    assert (target.read_bytes(), feedback.read_bytes(), git_command(root, 'status', '--porcelain'), owner.observe(42)) == before


@pytest.mark.parametrize('query', [('diff', '--name-only', '-z'),
    ('diff', '--cached', '--name-only', '-z'), ('ls-files', '--others', '--exclude-standard', '-z'),
    ('ls-files', '-v', '-z'), ('ls-files', '-f', '-z')])
def test_original_handoff_refuses_failed_git_enumeration(real_git_owner, query):
    owner, root, head, feedback = real_git_owner
    real_git = GitCLI(runner=LocalCommandRunner())
    git = MagicMock(spec=Git)
    def read(worktree, args, **kwargs):
        if tuple(args) == query:
            raise GitError(GitResult(argv=['git', *args], returncode=128, stdout='', stderr='Read failed'))
        return real_git.run(worktree, args, **kwargs)
    git.run.side_effect = read
    owner.working_copy = GitWorkingCopy(git=git)
    before = (feedback.read_bytes(), owner.observe(42))
    with pytest.raises(ValueError, match='unpublished work'):
        owner.execute(42, command(owner, 'handoff', head_sha=head))
    assert (feedback.read_bytes(), owner.observe(42)) == before


def test_original_handoff_does_not_accept_checkout_runtime_ignore_policy(real_git_owner):
    owner, root, head, feedback = real_git_owner
    local_policy = root/'.issue-orchestrator/runtime-ignore'
    local_policy.write_text('operator-work.txt\n')
    (root/'.git/info/exclude').write_text('.issue-orchestrator/runtime-ignore\n')
    unpublished = root/'operator-work.txt'
    unpublished.write_bytes(b'Operator-owned unpublished work\n')
    before = (unpublished.read_bytes(), feedback.read_bytes(), owner.observe(42))
    with pytest.raises(ValueError, match='unpublished work'):
        owner.execute(42, command(owner, 'handoff', head_sha=head))
    assert (unpublished.read_bytes(), feedback.read_bytes(), owner.observe(42)) == before


def test_second_original_correction_preserves_prior_feedback_through_actual_git_reuse(
        original_owner, tmp_path, mock_event_sink):
    from pathlib import Path
    from issue_orchestrator.adapters.worktree.api import create_worktree
    from issue_orchestrator.ports.worktree_manager import WorktreeInfo, WorktreeManager
    from issue_orchestrator.ports.worktree_policy import WorktreePolicy, ValidationResult, SyncResult
    from tests.unit.worktree_git_helpers import make_git_worktree
    from tests.unit.test_session_launcher import _build_launcher_bundle, MockCommandRunner

    owner, original = original_owner
    rig = make_git_worktree(tmp_path, name='main-42', branch='delivery')
    remote = tmp_path/'remote.git'
    git_command(tmp_path, 'clone', '--bare', str(rig.main_repo), str(remote))
    git_command(rig.main_repo, 'remote', 'add', 'origin', str(remote))
    base = git_command(rig.main_repo, 'branch', '--show-current')
    head = git_command(rig.worktree_path, 'rev-parse', 'HEAD')
    original.worktree_path = rig.worktree_path
    original.run_assets = SessionRunAssets.from_paths(session_name='coding-1', run_id='original', started_at='start',
        worktree_path=rig.worktree_path, run_dir=rig.worktree_path/'.issue-orchestrator/sessions/original__coding-1',
        manifest_path=rig.worktree_path/'.issue-orchestrator/sessions/original__coding-1/manifest.json',
        terminal_recording_path=rig.worktree_path/'.issue-orchestrator/sessions/original__coding-1/log')
    owner.config.repo_root = rig.main_repo
    owner.config.max_rework_cycles = 2
    owner.config.refresh_config_fingerprint()
    owner.working_copy = GitWorkingCopy()
    owner.repository.get_pr.return_value = replace(owner.repository.get_pr.return_value, head_sha=head, base_sha=head)
    owner.repository.get_pr_reviews.return_value = []
    policy = MagicMock(spec=WorktreePolicy)
    policy.validate_for_reuse.return_value = ValidationResult(True, 'fixture branch')
    policy.sync_remote_refs.return_value = SyncResult(True)
    manager = MagicMock(spec=WorktreeManager)
    def create(**kwargs):
        result = create_worktree(rig.main_repo, 42, 'Original correction', worktree_base=tmp_path,
            base_branch=base, branch_name='delivery', enforce_hooks=False,
            reuse_options=kwargs['reuse_options'], policy=policy)
        assert result[2] == 'reused'
        return WorktreeInfo(result[0], result[1], reuse_status=result[2])
    manager.create.side_effect = create
    bundle = _build_launcher_bundle(owner.config, mock_event_sink, owner.repository, manager,
        owner.working_copy, MockCommandRunner(), claim_manager=owner.claims, original_runtime_identity=owner.identity)
    owner.launch = lambda rework: bundle.launcher.launch_rework_session(rework, active_sessions=[]).session
    fields = {'head_sha': head, 'base_sha': head}
    owner.execute(42, command(owner, 'register'))
    owner.state.active_sessions.clear()
    owner.execute(42, command(owner, 'handoff', **fields))
    owner.execute(42, command(owner, 'correct', request_id='first', feedback='First finding', **fields))
    owner.execute(42, command(owner, 'launch', request_id='first', **fields))
    feedback = rig.worktree_path/'.issue-orchestrator/review-feedback/cycle-1.md'
    feedback.chmod(0o400)
    git_dir = Path(git_command(rig.worktree_path, 'rev-parse', '--absolute-git-dir'))
    before = (feedback.read_bytes(), feedback.stat().st_mode, (git_dir/'index').read_bytes())
    owner.execute(42, command(owner, 'handoff', request_id='first-handoff', **fields))
    owner.execute(42, command(owner, 'correct', request_id='second', feedback='Second finding', **fields))
    final = owner.execute(42, command(owner, 'launch', request_id='second', **fields))
    assert (feedback.read_bytes(), feedback.stat().st_mode, (git_dir/'index').read_bytes()) == before
    assert (feedback.parent/'cycle-2.md').exists()
    assert git_command(rig.worktree_path, 'rev-parse', 'HEAD') == head
    assert final['owner']['cycles'] == 2
    assert len(bundle.create_session_calls) == 2
    assert all(call.kwargs['reuse_options'].preserve_branch for call in manager.create.call_args_list)


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
