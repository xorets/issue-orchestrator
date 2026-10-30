"""CODE-only parent proof uses exact allocations, original owner and dual auth."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from issue_orchestrator.control.original_delivery import DockerFirstModelCommand
from issue_orchestrator.domain.original_delivery import DockerCustody
from issue_orchestrator.domain.session_run import SessionRunIdentity
from issue_orchestrator.domain.completion_intake import IntakeUnauthorized
from issue_orchestrator.entrypoints import control_api
from issue_orchestrator.entrypoints.control_api_issue_support import ControlApiIssueDependencies, get_control_api_issue_dependencies
from tests.unit.adapters.github.test_original_delivery_owner import original_owner
from tests.unit.test_docker_worker_authority import authority, model_authority, model_control_marker

@pytest.fixture
def claim_http():
    from tests.unit.adapters.github.fake_git_data import FakeGitHubRefClient
    from hashlib import sha1
    class HexGitData(FakeGitHubRefClient):
        def _mint(self, kind):
            return sha1(super()._mint(kind).encode()).hexdigest()
    return HexGitData()

@pytest.fixture
def first_model_owner(original_owner,claim_http):
    owner, session = original_owner
    from issue_orchestrator.adapters.github.ref_claim_adapter import GitHubRefClaimAdapter
    claims=GitHubRefClaimAdapter(claim_http,'original')
    acquired=claims.attempt_claim(42)
    assert acquired.success
    owner.claims=claims
    session.lease_id=acquired.lease_id
    run_id = '20261022-211413Z-' + 'a' * 32
    root = session.run_assets.run_dir.parent / (run_id + '__coding-1')
    run = replace(session.run_assets, identity=SessionRunIdentity('coding-1', run_id, 'start'), run_dir=root,
        manifest=replace(session.run_assets.manifest, run_dir=root, path=root/'manifest.json'),
        terminal_recording=replace(session.run_assets.terminal_recording, run_dir=root, path=root/'log'))
    session.run_assets = run
    owner.config.terminal_adapter = 'issue_orchestrator.execution.terminal_docker:DockerPlugin'
    owner.state.startup_status = 'complete'
    custody = DockerCustody(1, run_id, 'daemon', '1'*64, '2'*64, '3'*64, '4'*64)
    snapshot = {'role':'standard-implementation','builder_run_id': 'run-'+'b'*32, 'outer_sha256':'5'*64, 'projection_sha256':'6'*64,
        'custody':vars(custody) if hasattr(custody,'__dict__')else {n:getattr(custody,n)for n in custody.__dataclass_fields__},
        'worker':{'daemon_id':'daemon','controller_container_id':'1'*64,'container_id':'2'*64,'provider_exec_id':'3'*64,
            'image_id':'sha256:'+'7'*64,'running':True,'paused':False,'restarting':False,'oom_killed':False,
            'restart_count':0,'provider_running':True,'provider_exit_code':None}}
    adapter = Mock()
    adapter.capture.return_value = custody
    adapter.first_model_snapshot.return_value = snapshot
    adapter.seal_first_model.return_value = {'path':'/private/receipt.json','sha256':'8'*64}
    owner.docker_custody = adapter
    return owner, session, adapter, DockerFirstModelCommand(run_id,'a'*64,'4'*64)

def test_first_model_registers_only_existing_original_and_returns_exact_receipt(first_model_owner):
    owner, session, adapter, command = first_model_owner
    result = owner.first_model(session.run_assets, command)
    receipt = result['receipt']
    assert receipt['original_delivery']['owner']['run_id'] == command.run_id
    assert receipt['claim_ref_sha'] == owner.observe(42)['fence']
    assert receipt['barrier'] == {'paused':True,'pause_reason':'operator'}
    assert adapter.first_model_snapshot.call_count == 2
    adapter.seal_first_model.assert_called_once_with(session, receipt)
    assert receipt['worker']['provider_running'] is True

@pytest.mark.parametrize('change',['missing-custody','foreign-run','review','rework','startup','unpaused','stale-custody'])
def test_first_model_refuses_invalid_selection_before_evidence(first_model_owner, change):
    from issue_orchestrator.domain.session_kind import SessionKind
    owner, session, adapter, command = first_model_owner
    run = session.run_assets
    if change == 'missing-custody': adapter.first_model_snapshot.side_effect=ValueError('missing')
    elif change == 'foreign-run': command=replace(command,run_id='20261022-211413Z-'+'f'*32)
    elif change == 'review': session.key=replace(session.key,kind=SessionKind.REVIEW)
    elif change == 'rework': session.rework_cycle=1
    elif change == 'startup': owner.state.startup_status='pending'
    elif change == 'unpaused': owner.state.pause_state=owner.state.pause_state.running()
    else: adapter.first_model_snapshot.side_effect=[adapter.first_model_snapshot.return_value,{}]
    with pytest.raises(ValueError):owner.first_model(run,command)
    adapter.seal_first_model.assert_not_called()
    if change != 'stale-custody':assert owner.observe(42)['owner'] is None

@pytest.mark.parametrize('auth,capability,extra,status',[
    ('agent','cap',{},200),('admin','cap',{},401),('wrong','cap',{},401),
    ('agent','wrong',{},401),('agent','cap',{'path':'/private'},422),
])
def test_exact_route_requires_docker_callback_and_active_capability(first_model_owner, monkeypatch, auth, capability, extra, status, auth_enabled_control_client):
    owner, session, adapter, command = first_model_owner
    def execute(cap, selected):
        if cap != 'cap':raise IntakeUnauthorized('closed or foreign')
        return owner.first_model(session.run_assets,selected)
    engine=SimpleNamespace(docker_first_model=execute)
    deps=ControlApiIssueDependencies(get_orchestrator=lambda:engine,with_state_lock=lambda fn:fn())
    monkeypatch.setitem(control_api.control_app.dependency_overrides,get_control_api_issue_dependencies,lambda:deps)
    control_api.configure_api_token('admin',agent_callback='agent',agent_callback_scope='docker')
    try:
        response=auth_enabled_control_client.post('/api/docker/first-model',json={**vars(command),**extra},headers={'Authorization':'Bearer '+auth,'X-Completion-Capability':capability})
        assert response.status_code==status,response.text
        if status==200:
            receipt=response.json()['receipt']
            assert 'review_parent' not in receipt
            assert 'provider_exit_code' in receipt['worker'] and receipt['worker']['provider_exit_code'] is None
    finally:control_api.configure_api_token(None)


@pytest.mark.parametrize('control', ['pause', 'cancel'])
def test_actual_callback_rechecks_controller_only_control_without_worker_mount(
    sample_orchestrator, first_model_owner, model_authority, monkeypatch, auth_enabled_control_client, control,
):
    from issue_orchestrator.control.health_gate import HealthGate
    from issue_orchestrator.execution.docker_worker_authority import model_projection_snapshot
    owner, session, adapter, command = first_model_owner
    packet, _, _, _, _, _ = model_authority
    snapshot = adapter.first_model_snapshot.return_value

    def live_custody(*args):
        model_projection_snapshot(packet)
        return snapshot

    adapter.first_model_snapshot.side_effect = live_custody
    orchestrator = sample_orchestrator
    orchestrator.state.active_sessions = [session]
    orchestrator.state.startup_status = 'complete'
    owner.state = orchestrator.state
    ledger = Mock(spec=orchestrator.deps.issue_run_ledger)
    ledger.run_for_capability.return_value = session.run_assets
    orchestrator.deps = replace(orchestrator.deps, original_delivery_owner=owner, issue_run_ledger=ledger, health_gate=HealthGate())
    deps = ControlApiIssueDependencies(get_orchestrator=lambda: orchestrator, with_state_lock=lambda fn: fn())
    monkeypatch.setitem(control_api.control_app.dependency_overrides, get_control_api_issue_dependencies, lambda: deps)
    control_api.configure_api_token('admin', agent_callback='agent', agent_callback_scope='docker')
    headers = {'Authorization': 'Bearer agent', 'X-Completion-Capability': 'cap'}
    try:
        before = auth_enabled_control_client.post('/api/docker/first-model', json=vars(command), headers=headers)
        assert before.status_code == 200, before.text
        original = owner.observe(42)
        adapter.seal_first_model.reset_mock()
        mounts = list(packet['mounts'])
        marker = model_control_marker(packet, control)
        assert all(not marker.is_relative_to(Path(mount['source'])) for mount in mounts)
        after = auth_enabled_control_client.post('/api/docker/first-model', json=vars(command), headers=headers)
        assert after.status_code == 409, after.text
        adapter.seal_first_model.assert_not_called()
        assert owner.observe(42) == original and packet['mounts'] == mounts
    finally:
        control_api.configure_api_token(None)


@pytest.fixture
def reviewer_owner(first_model_owner):
    import copy
    from issue_orchestrator.domain.session_kind import SessionKind
    from issue_orchestrator.domain.session_run import SessionRunAssets
    owner, original, adapter, command = first_model_owner
    code = owner.first_model(original.run_assets, command)['receipt']
    claim, fence = owner.claims.original_claim(42)
    original_owner = claim.original
    reviewer_config = copy.deepcopy(owner.config)
    reviewer_config.max_rework_cycles = 0
    reviewer_config.refresh_config_fingerprint()
    assert reviewer_config.config_fingerprint != original_owner.config_fingerprint
    owner.config = reviewer_config
    owner.identity = lambda: ('reviewer-host', 99, 'reviewer-birth')
    assert owner.identity() != (original_owner.engine_host, original_owner.engine_pid, original_owner.engine_birth)
    root = original.worktree_path / 'independent-review'
    run_id = '20261022-221413Z-'+'c'*32
    run_dir = root/'.issue-orchestrator'/'sessions'/(run_id+'__review-1')
    run = SessionRunAssets.from_paths(session_name='review-1',run_id=run_id,started_at='review-start',worktree_path=root,
        run_dir=run_dir,manifest_path=run_dir/'manifest.json',terminal_recording_path=run_dir/'log')
    session = replace(original,key=replace(original.key,kind=SessionKind.REVIEW),worktree_path=root,run_assets=run,terminal_id='review-42')
    owner.state.active_sessions = [session]
    parent = {'schema_version':1,'kind':'builder-docker-review-parent','subject_sha256':'1'*64,'head_sha':'2'*40,
        'reviewer_authority_sha256':'3'*64,'original_outer_sha256':code['outer_sha256'],
        'original_inner_sha256':command.contract_sha256,'builder_run_id':code['builder_run_id'],
        'engine_run_id':command.run_id,'fence':fence}
    snapshot = {**adapter.first_model_snapshot.return_value,'role':'standard-review','builder_run_id':'run-'+'c'*32,
        'review_parent':parent,'original_inner':{'execution':{'workspace':str(original.worktree_path)},'branch':{'name':original.branch_name}},
        'custody':{**adapter.first_model_snapshot.return_value['custody'],'run_id':run_id,'container_id':'c'*64,'provider_exec_id':'d'*64}}
    adapter.first_model_snapshot.return_value = snapshot
    adapter.reset_mock()
    return owner,session,adapter,DockerFirstModelCommand(run_id,'e'*64,'f'*64),parent,claim


def test_review_parent_preserves_different_original_engine_and_config_without_second_claim(reviewer_owner):
    owner,session,adapter,command,parent,original_claim = reviewer_owner
    result = owner.first_model(session.run_assets,command)
    receipt = result['receipt']
    assert receipt['run_id'] == command.run_id != parent['engine_run_id']
    assert receipt['original_delivery']['owner'] == original_claim.original.to_dict()
    assert receipt['review_parent'] == parent
    assert receipt['barrier'] == {'paused':True,'pause_reason':'operator'}
    claim,fence = owner.claims.original_claim(42)
    assert claim == original_claim and fence == parent['fence']
    adapter.capture.assert_not_called()
    assert adapter.verify_review_parent.call_count == 3


@pytest.mark.parametrize('change',['wrong-fence','wrong-original-run','wrong-inner','shared-container','parent-live','wrong-head','pending','expired'])
def test_review_parent_refuses_before_evidence_and_never_registers(reviewer_owner,change):
    from datetime import timedelta
    owner,session,adapter,command,parent,original_claim = reviewer_owner
    snapshot = adapter.first_model_snapshot.return_value
    if change == 'wrong-fence':parent['fence']='0'*40
    elif change == 'wrong-original-run':parent['engine_run_id']='20261022-221413Z-'+'0'*32
    elif change == 'wrong-inner':parent['original_inner_sha256']='0'*64
    elif change == 'shared-container':snapshot['custody']['container_id']=original_claim.original.docker_custody[0].container_id
    elif change == 'parent-live':adapter.verify_review_parent.side_effect=ValueError('parent active')
    elif change == 'wrong-head':owner.working_copy.matches_exact_commit.return_value=False
    elif change in {'pending','expired'}:
        changed = replace(original_claim, original=replace(original_claim.original,pending=True)) if change == 'pending' else replace(original_claim,expires_at=original_claim.started_at-timedelta(seconds=1))
        owner.claims=Mock(wraps=owner.claims)
        owner.claims.original_claim.return_value=(changed,parent['fence'])
    with pytest.raises(ValueError):owner.first_model(session.run_assets,command)
    adapter.capture.assert_not_called()
    adapter.seal_first_model.assert_not_called()


@pytest.mark.parametrize('change',[None,'foreign-capability','bad-grant','wrong-lease','incident','startup'])
def test_actual_facade_commits_only_authenticated_fixed_operator_barrier(sample_orchestrator,first_model_owner,change):
    from issue_orchestrator.domain.pause_state import PauseState,PauseReason,PauseActor
    from issue_orchestrator.control.health_gate import HealthGate
    owner,session,adapter,command=first_model_owner
    orchestrator=sample_orchestrator
    orchestrator.state.active_sessions=[session]
    orchestrator.state.startup_status='complete'
    orchestrator.state.pause_state=PauseState.running()
    owner.state=orchestrator.state
    ledger=Mock(spec=orchestrator.deps.issue_run_ledger)
    ledger.run_for_capability.return_value=session.run_assets
    orchestrator.deps=replace(orchestrator.deps,original_delivery_owner=owner,issue_run_ledger=ledger,health_gate=HealthGate())
    if change == 'foreign-capability':ledger.run_for_capability.side_effect=IntakeUnauthorized('closed/foreign')
    elif change == 'bad-grant':adapter.first_model_snapshot.side_effect=ValueError('expired grant')
    elif change == 'wrong-lease':session.lease_id='foreign-lease'
    elif change in {'incident','startup'}:
        orchestrator.pause(reason=PauseReason.LOOP_ERROR_THRESHOLD if change=='incident' else PauseReason.STARTUP,actor=PauseActor.SYSTEM)
    before=orchestrator.state.pause_state
    if change is None:
        result=orchestrator.docker_first_model('cap',command)
        assert result['receipt']['barrier']=={'paused':True,'pause_reason':'operator'}
        assert orchestrator.pause_controller.state.reason==PauseReason.OPERATOR
        assert orchestrator.pause_controller.state.actor==PauseActor.CONTROL_API
        assert not before.paused
    else:
        with pytest.raises((ValueError,IntakeUnauthorized)):orchestrator.docker_first_model('cap',command)
        assert orchestrator.state.pause_state is before
        adapter.seal_first_model.assert_not_called()
        assert owner.observe(42)['owner'] is None


def test_review_accepts_only_expiry_heartbeat_and_reports_current_fence(reviewer_owner):
    owner,session,adapter,command,parent,anchor=reviewer_owner
    assert owner.claims.original_claim_at(42,parent['fence'])==anchor
    assert owner.claims.renew_claim(42,anchor.lease_id)
    current,current_fence=owner.claims.original_claim(42)
    assert current_fence!=parent['fence']
    result=owner.first_model(session.run_assets,command)['receipt']
    assert result['claim_ref_sha']==current_fence==result['original_delivery']['fence']
    assert result['review_parent']['fence']==parent['fence']
    assert result['original_delivery']['owner']==anchor.original.to_dict()
    assert current.original==anchor.original and current.lease_id==anchor.lease_id
    adapter.capture.assert_not_called()


@pytest.mark.parametrize('change',['lease','claimant','started','priority','owner','cancelled','shortened-expiry'])
def test_review_refuses_any_anchor_change_beyond_expiry_renewal(reviewer_owner,claim_http,change):
    from datetime import timedelta
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    owner,session,adapter,command,parent,anchor=reviewer_owner
    if change=='lease':current=replace(anchor,lease_id='replacement-lease')
    elif change=='claimant':current=replace(anchor,claimant='other-engine')
    elif change=='started':current=replace(anchor,started_at=anchor.started_at+timedelta(seconds=1))
    elif change=='priority':current=replace(anchor,priority=anchor.priority+1)
    elif change=='owner':current=replace(anchor,original=replace(anchor.original,engine_pid=anchor.original.engine_pid+1))
    elif change=='cancelled':current=replace(anchor,original=replace(anchor.original,cancelled=True))
    else:current=replace(anchor,expires_at=anchor.expires_at-timedelta(seconds=1))
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42',format_claim_comment(current))
    with pytest.raises(ValueError,match='only the selected lease expiry renewal'):
        owner.first_model(session.run_assets,command)
    adapter.capture.assert_not_called()
    adapter.seal_first_model.assert_not_called()


def test_review_ordinary_heartbeat_between_custody_observations_needs_no_new_grant(reviewer_owner):
    owner,session,adapter,command,parent,anchor=reviewer_owner
    observations=[]
    def stopped(*args):
        observations.append(True)
        if len(observations)==2:
            assert owner.claims.renew_claim(42,anchor.lease_id)
    adapter.verify_review_parent.side_effect=stopped
    receipt=owner.first_model(session.run_assets,command)['receipt']
    current,fence=owner.claims.original_claim(42)
    assert receipt['claim_ref_sha']==fence!=parent['fence']
    assert receipt['review_parent']['fence']==parent['fence']
    assert receipt['original_delivery']['owner']==anchor.original.to_dict()


def test_review_refuses_missing_optional_claim_history_capability(reviewer_owner):
    owner,session,adapter,command,parent,anchor=reviewer_owner
    class CurrentOnlyClaims:
        def original_claim(self,issue_number):return anchor,parent['fence']
    owner.claims=CurrentOnlyClaims()
    with pytest.raises(ValueError,match='selection-anchor history'):
        owner.first_model(session.run_assets,command)
    adapter.seal_first_model.assert_not_called()


def test_facade_rechecks_shutdown_after_acquiring_shared_state_custody(sample_orchestrator, first_model_owner):
    """A shutdown committed while this request waits must win before the barrier."""
    from issue_orchestrator.control.health_gate import HealthGate
    from issue_orchestrator.domain.pause_state import PauseState
    owner, session, adapter, command = first_model_owner
    orchestrator = sample_orchestrator
    orchestrator.state.active_sessions = [session]
    orchestrator.state.startup_status = 'complete'
    orchestrator.state.pause_state = PauseState.running()
    owner.state = orchestrator.state
    ledger = Mock(spec=orchestrator.deps.issue_run_ledger)
    ledger.run_for_capability.return_value = session.run_assets
    orchestrator.deps = replace(orchestrator.deps, original_delivery_owner=owner,
        issue_run_ledger=ledger, health_gate=HealthGate())
    actual_lock = orchestrator.state_lock

    class ShutdownAtLockAcquisition:
        def __enter__(self):
            actual_lock.acquire()
            orchestrator.shutdown_requested = True

        def __exit__(self, *_):
            actual_lock.release()

    orchestrator.state_lock = ShutdownAtLockAcquisition()
    with pytest.raises(ValueError, match='health unavailable'):
        orchestrator.docker_first_model('cap', command)
    assert not orchestrator.state.paused
    assert owner.observe(42)['owner'] is None
    adapter.first_model_snapshot.assert_not_called()
    adapter.seal_first_model.assert_not_called()


def test_model_gateway_requires_live_original_and_rechecks_custody(first_model_owner):
    owner, session, adapter, command = first_model_owner
    owner.first_model(session.run_assets, command)
    observed = adapter.first_model_snapshot.return_value
    gateway = {**observed, 'engine_run_id':command.run_id, 'contract_sha256':command.contract_sha256,
               'launch_sha256':command.launch_sha256, 'model':'selected', 'grant_sha256':'9'*64,
               'grant_kind':'builder-docker-container-model-authorization',
               'max_model_requests':2, 'deadline_unix_ns':1, 'max_output_bytes':100,
               'outer_contract_path':'/controller/outer','inner_contract_path':'/controller/inner',
               'launch_path':'/controller/launch','controller_home':'/controller'}
    adapter.model_gateway_snapshot.return_value = gateway
    result=owner.model_gateway_context(session.run_assets)
    assert result['engine_run_id']==command.run_id
    assert result['claim_ref_sha']==owner.observe(42)['fence']
    assert adapter.model_gateway_snapshot.call_count==2
    adapter.model_gateway_snapshot.side_effect=[gateway,{}]
    with pytest.raises(ValueError): owner.model_gateway_context(session.run_assets)


def test_read_only_review_history_proves_selected_renewals(reviewer_owner, claim_http):
    """Real claim adapter/history with only GitHub storage substituted."""
    from hashlib import sha256
    import json
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    from issue_orchestrator.control.original_delivery_history import prove_history
    owner, _, _, _, parent, anchor = reviewer_owner
    selected = anchor
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(selected))
    selected, selected_fence = owner.claims.original_claim(42)
    assert owner.claims.renew_claim(42, selected.lease_id)
    current, current_fence = owner.claims.original_claim(42)
    assert current_fence != selected_fence
    request = {'issue_number':42, 'parent':{'fence':selected_fence,
        'original_inner_sha256':selected.original.contract_sha256, 'engine_run_id':selected.original.run_id,
        'head_sha':parent['head_sha']}, 'expected_current_fence':current_fence,
        'receipts':[{'claim_ref_sha':selected_fence,
                     'reserved_unix_ns':__import__('time').time_ns()}]}
    digest = sha256((json.dumps(request, sort_keys=True, indent=2)+'\n').encode()).hexdigest()
    assert prove_history(owner.claims, owner.config.repo, request) == {
        'status':'PASS', 'current_fence':current_fence, 'subject_sha256':digest}
    bad = {**request, 'receipts':[{'claim_ref_sha':selected_fence,
        'reserved_unix_ns':int(selected.expires_at.timestamp()*1_000_000_000)}]}
    with pytest.raises(ValueError, match='chronology'):
        prove_history(owner.claims, owner.config.repo, bad)
    with pytest.raises(ValueError, match='current fence'):
        prove_history(owner.claims, owner.config.repo, {**request, 'expected_current_fence':'f'*40})


@pytest.mark.parametrize('fault', ['lease', 'owner', 'custody', 'head', 'missing', 'backwards', 'current-drift'])
def test_read_only_review_history_refuses_foreign_or_drifting_claims(reviewer_owner, claim_http, fault):
    """Use actual immutable Git-ref reader; only the GitHub transport is fake."""
    from datetime import timedelta
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    from issue_orchestrator.control.original_delivery_history import prove_history
    owner, _, _, _, parent, anchor = reviewer_owner
    selected = replace(anchor, original=replace(anchor.original, head_sha=parent['head_sha']))
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(selected))
    selected, fence = owner.claims.original_claim(42)
    request = {'issue_number':42, 'parent':{'fence':fence,
        'original_inner_sha256':selected.original.contract_sha256, 'engine_run_id':selected.original.run_id,
        'head_sha':selected.original.head_sha}, 'expected_current_fence':fence, 'receipts':[]}
    if fault == 'missing':
        request['parent']['fence'] = 'f'*40
    elif fault == 'current-drift':
        request['expected_current_fence'] = 'f'*40
    else:
        altered = selected
        if fault == 'lease': altered = replace(selected, lease_id='foreign')
        if fault == 'owner': altered = replace(selected, original=replace(selected.original, engine_pid=selected.original.engine_pid+1))
        if fault == 'custody': altered = replace(selected, original=replace(selected.original, docker_custody=()))
        if fault == 'head': altered = replace(selected, original=replace(selected.original, head_sha='3'*40))
        if fault == 'backwards': altered = replace(selected, expires_at=selected.expires_at-timedelta(seconds=1))
        claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(altered))
        _, request['expected_current_fence'] = owner.claims.original_claim(42)
    from issue_orchestrator.domain.claim import ClaimFetchError
    with pytest.raises((ValueError, ClaimFetchError)):
        prove_history(owner.claims, owner.config.repo, request)


@pytest.mark.asyncio
async def test_history_mcp_returns_only_digest_and_current_fence(reviewer_owner, claim_http, monkeypatch):
    from contextlib import contextmanager
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    from issue_orchestrator.contracts.original_delivery_history import HistoryRequest
    from issue_orchestrator.entrypoints import mcp_original_delivery
    owner, _, _, _, parent, anchor = reviewer_owner
    selected = replace(anchor, original=replace(anchor.original, head_sha=parent['head_sha']))
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(selected))
    selected, fence = owner.claims.original_claim(42)
    request = HistoryRequest(issue_number=42, parent={'fence':fence,
        'original_inner_sha256':selected.original.contract_sha256, 'engine_run_id':selected.original.run_id,
        'head_sha':selected.original.head_sha}, expected_current_fence=fence, receipts=[])
    @contextmanager
    def offline(_config):
        yield owner
    monkeypatch.setattr(mcp_original_delivery, 'build_offline_original_delivery_owner', offline)
    monkeypatch.setattr(mcp_original_delivery.Config, 'load', lambda _: owner.config)
    response = await mcp_original_delivery.original_delivery_history_result(Path('/fixture'), request)
    assert not response.isError
    assert set(response.structuredContent) == {'status', 'current_fence', 'subject_sha256'}
    assert response.structuredContent['status'] == 'PASS'
    assert response.structuredContent['current_fence'] == fence
    assert selected.lease_id not in str(response.structuredContent)


def test_read_only_history_refuses_current_ref_change_after_history_read(reviewer_owner, claim_http):
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    from issue_orchestrator.control.original_delivery_history import prove_history
    owner, _, _, _, parent, anchor = reviewer_owner
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(anchor))
    selected, fence = owner.claims.original_claim(42)
    request = {'issue_number':42, 'parent':{'fence':fence,
        'original_inner_sha256':selected.original.contract_sha256, 'engine_run_id':selected.original.run_id,
        'head_sha':parent['head_sha']}, 'expected_current_fence':fence, 'receipts':[]}
    from unittest.mock import patch
    with patch.object(owner.claims, 'original_claim', side_effect=[(selected, fence), (selected, 'f'*40)]):
        with pytest.raises(ValueError, match='current fence changed'):
            prove_history(owner.claims, owner.config.repo, request)


def test_history_request_rejects_overflow_and_malformed_fence():
    from pydantic import ValidationError
    from issue_orchestrator.contracts.original_delivery_history import HistoryRequest
    data = {'issue_number':42, 'parent':{'fence':'a'*40, 'original_inner_sha256':'b'*64,
        'engine_run_id':'20261022-211413Z-'+'c'*32, 'head_sha':'d'*40},
        'expected_current_fence':'e'*40, 'receipts':[]}
    with pytest.raises(ValidationError):
        HistoryRequest.model_validate({**data, 'receipts':[{'claim_ref_sha':'a'*40, 'reserved_unix_ns':1}]*257})
    with pytest.raises(ValidationError):
        HistoryRequest.model_validate({**data, 'expected_current_fence':'bad'})


def test_history_reuses_same_immutable_receipt_snapshot(reviewer_owner, claim_http):
    import time
    from unittest.mock import patch
    from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
    from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
    from issue_orchestrator.control.original_delivery_history import prove_history
    owner, _, _, _, parent, anchor = reviewer_owner
    claim_http.seed_record(CLAIM_REF_PREFIX+'/issue-42', format_claim_comment(anchor))
    selected, selected_fence = owner.claims.original_claim(42)
    assert owner.claims.renew_claim(42, selected.lease_id)
    _, fence = owner.claims.original_claim(42)
    timestamp = time.time_ns()
    request = {'issue_number':42, 'parent':{'fence':selected_fence,
        'original_inner_sha256':selected.original.contract_sha256, 'engine_run_id':selected.original.run_id,
        'head_sha':parent['head_sha']}, 'expected_current_fence':fence,
        'receipts':[{'claim_ref_sha':selected_fence, 'reserved_unix_ns':timestamp} for _ in range(2)]}
    with patch.object(owner.claims, 'original_claim_at', wraps=owner.claims.original_claim_at) as read:
        assert prove_history(owner.claims, owner.config.repo, request)['status'] == 'PASS'
        assert read.call_count == 1


def test_prestart_registration_binds_fresh_claim_before_live_first_model(first_model_owner):
    import asyncio
    from pathlib import Path
    from issue_orchestrator.domain.pause_state import PauseActor, PauseReason
    from issue_orchestrator.entrypoints.mcp_original_delivery import original_delivery_result
    owner, session, adapter, command = first_model_owner
    owner.state.pause_state = owner.state.pause_state.running()
    custody = adapter.capture.return_value
    adapter.prestart_snapshot.return_value = {'contract_sha256':command.contract_sha256,
        'launch_sha256':command.launch_sha256, 'custody':custody}
    adapter.diagnostic.return_value = None
    before = owner.observe(42)
    assert before['owner'] is None
    owner.register_prestart(session)
    after = owner.observe(42)
    assert after['fence'] != before['fence'] and after['lease_current']
    assert after['owner']['run_id'] == session.run_assets.run_id
    assert after['owner']['docker_custody'][0]['provider_exec_id'] == custody.provider_exec_id
    class Api:
        async def original_delivery(self, issue_number, operation, payload):
            return owner.observe(issue_number)
    result = asyncio.run(original_delivery_result(Api(), Path('/unused'), 42, 'observe', None, running=True))
    assert not result.isError and result.structuredContent['fence'] == after['fence']
    owner.state.pause_state = owner.state.pause_state.paused_now(reason=PauseReason.OPERATOR, actor=PauseActor.MCP)
    assert owner.first_model(session.run_assets, command)['receipt']['claim_ref_sha'] == after['fence']


@pytest.mark.parametrize('failure', ['cancel', 'cas', 'custody', 'foreign', 'expired'])
def test_prestart_registration_refuses_changed_authority(first_model_owner, monkeypatch, failure):
    from datetime import datetime, timedelta
    owner, session, adapter, command = first_model_owner
    owner.state.pause_state = owner.state.pause_state.running()
    custody = adapter.capture.return_value
    adapter.prestart_snapshot.return_value = {'contract_sha256':command.contract_sha256,
        'launch_sha256':command.launch_sha256, 'custody':custody}
    if failure == 'cancel': owner.repository.get_issue.return_value.labels.append('dispatch:cancel-requested')
    if failure == 'cas': monkeypatch.setattr(owner.claims, 'bind_original', lambda *_:False)
    if failure == 'custody': adapter.prestart_snapshot.side_effect = ValueError('custody changed')
    if failure == 'foreign': session.lease_id = 'foreign'
    if failure == 'expired':
        claim, fence = owner.claims.original_claim(42)
        monkeypatch.setattr(owner.claims, 'original_claim', lambda _: (replace(claim, expires_at=datetime.now() - timedelta(seconds=1)), fence))
    with pytest.raises(ValueError): owner.register_prestart(session)
    assert owner.observe(42)['owner'] is None
