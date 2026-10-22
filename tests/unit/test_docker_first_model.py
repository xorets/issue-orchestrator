"""CODE-only parent proof uses exact allocations, original owner and dual auth."""
from dataclasses import replace
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

@pytest.fixture
def first_model_owner(original_owner):
    owner, session = original_owner
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
