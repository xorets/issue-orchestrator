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
    snapshot = {'builder_run_id': 'run-'+'b'*32, 'outer_sha256':'5'*64, 'projection_sha256':'6'*64,
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
    finally:control_api.configure_api_token(None)
