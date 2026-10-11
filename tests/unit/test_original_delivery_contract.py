"""Registration authenticates an inherited sealed ceiling, never caller metadata."""
from dataclasses import replace
import hashlib
import json

import pytest

from issue_orchestrator.domain.original_delivery import OriginalDelivery
from issue_orchestrator.execution.original_delivery_contract import sealed_execution_contract


def test_sealed_launch_ceiling_matches_engine_configuration(tmp_path, sample_config, monkeypatch):
    sample_config.refresh_config_fingerprint()
    owner = OriginalDelivery(repository=sample_config.repo, config_fingerprint=sample_config.config_fingerprint,
        contract_sha256='a'*64, run_id='native-run', session_name='issue-42', native_phase_name='coding-1', logical_child='code:42', started_at='start',
        branch='42-delivery', worktree=str(tmp_path), run_dir=str(tmp_path/'run'), agent='agent:web',
        engine_host='host', engine_pid=1, engine_birth='birth', max_cycles=sample_config.max_rework_cycles)
    ceiling = {'profile':'standard-implementation', 'model':'test'}
    contract = {'schema_version':4, 'controller_compatibility':'supervised-v4', 'repository':{'name':owner.repository, 'engine_root':str(sample_config.repo_root)},
        'execution':{'workspace':owner.worktree, 'agent_label':owner.agent, 'session_name':owner.session_name, 'logical_child':owner.logical_child,
            'configuration_sha256':'b'*64}, 'branch':{'name':owner.branch}, 'capabilities':ceiling,
        'supervised':{'correction':{'capabilities':{'originating':ceiling},
            'configuration_sha256':'b'*64, 'budget':{'max_rework_cycles':owner.max_cycles}}}}
    encoded = json.dumps(contract).encode()
    path = tmp_path/'contract.json'
    path.write_bytes(encoded)
    path.chmod(0o400)
    digest = hashlib.sha256(encoded).hexdigest()
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', str(path))
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST', digest)
    owner = replace(owner, contract_sha256=digest)
    sealed_execution_contract(owner, sample_config)
    with pytest.raises(ValueError, match='seal'):
        sealed_execution_contract(replace(owner, contract_sha256='c'*64), sample_config)
    with pytest.raises(ValueError, match='budget'):
        sealed_execution_contract(replace(owner, max_cycles=owner.max_cycles+1), sample_config)
    path.chmod(0o600)
    with pytest.raises(ValueError, match='sealed'):
        sealed_execution_contract(owner, sample_config)
    path.chmod(0o400)
    alias = tmp_path/'alias'
    alias.symlink_to(path)
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', str(alias))
    with pytest.raises(ValueError, match='canonical'):
        sealed_execution_contract(owner, sample_config)


def test_sealed_genuine_schema_hierarchy_refuses_sibling_config_mismatch(tmp_path, sample_config, monkeypatch):
    # Hierarchy retained from original native17 contract SHA
    # 950326c3454f2c790d93b3a4e90e46d62ab6eb2831d1023285acd1cd33891d90.
    # The configuration digest is a correction sibling, never a budget field.
    sample_config.refresh_config_fingerprint()
    ceiling = {'profile':'standard-implementation','revision':2,'model':'gpt-6-astra','originating':None}
    contract = {'schema_version':4,'controller_compatibility':'supervised-v4',
        'repository':{'name':sample_config.repo,'engine_root':str(tmp_path)},
        'execution':{'workspace':str(tmp_path),'agent_label':'agent:web','session_name':'issue-42',
            'logical_child':'code:42','configuration_sha256':'a'*64},'branch':{'name':'delivery'},
        'capabilities':ceiling,'supervised':{'correction':{'configuration_sha256':'a'*64,
            'budget':{'max_rework_cycles':sample_config.max_rework_cycles,'prefix':'',
                'needs_human':'needs-human','needs_rework':'needs-rework'},
            'capabilities':{'profile':'standard-remediation','revision':2,'originating':ceiling}}}}
    path = tmp_path/'contract.json'
    def seal():
        if path.exists():
            path.chmod(0o600)
        encoded = json.dumps(contract).encode()
        path.write_bytes(encoded)
        path.chmod(0o400)
        digest = hashlib.sha256(encoded).hexdigest()
        monkeypatch.setenv('XORETS_EXECUTION_CONTRACT',str(path))
        monkeypatch.setenv('XORETS_EXECUTION_DIGEST',digest)
        return OriginalDelivery(repository=sample_config.repo,config_fingerprint=sample_config.config_fingerprint,
            contract_sha256=digest,run_id='native-run',session_name='issue-42',native_phase_name='coding-1',
            logical_child='code:42',started_at='start',branch='delivery',worktree=str(tmp_path),run_dir=str(tmp_path/'run'),
            agent='agent:web',engine_host='host',engine_pid=1,engine_birth='birth',max_cycles=sample_config.max_rework_cycles)
    sealed_execution_contract(seal(),sample_config)
    contract['supervised']['correction']['configuration_sha256']='b'*64
    with pytest.raises(ValueError,match='budget'):
        sealed_execution_contract(seal(),sample_config)
    contract['supervised']['correction']['configuration_sha256']='a'*64
    contract['execution']['session_name']='coding-1'
    with pytest.raises(ValueError,match='session'):
        sealed_execution_contract(seal(),sample_config)
    contract['execution']['session_name']='issue-42'
    contract['capabilities']=None
    contract['supervised']['correction']['capabilities']['originating']=None
    with pytest.raises(ValueError,match='ceiling'):
        sealed_execution_contract(seal(),sample_config)
