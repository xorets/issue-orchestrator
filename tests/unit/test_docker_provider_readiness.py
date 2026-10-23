"""Actual selected proof bytes/private files and existing Codex parser at OS ports."""
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock
import json
import stat
from hashlib import sha256
from types import SimpleNamespace
import os
import pytest

from issue_orchestrator.execution.docker_launch_input import canonical
from issue_orchestrator.execution.docker_provider_readiness import docker_readiness_context,DockerReadinessRefused
from issue_orchestrator.execution.provider_readiness_probe import CLIProviderReadinessProbe
from issue_orchestrator.execution.agent_runner_providers import CodexProvider
from issue_orchestrator.ports.command_runner import CommandResult
from issue_orchestrator.ports.provider_credentials import ProviderCredentials
from tests.unit.test_docker_worker_authority import authority,model_authority


@pytest.fixture
def readiness(model_authority,tmp_path,monkeypatch):
    from issue_orchestrator.execution.terminal_docker import private_directory
    packet,outer_path,outer,files,controls,seal=model_authority
    bundle = tmp_path / 'capability'; (bundle / 'toolchain').mkdir(parents=True)
    selected = bundle / 'toolchain/codex'
    selected.write_text('#!/usr/bin/python3\nimport json,os,pathlib,sys\nassert sys.argv[1:]==["login","status"]\nassert set(os.environ)-{"LC_CTYPE"}=={"HOME","CODEX_HOME","PATH"}\nauth=json.loads((pathlib.Path(os.environ["CODEX_HOME"])/"auth.json").read_bytes())\nstatus=auth.get("token")\nprint("Logged in using ChatGPT" if status=="auth-canary" else "Not logged in" if status=="invalid" else "unexpected status failure", file=sys.stderr)\nraise SystemExit(0 if status=="auth-canary" else 1 if status=="invalid" else 7)\n')
    selected.chmod(0o555)
    files[str(selected)] = selected
    # Virtualize privileged ownership only; preserve real inode/link/mode evidence.
    selected_inode = selected.stat().st_ino
    original_fstat = os.fstat
    def selected_tool_stat(fd):
        info = original_fstat(fd)
        if info.st_ino == selected_inode:
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            fields['st_nlink'] = selected.stat().st_nlink
            return SimpleNamespace(**fields)
        return info
    monkeypatch.setattr(os, 'fstat', selected_tool_stat)
    parent_stat = Path.lstat
    protected_parents = set(selected.parents)
    def tool_parent_stat(path, *args, **kwargs):
        if path in protected_parents:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0)
        return parent_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', tool_parent_stat)
    inner_path = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(inner_path.read_bytes())
    inner['capabilities'].update(capability_bundle=str(bundle), codex_sha256=sha256(selected.read_bytes()).hexdigest())
    projection_path = Path(inner['execution']['worker_projection']['path'])
    projection = json.loads(projection_path.read_bytes())
    projection['CODEX_HOME'] = str(bundle / 'homes' / inner['role'])
    projection_path.chmod(0o600); projection_path.write_bytes(canonical(projection)); projection_path.chmod(0o400)
    inner['execution']['worker_projection']['sha256'] = sha256(projection_path.read_bytes()).hexdigest()
    inner_path.chmod(0o600); inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
    output=tmp_path/'private-output';output.mkdir(mode=0o700)
    logical='/srv/builder/tasks/'+packet['builder_run_id']+'/controller-output'
    packet.update(output_root=logical,limits={'max_output_bytes':131072})
    seal()
    template=tmp_path/'readiness-template.json'
    template.write_bytes(canonical(packet));template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE',str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT',packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST',packet['contract_sha256'])
    def directory(path,*,create=False):
        selected=output/Path(path).relative_to(logical)
        return private_directory(selected,create=create)
    monkeypatch.setattr('issue_orchestrator.execution.docker_provider_readiness.private_directory',directory)
    statvfs=os.statvfs
    monkeypatch.setattr(os,'statvfs',lambda path:statvfs(output if str(path)==logical else path))
    monkeypatch.setenv('GH_TOKEN','ambient-controller-must-not-leak')
    monkeypatch.setenv('CODEX_HOME','/ambient/controller-auth')
    monkeypatch.setattr('issue_orchestrator.execution.agent_runner_providers.base.shutil.which',lambda name:'/pinned/codex')
    credentials=Mock(spec=ProviderCredentials)
    credentials.session_env.return_value={'XORETS_DOCKER_MODEL_AUTH_JSON':'{"token":"auth-canary"}'}
    return packet,template,output,credentials


def test_private_auth_status_uses_actual_named_secret_and_existing_parser_then_removes_files(readiness,caplog):
    packet,template,output,credentials=readiness
    observed=[]
    class Runner:
        def __init__(self,environment,deadline,limit,executable):
            self.environment=environment
            assert executable.name == "codex" and executable.parent.name == "toolchain"
            assert deadline==packet['deadline_unix_ns'] and 0<limit<=65536
        def run(self,command,**kwargs):
            assert command==['codex','login','status']
            assert set(self.environment)=={'HOME','CODEX_HOME','PATH'}
            home=Path(self.environment['CODEX_HOME'])
            assert home.parent==output and home.stat().st_mode&0o777==0o700
            auth=home/'auth.json'
            assert auth.stat().st_mode&0o777==0o600
            assert json.loads(auth.read_bytes())=={'token':'auth-canary'}
            observed.append(home)
            return CommandResult(0,'','Logged in using ChatGPT')
    probe=CLIProviderReadinessProbe(Mock(),resolve_provider=lambda _:CodexProvider(),
        probe_context=lambda provider:docker_readiness_context(provider,Mock(),credentials,runner_factory=Runner))
    result=probe.check_launch_readiness('codex')
    assert result.authenticated and result.entitlement.auth_method=='chatgpt'
    credentials.session_env.assert_called_once_with('codex',docker=True)
    assert observed and not observed[0].exists() and list(output.iterdir())==[]
    assert 'auth-canary' not in caplog.text
    credentials.session_env.return_value={}
    assert not probe.check_launch_readiness('codex').launchable
    assert list(output.iterdir())==[]


@pytest.mark.parametrize('change',['provider','missing-secret','bad-json','oversize','deadline','untrusted-output','runner-failure'])
def test_selected_private_readiness_refuses_without_retaining_auth(readiness,change):
    packet,template,output,credentials=readiness
    provider='codex'
    if change=='provider':provider='claude'
    elif change=='missing-secret':credentials.session_env.return_value={}
    elif change=='bad-json':credentials.session_env.return_value={'XORETS_DOCKER_MODEL_AUTH_JSON':'[]'}
    elif change=='oversize':credentials.session_env.return_value={'XORETS_DOCKER_MODEL_AUTH_JSON':'x'*65537}
    elif change=='deadline':packet['deadline_unix_ns']=1
    elif change=='untrusted-output':packet['output_root']='/workspace/.auth'
    if change in {'deadline','untrusted-output'}:
        template.chmod(0o600);template.write_bytes(canonical(packet));template.chmod(0o400)
    class Failing:
        def __init__(self,*args):raise ValueError('status refused')
    with pytest.raises(DockerReadinessRefused):
        with docker_readiness_context(provider,Mock(),credentials,runner_factory=Failing):
            pytest.fail('refused context yielded')
    assert list(output.iterdir())==[]
    if change in {'provider','deadline','untrusted-output'}:credentials.session_env.assert_not_called()


def test_selected_context_refusal_is_typed_nonlaunchable_not_unknown():
    @contextmanager
    def refused(provider):
        raise DockerReadinessRefused('unsafe selected context')
        yield
    probe=CLIProviderReadinessProbe(Mock(),resolve_provider=lambda _:CodexProvider(),probe_context=refused)
    assert not probe.check_launch_readiness('codex').launchable


def test_auth_probe_runner_refuses_login_refresh_commands_before_spawn(tmp_path):
    import time
    from issue_orchestrator.execution.docker_provider_readiness import DockerAuthProbeRunner
    runner=DockerAuthProbeRunner({'PATH':'/usr/bin','HOME':str(tmp_path),'CODEX_HOME':str(tmp_path)},time.time_ns()+10_000_000_000,65536,tmp_path/'codex')
    for command in [['codex','login'],['codex','exec','model'],['sh','-c','codex login status']]:
        with pytest.raises(ValueError,match='only the existing local'):
            runner.run(command)


def test_existing_bounded_cli_capture_preserves_both_status_pipes_and_exit_code():
    import sys
    from issue_orchestrator.execution.terminal_docker import run_cli_capture
    output,error,code=run_cli_capture([sys.executable,'-c','import sys; print("not logged in",file=sys.stderr); raise SystemExit(1)'],environment={},timeout=5,output_limit=128)
    assert output==b'' and error==b'not logged in\n' and code==1
    with pytest.raises(ValueError,match='output bound exhausted'):
        run_cli_capture([sys.executable,'-c','print("x"*129)'],environment={},timeout=5,output_limit=128)


@pytest.mark.parametrize('token,authenticated', [('auth-canary', True), ('invalid', False), ('unknown', False)])
def test_actual_status_runner_ignores_builder_wrapper_first_PATH(readiness, monkeypatch, token, authenticated):
    packet, template, output, credentials = readiness
    inner = json.loads(Path(packet['worker_authority']['engine_contract_path']).read_bytes())
    bundle = Path(inner['capabilities']['capability_bundle'])
    wrapper = bundle / 'bin' / 'codex'; wrapper.parent.mkdir()
    marker = output.parent / 'wrapper-was-run'
    wrapper.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("wrong executable")\nraise SystemExit(9)\n')
    wrapper.chmod(0o555)
    # This is Builder's producer layout: ACP wrapper first, raw selected CLI outside PATH.
    monkeypatch.setenv('PATH', str(wrapper.parent) + ':/usr/bin:/bin')
    credentials.session_env.return_value = {'XORETS_DOCKER_MODEL_AUTH_JSON': json.dumps({'token': token})}
    probe = CLIProviderReadinessProbe(Mock(), resolve_provider=lambda _: CodexProvider(),
        probe_context=lambda provider: docker_readiness_context(provider, Mock(), credentials))
    result = probe.check_launch_readiness('codex')
    assert result.authenticated is authenticated
    assert result.launchable is authenticated
    if authenticated:
        assert result.entitlement.auth_method == 'chatgpt'
    assert not marker.exists() and list(output.iterdir()) == []


@pytest.mark.parametrize('change', ['missing-pin', 'wrong-pin', 'missing-binary', 'writable', 'hardlink', 'symlink'])
def test_selected_executable_provenance_refuses_before_secret_lookup(model_authority, readiness, change):
    packet, outer_path, outer, files, controls, seal = model_authority
    _, template, output, credentials = readiness
    inner_path = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(inner_path.read_bytes())
    tool = Path(inner['capabilities']['capability_bundle']) / 'toolchain/codex'
    if change == 'missing-pin': del inner['capabilities']['codex_sha256']
    elif change == 'wrong-pin': inner['capabilities']['codex_sha256'] = '0'*64
    elif change == 'missing-binary': tool.unlink()
    elif change == 'writable': tool.chmod(0o755)
    elif change == 'hardlink': os.link(tool, tool.with_name('another-link'))
    elif change == 'symlink':
        target = tool.with_name('actual'); tool.rename(target); tool.symlink_to(target)
    if change in {'missing-pin', 'wrong-pin'}:
        inner_path.chmod(0o600); inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
        seal(); template.chmod(0o600); template.write_bytes(canonical(packet)); template.chmod(0o400)
    with pytest.raises(DockerReadinessRefused):
        with docker_readiness_context('codex', Mock(), credentials):
            pytest.fail('unproven executable admitted')
    credentials.session_env.assert_not_called()
    assert list(output.iterdir()) == []
