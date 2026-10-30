"""The Docker provider handoff retains bounded untrusted status as a diagnostic."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from issue_orchestrator.control.provider_command_wrapper import ProviderCommandWrapper
from issue_orchestrator.domain.models import AgentConfig
from issue_orchestrator.execution.docker_provider_status import settle
from issue_orchestrator.infra.config_models import ProviderShortRetryConfig
from issue_orchestrator.infra.provider_resilience import read_provider_status


@pytest.mark.parametrize(('message', 'kind'), [('', None), ('authentication failed', 'auth'),
    ('connection refused', 'transient'), ('usage_limit_exceeded', 'quota')])
def test_actual_runner_status_survives_handoff(tmp_path, message, kind):
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    target = tmp_path / 'controller'; target.mkdir(mode=0o700)
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    agent = AgentConfig(prompt_path=tmp_path / 'prompt', provider='codex', provider_args={'execution_mode':'exec'})
    wrapper = ProviderCommandWrapper(ProviderShortRetryConfig(max_attempts=1, initial_backoff_seconds=1,
        max_backoff_seconds=1, jitter=False))
    command = 'true' if not message else f'printf "{message}\\n" >&2; exit 1'
    argv = __import__('shlex').split(wrapper.wrap(command, agent, slot))
    env = {**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[2] / 'src')}
    result = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, timeout=10)
    try:
        settle(slot, descriptor, 'codex', False, {'engine_run_dir':str(target)}, result.returncode)
    finally:
        os.close(descriptor)
    status = read_provider_status(target)
    assert status is not None and status.succeeded == (not message)
    assert (status.error_type.value if status.error_type else None) == kind


@pytest.mark.parametrize('attack', ['missing', 'symlink', 'hardlink', 'oversized', 'malformed', 'extra', 'exit', 'bool-attempt', 'foreign-provider', 'foreign-lane', 'heals', 'slot-symlink'])
def test_refuses_untrusted_provider_status(tmp_path, attack):
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    target = tmp_path / 'controller'; target.mkdir(mode=0o700)
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    status = {'provider':'codex', 'error_type':None, 'attempts':1, 'succeeded':True, 'exit_code':0,
        'timed_out':False, 'last_error_summary':None, 'last_attempt_at':'2026-10-30T00:00:00+00:00', 'quota_heals_on_timer':False}
    path = slot / 'provider-status.json'
    if attack == 'extra': status['extra'] = True
    if attack == 'exit': status['exit_code'] = 1
    if attack == 'bool-attempt': status['attempts'] = True
    if attack == 'foreign-provider': status['provider'] = 'other'
    if attack == 'foreign-lane': status['provider'] = 'codex:foreign'
    if attack == 'heals': status['quota_heals_on_timer'] = True
    path.write_text(json.dumps(status))
    if attack == 'missing': path.unlink()
    if attack == 'symlink': path.unlink(); path.symlink_to(target)
    if attack == 'hardlink': os.link(path, tmp_path / 'hardlink')
    if attack == 'oversized': path.write_bytes(b'x'*4097)
    if attack == 'malformed': path.write_text('{')
    if attack == 'slot-symlink':
        moved = tmp_path / 'moved'; slot.rename(moved); slot.symlink_to(moved)
    try:
        with pytest.raises((ValueError, OSError)): settle(slot, descriptor, 'codex', False, {'engine_run_dir':str(target)}, 0)
    finally:
        os.close(descriptor)
    assert not (target / 'provider-status.json').exists()


@pytest.mark.parametrize('attack', ['outside', 'symlink', 'missing-mount', 'overlap', 'foreign-provider'])
def test_scratch_allocation_requires_exact_selected_mount(tmp_path, attack):
    from hashlib import sha256
    from issue_orchestrator.execution.docker_launch_input import canonical
    from issue_orchestrator.execution.docker_provider_status import allocate
    root = tmp_path / 'task'; root.mkdir(mode=0o700)
    scratch = root / 'scratch'; scratch.mkdir(mode=0o700)
    path = tmp_path / 'inner.json'
    run = 'run-' + 'a'*32
    selected = tmp_path / 'foreign' if attack == 'outside' else scratch
    if attack == 'outside': selected.mkdir(mode=0o700)
    if attack == 'symlink':
        moved = root / 'moved'; scratch.rename(moved); scratch.symlink_to(moved)
    inner = {'run_id':run, 'capabilities':{'scratch':str(selected)}, 'execution':{'provider':'codex'}}
    raw = canonical(inner); path.write_bytes(raw); path.chmod(0o400)
    mount = {'source':str(selected), 'target':str(selected), 'read_only':False}
    packet = {'builder_run_id':run, 'run_id':'20261017-100000Z-' + 'a'*32,
        'contract_sha256':sha256(raw).hexdigest(), 'worker_authority':{'engine_contract_path':str(path)},
        'mounts':[] if attack == 'missing-mount' else [mount]}
    if attack == 'overlap': packet['mounts'].append({'source':str(root), 'target':str(root), 'read_only':False})
    provider = "other" if attack == "foreign-provider" else "codex"
    with pytest.raises((OSError, ValueError)):
        allocate(packet, root, "python -m issue_orchestrator.entrypoints.cli_tools.provider_runner --provider " + provider)


@pytest.mark.parametrize('worker_time', ['2099-01-01T00:00:00+00:00', '2001-01-01T00:00:00+00:00'])
def test_worker_timestamp_cannot_set_circuit_chronology(tmp_path, worker_time, monkeypatch):
    from datetime import datetime, timezone
    from issue_orchestrator.control.provider_circuit_effects import record_provider_resilience_effects
    from issue_orchestrator.control.provider_resilience import ProviderResilienceManager
    from issue_orchestrator.control.session_decision import SessionDecision, provider_success_from_status
    from issue_orchestrator.domain.models import SessionStatus
    from issue_orchestrator.infra.config import ProviderResilienceConfig
    from issue_orchestrator.ports import InMemoryProviderCircuitStore, NullEventSink

    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    target = tmp_path / 'controller'; target.mkdir(mode=0o700)
    value = {'provider':'codex', 'error_type':None, 'attempts':1, 'succeeded':True, 'exit_code':0,
        'timed_out':False, 'last_error_summary':None, 'last_attempt_at':worker_time, 'quota_heals_on_timer':False}
    (slot / 'provider-status.json').write_text(json.dumps(value))
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = datetime(2026, 10, 30, 15, 0, tzinfo=timezone.utc)
    monkeypatch.setattr('issue_orchestrator.execution.docker_provider_status.now_iso', lambda: observed.isoformat())
    try:
        settle(slot, descriptor, 'codex', False, {'engine_run_dir':str(target)}, 0)
    finally:
        os.close(descriptor)
    status = read_provider_status(target)
    assert status is not None
    store = InMemoryProviderCircuitStore()
    manager = ProviderResilienceManager(ProviderResilienceConfig(), store=store, events=NullEventSink())
    decision = SessionDecision(status=SessionStatus.COMPLETED, provider_success=provider_success_from_status(status))
    record_provider_resilience_effects(decision, manager)
    evidence = store.get_evidence('codex')
    assert evidence is not None
    assert evidence.success_observed_at == observed


def test_real_timed_out_runner_status_reports_timeout(tmp_path):
    import shlex
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    target = tmp_path / 'controller'; target.mkdir(mode=0o700)
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    agent = AgentConfig(prompt_path=tmp_path / 'prompt', provider='codex', provider_args={'execution_mode':'exec'})
    wrapper = ProviderCommandWrapper(ProviderShortRetryConfig(max_attempts=1, initial_backoff_seconds=1,
        max_backoff_seconds=1, jitter=False))
    command = wrapper.wrap("/usr/bin/python3 -c 'import select; select.select([], [], [])'", agent, slot)
    argv = shlex.split(command); argv[argv.index('--timeout-seconds') + 1] = '1'
    env = {**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[2] / 'src')}
    try:
        child = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, timeout=15)
        assert child.returncode == 124
        status = settle(slot, descriptor, 'codex', False, {'engine_run_dir':str(target)}, child.returncode)
    finally:
        os.close(descriptor)
    assert status.timed_out and status.diagnostic() == {'phase':'provider', 'reason':'provider_timeout'}

@pytest.mark.parametrize('kind', ['auth', 'quota'])
def test_observed_timeout_is_diagnostic_even_with_circuit_classification(kind):
    from issue_orchestrator.ports.provider_resilience import ProviderStatus
    payload = {'provider':'codex', 'error_type':kind, 'attempts':1, 'succeeded':False, 'exit_code':124,
        'timed_out':True, 'last_error_summary':None, 'last_attempt_at':'2026-10-30T00:00:00+00:00',
        'quota_heals_on_timer':False}
    status = ProviderStatus.from_worker_payload(payload, 124, 'codex', False)
    assert status.error_type.value == kind
    assert status.diagnostic() == {'phase':'provider', 'reason':'provider_timeout'}


def test_child_diagnostic_reads_selected_slot_without_changing_provider_status(tmp_path):
    from hashlib import sha256
    from issue_orchestrator.execution.docker_provider_status import read_child_diagnostic
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    controller = tmp_path / 'controller'; controller.mkdir(mode=0o700)
    run = '20261030-193948Z-' + 'a'*32
    launch = 'b'*64
    child = {'schema_version':1, 'kind':'builder-codex-child-diagnostic', 'run_id':run,
        'launch_sha256':launch, 'phase':'codex-child', 'reason':'nonzero', 'exit_code':2,
        'exception_type':None, 'stderr_bytes':3, 'stderr_sha256':sha256(b'bad').hexdigest(), 'stderr_truncated':False,
        'elapsed_ms':14, 'remaining_ms':100, 'own_timer_fired':False, 'secondary':[]}
    (slot / 'child-diagnostic.json').write_text(json.dumps(child)); (slot / 'child-diagnostic.json').chmod(0o600)
    status = {'provider':'codex', 'error_type':None, 'attempts':1, 'succeeded':False, 'exit_code':78,
        'timed_out':False, 'last_error_summary':None, 'last_attempt_at':'2026-10-30T00:00:00+00:00', 'quota_heals_on_timer':False}
    (slot / 'provider-status.json').write_text(json.dumps(status))
    fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        settled = settle(slot, fd, 'codex', False, {'engine_run_dir':str(controller)}, 78)
        assert read_child_diagnostic(fd, run, launch, settled, 78) == {**child, 'source':'slot'}
    finally:
        os.close(fd)
    assert set(json.loads((controller / 'provider-status.json').read_text())) == set(status)


@pytest.mark.parametrize(('message', 'accepted'), [
    ('ACPCHILD1|nonzero|2|n|10|20|0|1', True),
    ('ACPCHILD1|timeout|n|TimeoutExpired|10|20|1|0', True),
    ('ACPCHILD1|interrupted|n|KeyboardInterrupt|10|20|0|0', True),
    ('ACPCHILD1|nonzero|2|n|10|20|0|1 extra', False),
    ('ACPCHILD1|nonzero|2|n|10|20|0|1\nACPCHILD1|nonzero|2|n|10|20|0|1', False),
    ('ACPCHILD1|timeout|n|TimeoutExpired|10|20|0|0', False),
    ('ACPCHILD1|nonzero|2|n|10|20|0|', False),
    ('ACPCHILD1|nonzero|2|n|10|20|0|0' + 'x'*310, False),
])
def test_real_provider_runner_transports_only_exact_fallback_marker(tmp_path, message, accepted):
    import shlex
    from issue_orchestrator.execution.docker_provider_status import read_child_diagnostic
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    controller = tmp_path / 'controller'; controller.mkdir(mode=0o700)
    agent = AgentConfig(prompt_path=tmp_path / 'prompt', provider='codex', provider_args={'execution_mode':'exec'})
    wrapper = ProviderCommandWrapper(ProviderShortRetryConfig(max_attempts=1, initial_backoff_seconds=1,
        max_backoff_seconds=1, jitter=False))
    command = 'printf %s ' + shlex.quote(message) + ' >&2; exit 78'
    argv = shlex.split(wrapper.wrap(command, agent, slot))
    env = {**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[2] / 'src')}
    result = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, timeout=10)
    fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        status = settle(slot, fd, 'codex', False, {'engine_run_dir':str(controller)}, result.returncode)
        child = read_child_diagnostic(fd, '20261030-193948Z-' + 'a'*32, 'b'*64, status, result.returncode)
    finally:
        os.close(fd)
    assert (child is not None) is accepted
    if child:
        assert child['source'] == 'marker' and 'record_failed' in child['secondary']


@pytest.mark.parametrize('attack', ['malformed', 'foreign', 'mode', 'symlink', 'hardlink', 'oversized', 'duplicate'])
def test_present_unsafe_child_companion_cannot_use_marker_fallback(tmp_path, attack):
    from issue_orchestrator.execution.docker_provider_status import read_child_diagnostic
    from issue_orchestrator.ports.provider_resilience import ProviderStatus
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    path = slot / 'child-diagnostic.json'
    path.write_text('{"x":1,"x":2}' if attack == 'duplicate' else '{')
    path.chmod(0o600)
    if attack == 'foreign':
        path.write_text(json.dumps({'schema_version':1, 'kind':'builder-codex-child-diagnostic',
            'run_id':'foreign', 'launch_sha256':'b'*64, 'phase':'codex-child', 'reason':'nonzero',
            'exit_code':2, 'exception_type':None, 'stderr_bytes':None, 'stderr_sha256':None,
            'stderr_truncated':None, 'elapsed_ms':10, 'remaining_ms':20,
            'own_timer_fired':False, 'secondary':[]}))
    if attack == 'mode': path.chmod(0o644)
    if attack == 'symlink': path.unlink(); path.symlink_to(tmp_path / 'missing')
    if attack == 'hardlink': os.link(path, tmp_path / 'link')
    if attack == 'oversized': path.write_bytes(b'x'*4097)
    status = ProviderStatus(provider='codex', error_type=None, attempts=1, succeeded=False, exit_code=78,
        timed_out=False, last_error_summary='ACPCHILD1|nonzero|2|n|10|20|0|0', last_attempt_at='2026-10-30T00:00:00+00:00')
    fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        assert read_child_diagnostic(fd, '20261030-193948Z-' + 'a'*32, 'b'*64, status, 78) is None
    finally:
        os.close(fd)


def test_marker_metadata_does_not_open_a_provider_circuit(tmp_path, monkeypatch):
    from issue_orchestrator.execution.agent_runner_types import AgentSpec, RetryPolicy
    from issue_orchestrator.entrypoints.cli_tools.provider_runner import _DockerCodexRunner
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_CALLBACK_SCOPE', 'docker')
    runner = _DockerCodexRunner()
    marker = 'ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0'
    result = runner.run(AgentSpec(command=['/bin/sh', '-c', 'printf %s ' + __import__('shlex').quote(marker) + ' >&2; exit 78'],
        working_dir=tmp_path, timeout_seconds=5, output_dir=tmp_path / 'output', retry_policy=RetryPolicy(max_attempts=1)))
    assert result.stderr == marker
    assert result.provider_error_type is None


@pytest.mark.parametrize('extra', [' leading', 'trailing ', 'extra-newline'])
def test_docker_runner_does_not_normalize_ambiguous_marker(tmp_path, monkeypatch, extra):
    import shlex
    from issue_orchestrator.entrypoints.cli_tools.provider_runner import main
    from issue_orchestrator.execution import docker_provider_status
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_CALLBACK_SCOPE', 'docker')
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR', str(slot))
    monkeypatch.setattr(docker_provider_status, 'worker_slot', lambda value, run_dir: Path(value))
    marker = 'ACPCHILD1|nonzero|2|n|10|20|0|0'
    text = ' ' + marker if extra == ' leading' else marker + ' ' if extra == 'trailing ' else marker + '\n\n'
    command = 'printf %s ' + shlex.quote(text) + ' >&2; exit 78'
    assert main(['--command',command,'--provider','codex','--run-dir',str(slot), '--max-attempts','1']) == 78
    status = read_provider_status(slot)
    fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        assert docker_provider_status.read_child_diagnostic(fd, '20261030-193948Z-' + 'a'*32, 'b'*64, status, 78) is None
    finally:
        os.close(fd)


@pytest.mark.parametrize(('message', 'exact'), [
    ('ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0', True),
    ('ACPCHILD1|nonzero|2|n|500|401|0|0', True),
    (' ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0', False),
    ('ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0 extra', False),
    ('ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0\nACPCHILD1|timeout|n|TimeoutExpired|401|429|1|0', False),
    ('ACPCHILD1|timeout|n|TimeoutExpired|401|429|1|', False),
    ('provider authentication failed 401', False),
    ('provider service unavailable 500', False),
])
def test_marker_classification_is_narrow(tmp_path, message, exact):
    import shlex
    from issue_orchestrator.entrypoints.cli_tools.provider_runner import _DockerCodexRunner
    from issue_orchestrator.execution.agent_runner_errors import classify_provider_error
    from issue_orchestrator.execution.agent_runner_types import AgentSpec, RetryPolicy
    from issue_orchestrator.execution.subprocess_runner import SubprocessAgentRunner

    command = ['/bin/sh', '-c', 'printf %s ' + shlex.quote(message) + ' >&2; exit 78']
    spec = AgentSpec(command=command, working_dir=tmp_path, timeout_seconds=5,
        output_dir=tmp_path / 'output', retry_policy=RetryPolicy(max_attempts=1))
    actual = _DockerCodexRunner().run(spec)
    ordinary = SubprocessAgentRunner().run(spec)
    expected = classify_provider_error(stdout='', stderr=message, exit_code=78, timed_out=False)
    assert ordinary.provider_error_type == expected
    assert actual.provider_error_type == (None if exact else expected)
    assert actual.stderr == message and actual.attempts == 1


def test_selected_docker_entrypoint_does_not_classify_marker_metadata(tmp_path, monkeypatch):
    import shlex
    from issue_orchestrator.entrypoints.cli_tools.provider_runner import main
    from issue_orchestrator.execution import docker_provider_status
    slot = tmp_path / 'slot'; slot.mkdir(mode=0o700)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_CALLBACK_SCOPE', 'docker')
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR', str(slot))
    monkeypatch.setattr(docker_provider_status, 'worker_slot', lambda value, run_dir: Path(value))
    marker = 'ACPCHILD1|timeout|n|TimeoutExpired|401|500|1|0'
    command = 'printf %s ' + shlex.quote(marker + '\n') + ' >&2; exit 78'
    assert main(['--command', command, '--provider', 'codex', '--run-dir', str(slot), '--max-attempts', '1']) == 78
    status = read_provider_status(slot)
    assert status.error_type is None and status.last_error_summary == marker
