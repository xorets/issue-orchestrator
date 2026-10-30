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
        settle(slot, descriptor, {'engine_run_dir':str(target)}, result.returncode)
    finally:
        os.close(descriptor)
    status = read_provider_status(target)
    assert status is not None and status.succeeded == (not message)
    assert (status.error_type.value if status.error_type else None) == kind


@pytest.mark.parametrize('attack', ['missing', 'symlink', 'hardlink', 'oversized', 'malformed', 'extra', 'exit', 'bool-attempt', 'slot-symlink'])
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
    path.write_text(json.dumps(status))
    if attack == 'missing': path.unlink()
    if attack == 'symlink': path.unlink(); path.symlink_to(target)
    if attack == 'hardlink': os.link(path, tmp_path / 'hardlink')
    if attack == 'oversized': path.write_bytes(b'x'*4097)
    if attack == 'malformed': path.write_text('{')
    if attack == 'slot-symlink':
        moved = tmp_path / 'moved'; slot.rename(moved); slot.symlink_to(moved)
    try:
        with pytest.raises((ValueError, OSError)): settle(slot, descriptor, {'engine_run_dir':str(target)}, 0)
    finally:
        os.close(descriptor)
    assert not (target / 'provider-status.json').exists()


@pytest.mark.parametrize('attack', ['outside', 'symlink', 'missing-mount', 'overlap'])
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
    inner = {'run_id':run, 'capabilities':{'scratch':str(selected)}}
    raw = canonical(inner); path.write_bytes(raw); path.chmod(0o400)
    mount = {'source':str(selected), 'target':str(selected), 'read_only':False}
    packet = {'builder_run_id':run, 'run_id':'20261017-100000Z-' + 'a'*32,
        'contract_sha256':sha256(raw).hexdigest(), 'worker_authority':{'engine_contract_path':str(path)},
        'mounts':[] if attack == 'missing-mount' else [mount]}
    if attack == 'overlap': packet['mounts'].append({'source':str(root), 'target':str(root), 'read_only':False})
    with pytest.raises((OSError, ValueError)): allocate(packet, root)
