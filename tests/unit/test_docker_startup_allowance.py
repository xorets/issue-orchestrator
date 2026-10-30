"""Real filesystem checks for delivery startup reservations."""
from hashlib import sha256
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from issue_orchestrator.execution.docker_launch_input import canonical
from issue_orchestrator.execution.docker_startup_allowance import reserve_startup


@pytest.fixture
def delivery(tmp_path):
    root = tmp_path / 'authority'; root.mkdir(mode=0o700)
    templates = root / 'launch-templates-docker-v1'; templates.mkdir(mode=0o700)
    contracts = root / 'engine-contracts-docker-v1'; contracts.mkdir(mode=0o700)
    run = 'run-' + 'a' * 32
    template = templates / 'template.json'
    inner = {'run_id': run, 'bounds': {'transient_launch_max_attempts': 2},
        'execution': {'docker_launch': {'template_path': str(template)}}}
    path = contracts / (run + '.json'); path.write_bytes(canonical(inner)); path.chmod(0o400)
    return {'builder_run_id':run, 'run_id':'20261017-100000Z-' + 'a'*32, 'contract_sha256':sha256(canonical(inner)).hexdigest(),
        'worker_authority':{'engine_contract_path':str(path)}, 'mounts':[]}, template


def _attempt(packet, template, queue):
    try:
        reserve_startup(packet, template)
        queue.put(True)
    except (ValueError, OSError):
        queue.put(False)


def test_distinct_delivery_has_new_allowance(delivery):
    packet, template = delivery
    reserve_startup(packet, template)
    record = json.loads((template.parent / ('startup-' + packet['builder_run_id']) / '00000001.json').read_bytes())
    assert record['engine_run_id'] == packet['run_id']
    assert record['launch_sha256'] == sha256(canonical(packet)).hexdigest()
    with pytest.raises(ValueError): reserve_startup(packet, template)
    second = {**packet, 'run_id':'20261017-100000Z-' + 'b'*32}
    reserve_startup(second, template)
    with pytest.raises(ValueError): reserve_startup({**packet, 'run_id':'20261017-100000Z-' + 'c'*32}, template)
    run = 'run-' + 'b'*32
    path = Path(packet['worker_authority']['engine_contract_path']).with_name(run + '.json')
    inner = {'run_id':run, 'bounds':{'transient_launch_max_attempts':2},
        'execution':{'docker_launch':{'template_path':str(template)}}}
    path.write_bytes(canonical(inner)); path.chmod(0o400)
    fresh = {**packet, 'builder_run_id':run, 'contract_sha256':sha256(canonical(inner)).hexdigest(),
        'worker_authority':{'engine_contract_path':str(path)}}
    reserve_startup(fresh, template)


@pytest.mark.parametrize('builder', ['run-' + 'b'*32, '../escape', 'run-' + 'a'*31])
def test_changed_builder_identity_refused_before_namespace(delivery, builder):
    packet, template = delivery
    with pytest.raises(ValueError): reserve_startup({**packet, 'builder_run_id':builder}, template)
    assert list(template.parent.iterdir()) == []


def test_concurrent_processes_do_not_exceed_limit(delivery):
    packet, template = delivery
    context = multiprocessing.get_context('fork')
    queue = context.Queue()
    processes = [context.Process(target=_attempt, args=({**packet, 'run_id':'20261017-100000Z-' + format(index, '032x')}, template, queue)) for index in range(8)]
    for process in processes: process.start()
    results = [queue.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert 1 <= sum(results) <= 2
    while sum(results) < 2:
        reserve_startup({**packet, 'run_id':'20261017-100000Z-' + 'f'*32}, template); results.append(True)
    with pytest.raises(ValueError): reserve_startup(packet, template)


@pytest.mark.parametrize('change', ['empty', 'foreign', 'hardlink', 'symlink', 'mode', 'writable-source', 'writable-target'])
def test_unsafe_custody_never_resets_allowance(delivery, change, tmp_path):
    packet, template = delivery
    reserve_startup(packet, template)
    namespace = template.parent / ('startup-' + packet['builder_run_id'])
    record = namespace / '00000001.json'
    if change == 'empty': record.chmod(0o600); record.write_bytes(b''); record.chmod(0o400)
    if change == 'foreign': record.chmod(0o600); record.write_bytes(b'{}\n'); record.chmod(0o400)
    if change == 'hardlink': os.link(record, tmp_path / 'link')
    if change == 'symlink': record.unlink(); record.symlink_to(tmp_path / 'missing')
    if change == 'mode': record.chmod(0o600)
    if change.startswith('writable-'):
        source, target = '/unrelated', '/unrelated'
        if change == 'writable-source': source = str(template.parent)
        else: target = str(template.parent)
        packet['mounts'] = [{'source':source, 'target':target, 'read_only':False}]
    with pytest.raises((ValueError, OSError)): reserve_startup(packet, template)


def test_torn_record_never_replays(delivery):
    packet, template = delivery
    reserve_startup(packet, template)
    namespace = template.parent / ('startup-' + packet['builder_run_id'])
    record = namespace / '00000002.json'
    record.touch(mode=0o400)
    with pytest.raises(ValueError): reserve_startup(packet, template)


def _interrupt_before_record_fsync(packet, template):
    real_fsync = os.fsync
    def interrupt(fd):
        if os.path.basename(os.readlink('/proc/self/fd/' + str(fd))) == '00000001.json':
            os._exit(73)
        real_fsync(fd)
    os.fsync = interrupt
    reserve_startup(packet, template)


def test_interrupted_record_write_is_never_refunded(delivery):
    packet, template = delivery
    process = multiprocessing.get_context('fork').Process(target=_interrupt_before_record_fsync, args=(packet, template))
    process.start(); process.join(10)
    if process.is_alive():
        process.terminate(); process.join()
        pytest.fail('reservation process did not settle')
    assert process.exitcode == 73
    # The complete visible marker counts as spent; an incomplete marker fails closed.
    namespace = template.parent / ('startup-' + packet['builder_run_id'])
    assert (namespace / '00000001.json').exists()
    with pytest.raises(ValueError): reserve_startup(packet, template)
    next_run = {**packet, 'run_id':'20261017-100000Z-' + 'b'*32}
    try:
        reserve_startup(next_run, template)
    except ValueError:
        pass
    with pytest.raises(ValueError): reserve_startup({**packet, 'run_id':'20261017-100000Z-' + 'c'*32}, template)


def test_plugin_import_does_not_require_fcntl():
    import subprocess
    import sys
    script = '''
import builtins
original = builtins.__import__
def block(name, *args, **kwargs):
    if name == "fcntl":
        raise ImportError("fcntl unavailable")
    return original(name, *args, **kwargs)
builtins.__import__ = block
import issue_orchestrator.execution.terminal_docker
import issue_orchestrator.execution.docker_startup_allowance
'''
    subprocess.run([sys.executable, '-c', script], check=True, timeout=10)


def test_new_start_cannot_refund_unbound_original_allocation(delivery, monkeypatch):
    packet, template = delivery
    # Test-container root ownership is mapped to nobody; isolate that platform boundary.
    monkeypatch.setattr('issue_orchestrator.execution.docker_startup_allowance._require_custody',
        lambda packet, template, inner, inner_path: template.parent)
    contract = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(contract.read_bytes()); inner['role'] = 'standard-implementation'
    contract.chmod(0o600); contract.write_bytes(canonical(inner)); contract.chmod(0o400)
    packet['contract_sha256'] = sha256(canonical(inner)).hexdigest()
    reserve_startup(packet, template)
    next_packet = {**packet, 'run_id':'20261017-100000Z-' + 'b'*32}
    with pytest.raises((ValueError, OSError)): reserve_startup(next_packet, template)
    directory = template.parent / packet['run_id']; directory.mkdir(mode=0o700)
    receipt = directory / 'docker-session.json'
    value = {'run_id':packet['run_id'], 'launch_sha256':sha256(canonical(packet)).hexdigest(),
        'contract_sha256':packet['contract_sha256'], 'original_binding':'pending', 'start_gate_version':1}
    receipt.write_bytes(canonical(value)); receipt.chmod(0o600)
    with pytest.raises(ValueError): reserve_startup(next_packet, template)
    value.update(original_binding='bound', original_fence='a'*40)
    receipt.write_bytes(canonical(value))
    reserve_startup(next_packet, template)
