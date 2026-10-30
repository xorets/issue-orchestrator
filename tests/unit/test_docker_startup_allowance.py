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
    inner = {'bounds': {'transient_launch_max_attempts': 2},
        'execution': {'docker_launch': {'template_path': str(template)}}}
    path = contracts / (run + '.json'); path.write_bytes(canonical(inner)); path.chmod(0o400)
    return {'builder_run_id':run, 'contract_sha256':sha256(canonical(inner)).hexdigest(),
        'worker_authority':{'engine_contract_path':str(path)}, 'mounts':[]}, template


def _attempt(packet, template, queue):
    try:
        reserve_startup(packet, template)
        queue.put(True)
    except (ValueError, OSError):
        queue.put(False)


def test_distinct_delivery_has_new_allowance(delivery):
    packet, template = delivery
    reserve_startup(packet, template); reserve_startup(packet, template)
    with pytest.raises(ValueError): reserve_startup(packet, template)
    packet = {**packet, 'builder_run_id':'run-' + 'b' * 32}
    reserve_startup(packet, template)


def test_concurrent_processes_do_not_exceed_limit(delivery):
    packet, template = delivery
    context = multiprocessing.get_context('fork')
    queue = context.Queue()
    processes = [context.Process(target=_attempt, args=(packet, template, queue)) for _ in range(8)]
    for process in processes: process.start()
    results = [queue.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert 1 <= sum(results) <= 2
    while sum(results) < 2:
        reserve_startup(packet, template); results.append(True)
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
    try:
        reserve_startup(packet, template)
    except ValueError:
        pass
    with pytest.raises(ValueError): reserve_startup(packet, template)
