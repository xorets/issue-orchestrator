"""Source-owned no-start disposition under the Docker session lifecycle lock."""
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable

from ..domain.docker_execution import DockerSessionState
from .docker_launch_input import sealed_bytes
from .docker_worker_state import require_never_started_exec


class ProviderIntentError(RuntimeError):
    """The durable start intention could not be recorded."""


def refuse_uncertain_start(attempt_uncertain: bool, error: Exception) -> None:
    if attempt_uncertain:
        raise RuntimeError('Docker allocated original custody requires reconciliation') from error


def require_never_started(engine, launch_path: Path | None, record: dict, actual: dict | None = None) -> None:
    if launch_path is None:
        raise ValueError('Docker launch binding is unavailable')
    packet = json.loads(sealed_bytes(launch_path, expected=record['launch_sha256']))
    if engine.request('GET', '/info').get('ID') != record['daemon_id']:
        raise ValueError('Docker daemon changed before settlement')
    if actual is None:
        actual = engine.request('GET', f"/exec/{record['provider_exec_id']}/json")
    if not isinstance(actual, dict):
        raise ValueError('Docker provider observation is unknown')
    process = actual.get('ProcessConfig')
    if type(process) is not dict or type(process.get('arguments')) is not list:
        raise ValueError('Docker provider process identity is unknown')
    args = process['arguments']
    if (process.get('entrypoint') != '/bin/sh' or len(args) != 2 or args[0] != '-c' or
            type(args[1]) is not str or sha256(args[1].encode()).hexdigest() != packet['command_sha256']):
        raise ValueError('Docker provider command identity changed')
    require_never_started_exec(actual, record['container_id'], record['provider_exec_id'],
        packet['user'], ['/bin/sh', *args])


def after_stop(engine, launch_path: Path | None, record: dict) -> dict:
    if engine.request('GET', '/info').get('ID') != record['daemon_id']:
        raise ValueError('Docker daemon changed after stop')
    worker = engine.request('GET', f"/containers/{record['container_id']}/json")
    if (worker.get('Id') != record['container_id'] or worker.get('State', {}).get('Running') is not False or
            worker.get('Config', {}).get('Labels', {}).get('io.builder.launch') != record['launch_sha256']):
        raise ValueError('Docker stopped worker custody changed')
    result = engine.inspect_exec(record['provider_exec_id'])
    if result == {'status':404}:
        return {'kind':'exact-exec-not-found', 'status':404}
    if (type(result) is not dict or set(result) != {'status','value'} or type(result['status']) is not int or
            result['status'] != 200 or type(result['value']) is not dict):
        raise ValueError('Docker post-stop exec observation is unknown')
    require_never_started(engine, launch_path, record, result['value'])
    return {'running':False, 'pid':0, 'exit_code':None}


def stop_retained(engine, launch_path: Path | None, record: dict, save: Callable[[], None]) -> None:
    pending = (record.get('state') == DockerSessionState.EXEC_CREATED and
        type(record.get('start_gate_version')) is int and record['start_gate_version'] == 1 and
        record.get('start_intent') == 'not-requested' and record.get('original_binding') == 'bound' and
        re.fullmatch(r'[0-9a-f]{40}', record.get('original_fence', '')) is not None)
    failure = None
    if pending:
        try:
            record['start_intent'] = 'cancelled-before-start'
            save()
            require_never_started(engine, launch_path, record)
        except (OSError, ValueError, TypeError, KeyError) as error:
            failure = error
    engine.stop(record['container_id'])
    record['state'] = DockerSessionState.STOPPED
    if pending and failure is None:
        try:
            after = after_stop(engine, launch_path, record)
            observation = {'running':False, 'pid':0, 'exit_code':None}
            record['never_started'] = {'schema_version':1, 'kind':'docker-never-started',
                **{key:record[key] for key in ('run_id', 'contract_sha256', 'launch_sha256',
                    'daemon_id', 'controller_container_id', 'container_id', 'provider_exec_id')},
                'disposition':'cancelled-before-exec-start', 'before':observation,
                'stop_wait':'completed', 'after':after}
        except (OSError, ValueError, TypeError, KeyError) as error:
            failure = error
    save()
    if failure is not None:
        raise failure
