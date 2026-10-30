"""Worker seal projection is explicit and authenticates the controller envelope."""
from hashlib import sha256
from pathlib import Path
import pytest

from issue_orchestrator.execution.terminal_docker import canonical
from issue_orchestrator.execution.docker_worker_authority import worker_environment


@pytest.fixture
def authority(tmp_path):
    run = "run-" + "a" * 32
    outer_path = tmp_path / "execution-contracts-docker-v1" / (run + ".json")
    inner_path = tmp_path / "engine-contracts-docker-v1" / (run + ".json")
    packet = {"builder_run_id": run, "repository": "local/one", "working_dir": "/workspace",
        "session_name": "issue-42", "image_id": "sha256:" + "b" * 64,
        "worker_authority": {"contract_path": str(outer_path), "engine_contract_path": str(inner_path)},
        "mounts": [{"source": str(p), "target": str(p), "read_only": True} for p in (outer_path, inner_path)]}
    subject = {key: {} for key in ("repository", "issue", "branch", "role", "bounds", "capabilities", "supervised")}
    subject.update(run_id=run, repository={"name": "local/one"}, execution={"workspace": "/workspace",
        "session_name": "issue-42", "agent_label": "coding-1", "logical_child": "original", "backend": "docker",
        "callback": {"scope": "docker", "host": "controller", "bind_host": "0.0.0.0"},
        "docker_launch": {"template_path": "/private/template.json", "intent_sha256": sha256(canonical(packet)).hexdigest()}})
    inner = {"schema_version": 4, "controller_compatibility": "supervised-v4", **subject}
    packet["contract_sha256"] = sha256(canonical(inner)).hexdigest()
    outer = {"schema_version": 1, "kind": "builder-docker-delivery", "model_admission": False,
        "run_id": run, "subject": subject, "engine_contract": {"path": str(inner_path), "sha256": packet["contract_sha256"]},
        "worker": {"image_id": packet["image_id"], "manifest_sha256": "c" * 64}, "installed_acceptance": None}
    for p, value in ((inner_path, inner), (outer_path, outer)):
        p.parent.mkdir(mode=0o700)
        p.write_bytes(canonical(value)); p.chmod(0o400)
    return packet, outer_path, outer


def test_projects_only_verified_outer_authority_and_explicit_callback(authority, monkeypatch):
    packet, path, _ = authority
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_API_TOKEN", "admin-must-not-leak")
    monkeypatch.setenv("GH_TOKEN", "github-must-not-leak")
    before = canonical(packet)
    result = worker_environment(packet, {"PROVIDER_KEY": "provider-secret", "ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY": "e" * 64}, "d" * 64)
    assert result == {"XORETS_EXECUTION_CONTRACT": str(path), "XORETS_EXECUTION_DIGEST": sha256(path.read_bytes()).hexdigest(),
        "PROVIDER_KEY": "provider-secret", "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN": "d" * 64,
        "ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY": "e" * 64}

    assert canonical(packet) == before
    assert b"e" * 64 not in before


@pytest.mark.parametrize("change", ["subject", "inner", "image", "writable", "ancestor", "missing-mount"])
def test_refuses_changed_authority_or_writable_projection(authority, change):
    packet, path, outer = authority
    if change == "subject": outer["subject"]["issue"] = {"number": 999}
    if change == "inner": outer["engine_contract"]["sha256"] = "0" * 64
    if change == "image": outer["worker"]["image_id"] = "sha256:" + "0" * 64
    if change == "writable": packet["mounts"][0]["read_only"] = False
    if change == "ancestor": packet["mounts"].append({"source": str(path.parent), "target": str(path.parent), "read_only": False})
    if change == "missing-mount": packet["mounts"].pop()
    path.chmod(0o600); path.write_bytes(canonical(outer)); path.chmod(0o400)
    with pytest.raises(ValueError): worker_environment(packet, {"ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY": "e" * 64}, "d" * 64)


@pytest.mark.parametrize("name", ["XORETS_EXECUTION_CONTRACT", "XORETS_EXECUTION_DIGEST", "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN", "ISSUE_ORCHESTRATOR_MODEL_GATEWAY_TOKEN", "ISSUE_ORCHESTRATOR_API_TOKEN", "GH_TOKEN"])
def test_provider_credentials_cannot_override_authority_or_add_controller_credentials(authority, name):
    with pytest.raises(ValueError): worker_environment(authority[0], {name: "forged"}, "d" * 64)


def test_unprojected_primitive_receives_no_controller_authority(monkeypatch):
    monkeypatch.setenv("XORETS_EXECUTION_CONTRACT", "/private/controller.json")
    assert worker_environment({}, {"PROVIDER_KEY": "secret"}, None) == {"PROVIDER_KEY": "secret"}


@pytest.mark.parametrize("capability", [None, "", "wrong-format"])
def test_projected_worker_requires_private_completion_capability(authority, monkeypatch, capability):
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY", "e" * 64)
    supplied = {} if capability is None else {"ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY": capability}
    with pytest.raises(ValueError, match="completion capability"):
        worker_environment(authority[0], supplied, "d" * 64)


@pytest.fixture
def model_authority(authority, tmp_path, monkeypatch):
    """Real held proof bytes, with only privileged public custody virtualized."""
    import json
    import os
    import stat
    import time
    from types import SimpleNamespace

    packet, outer_path, outer = authority
    acceptance = canonical({'kind': 'builder-docker-installed-acceptance', 'run_id': packet['builder_run_id']})
    grant = canonical({'kind': 'builder-docker-model-authorization', 'run_id': packet['builder_run_id']})
    paths = {'acceptance': '/srv/builder/admission/acceptances/' + sha256(acceptance).hexdigest() + '.json',
        'authorization': '/srv/builder/admission/authorizations/' + packet['builder_run_id'] + '.json'}
    files = {}
    for name, raw in [('acceptance', acceptance), ('authorization', grant)]:
        path = tmp_path / (name + '.json'); path.write_bytes(raw); path.chmod(0o444)
        files[paths[name]] = path
    packet.update(image=packet['image_id'], run_id='20261022-211413Z-' + 'f' * 32,
        engine_run_dir='/workspace/.issue-orchestrator/session', deadline_unix_ns=time.time_ns()+300_000_000_000)
    projection = {'kind': 'docker-worker-projection', 'model_admission': False,
        'ISSUE_ORCHESTRATOR_CALLBACK_SCOPE': 'docker',
        'image': {'reference': packet['image'], 'kind': 'local-image-id', 'image_id': packet['image_id']},
        'worker_manifest_sha256': outer['worker']['manifest_sha256'],
        'CODEX_HOME': '/baked/capability/homes/standard-implementation',
        'ISSUE_ORCHESTRATOR_CODEX_RUNTIME_ROOT': '/tmp/builder-' + packet['builder_run_id'] + '-provider-runtime'}
    projection_path = tmp_path / 'projection.json'; projection_path.write_bytes(canonical(projection)); projection_path.chmod(0o400)
    inner_path = Path(packet['worker_authority']['engine_contract_path'])
    inner = json.loads(inner_path.read_bytes())
    inner['role'] = 'standard-implementation'
    inner['bounds'] = {'deadline_unix_ns':packet['deadline_unix_ns']}
    inner['capabilities']['model'] = 'test-model'
    inner['capabilities']['capability_bundle'] = '/baked/capability'
    inner['execution']['worker_projection'] = {'path': str(projection_path), 'sha256': sha256(canonical(projection)).hexdigest()}
    inner_path.chmod(0o600); inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
    packet['admission_proofs'] = paths
    packet['mounts'] += [{'source': value, 'target': value, 'read_only': True} for value in paths.values()]
    outer.update(schema_version=2, model_admission=True,
        installed_acceptance={'path': paths['acceptance'], 'sha256': sha256(acceptance).hexdigest()},
        authorization={'path': paths['authorization'], 'sha256': sha256(grant).hexdigest()})

    def seal():
        inner_path = Path(packet['worker_authority']['engine_contract_path'])
        inner = json.loads(inner_path.read_bytes())
        intent = {key: value for key, value in packet.items() if key not in {'contract_sha256', 'run_id', 'engine_run_dir', 'command_sha256'}}
        inner['execution']['docker_launch']['intent_sha256'] = sha256(canonical(intent)).hexdigest()
        inner_path.chmod(0o600); inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
        packet['contract_sha256'] = sha256(canonical(inner)).hexdigest()
        outer['subject'] = {key: value for key, value in inner.items() if key not in {'schema_version', 'controller_compatibility'}}
        outer['engine_contract']['sha256'] = packet['contract_sha256']
        grant_path = files[paths['authorization']]
        grant_value = json.loads(grant_path.read_bytes())
        if isinstance(grant_value, dict) and 'role' not in grant_value:
            grant_value.update(schema_version=1,role=inner['role'],model=inner['capabilities']['model'],
                bounds=inner['bounds'],expires_unix_ns=packet['deadline_unix_ns']+60_000_000_000)
        delivery = sha256(canonical(outer['subject'])).hexdigest()
        if isinstance(grant_value, dict) and grant_value.get('run_id') == packet['builder_run_id'] and grant_value.get('delivery_sha256') != delivery:
            grant_value.update(delivery_sha256=delivery, acceptance_sha256=outer['installed_acceptance']['sha256'])
            grant_path.chmod(0o600); grant_path.write_bytes(canonical(grant_value)); grant_path.chmod(0o444)
            outer['authorization']['sha256'] = sha256(canonical(grant_value)).hexdigest()
        outer_path.chmod(0o600); outer_path.write_bytes(canonical(outer)); outer_path.chmod(0o400)

    seal()
    original_open, original_close, original_fstat = os.open, os.close, os.fstat
    original_resolve, original_lstat = Path.resolve, Path.lstat
    descriptors = set()
    parents = {parent for path in paths.values() for parent in Path(path).parents}
    controls = {'uid': 0, 'nlink': 1, 'writable_parent': False, 'changed_read': False}

    def open_file(path, *args, **kwargs):
        fd = original_open(files.get(str(path), path), *args, **kwargs)
        if str(path) in files: descriptors.add(fd)
        return fd

    def close_file(fd):
        descriptors.discard(fd)
        return original_close(fd)

    def file_stat(fd):
        value = original_fstat(fd)
        if fd not in descriptors: return value
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        fields.update(st_uid=controls['uid'], st_nlink=controls['nlink'])
        if controls['changed_read']:
            controls['changed_read'] = False
            fields['st_mtime_ns'] += 1
        return SimpleNamespace(**fields)

    def path_stat(path, *args, **kwargs):
        if path in parents:
            return SimpleNamespace(st_mode=stat.S_IFDIR | (0o777 if controls['writable_parent'] else 0o755), st_uid=0)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, 'open', open_file)
    monkeypatch.setattr(os, 'close', close_file)
    monkeypatch.setattr(os, 'fstat', file_stat)
    monkeypatch.setattr(Path, 'resolve', lambda path, **kwargs: path if str(path) in files else original_resolve(path, **kwargs))
    monkeypatch.setattr(Path, 'lstat', path_stat)
    return packet, outer_path, outer, files, controls, seal


def test_v2_rendered_intent_projects_verified_public_proofs(model_authority):
    packet, path, _, _, _, _ = model_authority
    before = canonical(packet)
    result = worker_environment(packet, {'PROVIDER_KEY': 'provider-secret', 'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64, 'XORETS_DOCKER_MODEL_AUTH_JSON': '{"token":"canary-secret"}'}, 'd' * 64)
    assert result['XORETS_EXECUTION_CONTRACT'] == str(path)
    assert result['XORETS_EXECUTION_DIGEST'] == sha256(path.read_bytes()).hexdigest()
    assert 'admission_proofs' not in result
    assert canonical(packet) == before


@pytest.mark.parametrize('change', ['digest', 'path', 'missing-proof', 'directory', 'writable', 'writable-child',
    'uid', 'hardlink', 'parent', 'payload', 'encoding', 'changed-read', 'subject', 'grant-path'])
def test_v2_public_proof_or_projection_changes_refuse(model_authority, change):
    packet, _, outer, files, controls, seal = model_authority
    path = files[packet['admission_proofs']['authorization']]
    if change == 'digest': outer['authorization']['sha256'] = '0' * 64
    elif change == 'path': packet['admission_proofs']['acceptance'] = '/srv/private/controller.json'
    elif change == 'missing-proof': packet['mounts'].pop()
    elif change == 'directory': packet['mounts'].append({'source': '/srv/builder/admission', 'target': '/srv/builder/admission', 'read_only': True})
    elif change == 'writable': packet['mounts'][-1]['read_only'] = False
    elif change == 'writable-child': packet['mounts'].append({'source': str(path) + '/child', 'target': packet['admission_proofs']['authorization'] + '/child', 'read_only': False})
    elif change == 'uid': controls['uid'] = 1000
    elif change == 'hardlink': controls['nlink'] = 2
    elif change == 'parent': controls['writable_parent'] = True
    elif change in {'payload', 'encoding'}:
        path.chmod(0o600); path.write_bytes(b'[]\n' if change == 'payload' else b'{"kind":"changed"}\n'); path.chmod(0o444)
        outer['authorization']['sha256'] = sha256(path.read_bytes()).hexdigest()
    elif change == 'changed-read': controls['changed_read'] = True
    elif change == 'grant-path': outer['authorization']['path'] = '/srv/builder/admission/acceptances/' + 'f' * 64 + '.json'
    seal()
    if change == 'subject':
        outer['subject']['issue'] = {'number': 999}
        outer_path = Path(packet['worker_authority']['contract_path'])
        outer_path.chmod(0o600); outer_path.write_bytes(canonical(outer)); outer_path.chmod(0o400)
    with pytest.raises(ValueError):
        worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64,
            'XORETS_DOCKER_MODEL_AUTH_JSON': '{"token":"canary-secret"}'}, 'd' * 64)


def test_v1_cannot_relabel_model_admission(authority):
    packet, path, outer = authority
    outer['model_admission'] = True
    path.chmod(0o600); path.write_bytes(canonical(outer)); path.chmod(0o400)
    with pytest.raises(ValueError):
        worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)


def test_unprojected_proof_paths_cannot_confer_authority():
    with pytest.raises(ValueError):
        worker_environment({'admission_proofs': {}}, {}, None)


def test_selected_provider_port_projects_only_named_model_secret(model_authority, tmp_path, monkeypatch, caplog):
    import json
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    packet, _, _, _, _, _ = model_authority
    template = tmp_path / 'template.json'; template.write_bytes(canonical(packet)); template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST', packet['contract_sha256'])
    reads = []
    secret = '{"token":"private-auth-canary"}'
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key', lambda name: reads.append(name) or secret)
    resolver = KeyringProviderCredentials()
    assert resolver.session_env('codex') == {}
    assert reads == []
    private = dict(resolver.session_env('codex', docker=True))
    assert private == {'XORETS_DOCKER_MODEL_AUTH_JSON': secret}
    assert reads == ['XORETS_DOCKER_MODEL_AUTH_JSON']
    result = worker_environment(packet, {**private, 'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)
    assert json.loads(result['XORETS_DOCKER_LAUNCH_JSON']) == packet
    assert json.loads(result['XORETS_DOCKER_PROJECTION_JSON'])['CODEX_HOME'] == '/baked/capability/homes/standard-implementation'
    assert secret not in result['XORETS_DOCKER_LAUNCH_JSON'] + result['XORETS_DOCKER_PROJECTION_JSON'] + caplog.text
    assert 'XORETS_DOCKER_MODEL_AUTH_JSON' not in result
    assert secret not in str(result)


def model_control_marker(packet, command):
    path = Path(packet['worker_authority']['engine_contract_path']).with_name(packet['builder_run_id'] + '-' + command + '.json')
    path.write_bytes(canonical({'run_id': packet['builder_run_id'] + '-' + command,
        'contract_sha256': packet['contract_sha256']}))
    path.chmod(0o400)
    return path


@pytest.mark.parametrize('control', ['pause', 'cancel', 'foreign-digest', 'foreign-run', 'malformed',
    'writable', 'symlink', 'dangling-symlink', 'hardlink', 'directory', 'fifo'])
def test_controller_control_refuses_credentials_before_secret_resolution(model_authority, tmp_path, monkeypatch, control):
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    packet, _, _, _, _, _ = model_authority
    marker = model_control_marker(packet, 'cancel' if control == 'cancel' else 'pause')
    if control in {'foreign-digest', 'foreign-run', 'malformed'}:
        value = {'run_id': packet['builder_run_id'] + '-pause', 'contract_sha256': packet['contract_sha256']}
        value['contract_sha256' if control == 'foreign-digest' else 'run_id'] = 'foreign'
        marker.chmod(0o600)
        marker.write_bytes(b'not-json' if control == 'malformed' else canonical(value))
        marker.chmod(0o400)
    elif control == 'writable':
        marker.chmod(0o600)
    elif control in {'symlink', 'dangling-symlink', 'hardlink', 'directory', 'fifo'}:
        held = marker.with_name('held.json')
        marker.rename(held)
        if control == 'directory': marker.mkdir(mode=0o700)
        elif control == 'fifo':
            import os
            os.mkfifo(marker, mode=0o400)
        elif control == 'hardlink': marker.hardlink_to(held)
        else: marker.symlink_to(held if control == 'symlink' else held.with_name('missing.json'))
    template = tmp_path / 'template.json'
    template.write_bytes(canonical(packet)); template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST', packet['contract_sha256'])
    reads = []
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key', lambda name: reads.append(name) or '{"token":"canary"}')
    assert all(not marker.is_relative_to(Path(mount['source'])) for mount in packet['mounts'])
    with pytest.raises((ValueError, OSError)):
        KeyringProviderCredentials().session_env('codex', docker=True)
    assert reads == []


def test_nonmodel_authority_remains_observable_with_model_control_marker(authority):
    packet, path, _ = authority
    model_control_marker(packet, 'cancel')
    result = worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)
    assert result['XORETS_EXECUTION_DIGEST'] == sha256(path.read_bytes()).hexdigest()
    assert 'XORETS_DOCKER_MODEL_AUTH_JSON' not in result


@pytest.mark.parametrize('change', ['provider', 'foreign-inner', 'wrong-role', 'untrusted-project', 'changed-projection', 'missing'])
def test_credential_port_refuses_before_secret_resolution(model_authority, tmp_path, monkeypatch, change):
    import json
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    packet, _, _, _, _, seal = model_authority
    if change in {'wrong-role', 'untrusted-project', 'changed-projection'}:
        inner_path = Path(packet['worker_authority']['engine_contract_path'])
        inner = json.loads(inner_path.read_bytes())
        projection_path = Path(inner['execution']['worker_projection']['path'])
        if change == 'wrong-role': inner['role'] = 'standard-review'
        elif change == 'untrusted-project':
            projection = json.loads(projection_path.read_bytes()); projection['CODEX_HOME'] = '/workspace/.codex'
            projection_path.chmod(0o600); projection_path.write_bytes(canonical(projection)); projection_path.chmod(0o400)
            inner['execution']['worker_projection']['sha256'] = sha256(canonical(projection)).hexdigest()
        else:
            projection_path.chmod(0o600); projection_path.write_bytes(b'{}\n'); projection_path.chmod(0o400)
        inner_path.chmod(0o600); inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
        seal()
    template = tmp_path / 'template.json'; template.write_bytes(canonical(packet)); template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST', '0' * 64 if change == 'foreign-inner' else packet['contract_sha256'])
    reads = []
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key', lambda name: reads.append(name) or None)
    with pytest.raises(ValueError):
        KeyringProviderCredentials().session_env('deepseek' if change == 'provider' else 'codex', docker=True)
    assert reads == (['XORETS_DOCKER_MODEL_AUTH_JSON'] if change == 'missing' else [])


@pytest.mark.parametrize('secret', [None, '', '[]', '{}', '{bad', 'x' * 65537])
def test_model_secret_must_be_explicit_bounded_nonempty_json(model_authority, secret):
    provider = {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}
    if secret is not None: provider['XORETS_DOCKER_MODEL_AUTH_JSON'] = secret
    with pytest.raises(ValueError, match='model secret'):
        worker_environment(model_authority[0], provider, 'd' * 64)


@pytest.mark.parametrize('name', ['XORETS_DOCKER_LAUNCH_JSON', 'XORETS_DOCKER_PROJECTION_JSON'])
def test_provider_cannot_forge_public_model_transport(model_authority, name):
    with pytest.raises(ValueError, match='overrides'):
        worker_environment(model_authority[0], {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64,
            'XORETS_DOCKER_MODEL_AUTH_JSON': '{"token":"secret"}', name: '{}'}, 'd' * 64)


def test_v1_provider_never_resolves_or_accepts_model_auth(authority, tmp_path, monkeypatch):
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    packet = authority[0]
    template = tmp_path / 'template.json'; template.write_bytes(canonical(packet)); template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template))
    reads = []
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key', lambda name: reads.append(name) or 'secret')
    assert KeyringProviderCredentials().session_env('codex', docker=True) == {}
    assert reads == []
    with pytest.raises(ValueError, match='v1'):
        worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64,
            'XORETS_DOCKER_MODEL_AUTH_JSON': '{"token":"secret"}'}, 'd' * 64)


@pytest.mark.parametrize('key,value', [('run_id', 'foreign'), ('delivery_sha256', '0' * 64), ('acceptance_sha256', '0' * 64)])
def test_root_grant_must_bind_current_delivery_before_secret_lookup(model_authority, tmp_path, monkeypatch, key, value):
    import json
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    packet, outer_path, outer, files, _, _ = model_authority
    grant_path = files[packet['admission_proofs']['authorization']]
    grant = json.loads(grant_path.read_bytes()); grant[key] = value
    grant_path.chmod(0o600); grant_path.write_bytes(canonical(grant)); grant_path.chmod(0o444)
    outer['authorization']['sha256'] = sha256(canonical(grant)).hexdigest()
    outer_path.chmod(0o600); outer_path.write_bytes(canonical(outer)); outer_path.chmod(0o400)
    template = tmp_path / 'template.json'; template.write_bytes(canonical(packet)); template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template))
    reads = []
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key', lambda name: reads.append(name) or 'secret')
    with pytest.raises(ValueError, match='another delivery'):
        KeyringProviderCredentials().session_env('codex', docker=True)
    assert reads == []


@pytest.fixture
def review_authority(model_authority):
    import json
    import copy
    packet, outer_path, outer, files, controls, seal = model_authority
    original_run='run-'+'b'*32
    inner_path=Path(packet['worker_authority']['engine_contract_path'])
    original_inner=json.loads(inner_path.read_bytes())
    original_inner['run_id']=original_run
    original_inner['execution']['workspace']='/original-workspace'
    original_inner_path=inner_path.with_name(original_run+'.json')
    original_inner_path.write_bytes(canonical(original_inner));original_inner_path.chmod(0o400)
    original_outer=copy.deepcopy(outer)
    original_outer.update(run_id=original_run,engine_contract={'path':str(original_inner_path),'sha256':sha256(canonical(original_inner)).hexdigest()})
    original_outer_path=outer_path.with_name(original_run+'.json')
    original_outer_path.write_bytes(canonical(original_outer));original_outer_path.chmod(0o400)
    inner=json.loads(inner_path.read_bytes());inner['role']='standard-review'
    inner_path.chmod(0o600);inner_path.write_bytes(canonical(inner));inner_path.chmod(0o400)
    projection_path=Path(inner['execution']['worker_projection']['path'])
    projection=json.loads(projection_path.read_bytes());projection['CODEX_HOME']='/baked/capability/homes/standard-review'
    projection_path.chmod(0o600);projection_path.write_bytes(canonical(projection));projection_path.chmod(0o400)
    inner['execution']['worker_projection']['sha256']=sha256(canonical(projection)).hexdigest()
    inner_path.chmod(0o600);inner_path.write_bytes(canonical(inner));inner_path.chmod(0o400)
    parent={'schema_version':1,'kind':'builder-docker-review-parent','subject_sha256':'1'*64,'head_sha':'2'*40,
        'reviewer_authority_sha256':'3'*64,'original_outer_sha256':sha256(canonical(original_outer)).hexdigest(),
        'original_inner_sha256':sha256(canonical(original_inner)).hexdigest(),'builder_run_id':original_run,
        'engine_run_id':'20261022-211413Z-'+'b'*32,'fence':'4'*40}
    grant_path=files[packet['admission_proofs']['authorization']]
    grant=json.loads(grant_path.read_bytes());grant['review_parent']=parent;grant['role']='standard-review'
    def reseal():
        grant_path.chmod(0o600);grant_path.write_bytes(canonical(grant));grant_path.chmod(0o444)
        outer['authorization']['sha256']=sha256(canonical(grant)).hexdigest()
        seal()
    reseal()
    return packet, parent, grant, original_inner_path, reseal


def test_review_parent_reads_real_sealed_original_and_root_grant(review_authority):
    from issue_orchestrator.execution.docker_worker_authority import model_projection_snapshot, model_review_parent
    packet,parent,grant,original_inner_path,reseal=review_authority
    outer,inner,projection=model_projection_snapshot(packet)
    context=model_review_parent(packet,outer,inner)
    assert context['review_parent']==parent
    assert context['original_inner']['execution']['workspace']=='/original-workspace'
    assert inner['role']=='standard-review'


@pytest.mark.parametrize('change',['wrong-role','shared-run','bad-fence','extra-field','changed-original'])
def test_review_parent_refuses_bad_root_binding_or_held_original(review_authority,change):
    from issue_orchestrator.execution.docker_worker_authority import model_projection_snapshot, model_review_parent
    packet,parent,grant,original_inner_path,reseal=review_authority
    if change == 'shared-run':parent['builder_run_id']=packet['builder_run_id']
    elif change == 'bad-fence':parent['fence']='f'*64
    elif change == 'extra-field':parent['path']='/unselected'
    elif change == 'changed-original':
        original_inner_path.chmod(0o600);original_inner_path.write_bytes(b'{}\n');original_inner_path.chmod(0o400)
    reseal()
    outer,inner,projection=model_projection_snapshot(packet)
    if change == 'wrong-role':inner['role']='standard-implementation'
    with pytest.raises(ValueError):model_review_parent(packet,outer,inner)


@pytest.mark.parametrize('change',['expired','missing-expiry','bool-expiry','far-future','role','model','bounds','kind'])
def test_current_model_permission_refuses_before_named_credential_lookup(model_authority,tmp_path,monkeypatch,change):
    import json
    import time
    from issue_orchestrator.execution.provider_credentials_adapter import KeyringProviderCredentials
    from issue_orchestrator.execution.docker_worker_authority import model_projection_snapshot
    packet,outer_path,outer,files,controls,seal=model_authority
    grant_path=files[packet['admission_proofs']['authorization']]
    grant=json.loads(grant_path.read_bytes())
    if change=='expired':grant['expires_unix_ns']=1
    elif change=='missing-expiry':grant.pop('expires_unix_ns')
    elif change=='bool-expiry':grant['expires_unix_ns']=True
    elif change=='far-future':grant['expires_unix_ns']=time.time_ns()+3601_000_000_000
    elif change=='role':grant['role']='standard-review'
    elif change=='model':grant['model']='foreign-model'
    elif change=='bounds':grant['bounds']={}
    else:grant['kind']='unselected-kind'
    grant_path.chmod(0o600);grant_path.write_bytes(canonical(grant));grant_path.chmod(0o444)
    outer['authorization']['sha256']=sha256(canonical(grant)).hexdigest()
    seal()
    template=tmp_path/'current-template.json';template.write_bytes(canonical(packet));template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE',str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT',packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST',packet['contract_sha256'])
    reads=[]
    monkeypatch.setattr('issue_orchestrator.infra.ai_keys.read_ai_key',lambda name:reads.append(name))
    with pytest.raises(ValueError,match='current finite'):
        KeyringProviderCredentials().session_env('codex',docker=True)
    with pytest.raises(ValueError,match='current finite'):
        model_projection_snapshot(packet)
    assert reads==[]


def test_container_model_grant_requires_finite_request_limit():
    import time
    from issue_orchestrator.execution.docker_worker_authority import require_current_model_grant
    now = time.time_ns()
    bounds = {'deadline_unix_ns': now + 10_000_000_000}
    inner = {'role': 'standard-implementation', 'capabilities': {'model': 'model-a'}, 'bounds': bounds}
    packet = {'deadline_unix_ns': now + 5_000_000_000}
    grant = {'schema_version': 2, 'kind': 'builder-docker-container-model-authorization',
             'role': 'standard-implementation', 'model': 'model-a', 'bounds': bounds,
             'expires_unix_ns': now + 20_000_000_000, 'max_model_requests': 2}
    require_current_model_grant(packet, inner, grant)
    for bad in (0, True, 100001, None):
        with pytest.raises(ValueError):
            require_current_model_grant(packet, inner, dict(grant, max_model_requests=bad))


def test_container_model_worker_rejects_unapproved_provider_environment(model_authority):
    import json
    packet, _, outer, files, _, seal = model_authority
    grant_path = files[packet['admission_proofs']['authorization']]
    grant = json.loads(grant_path.read_bytes())
    grant.update(schema_version=2, kind='builder-docker-container-model-authorization', max_model_requests=3)
    grant_path.chmod(0o600);grant_path.write_bytes(canonical(grant));grant_path.chmod(0o400)
    outer['authorization']['sha256'] = sha256(canonical(grant)).hexdigest()
    packet['mounts'].extend({'source': str(Path(packet['working_dir']) / name), 'target': str(Path(packet['working_dir']) / name), 'read_only': True} for name in ('.codex', '.agents', '.issue-orchestrator'))
    seal()
    allowed = {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY':'e'*64,
               'XORETS_DOCKER_MODEL_AUTH_JSON':'{"token":"controller-only"}'}
    value = worker_environment(packet, allowed, 'd'*64)
    assert 'XORETS_DOCKER_MODEL_AUTH_JSON' not in value
    for extra in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'ARBITRARY_TRANSPORT_SECRET'):
        with pytest.raises(ValueError): worker_environment(packet, {**allowed, extra:'sentinel'}, 'd'*64)


def test_danger_full_access_requires_selected_root_sealed_container_grant(model_authority, tmp_path, monkeypatch):
    import json
    from issue_orchestrator.execution.agent_runner_providers.codex import _validate_orchestrated_safety
    packet, _, outer, files, _, seal = model_authority
    grant_path = files[packet['admission_proofs']['authorization']]
    grant = json.loads(grant_path.read_bytes())
    grant.update(schema_version=2, kind='builder-docker-container-model-authorization', max_model_requests=3)
    grant_path.chmod(0o600);grant_path.write_bytes(canonical(grant));grant_path.chmod(0o400)
    outer['authorization']['sha256'] = sha256(canonical(grant)).hexdigest()
    packet['mounts'].extend({'source': str(Path(packet['working_dir']) / name), 'target': str(Path(packet['working_dir']) / name), 'read_only': True} for name in ('.codex', '.agents', '.issue-orchestrator'))
    seal()
    template = tmp_path/'template.json';template.write_bytes(canonical(packet));template.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE',str(template))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT',packet['worker_authority']['engine_contract_path'])
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST',packet['contract_sha256'])
    _validate_orchestrated_safety(sandbox_scope=None,approval_mode='full-auto',sandbox_mode='danger-full-access')
    with pytest.raises(ValueError):
        _validate_orchestrated_safety(sandbox_scope=None,approval_mode='yolo',sandbox_mode='danger-full-access')
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST','f'*64)
    with pytest.raises(ValueError):
        _validate_orchestrated_safety(sandbox_scope=None,approval_mode='full-auto',sandbox_mode='danger-full-access')


@pytest.mark.parametrize('change',['missing','writable','duplicate','nested','foreign-alias','traversal','overlimit'])
def test_container_workspace_overlay_refuses_unsafe_mounts(change):
    from issue_orchestrator.execution.docker_worker_authority import require_container_only_mounts
    root='/srv/builder/tasks/run-'+'a'*32
    workspace=root+'/workspace'
    overlays=[{'source':workspace+'/'+name,'target':workspace+'/'+name,'read_only':True}
              for name in ('.codex','.agents','.issue-orchestrator')]
    packet={'builder_run_id':'run-'+'a'*32,'working_dir':workspace,'mounts':overlays}
    require_container_only_mounts(packet)
    if change=='missing': packet['mounts'].pop()
    elif change=='writable': packet['mounts'][0]['read_only']=False
    elif change=='duplicate': packet['mounts'].append(dict(overlays[0]))
    elif change=='nested': packet['mounts'].append({'source':workspace+'/.codex/x','target':workspace+'/.codex/x','read_only':True})
    elif change=='foreign-alias': packet['mounts'].append({'source':root+'/readonly-empty','target':workspace+'/other','read_only':True})
    elif change=='traversal': packet['mounts'].append({'source':workspace+'/.codex/../escape','target':workspace+'/.codex/../escape','read_only':False})
    else: packet['mounts'].extend({'source':workspace+'/p'+str(i),'target':workspace+'/p'+str(i),'read_only':True} for i in range(34))
    with pytest.raises(ValueError): require_container_only_mounts(packet)


def test_synthetic_grant_requires_exact_subject_and_capability():
    import time
    from issue_orchestrator.execution.docker_worker_authority import require_current_model_grant
    now = time.time_ns()
    bounds = {'deadline_unix_ns': now + 60_000_000_000}
    inner = {'repository': {'name': 'local/one'}, 'issue': {'number': 42},
             'role': 'standard-implementation', 'bounds': bounds,
             'capabilities': {'model': 'test', 'capability_bundle_sha256': 'a' * 64}}
    grant = {'schema_version': 2, 'kind': 'builder-docker-container-synthetic-authorization',
             'max_model_requests': 8, 'fixture_capability_sha256': 'a' * 64,
             'role': inner['role'], 'model': 'test', 'bounds': bounds,
             'expires_unix_ns': now + 120_000_000_000}
    packet = {'deadline_unix_ns': bounds['deadline_unix_ns']}
    require_current_model_grant(packet, inner, grant)
    for key, value in [('fixture_capability_sha256', 'b' * 64), ('max_model_requests', 0)]:
        with pytest.raises(ValueError):
            require_current_model_grant(packet, inner, {**grant, key: value})
    with pytest.raises(ValueError):
        require_current_model_grant(packet, {**inner, 'repository': {'name': 'other/repo'}}, grant)


def test_builder_generated_overlay_fixture(monkeypatch):
    """Consume the actual Builder producer output when explicitly supplied."""
    import json
    import os
    from issue_orchestrator.execution.docker_worker_authority import require_container_only_mounts
    path = os.environ.get('BUILDER_OVERLAY_FIXTURE')
    if not path:
        pytest.skip('Builder overlay fixture not supplied')
    packet = json.loads(Path(path).read_bytes())
    require_container_only_mounts(packet)
    overlay = next(item for item in packet['mounts'] if item['target'] == packet['working_dir'] + '/.codex')
    overlay['read_only'] = False
    with pytest.raises(ValueError):
        require_container_only_mounts(packet)


def test_review_request_bound_matches_history_proof_capacity():
    import time
    from issue_orchestrator.execution.docker_worker_authority import require_current_model_grant
    now = time.time_ns()
    bounds = {'deadline_unix_ns':now + 60_000_000_000}
    inner = {'role':'standard-review', 'bounds':bounds, 'capabilities':{'model':'fixture'}}
    grant = {'schema_version':2, 'kind':'builder-docker-container-model-authorization',
        'role':'standard-review', 'model':'fixture', 'bounds':bounds, 'max_model_requests':256,
        'expires_unix_ns':now + 120_000_000_000}
    packet = {'deadline_unix_ns':bounds['deadline_unix_ns']}
    require_current_model_grant(packet, inner, grant)
    with pytest.raises(ValueError, match='history proof bound'):
        require_current_model_grant(packet, inner, {**grant, 'max_model_requests':257})
