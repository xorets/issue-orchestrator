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


@pytest.mark.parametrize("name", ["XORETS_EXECUTION_CONTRACT", "XORETS_EXECUTION_DIGEST", "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN", "ISSUE_ORCHESTRATOR_API_TOKEN", "GH_TOKEN"])
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
    result = worker_environment(packet, {'PROVIDER_KEY': 'provider-secret', 'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)
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
        worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)


def test_v1_cannot_relabel_model_admission(authority):
    packet, path, outer = authority
    outer['model_admission'] = True
    path.chmod(0o600); path.write_bytes(canonical(outer)); path.chmod(0o400)
    with pytest.raises(ValueError):
        worker_environment(packet, {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY': 'e' * 64}, 'd' * 64)


def test_unprojected_proof_paths_cannot_confer_authority():
    with pytest.raises(ValueError):
        worker_environment({'admission_proofs': {}}, {}, None)
