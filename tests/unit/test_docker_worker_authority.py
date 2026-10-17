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
