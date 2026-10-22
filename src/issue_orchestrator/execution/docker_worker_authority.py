"""Project the exact sealed worker authority without ambient credentials."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time

from .agent_runner_env import DEFAULT_FORBIDDEN_ENV_VARS
from .docker_launch_input import canonical, sealed_bytes

MODEL_AUTH_ENV = "XORETS_DOCKER_MODEL_AUTH_JSON"
MODEL_LAUNCH_ENV = "XORETS_DOCKER_LAUNCH_JSON"
MODEL_PROJECTION_ENV = "XORETS_DOCKER_PROJECTION_JSON"


def _require_mounts(packet: dict, paths: tuple[Path, ...]) -> None:
    mounts = packet["mounts"]
    for path in paths:
        if {"source": str(path), "target": str(path), "read_only": True} not in mounts:
            raise ValueError("Docker worker authority lacks exact read-only file mount")
        for mount in mounts:
            if not mount["read_only"] and any(path.is_relative_to(root) or root.is_relative_to(path)
                    for root in (Path(mount["source"]), Path(mount["target"]))):
                raise ValueError("Docker worker authority overlaps writable mount")


def _public_proof(descriptor: dict, expected_path: Path, packet: dict) -> dict:
    """Authenticate public root custody; Builder owns admission policy content."""
    if (type(descriptor) is not dict or set(descriptor) != {"path", "sha256"} or
            descriptor.get("path") != str(expected_path) or
            not isinstance(descriptor.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", descriptor["sha256"])):
        raise ValueError("Docker public admission descriptor differs")
    _require_mounts(packet, (expected_path,))
    exact = {"source": str(expected_path), "target": str(expected_path), "read_only": True}
    for mount in packet["mounts"]:
        if mount != exact and any(expected_path.is_relative_to(root) or root.is_relative_to(expected_path)
                for root in (Path(mount["source"]), Path(mount["target"]))):
            raise ValueError("Docker public admission requires isolated file mounts")
    raw = _public_proof_bytes(expected_path)
    value = json.loads(raw)
    if type(value) is not dict or canonical(value) != raw or sha256(raw).hexdigest() != descriptor["sha256"]:
        raise ValueError("Docker public admission digest or encoding changed")
    return value


def _public_proof_bytes(path: Path) -> bytes:
    """Hold a bounded immutable public file across identity and content checks."""
    if path.resolve(strict=True) != path:
        raise ValueError("Docker public admission path is not canonical")
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError("Docker public admission ancestry is not protected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                before.st_mode & 0o222 or not 0 < before.st_size <= 65536):
            raise ValueError("Docker public admission proof is not immutable root custody")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            if not chunk:
                raise ValueError("Docker public admission proof short read")
            raw.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if os.read(fd, 1) or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("Docker public admission proof changed during read")
    finally:
        os.close(fd)
    return bytes(raw)


def _require_admission(packet: dict, outer: dict, inner: dict) -> None:
    if type(outer.get("schema_version")) is not int:
        raise ValueError("Docker worker admission version is invalid")
    if outer.get("schema_version") == 1:
        if (outer.get("model_admission") is not False or outer.get("installed_acceptance") is not None or
                "authorization" in outer or "admission_proofs" in packet):
            raise ValueError("Docker non-model authority cannot project admission proofs")
        return
    if outer.get("schema_version") != 2 or outer.get("model_admission") is not True:
        raise ValueError("Docker worker admission version is invalid")
    proofs = packet.get("admission_proofs")
    if type(proofs) is not dict or set(proofs) != {"acceptance", "authorization"}:
        raise ValueError("Docker worker admission proof projection is incomplete")
    acceptance = outer.get("installed_acceptance")
    if type(acceptance) is not dict or not isinstance(acceptance.get("sha256"), str):
        raise ValueError("Docker worker acceptance descriptor is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", acceptance["sha256"]):
        raise ValueError("Docker worker acceptance digest is invalid")
    root = Path("/srv/builder/admission")
    paths = {"acceptance": root / "acceptances" / (acceptance["sha256"] + ".json"),
        "authorization": root / "authorizations" / (packet["builder_run_id"] + ".json")}
    if proofs != {name: str(path) for name, path in paths.items()}:
        raise ValueError("Docker worker admission paths leave public custody")
    _public_proof(acceptance, paths["acceptance"], packet)
    authorization = _public_proof(outer.get("authorization"), paths["authorization"], packet)
    if (authorization.get("run_id") != packet["builder_run_id"] or
            authorization.get("delivery_sha256") != sha256(canonical(outer["subject"])).hexdigest() or
            authorization.get("acceptance_sha256") != acceptance["sha256"]):
        raise ValueError("Docker root authorization belongs to another delivery subject")
    require_current_model_grant(packet, inner, authorization)


def require_current_model_grant(packet: dict, inner: dict, grant: dict) -> None:
    """Current finite permission is distinct from authentic retained material."""
    now = time.time_ns()
    bounds = inner.get('bounds', {})
    deadline, expiry = bounds.get('deadline_unix_ns'), grant.get('expires_unix_ns')
    if (type(grant.get('schema_version')) is not int or grant['schema_version'] != 1 or
            grant.get('kind') != 'builder-docker-model-authorization' or grant.get('role') != inner.get('role') or
            not isinstance(inner.get('capabilities', {}).get('model'), str) or not inner['capabilities']['model'] or
            grant.get('model') != inner['capabilities']['model'] or grant.get('bounds') != bounds or
            type(deadline) is not int or type(expiry) is not int or not now < deadline <= expiry <= now + 3600_000_000_000 or
            type(packet.get('deadline_unix_ns')) is not int or not now < packet['deadline_unix_ns'] <= deadline):
        raise ValueError('Docker current finite model authorization differs from selected execution')


def _authority_environment(packet: dict) -> dict[str, str]:
    descriptor = packet.get("worker_authority")
    if descriptor is None:
        if "admission_proofs" in packet:
            raise ValueError("Docker admission proofs require worker authority")
        return {}
    if type(descriptor) is not dict or set(descriptor) != {"contract_path", "engine_contract_path"}:
        raise ValueError("Docker worker authority descriptor is invalid")
    outer_path, inner_path = (Path(descriptor[name]) for name in ("contract_path", "engine_contract_path"))
    filename = packet["builder_run_id"] + ".json"
    if (outer_path.parent.name != "execution-contracts-docker-v1" or outer_path.name != filename or
            inner_path != outer_path.parent.parent / "engine-contracts-docker-v1" / filename):
        raise ValueError("Docker worker authority namespace differs")
    _require_mounts(packet, (outer_path, inner_path))
    outer_raw = sealed_bytes(outer_path)
    inner_raw = sealed_bytes(inner_path, expected=packet["contract_sha256"])
    outer, inner = json.loads(outer_raw), json.loads(inner_raw)
    if canonical(outer) != outer_raw or canonical(inner) != inner_raw:
        raise ValueError("Docker worker authority encoding changed")
    _require_subject(packet, outer, inner, inner_path)
    _require_admission(packet, outer, inner)
    return {"XORETS_EXECUTION_CONTRACT": str(outer_path), "XORETS_EXECUTION_DIGEST": sha256(outer_raw).hexdigest()}


def _require_subject(packet: dict, outer: dict, inner: dict, inner_path: Path) -> None:
    if type(outer) is not dict or type(inner) is not dict or type(inner.get("execution")) is not dict:
        raise ValueError("Docker worker authority shape is invalid")
    subject = {key: inner[key] for key in ("run_id", "repository", "issue", "branch", "role", "bounds", "capabilities", "supervised")}
    execution = inner["execution"]
    if any(type(execution.get(key)) is not dict for key in ("callback", "docker_launch")):
        raise ValueError("Docker worker callback/launch authority is invalid")
    subject["execution"] = {key: execution[key] for key in
        ("workspace", "session_name", "agent_label", "logical_child", "backend", "docker_launch", "callback")}
    if "worker_projection" in execution:
        subject["execution"]["worker_projection"] = execution["worker_projection"]
    intent = {key: value for key, value in packet.items() if key not in {"contract_sha256", "run_id", "engine_run_dir", "command_sha256"}}
    keys = {"schema_version", "kind", "model_admission", "run_id", "subject", "engine_contract", "worker", "installed_acceptance"}
    if outer.get("schema_version") == 2:
        keys.add("authorization")
    if (set(outer) != keys or outer.get("kind") != "builder-docker-delivery" or
            outer.get("run_id") != packet["builder_run_id"] or outer.get("subject") != subject or
            outer.get("engine_contract") != {"path": str(inner_path), "sha256": packet["contract_sha256"]} or
            set(outer.get("worker", {})) != {"image_id", "manifest_sha256"} or
            outer["worker"]["image_id"] != packet["image_id"] or
            not re.fullmatch(r"[0-9a-f]{64}", outer["worker"].get("manifest_sha256", "")) or
            inner.get("schema_version") != 4 or inner.get("controller_compatibility") != "supervised-v4" or
            inner.get("run_id") != packet["builder_run_id"] or inner.get("repository", {}).get("name") != packet["repository"] or
            (execution.get("workspace"), execution.get("session_name"), execution.get("backend")) !=
                (packet["working_dir"], packet["session_name"], "docker") or
            execution.get("callback", {}).get("scope") != "docker" or
            execution.get("docker_launch", {}).get("intent_sha256") != sha256(canonical(intent)).hexdigest()):
        raise ValueError("Docker worker outer authority differs from selected inner intent")


def _model_projection(packet: dict, outer: dict, inner: dict) -> dict:
    descriptor = inner["execution"].get("worker_projection")
    if type(descriptor) is not dict or set(descriptor) != {"path", "sha256"}:
        raise ValueError("Docker model projection is missing")
    raw = sealed_bytes(Path(descriptor["path"]), expected=descriptor["sha256"], limit=65536)
    projection = json.loads(raw)
    capability = inner["capabilities"].get("capability_bundle")
    role = inner.get("role")
    if (type(projection) is not dict or canonical(projection) != raw or
            not isinstance(capability, str) or not Path(capability).is_absolute() or
            not isinstance(role, str) or not re.fullmatch(r"standard-(implementation|review|remediation)", role) or
            projection.get("kind") != "docker-worker-projection" or projection.get("model_admission") is not False or
            projection.get("ISSUE_ORCHESTRATOR_CALLBACK_SCOPE") != "docker" or
            projection.get("image") != {"reference": packet["image"], "kind": "local-image-id" if packet["image"].startswith("sha256:") else "registry-digest", "image_id": packet["image_id"]} or
            projection.get("worker_manifest_sha256") != outer["worker"]["manifest_sha256"] or
            projection.get("CODEX_HOME") != str(Path(capability) / "homes" / role) or
            projection.get("ISSUE_ORCHESTRATOR_CODEX_RUNTIME_ROOT") != "/tmp/builder-" + packet["builder_run_id"] + "-provider-runtime"):
        raise ValueError("Docker model projection differs from selected role/image")
    return projection


def _model_authority(packet: dict, environment: dict[str, str]) -> tuple[dict, dict]:
    outer = json.loads(sealed_bytes(Path(environment["XORETS_EXECUTION_CONTRACT"]), expected=environment["XORETS_EXECUTION_DIGEST"]))
    inner = json.loads(sealed_bytes(Path(packet["worker_authority"]["engine_contract_path"]), expected=packet["contract_sha256"]))
    return outer, inner


def model_projection_snapshot(packet: dict) -> tuple[dict, dict, dict]:
    """Read only the selected v2 public transport, without resolving secrets."""
    environment = _authority_environment(packet)
    if not environment:
        raise ValueError("Docker model authority is unavailable")
    outer, inner = _model_authority(packet, environment)
    if outer["schema_version"] != 2:
        raise ValueError("Docker first-model requires v2 authority")
    return outer, inner, _model_projection(packet, outer, inner)


def docker_model_auth_requested() -> bool:
    """Authenticate the selected template before resolving one named secret."""
    template = os.environ.get("ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE")
    if not template:
        return False
    raw = sealed_bytes(Path(template))
    packet = json.loads(raw)
    if canonical(packet) != raw:
        raise ValueError("Docker model template encoding changed")
    environment = _authority_environment(packet)
    if not environment:
        return False
    outer, inner = _model_authority(packet, environment)
    if outer["schema_version"] == 1:
        return False
    if (os.environ.get("XORETS_EXECUTION_CONTRACT") != packet["worker_authority"]["engine_contract_path"] or
            os.environ.get("XORETS_EXECUTION_DIGEST") != packet["contract_sha256"]):
        raise ValueError("Docker model credential request differs from active engine contract")
    _model_projection(packet, outer, inner)
    return True


def _model_environment(packet: dict, provider: dict[str, str], environment: dict[str, str]) -> dict[str, str]:
    if not environment:
        if MODEL_AUTH_ENV in provider:
            raise ValueError("Docker model secret requires selected v2 authority")
        return {}
    outer, inner = _model_authority(packet, environment)
    if outer["schema_version"] == 1:
        if MODEL_AUTH_ENV in provider:
            raise ValueError("Docker model secret cannot enter a v1 worker")
        return {}
    secret = provider.get(MODEL_AUTH_ENV)
    try:
        value = json.loads(secret) if isinstance(secret, str) and 0 < len(secret.encode()) <= 65536 else None
    except ValueError:
        value = None
    if not isinstance(value, dict) or not value:
        raise ValueError("Docker model secret requires bounded nonempty JSON")
    projection = _model_projection(packet, outer, inner)
    launch = canonical(packet)
    if len(launch) > 65536:
        raise ValueError("Docker public launch transport exceeds bound")
    return {MODEL_LAUNCH_ENV: launch.decode(), MODEL_PROJECTION_ENV: canonical(projection).decode()}


def worker_environment(packet: dict, provider: dict[str, str], callback_token: str | None) -> dict[str, str]:
    """Only explicit provider secrets, scoped callback and verified seals cross."""
    reserved = {*DEFAULT_FORBIDDEN_ENV_VARS, "ISSUE_ORCH_GITHUB_TOKEN", "XORETS_EXECUTION_CONTRACT",
        "XORETS_EXECUTION_DIGEST", "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN", MODEL_LAUNCH_ENV, MODEL_PROJECTION_ENV}
    if any(name in reserved or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or "\x00" in value
            for name, value in provider.items()):
        raise ValueError("Docker provider environment overrides controller authority")
    if packet.get("worker_authority") is not None and not re.fullmatch(
            r"[A-Za-z0-9_-]{64}", provider.get("ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY", "")):
        raise ValueError("Docker worker authority requires allocation-bound completion capability")
    authority_environment = _authority_environment(packet)
    environment = {**provider, **authority_environment, **_model_environment(packet, provider, authority_environment)}
    if callback_token:
        if not re.fullmatch(r"[0-9a-f]{64}", callback_token):
            raise ValueError("Docker callback token is invalid")
        environment["ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN"] = callback_token
    elif packet.get("worker_authority") is not None:
        raise ValueError("Docker worker authority requires scoped callback authentication")
    return environment


def model_review_parent(packet: dict, outer: dict, inner: dict) -> dict:
    """Authenticate a REVIEW parent from its exact root-held grant and namespace."""
    grant = _public_proof(outer['authorization'], Path(packet['admission_proofs']['authorization']), packet)
    parent = grant.get('review_parent')
    fields = {'schema_version', 'kind', 'subject_sha256', 'head_sha', 'reviewer_authority_sha256',
        'original_outer_sha256', 'original_inner_sha256', 'builder_run_id', 'engine_run_id', 'fence'}
    if (inner['role'] != 'standard-review' or type(parent) is not dict or set(parent) != fields or
            type(parent['schema_version']) is not int or parent['schema_version'] != 1 or
            parent['kind'] != 'builder-docker-review-parent' or
            any(not isinstance(parent[key], str) or not re.fullmatch('[0-9a-f]{64}', parent[key]) for key in
                ('subject_sha256', 'reviewer_authority_sha256', 'original_outer_sha256', 'original_inner_sha256')) or
            any(not isinstance(parent[key], str) or not re.fullmatch('[0-9a-f]{40}', parent[key]) for key in ('head_sha', 'fence')) or
            not isinstance(parent['builder_run_id'], str) or not re.fullmatch('run-[0-9a-f]{32}', parent['builder_run_id']) or
            parent['builder_run_id'] == packet['builder_run_id'] or
            not isinstance(parent['engine_run_id'], str) or not re.fullmatch('[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}', parent['engine_run_id'])):
        raise ValueError('Docker REVIEW requires its separate root-granted original parent')
    namespace = Path(packet['worker_authority']['contract_path']).parent.parent
    name = parent['builder_run_id'] + '.json'
    outer_path, inner_path = namespace/'execution-contracts-docker-v1'/name, namespace/'engine-contracts-docker-v1'/name
    original_outer = json.loads(sealed_bytes(outer_path, expected=parent['original_outer_sha256']))
    original_inner = json.loads(sealed_bytes(inner_path, expected=parent['original_inner_sha256']))
    if (original_outer.get('kind') != 'builder-docker-delivery' or original_outer.get('run_id') != parent['builder_run_id'] or
            original_outer.get('engine_contract') != {'path':str(inner_path),'sha256':parent['original_inner_sha256']} or
            original_inner.get('run_id') != parent['builder_run_id'] or original_inner.get('role') != 'standard-implementation' or
            original_inner.get('repository') != inner.get('repository') or original_inner.get('issue') != inner.get('issue') or
            original_inner['execution']['workspace'] == inner['execution']['workspace']):
        raise ValueError('Docker REVIEW original material differs from granted parent')
    return {'review_parent':parent, 'original_inner':original_inner}
