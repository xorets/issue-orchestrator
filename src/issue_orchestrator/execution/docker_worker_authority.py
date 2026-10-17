"""Project the exact sealed worker authority without ambient credentials."""
from hashlib import sha256
import json
from pathlib import Path
import re

from .agent_runner_env import DEFAULT_FORBIDDEN_ENV_VARS
from .docker_launch_input import canonical, sealed_bytes


def _require_mounts(packet: dict, paths: tuple[Path, Path]) -> None:
    mounts = packet["mounts"]
    for path in paths:
        if {"source": str(path), "target": str(path), "read_only": True} not in mounts:
            raise ValueError("Docker worker authority lacks exact read-only file mount")
        for mount in mounts:
            if not mount["read_only"] and any(path == root or path.is_relative_to(root)
                    for root in (Path(mount["source"]), Path(mount["target"]))):
                raise ValueError("Docker worker authority overlaps writable mount")


def _authority_environment(packet: dict) -> dict[str, str]:
    descriptor = packet.get("worker_authority")
    if descriptor is None:
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
    if (set(outer) != {"schema_version", "kind", "model_admission", "run_id", "subject", "engine_contract", "worker", "installed_acceptance"} or
            outer.get("schema_version") != 1 or outer.get("kind") != "builder-docker-delivery" or
            outer.get("model_admission") is not False or outer.get("installed_acceptance") is not None or
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


def worker_environment(packet: dict, provider: dict[str, str], callback_token: str | None) -> dict[str, str]:
    """Only explicit provider secrets, scoped callback and verified seals cross."""
    reserved = {*DEFAULT_FORBIDDEN_ENV_VARS, "ISSUE_ORCH_GITHUB_TOKEN", "XORETS_EXECUTION_CONTRACT",
        "XORETS_EXECUTION_DIGEST", "ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN"}
    if any(name in reserved or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or "\x00" in value
            for name, value in provider.items()):
        raise ValueError("Docker provider environment overrides controller authority")
    if packet.get("worker_authority") is not None and not re.fullmatch(
            r"[A-Za-z0-9_-]{64}", provider.get("ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY", "")):
        raise ValueError("Docker worker authority requires allocation-bound completion capability")
    environment = {**provider, **_authority_environment(packet)}
    if callback_token:
        if not re.fullmatch(r"[0-9a-f]{64}", callback_token):
            raise ValueError("Docker callback token is invalid")
        environment["ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN"] = callback_token
    elif packet.get("worker_authority") is not None:
        raise ValueError("Docker worker authority requires scoped callback authentication")
    return environment
