"""Authenticate the launch-inherited immutable supervised authority ceiling."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import TYPE_CHECKING

from ..domain.original_delivery import OriginalDelivery

if TYPE_CHECKING:
    from ..infra.config import Config


def sealed_execution_contract(owner: OriginalDelivery, config: Config) -> None:
    raw_path = os.environ.get("XORETS_EXECUTION_CONTRACT", "")
    expected_digest = os.environ.get("XORETS_EXECUTION_DIGEST", "")
    if not raw_path or expected_digest != owner.contract_sha256:
        raise ValueError("Original launch-inherited contract seal is unavailable")
    path = Path(raw_path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("Original execution contract path is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o400):
            raise ValueError("Original execution contract is not a sealed owned file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            encoded = stream.read(1024 * 1024 + 1)
        if len(encoded) > 1024 * 1024 or hashlib.sha256(encoded).hexdigest() != expected_digest:
            raise ValueError("Original execution contract digest changed")
    finally:
        os.close(descriptor)
    contract = json.loads(encoded)
    _require_contract_binding(contract, owner, config)


def require_contract_schema(contract: dict) -> None:
    """Schema 5 binds current-state retry identity; schema 4 keeps its original meaning."""
    version = contract.get("schema_version")
    issue = contract.get("issue", {})
    if type(version) is not int or version not in (4, 5) or not isinstance(issue, dict):
        raise ValueError("Original supervised contract schema is unsupported")
    if version == 4:
        if "request" in issue or str(contract.get("generation", "")).startswith("request-v1-"):
            raise ValueError("Legacy contract cannot carry current request identity")
        return
    request = issue.get("request")
    repository = contract.get("repository", {})
    if (contract.get("execution", {}).get("backend") != "docker" or not isinstance(request, dict) or
            set(request) != {"schema_version", "id", "action", "repository", "issue_id",
                             "requirements_sha256", "predecessor_sha256", "history"} or
            set(issue) != {"id", "number", "requirements_sha256", "request", "satisfied_dependencies"} or
            type(request.get("schema_version")) is not int or request["schema_version"] != 1 or
            request.get("action") != "retry" or request.get("repository") != repository.get("name") or
            request.get("issue_id") != issue.get("id") or
            request.get("requirements_sha256") != issue.get("requirements_sha256")):
        raise ValueError("Current request contract subject is invalid")
    request_digest = hashlib.sha256(json.dumps({k: v for k, v in request.items() if k != "id"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    generation = "request-v1-" + request_digest
    run_id = "run-" + hashlib.sha256(json.dumps([repository.get("id"), issue["id"], generation],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    if (request.get("id") != request_digest or contract.get("generation") != generation or
            contract.get("run_id") != run_id):
        raise ValueError("Current request contract identity changed")


def _require_contract_binding(contract: object, owner: OriginalDelivery, config: Config) -> None:
    if not isinstance(contract, dict) or contract.get("controller_compatibility") != "supervised-v4":
        raise ValueError("Original supervised contract schema is unsupported")
    require_contract_schema(contract)
    repository = contract.get("repository", {})
    execution = contract.get("execution", {})
    branch = contract.get("branch", {})
    supervised = contract.get("supervised", {})
    if not all(isinstance(part, dict) for part in (repository, execution, branch, supervised)):
        raise ValueError("Original supervised contract binding is invalid")
    if execution.get("backend", "native") != owner.execution_backend:
        raise ValueError("Original supervised execution backend changed")
    if (repository.get("name"), repository.get("engine_root"), execution.get("workspace"),
            execution.get("agent_label"), execution.get("session_name"), execution.get("logical_child"), branch.get("name")) != (
            owner.repository, str(config.repo_root), owner.worktree, owner.agent, owner.session_name, owner.logical_child, owner.branch):
        raise ValueError("Original supervised contract session/repository changed")
    correction = supervised.get("correction", {})
    if not isinstance(correction, dict):
        raise ValueError("Original correction ceiling is unavailable")
    capabilities = correction.get("capabilities", {})
    budget = correction.get("budget", {})
    if not isinstance(capabilities, dict) or not isinstance(budget, dict):
        raise ValueError("Original correction ceiling is invalid")
    maximum = budget.get("max_rework_cycles")
    if (not isinstance(contract.get("capabilities"), dict) or not contract["capabilities"] or
            type(maximum) is not int or maximum != config.max_rework_cycles or maximum != owner.max_cycles or
            capabilities.get("originating") != contract.get("capabilities") or
            not correction.get("configuration_sha256") or
            correction.get("configuration_sha256") != execution.get("configuration_sha256")):
        raise ValueError("Original engine correction budget/authority ceiling changed")
