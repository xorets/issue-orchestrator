"""Repository Engine child configuration-boundary tests."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from issue_orchestrator.adapters.github.claim_parser import format_claim_comment
from issue_orchestrator.adapters.github.ref_claim_adapter import CLAIM_REF_PREFIX
from issue_orchestrator.domain.claim import Claim
from issue_orchestrator.entrypoints.bootstrap import _create_claim_components
from issue_orchestrator.entrypoints.run_orchestrator import _load_config_for_instance, parse_args
from issue_orchestrator.infra.config import Config
from issue_orchestrator.infra.config_identity import (
    ConfigurationFingerprintMismatch,
    EXPECTED_CONFIG_FINGERPRINT_ENV,
)
from tests.unit.adapters.github.fake_git_data import FakeGitHubRefClient


def _write_mode_config(repo: Path, content: str = "agents: {}\n") -> Path:
    path = repo / ".issue-orchestrator/config/modes/codex/main.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_child_rejects_maintenance_config_before_runtime_start(tmp_path: Path) -> None:
    path = tmp_path / ".issue-orchestrator/config/maintenance/hooks-validate.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("agents: {}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="maintenance config cannot launch"):
        _load_config_for_instance(tmp_path, path, None)


def test_child_rejects_config_changed_after_parent_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_mode_config(tmp_path)
    monkeypatch.setenv(EXPECTED_CONFIG_FINGERPRINT_ENV, "preflight-fingerprint")

    with pytest.raises(ConfigurationFingerprintMismatch):
        _load_config_for_instance(tmp_path, path, None, mode="codex")


def test_instance_cli_keeps_expected_predecessor_through_bootstrap(tmp_path, monkeypatch) -> None:
    predecessor = "a" * 40
    path = _write_mode_config(tmp_path, f"""agents: {{}}
filtering:
  issue: 42
claims:
  enabled: true
  expected_predecessor:
    issue_number: 42
    ref_sha: {predecessor}
""")
    monkeypatch.setenv(EXPECTED_CONFIG_FINGERPRINT_ENV, Config.load(path).config_fingerprint)
    monkeypatch.setattr(sys, "argv", ["run_orchestrator", "--repo-root", str(tmp_path), "--config",
                                      str(path), "--mode", "codex", "--instance-id", "fixture-instance"])
    args = parse_args()
    config = _load_config_for_instance(args.repo_root, args.config, args.instance_id, args.mode)

    client = FakeGitHubRefClient()
    now = datetime.now()
    claim = Claim(lease_id="moved", claimant="peer", issue_number=42, started_at=now - timedelta(days=2),
                  expires_at=now - timedelta(days=1), priority=1)
    ref = f"{CLAIM_REF_PREFIX}/issue-42"
    moved_sha = client.seed_record(ref, format_claim_comment(claim))
    github = SimpleNamespace(http_client=client, add_label=Mock())
    components = _create_claim_components(config, github, Mock())

    result = components.claim_manager.attempt_claim(42)

    assert config.claims.claimant_id == "fixture-instance"
    assert not result.success and result.error == "Expected claim predecessor no longer holds the ref"
    assert client.refs[ref] == moved_sha and not client.updated_refs and not client.deleted_refs
    github.add_label.assert_not_called()
