"""Docker completion authority uses private exec state, not controller file paths."""

import subprocess

import pytest

from issue_orchestrator.control.session_env import completion_capability_export, docker_session_secret_env
from issue_orchestrator.domain.completion_intake import CompletionIntakeError, IntakeClosed, IntakeUnauthorized
from tests.unit.test_completion_evidence_intake import setup
from tests.unit.test_issue_run_evidence import run_record


CAPABILITY = "ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY"


def test_docker_exports_preserve_only_the_exact_allocated_run_capability(tmp_path):
    ledger, run, capability, _, _, _ = setup(tmp_path)
    private = docker_session_secret_env(ledger, run, {"PROVIDER_KEY": "provider-value"})
    assert private == {"PROVIDER_KEY": "provider-value", CAPABILITY: capability}
    export = completion_capability_export(ledger, run, docker=True)
    assert capability not in export
    assert "cat " not in export
    assert not (tmp_path / "state" / "completion-intake-capabilities").exists()
    process = subprocess.run(["/bin/sh", "-c", "export" + export + '; test -n "$ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY"'],
        env=private, capture_output=True, text=True, timeout=5, check=False)
    assert process.returncode == 0
    assert capability not in process.stdout + process.stderr
    process = subprocess.run(["/bin/sh", "-c", "unset " + CAPABILITY + "; export" + export],
        env={}, capture_output=True, text=True, timeout=5, check=False)
    assert process.returncode != 0


@pytest.mark.parametrize("closed", [False, True])
def test_docker_private_environment_refuses_unknown_or_closed_run(tmp_path, closed):
    ledger, run, _, owner, _, _ = setup(tmp_path)
    if closed:
        owner.close_and_drain(42)
    else:
        run = run_record(tmp_path / "other", "unallocated").run
    with pytest.raises((CompletionIntakeError, IntakeClosed, IntakeUnauthorized)):
        docker_session_secret_env(ledger, run, {})


def test_provider_cannot_supply_completion_authority(tmp_path):
    ledger, run, _, _, _, _ = setup(tmp_path)
    with pytest.raises(ValueError, match="provider.*completion"):
        docker_session_secret_env(ledger, run, {CAPABILITY: "forged"})


def test_native_export_retains_private_file_locator(tmp_path):
    ledger, run, capability, _, _, _ = setup(tmp_path)
    export = completion_capability_export(ledger, run)
    artifact = ledger.submission_capability_file(run)
    assert str(artifact.path) in export
    assert "$(cat " in export
    assert capability not in export
