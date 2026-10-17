"""Docker custody is discriminated and old Native claims remain readable."""
from dataclasses import replace
import pytest
from issue_orchestrator.domain.original_delivery import DockerCustody, OriginalDelivery
from tests.unit.test_original_delivery import custody


def docker_custody():
    return DockerCustody(schema_version=1, run_id="run-1", daemon_id="daemon", controller_container_id="1" * 64,
        container_id="2" * 64, provider_exec_id="3" * 64, launch_sha256="4" * 64)


def test_docker_claim_roundtrip_retains_full_identity():
    owner = replace(custody(), execution_backend="docker", docker_custody=(docker_custody(),))
    assert OriginalDelivery.from_dict(owner.to_dict()) == owner


def test_old_native_record_is_readable_without_new_fields():
    old = custody().to_dict()
    old.pop("execution_backend")
    old.pop("docker_custody")
    assert OriginalDelivery.from_dict(old) == custody()


def test_unknown_backend_and_mixed_custody_refuse():
    with pytest.raises(ValueError, match="backend"):
        replace(custody(), execution_backend="unknown")
    with pytest.raises(ValueError, match="custody"):
        replace(custody(), docker_custody=(docker_custody(),))
    with pytest.raises(ValueError, match="custody"):
        replace(custody(), execution_backend="docker", process_roots=(("run-1", 1, "birth", 1, "birth"),))


def test_docker_custody_unknown_or_invalid_fields_refuse():
    with pytest.raises(ValueError):
        replace(docker_custody(), schema_version=2)
    with pytest.raises(ValueError):
        replace(docker_custody(), container_id="short")


def test_docker_quiescence_requires_worker_and_prior_controller_to_be_inactive():
    from issue_orchestrator.execution.original_delivery_docker import DockerOriginalCustody
    from issue_orchestrator.execution.terminal_docker import DockerPlugin
    class Engine:
        worker_running = True
        controller_running = True
        daemon = "daemon"
        def request(self, method, route, payload=None):
            if route == "/info":
                return {"ID": self.daemon}
            if route == "/containers/" + "2" * 64 + "/json":
                return {"Id": "2" * 64, "State": {"Running": self.worker_running}, "Config": {"Labels": {"io.builder.launch": "4" * 64}}}
            if route == "/containers/" + "1" * 64 + "/json":
                return {"Id": "1" * 64, "State": {"Running": self.controller_running}}
            if route == "/exec/" + "3" * 64 + "/json":
                return {"ID": "3" * 64, "ContainerID": "2" * 64}
            raise AssertionError(route)
    engine = Engine()
    adapter = DockerOriginalCustody(DockerPlugin(engine=engine))
    owner = replace(custody(), execution_backend="docker", docker_custody=(docker_custody(),))
    with pytest.raises(ValueError, match="worker remains"):
        adapter.quiescent(owner, offline=False)
    engine.worker_running = False
    adapter.quiescent(owner, offline=False)
    with pytest.raises(ValueError, match="controller"):
        adapter.quiescent(owner, offline=True)
    engine.controller_running = False
    adapter.quiescent(owner, offline=True)
    engine.daemon = "foreign"
    with pytest.raises(ValueError, match="daemon"):
        adapter.termination_scope(owner, "run-1")


def test_public_docker_owner_payload_accepts_discriminated_claim():
    from issue_orchestrator.contracts.ui_openapi_models import OriginalDeliveryOwnerPayload
    owner = replace(custody(), execution_backend="docker", docker_custody=(docker_custody(),))
    parsed = OriginalDeliveryOwnerPayload.model_validate(owner.to_dict())
    assert parsed.execution_backend == "docker"
