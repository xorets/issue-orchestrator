"""The non-model proof cannot inherit a remote daemon or pull a mutable image."""
import pytest
from scripts.probe_docker_sessions import docker_cli, validate_image


def test_probe_docker_client_pins_local_host_and_scrubs_ambient_context(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://foreign:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    observed = []
    def command(argv, **kwargs):
        observed.append((argv, kwargs))
        return "fixed-id\n"
    monkeypatch.setattr("scripts.probe_docker_sessions.subprocess.check_output", command)
    assert docker_cli("run", "--pull=never", "immutable-image") == "fixed-id"
    argv, options = observed[0]
    assert argv == ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "run", "--pull=never", "immutable-image"]
    assert options["env"] == {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "DOCKER_CONFIG": "/nonexistent"}


@pytest.mark.parametrize("image", ["alpine:latest", "alpine", "sha256:" + "a" * 64, "alpine@sha256:short"])
def test_probe_mutable_or_invalid_image_refuses(image):
    with pytest.raises(ValueError, match="immutable"):
        validate_image(image)
