"""One sealed Dev Container session through the existing terminal plugin seam.

Builder owns admission. This adapter only executes the immutable admitted
packet, retains Docker identities before start, and never replays a launch.
"""
from __future__ import annotations

from contextlib import suppress
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
from uuid import uuid4

from ..domain.original_delivery import DockerCustody
from ..domain.docker_execution import DockerSessionState
from ..domain.session_run import SessionRunAssets
from ..infra.hooks.hookspec import hookimpl
from .docker_engine import DockerEngine
from .docker_worker_state import (
    require_worker_identity, require_first_model_liveness as require_first_model_liveness,
    require_selected_bridge, require_worker_network as require_worker_network,
    require_bridge_endpoint as require_bridge_endpoint, worker_network_endpoint as worker_network_endpoint,
    require_stopped_parent_state, require_stopped_worker_network,
)
from .docker_launch_input import canonical as canonical, sealed_bytes as sealed_bytes, network_arguments as network_arguments, control_manifest_bytes, require_create_intent, hook_argv
from .docker_worker_authority import worker_environment, model_projection_snapshot, model_review_parent

logger = logging.getLogger(__name__)


def private_directory(path: Path, *, create: bool = False) -> Path:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Docker ordinary output directory is not private and canonical")
    return path


def seed_control_manifest(packet: dict, temporary: Path) -> None:
    """Use the pinned CLI cache path and the actual fetch time, never copy time."""
    if "control_manifest" not in packet:
        return
    raw = control_manifest_bytes(packet["control_manifest"])
    username = pwd.getpwuid(os.geteuid()).pw_name
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValueError("Docker CLI account name is unsafe")
    cache = private_directory(temporary / ("devcontainercli-" + username), create=True) / "control-manifest.json"
    descriptor = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(raw)
    fetched = packet["control_manifest"]["fetched_unix_ns"]
    os.utime(cache, ns=(fetched, fetched), follow_symlinks=False)


def seal_first_model_bytes(directory: Path, raw: bytes) -> dict[str, str]:
    """Write one exclusive immutable bounded receipt in controller-only custody."""
    name = "receipt-" + uuid4().hex + ".json"
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o400, dir_fd=directory_fd)
        with os.fdopen(fd, "w+b") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno()); stream.seek(0)
            before = os.fstat(stream.fileno())
            if (before.st_uid != os.getuid() or before.st_nlink != 1 or
                    not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400 or stream.read(65537) != raw):
                raise ValueError("Docker first-model evidence custody changed")
            after = os.fstat(stream.fileno())
            fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise ValueError("Docker first-model evidence changed during readback")
        os.fsync(directory_fd)
        if private_directory(directory) != directory:
            raise ValueError("Docker first-model evidence directory changed")
    finally:
        os.close(directory_fd)
    return {"path": str(directory / name), "sha256": sha256(raw).hexdigest()}


def first_model_evidence_size(directory: Path) -> int:
    """Account only authenticated immutable receipts in the private output allocation."""
    previous_bytes = 0
    for entry in directory.iterdir():
        info = entry.lstat()
        if (not re.fullmatch(r"receipt-[0-9a-f]{32}\.json", entry.name) or
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400 or not 0 < info.st_size <= 65536):
            raise ValueError("Docker first-model previous evidence custody changed")
        previous_bytes += info.st_size
    return previous_bytes


def run_cli_capture(argv: list[str], *, environment: dict[str, str], timeout: float,
                    output_limit: int = 1024 * 1024, diagnostic_path: Path | None = None) -> tuple[bytes, bytes, int]:
    """Bound both CLI pipes before allocation and kill descendants on timeout."""
    if timeout <= 0:
        raise ValueError("Dev Container CLI deadline exhausted")
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, start_new_session=True)
    assert child.stdout is not None and child.stderr is not None
    output, errors = bytearray(), bytearray()
    completed = False
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(child.stdout, selectors.EVENT_READ, output)
        selector.register(child.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Dev Container CLI deadline exhausted")
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif len(output) + len(errors) + len(chunk) > output_limit:
                    raise ValueError("Dev Container CLI output bound exhausted")
                else:
                    key.data.extend(chunk)
        exit_code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        completed = exit_code == 0
        return bytes(output), bytes(errors), exit_code
    finally:
        selector.close()
        if not completed:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()
        if diagnostic_path is not None:
            descriptor = os.open(diagnostic_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(bytes(output) + b"\n--- stderr ---\n" + bytes(errors))
                destination.flush()
                os.fsync(destination.fileno())


def run_cli(argv: list[str], *, environment: dict[str, str], timeout: float, diagnostic_path: Path | None = None) -> bytes:
    """Run admitted CLI input, retaining the existing success-only byte interface."""
    output, _, exit_code = run_cli_capture(argv, environment=environment, timeout=timeout, diagnostic_path=diagnostic_path)
    if exit_code != 0:
        raise ValueError("Dev Container CLI refused")
    return output


class DockerPlugin:
    """SessionRunner implementation; an absent/mismatched packet always refuses."""
    def __init__(self, *, launch_path: Path | None = None, engine: DockerEngine | None = None, callback_token: str | None = None):
        self._callback_token = callback_token
        raw = launch_path or os.environ.get("ISSUE_ORCHESTRATOR_DOCKER_LAUNCH")
        self.launch_path = Path(raw) if raw else None
        template = os.environ.get("ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE")
        self.template_path = Path(template) if template else None
        if self.launch_path is None and self.template_path is not None:
            active = self.template_path.with_name("docker-active.json")
            if active.exists():
                selected = json.loads(active.read_bytes())
                self.select_run(selected["run_id"])
        self.engine = engine or DockerEngine()
        self._record: dict | None = None
        self._packet: dict | None = None
        self._lock = threading.RLock()
        self._watcher: threading.Thread | None = None
        self._watched_record: dict | None = None

    def select_run(self, run_id: str) -> None:
        if self.template_path is None or not re.fullmatch(r"[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}", run_id):
            raise ValueError("Docker engine run identity is invalid")
        path = self.template_path.parent / run_id / "launch.json"
        if path.resolve(strict=True) != path:
            raise ValueError("Docker prepared launch path is not canonical")
        if self.launch_path != path:
            self.launch_path = path
            self._record = None

    @hookimpl
    def prepare_session(self, run: SessionRunAssets, session_name: str, command: str) -> bool:
        """Fill only engine-assigned values in the controller's immutable template."""
        if self.template_path is None:
            raise ValueError("Docker launch template is unavailable")
        packet = json.loads(sealed_bytes(self.template_path))
        if (packet.get("run_id"), packet.get("engine_run_dir"), packet.get("command_sha256")) != ("", "", "0" * 64):
            raise ValueError("Docker template has no unbound engine assignment")
        if (packet.get("session_name"), packet.get("working_dir"), packet.get("contract_sha256")) != (
                session_name, str(run.worktree_path), os.environ.get("XORETS_EXECUTION_DIGEST")):
            raise ValueError("Docker template session/worktree/contract binding changed")
        contract_path = Path(os.environ.get("XORETS_EXECUTION_CONTRACT", ""))
        if packet.get("worker_authority", {}).get("engine_contract_path", str(contract_path)) != str(contract_path):
            raise ValueError("Docker worker projection differs from controller contract path")
        contract = json.loads(sealed_bytes(contract_path, expected=packet["contract_sha256"]))
        declaration = contract.get("execution", {}).get("docker_launch", {})
        intent = {key: value for key, value in packet.items() if key not in {"contract_sha256", "run_id", "engine_run_dir", "command_sha256"}}
        if (contract.get("execution", {}).get("backend") != "docker" or
                declaration.get("template_path") != str(self.template_path) or
                declaration.get("intent_sha256") != sha256(canonical(intent)).hexdigest()):
            raise ValueError("Docker template differs from immutable contract intent")
        if (not re.fullmatch(r"[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}", run.run_id) or
                run.run_dir.resolve(strict=True) != run.run_dir or run.run_dir.stat().st_uid != os.getuid()):
            raise ValueError("Docker typed run assets are not owned/canonical")
        if self._watcher is not None and self._watcher.is_alive():
            raise ValueError("Docker prior session has not settled")
        packet = {**packet, "run_id": run.run_id, "engine_run_dir": str(run.run_dir),
            "command_sha256": sha256(command.encode()).hexdigest()}
        root = self.template_path.parent / run.run_id
        root.mkdir(mode=0o700, exist_ok=False)
        path = root / "launch.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(canonical(packet))
            destination.flush()
            os.fsync(destination.fileno())
        self.launch_path = path
        self._record = None
        self._load_packet()  # Every unfilled/freshly bound prerequisite still applies.
        active = self.template_path.with_name("docker-active.json")
        temporary = active.with_name(".docker-active.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(canonical({"run_id": run.run_id}))
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, active)
        directory = os.open(root.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return True

    @staticmethod
    def _validate_identity(packet: dict) -> None:
        if type(packet) is not dict or packet.get("schema_version") != 1:
            raise ValueError("Unsupported Docker launch packet")
        for name in ("repository", "run_id", "session_name", "working_dir", "daemon_id", "container_name", "network_id", "user"):
            if type(packet.get(name)) is not str or not packet[name]:
                raise ValueError("Docker launch identity is missing: " + name)
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", packet["container_name"]) or
                not re.fullmatch(r"[0-9]{8}-[0-9]{6}Z-[0-9a-f]{32}", packet["run_id"]) or
                not re.fullmatch(r"run-[0-9a-f]{32}", packet.get("builder_run_id", "")) or
                type(packet.get("engine_run_dir")) is not str or not Path(packet["engine_run_dir"]).is_absolute()):
            raise ValueError("Docker Builder/engine run identity is invalid")
        for name in ("contract_sha256", "command_sha256", "devcontainer_config_sha256", "devcontainer_cli_sha256",
                     "docker_cli_sha256", "node_sha256", "storage_policy_sha256", "network_policy_sha256", "controller_container_id"):
            if type(packet.get(name)) is not str or not re.fullmatch(r"[0-9a-f]{64}", packet[name]):
                raise ValueError("Docker launch digest is invalid: " + name)
        image = packet.get("image", "")
        if (type(image) is not str or not (re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) or
                re.fullmatch(r"sha256:[0-9a-f]{64}", image)) or
                not re.fullmatch(r"sha256:[0-9a-f]{64}", packet.get("image_id", ""))):
            raise ValueError("Docker image is not immutable")
        if image.startswith("sha256:") and image != packet["image_id"]:
            raise ValueError("Docker local image identity changed")
        if packet.get("read_only") is not True or not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", packet["user"]):
            raise ValueError("Docker root/user policy is invalid")

    @staticmethod
    def _validate_limits(packet: dict) -> None:
        limits = packet.get("limits", {})
        for name in ("memory_bytes", "swap_bytes", "cpu_nano", "pids", "max_output_bytes"):
            if type(limits.get(name)) is not int or limits[name] <= 0:
                raise ValueError("Docker launch lacks a hard resource bound: " + name)
        if limits["swap_bytes"] < limits["memory_bytes"]:
            raise ValueError("Docker swap ceiling is invalid")
        if type(packet.get("deadline_unix_ns")) is not int or packet["deadline_unix_ns"] <= time.time_ns():
            raise ValueError("Docker launch deadline exhausted")

    @staticmethod
    def _verify_tools(packet: dict) -> None:
        for name in ("devcontainer_cli", "docker_cli", "node"):
            path = Path(packet[name])
            if not path.is_absolute() or path.resolve(strict=True) != path or sha256(path.read_bytes()).hexdigest() != packet[name + "_sha256"]:
                raise ValueError("Docker launch tool identity changed")
        files = packet.get("tool_files")
        if type(files) is not dict or not files:
            raise ValueError("Docker launch tool closure is missing")
        for name, digest in files.items():
            path = Path(name)
            if not path.is_absolute() or path.resolve(strict=True) != path or sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("Docker launch tool closure changed")

    def _load_packet(self) -> dict:
        if self.launch_path is None:
            raise ValueError("No admitted Docker launch packet")
        packet = json.loads(sealed_bytes(self.launch_path))
        self._validate_identity(packet)
        self._validate_limits(packet)
        if "control_manifest" in packet:
            control_manifest_bytes(packet["control_manifest"])
        self._verify_tools(packet)
        self._output_root(packet)
        config = json.loads(sealed_bytes(Path(packet["devcontainer_config"]), expected=packet["devcontainer_config_sha256"]))
        require_create_intent(config, packet)
        image = self.engine.request("GET", f"/images/{packet['image_id']}/json")
        if image.get("Id") != packet["image_id"] or image.get("Config", {}).get("Volumes"):
            raise ValueError("Docker image identity changed or declares unbounded volumes")
        if self.engine.request("GET", "/info").get("ID") != packet["daemon_id"]:
            raise ValueError("Docker daemon identity changed")
        controller = self.engine.request("GET", f"/containers/{packet['controller_container_id']}/json")
        if controller.get("Id") != packet["controller_container_id"] or controller.get("State", {}).get("Running") is not True:
            raise ValueError("Docker controller identity is unavailable")
        require_selected_bridge(self.engine, packet, controller)
        return packet

    def _output_root(self, packet: dict) -> Path:
        raw = packet.get("output_root")
        if not isinstance(raw, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", raw):
            raise ValueError("Docker output_root is required")
        root = Path(raw)
        if str(root) != raw or ".." in root.parts:
            raise ValueError("Docker output root is not normalized")
        if "worker_authority" in packet and root != Path("/srv/builder/tasks") / packet["builder_run_id"] / "controller-output":
            raise ValueError("Docker output root leaves selected task allocation")
        assert self.launch_path is not None
        paths = [self.launch_path.parent, *(Path(m[key]) for m in packet["mounts"] for key in ("source", "target"))]
        if self.template_path is not None:
            paths.append(self.template_path.parent)
        if any(root.is_relative_to(path.resolve()) or path.resolve().is_relative_to(root) for path in paths):
            raise ValueError("Docker ordinary output overlaps settlement or worker mounts")
        return private_directory(root)

    def _output_directory(self, packet: dict) -> Path:
        return private_directory(self._output_root(packet) / packet["run_id"])

    def receipt_path(self) -> Path:
        if self.launch_path is None:
            raise ValueError("Docker launch path unavailable")
        return self.launch_path.with_name("docker-session.json")

    def _save(self) -> None:
        with self._lock:
            path = self.receipt_path()
            temporary = path.with_name(".docker-session.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as destination:
                    destination.write(canonical(self._record or {}))
                    destination.flush()
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def _record_for(self, session_name: str) -> dict | None:
        if self._record is None and self.launch_path and self.receipt_path().exists():
            self._record = json.loads(self.receipt_path().read_bytes())
        if self._record is None or self._record.get("session_name") != session_name:
            return None
        return self._record

    def _inspect_owned(self, record: dict) -> dict:
        if self.engine.request("GET", "/info").get("ID") != record["daemon_id"]:
            raise ValueError("Docker daemon identity changed")
        actual = self.engine.request("GET", f"/containers/{record['container_id']}/json")
        require_worker_identity(actual, record["container_id"], record["launch_sha256"])
        return actual

    def _recover_created_identity(self, packet: dict) -> None:
        """Resolve lost CLI acknowledgement by name, then retain immutable ID."""
        assert self._record is not None
        if self._record.get("container_id"):
            return
        if self.engine.request("GET", "/info").get("ID") != packet["daemon_id"]:
            raise ValueError("Docker daemon changed during create reconciliation")
        actual = self.engine.request("GET", f"/containers/{packet['container_name']}/json")
        container_id = actual.get("Id", "")
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise ValueError("Docker unacknowledged create identity is unknown")
        require_worker_identity(actual, container_id, self._record["launch_sha256"])
        self._record["container_id"] = container_id
        self._save()

    def _validate_created(self, packet: dict, container_id: str, launch_digest: str, *, stopped_parent: bool = False) -> dict:
        actual = self.engine.request("GET", f"/containers/{container_id}/json")
        host = actual.get("HostConfig", {})
        config = actual.get("Config", {})
        limits = packet["limits"]
        require_worker_identity(actual, container_id, launch_digest)
        if stopped_parent:
            require_stopped_parent_state(actual)
        if (actual.get("Image") != packet["image_id"] or
                actual.get("Name") != "/" + packet["container_name"] or
                config.get("User") != packet["user"] or
                config.get("Volumes") or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False or
                host.get("CapAdd") or set(host.get("CapDrop") or []) != {"ALL"} or
                set(host.get("SecurityOpt") or []) != {"no-new-privileges:true"} or
                host.get("PidMode") or host.get("IpcMode") not in {"private", ""} or
                host.get("NetworkMode") != packet["network_id"] or host.get("Devices") or host.get("DeviceRequests") or
                host.get("PortBindings") or host.get("PublishAllPorts") or host.get("ExtraHosts") or
                host.get("LogConfig", {}).get("Type") != "none" or host.get("RestartPolicy", {}).get("Name") != "no" or
                host.get("Memory") != limits["memory_bytes"] or host.get("MemorySwap") != limits["swap_bytes"] or
                host.get("NanoCpus") != limits["cpu_nano"] or host.get("PidsLimit") != limits["pids"] or
                host.get("Tmpfs") != packet.get("tmpfs")):
            raise ValueError("Docker created result differs from admitted security/resource intent")
        expected = {(item["source"], item["target"], item["read_only"]) for item in packet["mounts"]}
        observed = {(item.get("Source"), item.get("Destination"), not item.get("RW")) for item in actual.get("Mounts", []) if item.get("Type") == "bind"}
        if expected != observed or any(item.get("Type") not in {"bind", "tmpfs"} for item in actual.get("Mounts", [])):
            raise ValueError("Docker created mounts differ from admitted mounts")
        if any(item.get("Destination") not in packet["tmpfs"] for item in actual.get("Mounts", []) if item.get("Type") == "tmpfs"):
            raise ValueError("Docker created an unbounded temporary mount")
        if stopped_parent:
            require_stopped_worker_network(actual, packet)
        else:
            require_worker_network(actual, packet)
        if "network" in packet:
            controller = self.engine.request("GET", f"/containers/{packet['controller_container_id']}/json")
            if controller.get("Id") != packet["controller_container_id"] or controller.get("State", {}).get("Running") is not True:
                raise ValueError("Docker controller identity is unavailable")
            require_selected_bridge(self.engine, packet, controller)
        return actual

    @hookimpl
    def create_session(self, session_id: int, command: str, working_dir: str, title: str | None,
                       session_name: str, secret_env: dict[str, str] | None) -> bool:
        reserved = False
        packet = None
        try:
            packet = self._load_packet()
            assert self.launch_path is not None
            if (packet["session_name"], packet["working_dir"], packet["command_sha256"]) != (session_name, working_dir, sha256(command.encode()).hexdigest()):
                raise ValueError("Docker launch command/session/worktree changed")
            environment_values = worker_environment(packet, secret_env or {},
                self._callback_token or os.environ.get("ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN"))
            launch_digest = sha256(canonical(packet)).hexdigest()
            with self._lock:
                descriptor = os.open(self.receipt_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
                reserved = True
                self._packet = packet
                self._record = {"schema_version": 1, "execution_backend": "docker", "repository": packet["repository"],
                    "run_id": packet["run_id"], "session_name": session_name, "issue_number": session_id,
                    "contract_sha256": packet["contract_sha256"], "launch_sha256": launch_digest,
                    "daemon_id": packet["daemon_id"], "controller_container_id": packet["controller_container_id"],
                    "container_id": "", "provider_exec_id": "", "state": DockerSessionState.RESERVED, "output_bytes": 0,
                    "overflow": False, "provider_exit_code": None, "error": ""}
                self._record["hook_execs"] = []
                self._save()
            # CLI sees only generated admitted config. The provider command never
            # reaches the service shell or Dev Container lifecycle machinery.
            ordinary = private_directory(self._output_root(packet) / packet["run_id"], create=True)
            home = private_directory(ordinary / "home", create=True)
            temporary = private_directory(ordinary / "tmp", create=True)
            seed_control_manifest(packet, temporary)
            environment = {"PATH": str(Path(packet["node"]).parent) + ":/usr/bin:/bin", "HOME": str(home),
                "TMPDIR": str(temporary),
                "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONFIG": "/nonexistent"}
            self._validate_limits(packet)
            result = run_cli([packet["node"], packet["devcontainer_cli"], "up", "--workspace-folder", working_dir,
                "--config", packet["devcontainer_config"], "--docker-path", packet["docker_cli"],
                "--skip-post-create", "--skip-non-blocking-commands",
                "--mount-workspace-git-root", "false",
                "--default-user-env-probe", "none", "--update-remote-user-uid-default", "never",
                "--container-data-folder", "/tmp/devcontainer-user", "--container-system-data-folder", "/var/devcontainer",
                "--container-session-data-folder", "/tmp/devcontainer-session",
                "--id-label", "io.builder.launch=" + launch_digest],
                environment=environment, timeout=(packet["deadline_unix_ns"] - time.time_ns()) / 1e9,
                diagnostic_path=ordinary / "docker-cli.log")
            created = json.loads(result)
            container_id = created.get("containerId", "")
            if not re.fullmatch(r"[0-9a-f]{64}", container_id):
                raise ValueError("Dev Container CLI did not return immutable container identity")
            self._record["container_id"] = container_id
            self._record["state"] = DockerSessionState.CREATED
            self._save()
            self._validate_created(packet, container_id, launch_digest)
            self._validate_limits(packet)
            self._run_hooks(packet)
            self._validate_limits(packet)
            # API payload is over the trusted Unix socket, never provider argv.
            payload = {"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False,
                "User": packet["user"], "WorkingDir": working_dir, "Cmd": ["/bin/sh", "-c", command],
                "Env": [name + "=" + value for name, value in environment_values.items()]}
            exec_id = self.engine.request("POST", f"/containers/{container_id}/exec", payload)["Id"]
            if not re.fullmatch(r"[0-9a-f]{64}", exec_id):
                raise ValueError("Docker did not return immutable provider exec identity")
            self._record["provider_exec_id"] = exec_id
            self._record["state"] = DockerSessionState.EXEC_CREATED
            self._save()  # Durable before the only allowed exec start.
            self._watched_record = self._record
            self._watcher = threading.Thread(target=self._run_provider, daemon=True)
            self._watcher.start()
            return True
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            logger.exception("Docker session creation refused; no Native fallback")
            if reserved and self._record is not None:
                self._record["error"] = "launch-refused-or-uncertain"
                self._record["state"] = DockerSessionState.RETAINED
                self._save()
                if not self._record.get("container_id") and packet is not None:
                    try:
                        self._recover_created_identity(packet)
                    except (OSError, ValueError, KeyError):
                        logger.error("Docker create acknowledgement unknown; immutable reservation retained")
                if self._record.get("container_id"):
                    try:
                        self.kill_session(session_id, session_name)
                    except Exception:
                        self._record["error"] = "container-stop-unproven"
                        self._record["state"] = DockerSessionState.RETAINED
                        self._save()
            return False

    def _deadline_stop(self) -> None:
        assert self._record is not None
        self._record["error"] = "global-deadline-exhausted"
        try:
            self.kill_session(self._record["issue_number"], self._record["session_name"])
        except Exception:
            self._record["error"] = "deadline-stop-unproven"
            self._record["state"] = DockerSessionState.RETAINED
            self._save()

    def _run_hooks(self, packet: dict) -> None:
        hooks = packet.get("hooks", {})
        phases = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand")
        if type(hooks) is not dict or set(hooks) - set(phases):
            raise ValueError("Unsupported Docker lifecycle phase")
        if not hooks:
            return
        assert self._record is not None
        record = self._record
        output = self._output_directory(packet) / "docker-hook-output.log"
        with output.open("xb") as destination:
            for phase in phases:
                if phase not in hooks:
                    continue
                argv = hook_argv(hooks[phase])
                payload = {"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False,
                    "User": packet["user"], "WorkingDir": packet["working_dir"], "Cmd": argv, "Env": []}
                exec_id = self.engine.request("POST", f"/containers/{record['container_id']}/exec", payload)["Id"]
                if not re.fullmatch(r"[0-9a-f]{64}", exec_id):
                    raise ValueError("Docker lifecycle exec identity is invalid")
                row = {"phase": phase, "exec_id": exec_id, "exit_code": None}
                record["hook_execs"].append(row)
                self._save()
                def consume(chunk: bytes) -> None:
                    with self._lock:
                        if record["output_bytes"] + record.get("first_model_bytes", 0) + len(chunk) > packet["limits"]["max_output_bytes"]:
                            record["overflow"] = True
                            raise ValueError("Docker lifecycle output bound exhausted")
                        destination.write(chunk)
                        destination.flush()
                        record["output_bytes"] += len(chunk)
                remaining = (packet["deadline_unix_ns"] - time.time_ns()) / 1e9
                if remaining <= 0:
                    raise ValueError("Docker lifecycle deadline exhausted")
                timer = threading.Timer(remaining, self._deadline_stop)
                timer.daemon = True
                timer.start()
                try:
                    self.engine.start_exec(exec_id, consume, remaining)
                finally:
                    timer.cancel()
                observed = self.engine.request("GET", f"/exec/{exec_id}/json")
                if observed.get("ContainerID") != record["container_id"] or observed.get("Running") is not False or observed.get("ExitCode") != 0:
                    raise ValueError("Docker lifecycle failed or did not settle")
                row["exit_code"] = 0
                self._save()

    def _run_provider(self) -> None:
        assert self._record is not None and self._packet is not None
        record, packet = self._record, self._packet
        remaining = max(0, (packet["deadline_unix_ns"] - time.time_ns()) / 1e9)
        deadline = threading.Timer(remaining, self._deadline_stop)
        deadline.daemon = True
        deadline.start()
        try:
            output = self._output_directory(packet) / "docker-output.log"
            with output.open("xb") as destination:
                def consume(chunk: bytes) -> None:
                    with self._lock:
                        if record["output_bytes"] + record.get("first_model_bytes", 0) + len(chunk) > packet["limits"]["max_output_bytes"]:
                            record["overflow"] = True
                            raise ValueError("Docker raw output hard bound exhausted")
                        destination.write(chunk)
                        destination.flush()
                        record["output_bytes"] += len(chunk)
                record["state"] = DockerSessionState.STARTING
                self._save()
                remaining = (packet["deadline_unix_ns"] - time.time_ns()) / 1e9
                if remaining <= 0:
                    raise ValueError("Docker launch deadline exhausted")
                self.engine.start_exec(record["provider_exec_id"], consume, remaining)
            provider = self.engine.request("GET", f"/exec/{record['provider_exec_id']}/json")
            if provider.get("ContainerID") != record["container_id"] or provider.get("Running") is not False:
                raise ValueError("Docker provider did not settle")
            record["provider_exit_code"] = provider.get("ExitCode")
        except Exception:
            logger.exception("Docker provider result retained as unknown")
            record["error"] = "provider-unsettled-or-bound-exhausted"
        finally:
            deadline.cancel()
            try:
                self.kill_session(record["issue_number"], record["session_name"])
            except Exception:
                record["error"] = "container-stop-unproven"
                record["state"] = DockerSessionState.RETAINED
                self._save()

    def custody(self, session_name: str) -> DockerCustody:
        record = self._record_for(session_name)
        if record is None:
            raise ValueError("Docker session custody is unavailable")
        self._inspect_owned(record)
        provider = self.engine.request("GET", f"/exec/{record['provider_exec_id']}/json")
        if provider.get("ID") != record["provider_exec_id"] or provider.get("ContainerID") != record["container_id"]:
            raise ValueError("Docker provider custody changed")
        return DockerCustody(**{key: record[key] for key in DockerCustody.__dataclass_fields__})

    def first_model_snapshot(self, run: SessionRunAssets, session_name: str, contract_sha256: str, launch_sha256: str) -> dict:
        """Fresh filtered live custody through the existing admitted worker checks."""
        if self.template_path is not None:
            self.select_run(run.run_id)
        packet = self._load_packet()
        if ((packet["run_id"], packet["engine_run_dir"], packet["working_dir"], packet["session_name"], packet["contract_sha256"]) !=
                (run.run_id, str(run.run_dir), str(run.worktree_path), session_name, contract_sha256) or
                sha256(canonical(packet)).hexdigest() != launch_sha256):
            raise ValueError("Docker first-model assigned launch changed")
        outer, inner, projection = model_projection_snapshot(packet)
        if inner["role"] not in {"standard-implementation", "standard-review"}:
            raise ValueError("Docker first-model requires selected CODE or REVIEW authority")
        review = model_review_parent(packet, outer, inner) if inner['role'] == 'standard-review' else {}
        custody = self.custody(session_name)
        if custody.run_id != run.run_id or custody.launch_sha256 != launch_sha256:
            raise ValueError("Docker first-model original custody changed")
        actual = self._validate_created(packet, custody.container_id, launch_sha256)
        provider = self.engine.request("GET", "/exec/" + custody.provider_exec_id + "/json")
        require_first_model_liveness(actual, provider, custody)
        worker = {"daemon_id": custody.daemon_id, "controller_container_id": custody.controller_container_id,
            "container_id": custody.container_id, "provider_exec_id": custody.provider_exec_id, "image_id": packet["image_id"],
            "running": True, "paused": False, "restarting": False, "oom_killed": False, "restart_count": 0,
            "provider_running": True, "provider_exit_code": None}
        return {"role":inner['role'], **review, "builder_run_id": packet["builder_run_id"], "outer_sha256": sha256(canonical(outer)).hexdigest(),
            "projection_sha256": sha256(canonical(projection)).hexdigest(),
            "custody": {key: getattr(custody, key) for key in DockerCustody.__dataclass_fields__}, "worker": worker}

    def verify_stopped_parent(self, packet: dict, custody: DockerCustody) -> None:
        """Read-only daemon proof of the granted implementation's terminal custody."""
        if self.engine.request('GET', '/info').get('ID') != custody.daemon_id:
            raise ValueError('Docker review parent daemon changed')
        self._validate_created(packet, custody.container_id, custody.launch_sha256, stopped_parent=True)
        provider = self.engine.request('GET', '/exec/' + custody.provider_exec_id + '/json')
        if (provider.get('ID') != custody.provider_exec_id or provider.get('ContainerID') != custody.container_id or
                provider.get('Running') is not False or type(provider.get('ExitCode')) is not int or provider['ExitCode'] != 0):
            raise ValueError('Docker review parent implementation is not successfully stopped')

    def seal_first_model(self, run: SessionRunAssets, receipt: dict) -> dict:
        """Exclusive controller-only evidence in the existing bounded output root."""
        with self._lock:
            return self._seal_first_model(run, receipt)

    def _seal_first_model(self, run: SessionRunAssets, receipt: dict) -> dict:
        packet = self._load_packet()
        if (packet["run_id"] != run.run_id or receipt["run_id"] != run.run_id or
                receipt["launch_sha256"] != sha256(canonical(packet)).hexdigest()):
            raise ValueError("Docker first-model evidence run changed")
        raw = canonical(receipt)
        if not 0 < len(raw) <= min(65536, packet["limits"]["max_output_bytes"]):
            raise ValueError("Docker first-model evidence exceeds metadata bound")
        root = self._output_directory(packet)
        available = os.statvfs(root)
        if available.f_bavail * available.f_frsize < len(raw) + 8192:
            raise ValueError("Docker first-model output allocation exhausted")
        directory = root / "builder-first-model"
        if not directory.exists():
            private_directory(directory, create=True)
        private_directory(directory)
        previous_bytes = first_model_evidence_size(directory)
        record = self._record_for(packet["session_name"])
        if record is not None and record.get("first_model_bytes", 0) != previous_bytes:
            raise ValueError("Docker first-model evidence accounting changed")
        if previous_bytes + len(raw) + (record or {}).get("output_bytes", 0) > packet["limits"]["max_output_bytes"]:
            raise ValueError("Docker first-model aggregate output bound exhausted")
        result = seal_first_model_bytes(directory, raw)
        if record is not None:
            record["first_model_bytes"] = previous_bytes + len(raw)
            self._save()
        return result

    def public_receipt(self, session_name: str) -> dict:
        self.custody(session_name)
        record = self._record_for(session_name)
        assert record is not None
        return {"schema_version": 1, "backend": "docker", **{name: record[name] for name in
            ("repository", "run_id", "session_name", "contract_sha256", "daemon_id", "controller_container_id",
             "container_id", "provider_exec_id", "launch_sha256")}}

    @hookimpl
    def session_exists(self, session_id: int, session_name: str) -> bool:
        record = self._record_for(session_name)
        if record is None:
            return False
        actual = self._inspect_owned(record)
        return actual.get("State", {}).get("Running") is True

    @hookimpl
    def session_exists_by_name(self, session_name: str) -> bool:
        return self.session_exists(0, session_name)

    @hookimpl
    def kill_session(self, session_id: int, session_name: str) -> None:
        record = self._record_for(session_name)
        if record is None or not record.get("container_id"):
            raise ValueError("Docker stop target is unknown; retain evidence")
        self._inspect_owned(record)
        self.engine.stop(record["container_id"])
        record["state"] = DockerSessionState.STOPPED
        self._save()

    @hookimpl
    def discover_running_sessions(self) -> list[dict]:
        if self.launch_path is None:
            return []
        packet = json.loads(sealed_bytes(self.launch_path))
        record = self._record_for(packet["session_name"])
        if record and not record.get("container_id"):
            self._recover_created_identity(packet)
        if record and record.get("container_id") and self.session_exists(0, packet["session_name"]):
            if (record is self._watched_record and self._watcher is not None and
                    self._watcher.is_alive()):
                return []  # This exact in-process watcher still owns provider settlement.
            # Restart never starts/reattaches the provider. Stop the old worker;
            # the original owner must explicitly settle its retained claim.
            self.kill_session(record["issue_number"], record["session_name"])
            record["error"] = "controller-restart-provider-result-unknown"
            self._save()
        return []

    @hookimpl
    def cleanup_idle_sessions(self) -> int:
        return 0  # Evidence remains referenced; cleanup is a separate owner action.

    @hookimpl
    def get_session_output(self, session_id: int, lines: int, session_name: str) -> str | None:
        if self._record_for(session_name) is None:
            return None
        assert self.launch_path is not None
        packet = json.loads(sealed_bytes(self.launch_path))
        self._validate_identity(packet)
        record = self._record_for(session_name)
        assert record is not None
        if (sha256(canonical(packet)).hexdigest() != record["launch_sha256"] or
                packet["run_id"] != record["run_id"]):
            raise ValueError("Docker output launch identity changed")
        path = self._output_directory(packet) / "docker-output.log"
        if not path.exists():
            return None
        with path.open("rb") as source:
            source.seek(max(0, path.stat().st_size - 65536))
            return b"\n".join(source.read(65536).splitlines()[-max(0, min(lines, 1000)):]).decode(errors="replace")

    @hookimpl
    def send_to_session(self, session_id: int, text: str, session_name: str) -> bool:
        return False  # Initial noninteractive exec has no unaudited input channel.

    @hookimpl
    def send_to_session_by_name(self, session_name: str, text: str) -> bool:
        return False

    @hookimpl
    def focus_session(self, session_id: int, session_name: str) -> bool:
        return False

    @hookimpl
    def on_orchestrator_startup(self) -> None:
        self.discover_running_sessions()

    @hookimpl
    def on_orchestrator_shutdown(self) -> None:
        if self._record and self._record.get("container_id"):
            self.kill_session(self._record["issue_number"], self._record["session_name"])
        if self._watcher:
            self._watcher.join(timeout=3)

    @hookimpl
    def terminal_health_check(self) -> dict:
        try:
            self._load_packet()
            return {"healthy": True, "backend": "docker", "server_running": True, "session_exists": bool(self._record)}
        except (OSError, ValueError, KeyError, TypeError):
            return {"healthy": False, "backend": "docker", "error": "admitted-Docker-launch-unavailable"}
