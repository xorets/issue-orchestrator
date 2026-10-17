"""The SessionRunner boundary refuses unsealed or repeated Docker launches."""
from hashlib import sha256
import json
import os
from pathlib import Path
import pytest
import time

from issue_orchestrator.execution.terminal_docker import DockerPlugin, canonical


class Engine:
    def __init__(self, packet):
        self.packet = packet
        self.running = True
        self.starts = 0
        self.created_exec = None
        self.record_path = None
        self.daemon = packet["daemon_id"]
        self.exec_payloads = {}

    def worker(self):
        p = self.packet
        return {"Id": "2" * 64, "Name": "/" + p["container_name"], "Image": p["image_id"],
            "State": {"Running": self.running}, "Config": {"User": p["user"], "Labels": {"io.builder.launch": sha256(canonical(p)).hexdigest()}},
            "Mounts": [], "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
                "IpcMode": "private", "NetworkMode": p["network_id"], "LogConfig": {"Type": "none"}, "RestartPolicy": {"Name": "no"},
                "Memory": p["limits"]["memory_bytes"], "MemorySwap": p["limits"]["swap_bytes"], "NanoCpus": p["limits"]["cpu_nano"],
                "PidsLimit": p["limits"]["pids"], "Tmpfs": p["tmpfs"]}}

    def request(self, method, route, payload=None):
        if route == "/info":
            return {"ID": self.daemon}
        if route == "/images/" + self.packet["image_id"] + "/json":
            return {"Id": self.packet["image_id"], "Config": {}}
        if route == "/containers/" + "1" * 64 + "/json":
            return {"Id": "1" * 64, "State": {"Running": True}}
        if route == "/containers/" + "2" * 64 + "/json":
            return self.worker()
        if route == "/containers/" + "2" * 64 + "/exec":
            self.created_exec = payload
            exec_id = format(3 + len(self.exec_payloads), "x") * 64
            self.exec_payloads[exec_id] = payload
            return {"Id": exec_id}
        if route.startswith("/exec/"):
            exec_id = route.split("/")[2]
            assert exec_id in self.exec_payloads
            return {"ID": exec_id, "ContainerID": "2" * 64, "Running": False, "ExitCode": 0}
        raise AssertionError((method, route))

    def start_exec(self, exec_id, consume, timeout):
        record = json.loads(self.record_path.read_text())
        assert record["provider_exec_id"] == exec_id or exec_id in {row["exec_id"] for row in record["hook_execs"]}
        self.starts += 1
        consume(b"known-output\n")

    def stop(self, container_id):
        assert container_id == "2" * 64
        self.running = False


@pytest.fixture
def launch(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text("{}")
    tool = tmp_path / "tool"
    tool.write_text("trusted-tool")
    tool_digest = sha256(tool.read_bytes()).hexdigest()
    packet = {"schema_version": 1, "repository": "local/one", "run_id": "20261017-100000Z-" + "e" * 32,
        "builder_run_id": "run-" + "f" * 32, "engine_run_dir": str(tmp_path / "run-assets"), "hooks": {},
        "session_name": "issue-42", "working_dir": str(tmp_path),
        "daemon_id": "daemon", "container_name": "builder-run-1", "network_id": "none", "user": "1000:1000", "read_only": True,
        "contract_sha256": "a" * 64, "command_sha256": sha256(b"echo safe").hexdigest(), "controller_container_id": "1" * 64,
        "devcontainer_config": str(config), "devcontainer_config_sha256": sha256(config.read_bytes()).hexdigest(),
        "image": "repo@sha256:" + "a" * 64, "image_id": "sha256:" + "b" * 64,
        "devcontainer_cli": str(tool), "devcontainer_cli_sha256": tool_digest, "docker_cli": str(tool), "docker_cli_sha256": tool_digest,
        "node": str(tool), "node_sha256": tool_digest, "tool_files": {str(tool): tool_digest},
        "storage_policy_sha256": "c" * 64, "network_policy_sha256": "d" * 64, "deadline_unix_ns": time.time_ns() + 60_000_000_000,
        "limits": {"memory_bytes": 33554432, "swap_bytes": 33554432, "cpu_nano": 1000000000, "pids": 32, "max_output_bytes": 1024},
        "tmpfs": {}, "mounts": []}
    config.write_text(json.dumps({"image": packet["image"], "workspaceFolder": str(tmp_path),
        "containerUser": "1000:1000", "remoteUser": "1000:1000", "updateRemoteUserUID": False,
        "overrideCommand": True, "workspaceMount": None,
        "runArgs": ["--name", "builder-run-1", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--log-driver=none", "--network", "none", "--memory", "33554432", "--memory-swap", "33554432", "--pids-limit", "32", "--cpus", "1.0"]}))
    config.chmod(0o400)
    packet["devcontainer_config_sha256"] = sha256(config.read_bytes()).hexdigest()
    path = tmp_path / "launch.json"
    path.write_text(json.dumps(packet))
    path.chmod(0o400)
    engine = Engine(packet)
    engine.record_path = path.with_name("docker-session.json")
    calls = []
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return json.dumps({"containerId": "2" * 64}).encode()
    monkeypatch.setattr("issue_orchestrator.execution.terminal_docker.run_cli", run)
    return DockerPlugin(launch_path=path, engine=engine), engine, packet, calls


def test_missing_launch_refuses_without_native_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("ISSUE_ORCHESTRATOR_DOCKER_LAUNCH", raising=False)
    runner = DockerPlugin()
    assert runner.create_session(42, "echo safe", str(tmp_path), None, "issue-42") is False
    assert runner.terminal_health_check()["healthy"] is False


def test_packet_cannot_be_read_from_writable_or_symlinked_file(tmp_path):
    path = tmp_path / "launch.json"
    path.write_text("{}")
    runner = DockerPlugin(launch_path=path)
    assert runner.create_session(42, "echo safe", str(tmp_path), None, "issue-42") is False
    path.chmod(0o400)
    linked = tmp_path / "link"
    linked.symlink_to(path)
    assert DockerPlugin(launch_path=linked).create_session(42, "echo safe", str(tmp_path), None, "issue-42") is False


def test_launch_persists_exec_before_start_and_stops_entire_worker(launch):
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", {"SYNTHETIC_KEY": "secret-canary"})
    runner.on_orchestrator_shutdown()
    assert engine.starts == 1
    assert engine.created_exec["Cmd"] == ["/bin/sh", "-c", "echo safe"]
    assert engine.created_exec["Env"] == ["SYNTHETIC_KEY=secret-canary"]
    assert "echo safe" not in repr(calls) and "secret-canary" not in repr(calls)
    assert runner.get_session_output(42, 10, "issue-42") == "known-output"
    record = json.loads(runner.receipt_path().read_text())
    assert record["state"] == "stopped" and record["provider_exit_code"] == 0 and not engine.running
    assert runner.custody("issue-42").container_id == "2" * 64
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
    assert json.loads(runner.receipt_path().read_text()) == record
    assert engine.starts == 1


def test_wrong_command_never_creates_worker(launch):
    runner, engine, packet, calls = launch
    assert not runner.create_session(42, "unadmitted", packet["working_dir"], None, "issue-42")
    assert calls == [] and engine.starts == 0


def test_changed_daemon_never_stops_a_foreign_worker(launch):
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
    runner.on_orchestrator_shutdown()
    engine.daemon = "foreign-daemon"
    with pytest.raises(ValueError, match="daemon"):
        runner.kill_session(42, "issue-42")


def test_output_overflow_retains_unknown_result_and_stops(launch):
    runner, engine, packet, calls = launch
    packet["limits"]["max_output_bytes"] = 2
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_text(json.dumps(packet))
    runner.launch_path.chmod(0o400)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_text())
    assert record["overflow"] and record["provider_exit_code"] is None and not engine.running
    assert runner.receipt_path().with_name("docker-output.log").stat().st_size == 0


def test_hooks_are_executed_only_in_the_verified_worker_and_before_provider(launch):
    runner, engine, packet, calls = launch
    packet["hooks"] = {"postCreateCommand": ["/bin/echo", "hook-canary"]}
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_text(json.dumps(packet))
    runner.launch_path.chmod(0o400)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_text())
    assert engine.exec_payloads["3" * 64]["Cmd"] == ["/bin/echo", "hook-canary"]
    assert engine.exec_payloads["4" * 64]["Cmd"] == ["/bin/sh", "-c", "echo safe"]
    assert record["hook_execs"] == [{"phase": "postCreateCommand", "exec_id": "3" * 64, "exit_code": 0}]
    assert "hook-canary" not in repr(calls)


def test_typed_preparation_binds_engine_run_and_exact_command_through_pluggy(launch, monkeypatch):
    import pluggy
    from issue_orchestrator.execution.session_output_adapter import FileSystemSessionOutput
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    runner, engine, packet, calls = launch
    root = runner.launch_path.parent
    template_path = root / "template.json"
    template = {**packet, "run_id": "", "engine_run_dir": "", "command_sha256": "0" * 64}
    intent = {key: value for key, value in template.items() if key not in {"contract_sha256", "run_id", "engine_run_dir", "command_sha256"}}
    contract = {"execution": {"backend": "docker", "docker_launch": {"template_path": str(template_path), "intent_sha256": sha256(canonical(intent)).hexdigest()}}}
    contract_path = root / "contract.json"
    contract_path.write_bytes(canonical(contract))
    contract_path.chmod(0o400)
    digest = sha256(contract_path.read_bytes()).hexdigest()
    template["contract_sha256"] = digest
    template_path.write_bytes(canonical(template))
    template_path.chmod(0o400)
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE", str(template_path))
    monkeypatch.setenv("XORETS_EXECUTION_CONTRACT", str(contract_path))
    monkeypatch.setenv("XORETS_EXECUTION_DIGEST", digest)
    runner = DockerPlugin(engine=engine)
    pm = pluggy.PluginManager("issue_orchestrator")
    pm.add_hookspecs(TerminalSpec)
    pm.register(runner)
    assets = FileSystemSessionOutput().start_run(root, "coding-1", issue_number=42)
    PluggySessionRunner(pm).prepare_session(assets, "issue-42", "echo safe")
    prepared = json.loads(runner.launch_path.read_bytes())
    assert prepared["run_id"] == assets.run_id
    assert prepared["builder_run_id"] == template["builder_run_id"]
    assert prepared["engine_run_dir"] == str(assets.run_dir)
    assert prepared["command_sha256"] == sha256(b"echo safe").hexdigest()
    assert runner.launch_path.parent.stat().st_mode & 0o777 == 0o700
    assert runner.launch_path.stat().st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        PluggySessionRunner(pm).prepare_session(assets, "issue-42", "echo safe")
    engine.packet = prepared
    engine.record_path = runner.receipt_path()
    assert PluggySessionRunner(pm).create_session(42, "echo safe", str(root), None, "issue-42")
    runner.on_orchestrator_shutdown()
    assert runner.public_receipt("issue-42")["run_id"] == assets.run_id


def test_unsafe_generated_configuration_is_refused_before_cli_start(launch):
    runner, engine, packet, calls = launch
    config = Path(packet["devcontainer_config"])
    content = json.loads(config.read_bytes())
    content["runArgs"].append("--privileged")
    config.chmod(0o600)
    config.write_bytes(canonical(content))
    config.chmod(0o400)
    packet["devcontainer_config_sha256"] = sha256(config.read_bytes()).hexdigest()
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
    assert calls == [] and engine.starts == 0


def test_cli_timeout_kills_descendants_after_the_cli_leader_exits(tmp_path):
    import sys
    import select
    from issue_orchestrator.execution.terminal_docker import run_cli
    pidfile = tmp_path / "descendant.pid"
    child_code = "import os,signal;from pathlib import Path;Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid()));signal.pause()"
    parent_code = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child_code) + "])"
    with pytest.raises(ValueError, match="deadline"):
        run_cli([sys.executable, "-c", parent_code], environment={"PATH": "/usr/bin:/bin"}, timeout=0.5)
    pid = int(pidfile.read_text())
    try:
        descriptor = os.pidfd_open(pid)
        try:
            assert select.select([descriptor], [], [], 5)[0], "CLI descendant did not acknowledge termination"
        finally:
            os.close(descriptor)
        status = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        status = "gone"
    assert status in {"Z", "gone"}
