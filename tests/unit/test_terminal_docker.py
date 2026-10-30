"""The SessionRunner boundary refuses unsealed or repeated Docker launches."""
from hashlib import sha256
import json
import os
from pathlib import Path
import pytest
import time
import copy
import threading

from issue_orchestrator.execution.terminal_docker import DockerPlugin, canonical
from tests.unit.test_docker_first_model import claim_http, first_model_owner  # noqa: F401
from tests.unit.adapters.github.test_original_delivery_owner import original_owner  # noqa: F401


class Engine:
    def __init__(self, packet):
        self.packet = packet
        self.running = True
        self.starts = 0
        self.started_execs = set()
        self.completed_execs = set()
        self.started = threading.Event()
        self.created_exec = None
        self.record_path = None
        self.daemon = packet["daemon_id"]
        self.exec_payloads = {}

    def worker(self):
        p = self.packet
        return {"Id": "2" * 64, "Name": "/" + p["container_name"], "Image": p["image_id"],
            "State": {"Running": self.running, "Paused":False, "Restarting":False, "OOMKilled":False,
                "Error":"", "Pid":42 if self.running else 0}, "RestartCount":0,
            "Config": {"User": p["user"], "Labels": {"io.builder.launch": sha256(canonical(p)).hexdigest()}},
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
        if route == "/containers/" + self.packet["container_name"] + "/json":
            raise ValueError("reserved container has not been created")
        if route.startswith("/exec/"):
            exec_id = route.split("/")[2]
            assert exec_id in self.exec_payloads
            payload = self.exec_payloads[exec_id]
            command = payload.get('Cmd', ['/bin/sh', '-c', ''])
            return {"ID": exec_id, "ContainerID": "2" * 64, "Running": False,
                "Pid":0, "ExitCode":0 if exec_id in self.completed_execs else None,
                "ProcessConfig":{"entrypoint":command[0], 'arguments':command[1:],
                    'user':payload.get('User', '1000:1000'), 'privileged':False, 'tty':False}}
        raise AssertionError((method, route))

    def start_exec(self, exec_id, consume, timeout):
        record = json.loads(self.record_path.read_text())
        assert record["provider_exec_id"] == exec_id or exec_id in {row["exec_id"] for row in record["hook_execs"]}
        if exec_id not in self.started_execs:
            self.started_execs.add(exec_id)
            self.starts += 1
        self.started.set()
        consume(b"known-output\n")
        self.completed_execs.add(exec_id)

    def open_exec(self, exec_id, timeout):
        engine = self
        engine.started_execs.add(exec_id)
        engine.starts += 1
        class Stream:
            def consume(self, consume):
                engine.start_exec(exec_id, consume, timeout)
                engine.completed_execs.add(exec_id)
            def close(self): pass
        return Stream()

    def inspect_exec(self, exec_id):
        return {'status':200, 'value':self.request('GET', '/exec/' + exec_id + '/json')}

    def stop(self, container_id):
        assert container_id == "2" * 64
        self.running = False


@pytest.fixture
def launch(tmp_path, monkeypatch):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    config = tmp_path / "config.json"
    config.write_text("{}")
    tool = tmp_path / "tool"
    tool.write_text("trusted-tool")
    tool_digest = sha256(tool.read_bytes()).hexdigest()
    packet = {"schema_version": 1, "repository": "local/one", "run_id": "20261017-100000Z-" + "e" * 32,
        "builder_run_id": "run-" + "f" * 32, "engine_run_dir": str(tmp_path / "run-assets"),
        "output_root": str(output), "hooks": {},
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
    path = control / "launch.json"
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
    assert runner.create_session(42, "echo safe", str(tmp_path), None, "issue-42", secret_env=None) is False
    assert runner.terminal_health_check()["healthy"] is False


def test_packet_cannot_be_read_from_writable_or_symlinked_file(tmp_path):
    path = tmp_path / "launch.json"
    path.write_text("{}")
    runner = DockerPlugin(launch_path=path)
    assert runner.create_session(42, "echo safe", str(tmp_path), None, "issue-42", secret_env=None) is False
    path.chmod(0o400)
    linked = tmp_path / "link"
    linked.symlink_to(path)
    assert DockerPlugin(launch_path=linked).create_session(42, "echo safe", str(tmp_path), None, "issue-42", secret_env=None) is False


def test_launch_persists_exec_before_start_and_stops_entire_worker(launch):
    from tests.unit.threading_helpers import wait_for_event
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", {"SYNTHETIC_KEY": "secret-canary"})
    wait_for_event(engine.started, 5, label='provider start')
    runner.on_orchestrator_shutdown()
    assert engine.starts == 1
    assert engine.created_exec["Cmd"] == ["/bin/sh", "-c", "echo safe"]
    assert engine.created_exec["Env"] == ["SYNTHETIC_KEY=secret-canary"]
    assert "echo safe" not in repr(calls) and "secret-canary" not in repr(calls)
    assert runner.get_session_output(42, 10, "issue-42") == "known-output"
    record = json.loads(runner.receipt_path().read_text())
    assert record["state"] == "stopped" and record["provider_exit_code"] == 0 and not engine.running
    assert runner.custody("issue-42").container_id == "2" * 64
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert json.loads(runner.receipt_path().read_text()) == record
    assert engine.starts == 1


def test_real_pluggy_dispatch_preserves_allocated_completion_and_provider_secrets(
    launch, tmp_path, tmp_path_factory, monkeypatch, caplog,
):
    from dataclasses import replace
    import pluggy
    from issue_orchestrator.control.session_env import docker_session_secret_env
    from issue_orchestrator.execution.issue_run_ledger import SqliteIssueRunLedger
    from issue_orchestrator.execution.session_output_adapter import FileSystemSessionOutput
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    from tests.unit.test_issue_run_evidence import run_record

    plugin, engine, packet, calls = launch
    run = FileSystemSessionOutput().start_run(Path(packet["working_dir"]), "coding-1", issue_number=42)
    ledger = SqliteIssueRunLedger(tmp_path_factory.mktemp("controller-state") / "runs.sqlite", repo_slug="local/one")
    monkeypatch.setattr("secrets.token_urlsafe", lambda count: "s" * 64)
    ledger.record_run(42, replace(run_record(tmp_path), run=run))
    private = docker_session_secret_env(ledger, run, {"PROVIDER_KEY": "provider-secret-canary"})
    capability = ledger.submission_capability(run)
    packet.update(run_id=run.run_id, engine_run_dir=str(run.run_dir))
    plugin.launch_path.chmod(0o600)
    plugin.launch_path.write_bytes(canonical(packet))
    plugin.launch_path.chmod(0o400)
    manager = pluggy.PluginManager("issue_orchestrator")
    manager.add_hookspecs(TerminalSpec)
    manager.register(plugin)
    try:
        assert PluggySessionRunner(manager).create_session(42, "echo safe", packet["working_dir"],
            None, "issue-42", secret_env=private)
    finally:
        plugin.on_orchestrator_shutdown()
    assert set(engine.created_exec["Env"]) == {"PROVIDER_KEY=provider-secret-canary",
        "ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY=" + capability}
    for secret in (capability, "provider-secret-canary"):
        assert secret not in caplog.text
        assert secret not in repr(calls)
        assert secret not in plugin.launch_path.read_text()
        assert secret not in plugin.receipt_path().read_text()


def test_live_provider_survives_real_orchestrator_discovery(launch, monkeypatch, sample_orchestrator):
    import threading
    import pluggy
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    from tests.unit.threading_helpers import wait_for_event
    from issue_orchestrator.domain.pause_state import PauseActor, PauseReason

    plugin, engine, packet, calls = launch
    entered, release = threading.Event(), threading.Event()
    def provider(exec_id, consume, timeout):
        entered.set()
        wait_for_event(release, 5, label="provider release")
        consume(b"known-output\n")
    monkeypatch.setattr(engine, "start_exec", provider)
    manager = pluggy.PluginManager("issue_orchestrator")
    manager.add_hookspecs(TerminalSpec)
    manager.register(plugin)
    runner = PluggySessionRunner(manager)
    monkeypatch.setattr(sample_orchestrator.deps.runner, "discover_running_sessions", runner.discover_running_sessions)
    try:
        assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
        wait_for_event(entered, 5, label="provider entered")
        sample_orchestrator.pause(reason=PauseReason.OPERATOR, actor=PauseActor.MCP)
        sample_orchestrator.tick()
        assert engine.running
        record = json.loads(plugin.receipt_path().read_bytes())
        assert record["error"] == "" and record["provider_exit_code"] is None
        assert engine.starts == 1 and len(calls) == 1
    finally:
        release.set()
        plugin.on_orchestrator_shutdown()


@pytest.mark.parametrize("recovery", ["new-instance", "reselected-record"])
def test_discovery_without_matching_watcher_stops_worker_without_second_provider(launch, monkeypatch, recovery):
    import threading
    from tests.unit.threading_helpers import wait_for_event

    plugin, engine, packet, calls = launch
    entered, release = threading.Event(), threading.Event()
    def provider(exec_id, consume, timeout):
        entered.set()
        wait_for_event(release, 5, label="provider release")
    monkeypatch.setattr(engine, "start_exec", provider)
    try:
        assert plugin.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
        wait_for_event(entered, 5, label="provider entered")
        if recovery == "new-instance":
            restored = DockerPlugin(launch_path=plugin.launch_path, engine=engine)
        else:
            selected = plugin.launch_path.parent / packet["run_id"]
            selected.mkdir(mode=0o700)
            (selected / "launch.json").write_bytes(plugin.launch_path.read_bytes())
            (selected / "launch.json").chmod(0o400)
            (selected / "docker-session.json").write_bytes(plugin.receipt_path().read_bytes())
            plugin.template_path = plugin.launch_path
            plugin.select_run(packet["run_id"])
            restored = plugin
        assert restored.discover_running_sessions() == []
        assert not engine.running
        assert json.loads(restored.receipt_path().read_bytes())["error"] == "controller-restart-provider-result-unknown"
        assert engine.starts == 1 and len(calls) == 1
    finally:
        release.set()
        plugin.on_orchestrator_shutdown()


def wait_for_provider_completion(runner):
    from tests.unit.threading_helpers import join_or_fail
    assert runner._watcher is not None
    join_or_fail(runner._watcher, 5, label="provider watcher")


def test_finished_watcher_cannot_protect_a_running_worker(launch):
    plugin, engine, packet, calls = launch
    assert plugin.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(plugin)
    plugin.on_orchestrator_shutdown()
    completed = json.loads(plugin.receipt_path().read_bytes())
    assert plugin.discover_running_sessions() == []
    assert json.loads(plugin.receipt_path().read_bytes()) == completed
    engine.running = True  # Actual daemon boundary now reports an unsupervised worker.
    assert plugin.discover_running_sessions() == []
    assert not engine.running
    assert json.loads(plugin.receipt_path().read_bytes())["error"] == "controller-restart-provider-result-unknown"
    assert engine.starts == 1 and len(calls) == 1


def test_wrong_command_never_creates_worker(launch):
    runner, engine, packet, calls = launch
    assert not runner.create_session(42, "unadmitted", packet["working_dir"], None, "issue-42", secret_env=None)
    assert calls == [] and engine.starts == 0


class BridgeEngine(Engine):
    def __init__(self, packet):
        super().__init__(packet)
        self.bridge = {"Id": "5" * 64, "Driver": "bridge", "Scope": "local", "Internal": False,
            "EnableIPv6": False, "IPAM": {"Driver": "default",
                "Config": [{"Subnet": "172.28.64.0/28", "Gateway": "172.28.64.1"}]},
            "Options": {"com.docker.network.bridge.name": "br-fixture169",
                "com.docker.network.bridge.enable_icc": "true"}}
        self.controller_endpoint = {"NetworkID": "5" * 64, "IPAddress": "172.28.64.2",
            "IPPrefixLen": 28, "Gateway": "172.28.64.1", "GlobalIPv6Address": "", "IPv6Gateway": ""}
        self.worker_endpoint = {**self.controller_endpoint, "IPAddress": "172.28.64.3",
            "IPAMConfig": {"IPv4Address": "172.28.64.3"}}
        self.dns = ["1.1.1.1", "8.8.8.8"]
        self.sysctls = {"net.ipv6.conf.all.disable_ipv6": "1"}
        self.extra_worker_endpoint = False

    def worker(self):
        actual = super().worker()
        actual["HostConfig"].update(Dns=self.dns, Sysctls=self.sysctls)
        actual["NetworkSettings"] = {"Networks": {"fixture": self.worker_endpoint}}
        if self.extra_worker_endpoint:
            actual["NetworkSettings"]["Networks"]["foreign"] = self.controller_endpoint
        return actual

    def request(self, method, route, payload=None):
        if route == "/networks/" + "5" * 64:
            return self.bridge
        actual = super().request(method, route, payload)
        if route == "/containers/" + "1" * 64 + "/json":
            actual["NetworkSettings"] = {"Networks": {"fixture": self.controller_endpoint}}
        return actual


@pytest.fixture
def bridge_launch(launch):
    runner, _, packet, calls = launch
    packet["network_id"] = "5" * 64
    packet["network"] = {"worker_ipv4": "172.28.64.3", "controller_ipv4": "172.28.64.2",
        "subnet": "172.28.64.0/28", "gateway": "172.28.64.1",
        "bridge_name": "br-fixture169", "dns": ["1.1.1.1", "8.8.8.8"]}
    config = Path(packet["devcontainer_config"])
    content = json.loads(config.read_bytes())
    content["runArgs"][content["runArgs"].index("none")] = "5" * 64
    content["runArgs"].extend(["--ip", "172.28.64.3", "--dns", "1.1.1.1", "--dns", "8.8.8.8",
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=1"])
    config.chmod(0o600)
    config.write_bytes(canonical(content))
    config.chmod(0o400)
    packet["devcontainer_config_sha256"] = sha256(config.read_bytes()).hexdigest()
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    engine = BridgeEngine(packet)
    engine.record_path = runner.receipt_path()
    return DockerPlugin(launch_path=runner.launch_path, engine=engine), engine, packet, calls


def test_selected_bridge_launch_preserves_verified_endpoints(bridge_launch):
    runner, engine, packet, _ = bridge_launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(runner)
    runner.on_orchestrator_shutdown()
    assert engine.starts == 1
    assert runner.public_receipt("issue-42")["container_id"] == "2" * 64


def test_controller_membership_is_rechecked_after_create_before_any_exec(bridge_launch, monkeypatch):
    runner, engine, packet, calls = bridge_launch
    def create(*args, **kwargs):
        calls.append((args, kwargs))
        engine.controller_endpoint["IPAddress"] = "172.28.64.4"
        return json.dumps({"containerId": "2" * 64}).encode()
    monkeypatch.setattr("issue_orchestrator.execution.terminal_docker.run_cli", create)
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert len(calls) == 1 and engine.created_exec is None


@pytest.mark.parametrize("change", [
    {"worker_ipv4": "172.28.64.2"}, {"controller_ipv4": "172.28.65.2"},
    {"subnet": "172.28.64.1/28"}, {"dns": ["192.168.1.1"]},
    {"bridge_name": "eth0"}, {"gateway": "172.28.64.15"},
])
def test_invalid_sealed_network_refuses_before_cli(bridge_launch, change):
    runner, engine, packet, calls = bridge_launch
    packet["network"].update(change)
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert calls == [] and engine.created_exec is None


@pytest.mark.parametrize("subject,change", [
    ("bridge", {"Id": "6" * 64}), ("bridge", {"Driver": "overlay"}),
    ("bridge", {"Scope": "swarm"}), ("bridge", {"Internal": True}),
    ("bridge", {"EnableIPv6": True}),
    ("bridge", {"IPAM": {"Config": [{"Subnet": "172.28.65.0/28", "Gateway": "172.28.65.1"}]}}),
    ("bridge", {"Options": {"com.docker.network.bridge.name": "br-foreign",
        "com.docker.network.bridge.enable_icc": "true"}}),
    ("bridge", {"Options": {"com.docker.network.bridge.name": "br-fixture169",
        "com.docker.network.bridge.enable_icc": "false"}}),
    ("controller_endpoint", {"IPAddress": "172.28.64.4"}),
    ("controller_endpoint", {"NetworkID": "6" * 64}),
])
def test_network_or_controller_drift_refuses_before_cli(bridge_launch, subject, change):
    runner, engine, packet, calls = bridge_launch
    getattr(engine, subject).update(copy.deepcopy(change))
    accepted = runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    if accepted:
        runner.on_orchestrator_shutdown()
    assert not accepted
    assert calls == [] and engine.created_exec is None


@pytest.mark.parametrize("subject,change", [
    ("worker_endpoint", {"IPAddress": "172.28.64.4"}),
    ("worker_endpoint", {"NetworkID": "6" * 64}),
    ("worker_endpoint", {"IPPrefixLen": 24}),
    ("worker_endpoint", {"Gateway": "172.28.64.4"}),
    ("worker_endpoint", {"GlobalIPv6Address": "2001:db8::3"}),
    ("worker_endpoint", {"IPAMConfig": {"IPv4Address": "172.28.64.3", "IPv6Address": "2001:db8::3"}}),
    ("dns", ["192.168.1.1"]), ("sysctls", {}), ("extra_worker_endpoint", True),
])
def test_created_worker_network_drift_refuses_before_hooks_and_provider(bridge_launch, subject, change):
    runner, engine, packet, calls = bridge_launch
    packet["hooks"] = {"postCreateCommand": ["echo", "must-not-run"]}
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    if subject == "worker_endpoint":
        getattr(engine, subject).update(copy.deepcopy(change))
    else:
        setattr(engine, subject, change)
    accepted = runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    if accepted:
        runner.on_orchestrator_shutdown()
    assert not accepted
    assert len(calls) == 1 and engine.created_exec is None


def test_docker_exec_receives_only_the_explicit_scoped_callback_token(launch, monkeypatch):
    runner, engine, packet, calls = launch
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN", "d" * 64)
    monkeypatch.setenv("ISSUE_ORCHESTRATOR_API_TOKEN", "admin-not-forwarded")
    monkeypatch.setenv("GH_TOKEN", "github-not-forwarded")
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    assert engine.created_exec["Env"] == ["ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN=" + "d" * 64]
    assert "d" * 64 not in repr(calls)


def test_changed_daemon_never_stops_a_foreign_worker(launch):
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
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
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(runner)
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_text())
    assert record["overflow"] and record["provider_exit_code"] is None and not engine.running
    assert (Path(packet["output_root"]) / packet["run_id"] / "docker-output.log").stat().st_size == 0


def test_hooks_are_executed_only_in_the_verified_worker_and_before_provider(launch):
    runner, engine, packet, calls = launch
    packet["hooks"] = {"postCreateCommand": ["/bin/echo", "hook-canary"]}
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_text(json.dumps(packet))
    runner.launch_path.chmod(0o400)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_text())
    assert engine.exec_payloads["3" * 64]["Cmd"] == ["/bin/echo", "hook-canary"]
    assert engine.exec_payloads["4" * 64]["Cmd"] == ["/bin/sh", "-c", "echo safe"]
    assert record["hook_execs"] == [{"phase": "postCreateCommand", "exec_id": "3" * 64, "exit_code": 0}]
    assert "hook-canary" not in repr(calls)


@pytest.mark.parametrize("tamper_manifest", [False, True])
def test_typed_preparation_binds_engine_run_and_exact_command_through_pluggy(launch, monkeypatch, manifest_clock, tamper_manifest):
    import pluggy
    from issue_orchestrator.execution.session_output_adapter import FileSystemSessionOutput
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    runner, engine, packet, calls = launch
    packet["control_manifest"] = control_manifest()
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
    assets = FileSystemSessionOutput().start_run(Path(packet["working_dir"]), "coding-1", issue_number=42)
    if tamper_manifest:
        template["control_manifest"]["manifest"]["disallowedFeatures"] = []
        template_path.chmod(0o600)
        template_path.write_bytes(canonical(template))
        template_path.chmod(0o400)
        with pytest.raises(ValueError, match="immutable contract intent"):
            PluggySessionRunner(pm).prepare_session(assets, "issue-42", "echo safe")
        assert not (root / assets.run_id).exists() and not calls
        return
    PluggySessionRunner(pm).prepare_session(assets, "issue-42", "echo safe")
    prepared = json.loads(runner.launch_path.read_bytes())
    assert prepared["run_id"] == assets.run_id
    assert prepared["control_manifest"] == template["control_manifest"]
    assert prepared["builder_run_id"] == template["builder_run_id"]
    assert prepared["engine_run_dir"] == str(assets.run_dir)
    assert prepared["command_sha256"] == sha256(b"echo safe").hexdigest()
    assert runner.launch_path.parent.stat().st_mode & 0o777 == 0o700
    assert runner.launch_path.stat().st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        PluggySessionRunner(pm).prepare_session(assets, "issue-42", "echo safe")
    engine.packet = prepared
    engine.record_path = runner.receipt_path()
    assert PluggySessionRunner(pm).create_session(42, "echo safe", packet["working_dir"], None, "issue-42")
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
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert calls == [] and engine.starts == 0


def test_exact_local_image_id_is_supported_without_a_registry_digest(launch):
    runner, engine, packet, calls = launch
    packet["image"] = packet["image_id"]
    config = Path(packet["devcontainer_config"])
    content = json.loads(config.read_bytes())
    content["image"] = packet["image"]
    config.chmod(0o600)
    config.write_bytes(canonical(content))
    config.chmod(0o400)
    packet["devcontainer_config_sha256"] = sha256(config.read_bytes()).hexdigest()
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    assert runner.public_receipt("issue-42")["provider_exec_id"] == "3" * 64


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


def test_ordinary_output_and_cli_scratch_stay_outside_settlement(launch):
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(runner)
    runner.on_orchestrator_shutdown()
    ordinary = Path(packet["output_root"]) / packet["run_id"]
    assert calls[0][1]["environment"]["HOME"] == str(ordinary / "home")
    assert calls[0][1]["environment"]["TMPDIR"] == str(ordinary / "tmp")
    assert calls[0][1]["diagnostic_path"] == ordinary / "docker-cli.log"
    assert (ordinary / "docker-output.log").read_bytes() == b"known-output\n"
    assert runner.get_session_output(42, 10, "issue-42") == "known-output"
    assert not runner.receipt_path().with_name("docker-output.log").exists()
    for path in (ordinary, ordinary / "home", ordinary / "tmp"):
        assert path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("change", ["missing", "relative", "normalized", "symlink", "public", "settlement", "receipt-with-template", "mount-parent", "mount-child", "mount-alias", "projected-root", "absent"])
def test_output_custody_refuses_before_cli_and_exec(launch, change):
    runner, engine, packet, calls = launch
    output = Path(packet["output_root"])
    if change == "missing":
        packet.pop("output_root")
    elif change == "relative":
        packet["output_root"] = "output"
    elif change == "normalized":
        packet["output_root"] += "/../output"
    elif change == "symlink":
        alias = output.with_name("alias")
        alias.symlink_to(output, target_is_directory=True)
        packet["output_root"] = str(alias)
    elif change == "public":
        output.chmod(0o755)
    elif change == "settlement":
        packet["output_root"] = str(runner.launch_path.parent)
    elif change == "receipt-with-template":
        runner.template_path = output.parent / "other-settlement/template.json"
        packet["output_root"] = str(runner.launch_path.parent)
    elif change == "mount-alias":
        alias = output.with_name("alias")
        alias.symlink_to(output, target_is_directory=True)
        packet["mounts"] = [{"source": str(alias), "target": "/unused", "read_only": True}]
    elif change == "projected-root":
        packet["worker_authority"] = {}
    elif change == "absent":
        output.rmdir()
    else:
        exposed = output.parent if change == "mount-parent" else output / "child"
        packet["mounts"] = [{"source": str(exposed), "target": str(exposed), "read_only": True}]
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert calls == [] and engine.starts == 0


def test_ordinary_output_enospc_still_stops_worker_and_persists_receipt(launch, monkeypatch):
    import errno
    runner, engine, packet, _ = launch
    original_open = Path.open
    def open_file(path, *args, **kwargs):
        if path.name == "docker-output.log":
            raise OSError(errno.ENOSPC, "ordinary allocation exhausted")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", open_file)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_bytes())
    assert record["state"] == "stopped" and not engine.running
    assert record["error"] == "provider-unsettled-or-bound-exhausted"
    assert record["provider_exit_code"] is None and engine.starts == 0
    assert runner.public_receipt("issue-42")["container_id"] == "2" * 64


def test_restarted_runner_reads_same_ordinary_output_without_replay(launch):
    runner, engine, packet, calls = launch
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(runner)
    runner.on_orchestrator_shutdown()
    restored = DockerPlugin(launch_path=runner.launch_path, engine=engine)
    assert restored.get_session_output(42, 10, "issue-42") == "known-output"
    restored.on_orchestrator_startup()
    assert not restored.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    assert engine.starts == 1 and len(calls) == 1


def test_run_output_directory_substitution_still_stops_worker(launch, monkeypatch):
    runner, engine, packet, calls = launch
    def replace_output(*args, **kwargs):
        calls.append((args, kwargs))
        ordinary = Path(packet["output_root"]) / packet["run_id"]
        ordinary.rename(ordinary.with_name("original"))
        ordinary.symlink_to(ordinary.with_name("original"), target_is_directory=True)
        return json.dumps({"containerId": "2" * 64}).encode()
    monkeypatch.setattr("issue_orchestrator.execution.terminal_docker.run_cli", replace_output)
    assert not runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_bytes())
    assert record["state"] == "stopped" and not engine.running
    assert record["provider_exit_code"] is None and engine.starts == 0


def test_cli_writes_only_ordinary_home_and_tmp(launch, monkeypatch):
    runner, engine, packet, calls = launch
    def write_scratch(*args, **kwargs):
        calls.append((args, kwargs))
        environment = kwargs["environment"]
        Path(environment["HOME"], "cli-home-canary").write_text("home")
        Path(environment["TMPDIR"], "cli-tmp-canary").write_text("temporary")
        kwargs["diagnostic_path"].write_text("cli diagnostic")
        return json.dumps({"containerId": "2" * 64}).encode()
    monkeypatch.setattr("issue_orchestrator.execution.terminal_docker.run_cli", write_scratch)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    runner.on_orchestrator_shutdown()
    ordinary = Path(packet["output_root"]) / packet["run_id"]
    assert (ordinary / "home/cli-home-canary").read_text() == "home"
    assert (ordinary / "tmp/cli-tmp-canary").read_text() == "temporary"
    assert (ordinary / "docker-cli.log").read_text() == "cli diagnostic"
    assert {p.name for p in runner.receipt_path().parent.iterdir()} == {"launch.json", "docker-session.json"}


@pytest.fixture
def manifest_clock(monkeypatch):
    now = time.time_ns()
    monkeypatch.setattr(time, "time_ns", lambda: now)
    return now


def control_manifest():
    return {"fetched_unix_ns": time.time_ns() - 1_000_000_000,
        "manifest": json.loads((Path(__file__).parents[1] / "fixtures/devcontainer-control-manifest.json").read_bytes())}


@pytest.mark.parametrize("empty_policy", [False, True])
def test_sealed_control_manifest_seeds_actual_cli_cache_without_renewing_fetch_time(launch, manifest_clock, empty_policy):
    import pwd
    runner, engine, packet, calls = launch
    packet["control_manifest"] = control_manifest()
    if empty_policy:
        packet["control_manifest"]["manifest"] = {"disallowedFeatures": [], "featureAdvisories": []}
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
    wait_for_provider_completion(runner)
    runner.on_orchestrator_shutdown()
    cache = Path(calls[0][1]["environment"]["TMPDIR"]) / ("devcontainercli-" + pwd.getpwuid(os.geteuid()).pw_name) / "control-manifest.json"
    assert cache.read_bytes() == canonical(packet["control_manifest"]["manifest"])
    assert cache.stat().st_mtime_ns == packet["control_manifest"]["fetched_unix_ns"]
    assert cache.stat().st_mode & 0o777 == 0o600
    assert cache.parent.stat().st_mode & 0o777 == 0o700
    assert engine.starts == 1


@pytest.mark.parametrize("change", ["stale", "future", "missing-array", "wrong-array", "bad-row", "unbounded", "extra-envelope"])
def test_invalid_control_manifest_refuses_before_cli_or_external_effects(launch, monkeypatch, manifest_clock, change):
    runner, engine, packet, calls = launch
    value = control_manifest()
    if change == "stale":
        value["fetched_unix_ns"] -= 300_000_000_000
    elif change == "future":
        value["fetched_unix_ns"] += 10_000_000_000
    elif change == "missing-array":
        del value["manifest"]["disallowedFeatures"]
    elif change == "wrong-array":
        value["manifest"]["featureAdvisories"] = {}
    elif change == "bad-row":
        value["manifest"]["disallowedFeatures"][0]["featureIdPrefix"] = ["unsafe"]
    elif change == "unbounded":
        value["manifest"]["featureAdvisories"][0]["description"] = "x" * 65536
    else:
        value["cache_path"] = "/arbitrary/cache"
    packet["control_manifest"] = value
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    monkeypatch.setattr(engine, "request", lambda *args: pytest.fail("invalid input reached Docker"))
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None) is False
    assert not calls and engine.created_exec is None
    assert not runner.receipt_path().exists()


def test_expired_cli_timeout_refuses_before_spawning(monkeypatch):
    from issue_orchestrator.execution.terminal_docker import run_cli
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: pytest.fail("expired CLI spawned"))
    with pytest.raises(ValueError, match="deadline"):
        run_cli(["unused"], environment={}, timeout=0)


def test_cli_success_after_packet_deadline_stops_worker_without_provider_exec(launch, monkeypatch):
    runner, engine, packet, calls = launch
    clock = [packet["deadline_unix_ns"] - 1_000_000_000]
    monkeypatch.setattr(time, "time_ns", lambda: clock[0])
    def late_success(*args, **kwargs):
        clock[0] = packet["deadline_unix_ns"] + 1
        return json.dumps({"containerId": "2" * 64}).encode()
    monkeypatch.setattr("issue_orchestrator.execution.terminal_docker.run_cli", late_success)
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None) is False
    assert engine.created_exec is None and engine.starts == 0
    assert not engine.running


def test_unsafe_cli_account_name_cannot_choose_a_cache_path(launch, monkeypatch, manifest_clock):
    from types import SimpleNamespace
    runner, engine, packet, calls = launch
    packet["control_manifest"] = control_manifest()
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    monkeypatch.setattr("pwd.getpwuid", lambda uid: SimpleNamespace(pw_name="../../elsewhere"))
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None) is False
    assert not calls and engine.created_exec is None


def test_unbound_admission_proofs_refuse_before_cli_or_provider(launch):
    runner, engine, packet, calls = launch
    packet['admission_proofs'] = {'acceptance': '/srv/builder/admission/acceptances/' + 'a' * 64 + '.json',
        'authorization': '/srv/builder/admission/authorizations/' + packet['builder_run_id'] + '.json'}
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    assert not runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', secret_env=None)
    assert calls == [] and engine.starts == 0


def test_first_model_evidence_uses_controller_output_custody_and_exclusive_allocation(launch):
    from issue_orchestrator.domain.session_run import SessionRunAssets
    runner, engine, packet, calls = launch
    root = Path(packet['working_dir'])
    run_dir = root / '.issue-orchestrator' / 'sessions' / (packet['run_id'] + '__coding-1')
    run = SessionRunAssets.from_paths(session_name='coding-1', run_id=packet['run_id'], started_at='start',
        worktree_path=root, run_dir=run_dir, manifest_path=run_dir/'manifest.json', terminal_recording_path=run_dir/'log')
    ordinary = Path(packet['output_root']) / packet['run_id']
    ordinary.mkdir(mode=0o700)
    receipt = {'run_id': run.run_id, 'launch_sha256': sha256(canonical(packet)).hexdigest(), 'test_public_receipt': True}
    result = runner.seal_first_model(run, receipt)
    path = Path(result['path'])
    assert path.parent == ordinary / 'builder-first-model'
    assert path.name.startswith('receipt-') and path.suffix == '.json'
    assert path.read_bytes() == canonical(receipt)
    assert result['sha256'] == sha256(path.read_bytes()).hexdigest()
    assert path.stat().st_mode & 0o777 == 0o400
    assert path.stat().st_nlink == 1
    assert not path.is_relative_to(run.run_dir)
    second = runner.seal_first_model(run, receipt)
    assert second['path'] != result['path'] and second['sha256'] == result['sha256']
    for _ in range(1024 // len(canonical(receipt)) - 2):
        runner.seal_first_model(run, receipt)
    with pytest.raises(ValueError, match='aggregate output bound'):
        runner.seal_first_model(run, receipt)
    with pytest.raises(ValueError, match='metadata bound'):
        runner.seal_first_model(run, {**receipt, 'oversized':'x'*1024})
    assert not calls and engine.starts == 0


@pytest.mark.parametrize('order', ['receipt-first', 'provider-first', 'concurrent', 'settled'])
def test_composed_custody_shares_live_output_bound_and_preserves_settlement(
    launch, monkeypatch, sample_config, make_session, order,
):
    import threading
    from unittest.mock import Mock
    import pluggy
    from issue_orchestrator.entrypoints.bootstrap_original_delivery import build_original_delivery_owner
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    from issue_orchestrator.ports.original_delivery import OriginalDeliveryClaims
    from tests.unit.threading_helpers import wait_for_event

    plugin, engine, packet, calls = launch
    session = make_session(issue_number=42, worktree_path=Path(packet['working_dir']))
    packet.update(run_id=session.run_assets.run_id, engine_run_dir=str(session.run_assets.run_dir))
    plugin.launch_path.chmod(0o600)
    plugin.launch_path.write_bytes(canonical(packet))
    plugin.launch_path.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_LAUNCH', str(plugin.launch_path))
    monkeypatch.delenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', raising=False)
    monkeypatch.setattr('issue_orchestrator.execution.terminal_docker.DockerEngine', lambda: engine)
    sample_config.terminal_adapter = 'issue_orchestrator.execution.terminal_docker:DockerPlugin'
    owner = build_original_delivery_owner(sample_config, Mock(spec=OriginalDeliveryClaims), Mock(), None, None)
    assert owner is not None and owner.docker_custody is not None
    custody = owner.docker_custody
    manager = pluggy.PluginManager('issue_orchestrator')
    manager.add_hookspecs(TerminalSpec)
    manager.register(plugin)
    runner = PluggySessionRunner(manager)
    entered, release = threading.Event(), threading.Event()
    writers = threading.Barrier(2)
    output = b'x' * (100 if order == 'settled' else 900)

    def provider(exec_id, consume, timeout):
        if order not in {'receipt-first', 'concurrent'}:
            consume(output)
        entered.set()
        wait_for_event(release, 5, label='provider release')
        if order == 'concurrent':
            writers.wait(timeout=5)
        if order in {'receipt-first', 'concurrent'}:
            consume(output)

    monkeypatch.setattr(engine, 'start_exec', provider)
    receipt = {'run_id': packet['run_id'], 'launch_sha256': sha256(canonical(packet)).hexdigest()}
    accepted = False
    try:
        assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', secret_env=None)
        wait_for_event(entered, 5, label='provider entered')
        # The production custody observer caches live identity independently.
        assert custody.runner is not plugin
        custody.runner.public_receipt('issue-42')
        if order == 'provider-first':
            with pytest.raises(ValueError, match='aggregate output bound'):
                custody.seal_first_model(session, receipt)
        else:
            if order == 'concurrent':
                release.set()
                writers.wait(timeout=5)
            try:
                custody.seal_first_model(session, receipt)
                accepted = True
            except (ValueError, BlockingIOError) as error:
                assert order == 'concurrent'
                assert isinstance(error, BlockingIOError) or 'aggregate output bound' in str(error)
    finally:
        release.set()
        plugin.on_orchestrator_shutdown()

    record = json.loads(plugin.receipt_path().read_bytes())
    assert record['state'] == 'stopped'
    refused_output = order in {'receipt-first', 'concurrent'} and accepted
    if order != 'concurrent':
        assert record['overflow'] is refused_output
    assert record['provider_exit_code'] == (None if refused_output else 0)
    if order == 'settled':
        # A later seal must not restore the observer's cached STARTING state.
        custody.seal_first_model(session, receipt)
        assert json.loads(plugin.receipt_path().read_bytes()) == record
    ordinary = Path(packet['output_root']) / packet['run_id']
    retained = sum(path.stat().st_size for path in ordinary.rglob('*') if path.is_file())
    assert retained <= 1024
    assert record['output_bytes'] == (0 if refused_output else len(output))


@pytest.mark.parametrize('refusal', ['contended', 'expired-after-acquire'])
def test_first_model_allocation_refuses_contention_and_original_deadline(launch, monkeypatch, refusal):
    import fcntl
    from issue_orchestrator.domain.session_run import SessionRunAssets
    from tests.unit.threading_helpers import join_or_fail, run_in_thread

    runner, engine, packet, calls = launch
    root = Path(packet['working_dir'])
    run_dir = root / '.issue-orchestrator' / 'sessions' / (packet['run_id'] + '__coding-1')
    run = SessionRunAssets.from_paths(session_name='coding-1', run_id=packet['run_id'], started_at='start',
        worktree_path=root, run_dir=run_dir, manifest_path=run_dir/'manifest.json', terminal_recording_path=run_dir/'log')
    ordinary = Path(packet['output_root']) / packet['run_id']
    ordinary.mkdir(mode=0o700)
    receipt = {'run_id': run.run_id, 'launch_sha256': sha256(canonical(packet)).hexdigest()}
    if refusal == 'contended':
        descriptor = os.open(ordinary, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        thread, result = run_in_thread(runner.seal_first_model, run, receipt)
        try:
            join_or_fail(thread, 1, label='contended receipt refusal')
        finally:
            os.close(descriptor)
            join_or_fail(thread, 5, label='released receipt attempt')
        with pytest.raises(BlockingIOError):
            result.unwrap()
    else:
        now = [packet['deadline_unix_ns'] - 1]
        acquire = fcntl.flock

        def expire_after_acquire(descriptor, operation):
            acquire(descriptor, operation)
            now[0] = packet['deadline_unix_ns']

        monkeypatch.setattr('time.time_ns', lambda: now[0])
        monkeypatch.setattr(fcntl, 'flock', expire_after_acquire)
        with pytest.raises(ValueError, match='deadline exhausted'):
            runner.seal_first_model(run, receipt)
    assert list(ordinary.iterdir()) == []
    assert not runner.receipt_path().exists()
    assert not calls and engine.starts == 0


@pytest.mark.parametrize('changed', [None, 'false-restart-count', 'oom', 'paused', 'worker-pid', 'provider-pid', 'provider-exited', 'foreign-provider'])
def test_first_model_requires_strict_live_daemon_facts(launch, changed):
    from issue_orchestrator.domain.original_delivery import DockerCustody
    from issue_orchestrator.execution.terminal_docker import require_first_model_liveness
    runner, engine, packet, calls = launch
    actual = engine.worker()
    actual['State'].update(Paused=False, Restarting=False, OOMKilled=False, Error='', Pid=21)
    actual['RestartCount'] = 0
    custody = DockerCustody(1, packet['run_id'], packet['daemon_id'], packet['controller_container_id'], '2'*64, '3'*64, sha256(canonical(packet)).hexdigest())
    provider = {'ID':custody.provider_exec_id, 'ContainerID':custody.container_id, 'Running':True, 'ExitCode':None, 'Pid':22}
    if changed == 'false-restart-count': actual['RestartCount'] = False
    elif changed == 'oom': actual['State']['OOMKilled'] = True
    elif changed == 'paused': actual['State']['Paused'] = True
    elif changed == 'worker-pid': actual['State']['Pid'] = False
    elif changed == 'provider-pid': provider['Pid'] = False
    elif changed == 'provider-exited': provider.update(Running=False, ExitCode=0)
    elif changed == 'foreign-provider': provider['ContainerID'] = 'f'*64
    if changed is None:
        require_first_model_liveness(actual, provider, custody)
    else:
        with pytest.raises(ValueError, match='not live'):
            require_first_model_liveness(actual, provider, custody)
    assert not calls and engine.starts == 0


@pytest.mark.parametrize('changed',[None,'live-worker','live-provider','false-restart','oom','wrong-provider'])
def test_review_parent_requires_actual_successful_stopped_custody(launch,changed):
    from issue_orchestrator.domain.original_delivery import DockerCustody
    runner,engine,packet,calls=launch
    custody=DockerCustody(1,packet['run_id'],packet['daemon_id'],packet['controller_container_id'],'2'*64,'3'*64,sha256(canonical(packet)).hexdigest())
    actual=engine.worker()
    actual['State'].update(Running=False,Pid=0,Paused=False,Restarting=False,OOMKilled=False,Error='')
    actual['RestartCount']=0
    provider={'ID':custody.provider_exec_id,'ContainerID':custody.container_id,'Running':False,'ExitCode':0}
    if changed == 'live-worker':actual['State'].update(Running=True,Pid=123)
    elif changed == 'live-provider':provider.update(Running=True,ExitCode=None)
    elif changed == 'false-restart':actual['RestartCount']=False
    elif changed == 'oom':actual['State']['OOMKilled']=True
    elif changed == 'wrong-provider':provider['ContainerID']='f'*64
    engine.worker=lambda:actual
    original_request=engine.request
    engine.request=lambda method,path,payload=None:provider if path=='/exec/'+custody.provider_exec_id+'/json' else original_request(method,path,payload)
    if changed is None:
        runner.verify_stopped_parent(packet,custody)
    else:
        with pytest.raises(ValueError,match='successfully stopped'):
            runner.verify_stopped_parent(packet,custody)
    assert not calls and engine.starts == 0


@pytest.mark.parametrize('changed',[None,'live','foreign-network','foreign-ipam','ipv6','dns','network-mode','missing-gateway','partial-clear','false-prefix','changed-bridge'])
def test_stopped_review_parent_accepts_only_lifecycle_cleared_selected_bridge(bridge_launch,changed):
    from issue_orchestrator.domain.original_delivery import DockerCustody
    from issue_orchestrator.execution.terminal_docker import require_worker_network
    runner,engine,packet,calls=bridge_launch
    custody=DockerCustody(1,packet['run_id'],packet['daemon_id'],packet['controller_container_id'],'2'*64,'3'*64,sha256(canonical(packet)).hexdigest())
    endpoint=engine.worker_endpoint
    endpoint.update(IPAddress='',Gateway='',IPPrefixLen=0,MacAddress='',EndpointID='',GlobalIPv6Address='',GlobalIPv6PrefixLen=0,IPv6Gateway='')
    actual=engine.worker()
    actual['State'].update(Running=False,Pid=0,Paused=False,Restarting=False,OOMKilled=False,Error='')
    actual['RestartCount']=0
    if changed=='live':actual['State'].update(Running=True,Pid=123)
    elif changed=='foreign-network':endpoint['NetworkID']='f'*64
    elif changed=='foreign-ipam':endpoint['IPAMConfig']['IPv4Address']='172.28.64.4'
    elif changed=='ipv6':endpoint['GlobalIPv6Address']='2001:db8::1'
    elif changed=='dns':actual['HostConfig']['Dns']=['9.9.9.9']
    elif changed=='network-mode':actual['HostConfig']['NetworkMode']='host'
    elif changed=='missing-gateway':endpoint.pop('Gateway')
    elif changed=='partial-clear':endpoint['Gateway']=packet['network']['gateway']
    elif changed=='false-prefix':endpoint['IPPrefixLen']=False
    elif changed=='changed-bridge':engine.bridge['Id']='f'*64
    engine.worker=lambda:actual
    original_request=engine.request
    engine.request=lambda method,path,payload=None:({'ID':custody.provider_exec_id,'ContainerID':custody.container_id,'Running':False,'ExitCode':0}
        if path=='/exec/'+custody.provider_exec_id+'/json' else original_request(method,path,payload))
    if changed is None:
        runner.verify_stopped_parent(packet,custody)
        with pytest.raises(ValueError,match='IPv4 membership'):
            require_worker_network(actual,packet)
    else:
        with pytest.raises(ValueError):runner.verify_stopped_parent(packet,custody)
    assert not calls and engine.starts==0


def test_builder_delivery_startup_allowance_survives_fresh_engine_run(bridge_launch, tmp_path, monkeypatch):
    runner, engine, packet, calls = bridge_launch
    root = tmp_path / 'authority'; root.mkdir(mode=0o700)
    template_dir = root / 'launch-templates-docker-v1'; template_dir.mkdir(mode=0o700)
    template = template_dir / 'template.json'
    run = packet['builder_run_id']
    outer = root / 'execution-contracts-docker-v1' / (run + '.json')
    inner_path = root / 'engine-contracts-docker-v1' / (run + '.json')
    outer.parent.mkdir(mode=0o700); inner_path.parent.mkdir(mode=0o700)
    packet['worker_authority'] = {'contract_path': str(outer), 'engine_contract_path': str(inner_path)}
    packet['mounts'] += [{'source': str(p), 'target': str(p), 'read_only': True} for p in (outer, inner_path)]
    config = Path(packet['devcontainer_config']); data = json.loads(config.read_bytes())
    for mount in packet['mounts']:
        data['runArgs'].extend(['--mount', 'type=bind,source=' + mount['source'] + ',target=' + mount['target'] + ',readonly'])
    config.chmod(0o600); config.write_bytes(canonical(data)); config.chmod(0o400)
    packet['devcontainer_config_sha256'] = sha256(config.read_bytes()).hexdigest()
    intent = {k:v for k,v in packet.items() if k not in {'contract_sha256','run_id','engine_run_dir','command_sha256'}}
    subject = {'run_id':run, 'repository':{'name':packet['repository']}, 'issue':{'number':42}, 'branch':{},
        'role':'standard-implementation', 'bounds':{'transient_launch_max_attempts':1}, 'capabilities':{}, 'supervised':{},
        'execution':{'workspace':packet['working_dir'], 'session_name':packet['session_name'], 'agent_label':'coding-1',
        'logical_child':'original', 'backend':'docker', 'callback':{'scope':'docker'},
        'docker_launch':{'template_path':str(template), 'intent_sha256':sha256(canonical(intent)).hexdigest()}}}
    inner = {'schema_version':4, 'controller_compatibility':'supervised-v4', **subject}
    inner_path.write_bytes(canonical(inner)); inner_path.chmod(0o400)
    packet['contract_sha256'] = sha256(canonical(inner)).hexdigest()
    outer.write_bytes(canonical({'schema_version':1,'kind':'builder-docker-delivery','model_admission':False,
        'run_id':run,'subject':subject,'engine_contract':{'path':str(inner_path),'sha256':packet['contract_sha256']},
        'worker':{'image_id':packet['image_id'],'manifest_sha256':'c'*64},'installed_acceptance':None})); outer.chmod(0o400)
    template.write_bytes(canonical({**packet, 'run_id':'', 'engine_run_dir':'', 'command_sha256':'0'*64})); template.chmod(0o400)
    runner.template_path = template
    monkeypatch.setattr(DockerPlugin, '_output_root', lambda self, packet: Path(packet['output_root']))
    def fail(*args, **kwargs):
        calls.append(1)
        raise ValueError('external CLI failed')
    monkeypatch.setattr('issue_orchestrator.execution.terminal_docker.run_cli', fail)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_AGENT_CALLBACK_TOKEN', 'd'*64)
    secret = {'ISSUE_ORCHESTRATOR_COMPLETION_CAPABILITY':'e'*64}
    for char in ('e', 'f'):
        packet['run_id'] = '20261017-100000Z-' + char*32
        path = template_dir / packet['run_id']; path.mkdir(mode=0o700)
        runner.launch_path = path / 'launch.json'; runner.launch_path.write_bytes(canonical(packet)); runner.launch_path.chmod(0o400)
        assert not runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', secret)
    assert len(calls) == 1


@pytest.mark.parametrize('invalid', [False, True])
def test_terminal_provider_handoff_stops_worker_even_on_invalid_status(launch, tmp_path, invalid):
    from issue_orchestrator.infra.provider_resilience import read_provider_status
    runner, engine, packet, _ = launch
    run = tmp_path / 'controller-run'; run.mkdir(mode=0o700)
    packet['engine_run_dir'] = str(run)
    ordinary = Path(packet['output_root']) / packet['run_id']; ordinary.mkdir(mode=0o700)
    slot = tmp_path / 'worker-slot'; slot.mkdir(mode=0o700)
    status = {'provider':'codex', 'error_type':None, 'attempts':1, 'succeeded':True, 'exit_code':0,
        'timed_out':False, 'last_error_summary':None, 'last_attempt_at':'2026-10-30T00:00:00+00:00', 'quota_heals_on_timer':False}
    (slot / 'provider-status.json').write_text('{}' if invalid else json.dumps(status))
    fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    exec_id = '3'*64
    runner._provider_slot = (slot, fd, 'codex', False)  # noqa: SLF001
    runner._packet = packet  # noqa: SLF001
    runner._record = {  # noqa: SLF001
        'issue_number':42, 'session_name':'issue-42', 'daemon_id':packet['daemon_id'], 'run_id':packet['run_id'],
        'container_id':'2'*64, 'provider_exec_id':exec_id, 'launch_sha256':sha256(canonical(packet)).hexdigest(),
        'state':'exec-created', 'output_bytes':0, 'overflow':False, 'provider_exit_code':None, 'error':''}
    engine.exec_payloads[exec_id] = {}
    runner._run_provider()  # noqa: SLF001
    assert not engine.running
    assert runner._record['provider_exit_code'] == 0  # noqa: SLF001
    assert runner._record['error'] == ('provider-status-invalid' if invalid else '')  # noqa: SLF001
    assert (read_provider_status(run) is None) == invalid
    assert runner._record['diagnostic']['primary'] is None  # noqa: SLF001


@pytest.mark.parametrize(('outcome', 'status_recording_fails', 'receipt_recording_fails', 'transport_fails', 'corrupt_status'),
    [(outcome, *case) for outcome in ('failure', 'timeout') for case in
        [(False, False, False, ''), (True, False, False, ''), (False, True, False, ''),
         (True, True, False, ''), (False, True, True, ''), (False, True, False, 'malformed'),
         (False, True, False, 'foreign')]] + [('cancel', False, False, False, ''), ('cancel', True, False, False, ''),
            ('cancel', True, True, False, ''), ('active', False, False, False, ''),
            ('active_status', False, False, False, ''), ('deadline', False, False, False, ''), ('child', False, False, False, ''), ('child', False, True, False, ''),
            ('child_file', False, False, False, ''), ('child_file', True, False, False, ''),
            ('child_file', False, True, False, ''), ('producer_file', False, False, False, ''),
            ('producer_marker', False, False, False, ''), ('producer_timeout', False, False, False, ''),
            ('producer_interrupted', False, False, False, ''), ('producer_spawn', False, False, False, ''), ('producer_combined', False, False, False, '')])
def test_real_provider_failure_survives_stop_failure(launch, tmp_path, monkeypatch, status_recording_fails, receipt_recording_fails, transport_fails, corrupt_status, outcome):
    """Actual provider status must survive the later Docker stop error."""
    import shlex
    import subprocess
    import sys
    from issue_orchestrator.control.provider_command_wrapper import ProviderCommandWrapper
    from issue_orchestrator.domain.models import AgentConfig
    from issue_orchestrator.infra.config_models import ProviderShortRetryConfig

    runner, engine, packet, _ = launch
    protected = tmp_path / '.issue-orchestrator'; protected.mkdir(mode=0o700)
    sessions = protected / 'sessions'; sessions.mkdir(mode=0o700)
    run = sessions / (packet['run_id'] + '__coding-1'); run.mkdir(mode=0o700)
    packet['engine_run_dir'] = str(run)
    packet['mounts'].append({'source':str(protected), 'target':str(protected), 'read_only':True})
    scratch = tmp_path / 'scratch'; scratch.mkdir(mode=0o700)
    packet['mounts'].append({'source':str(scratch), 'target':str(scratch), 'read_only':False})
    inner = tmp_path / 'inner.json'; inner.write_bytes(canonical({'execution':{'provider':'codex'}, 'capabilities':{'scratch':str(scratch)}})); inner.chmod(0o400)
    packet['contract_sha256'] = sha256(inner.read_bytes()).hexdigest()
    packet['worker_authority'] = {'engine_contract_path':str(inner)}
    launch_dir = tmp_path / 'control' / packet['run_id']; launch_dir.mkdir(mode=0o700)
    runner.template_path = launch_dir.parent / 'template.json'
    runner.launch_path = launch_dir / 'launch.json'; runner.launch_path.write_bytes(canonical(packet)); runner.launch_path.chmod(0o400)
    engine.record_path = runner.receipt_path()
    monkeypatch.setattr(DockerPlugin, '_output_root', lambda self, packet: Path(packet['output_root']))
    ordinary = Path(packet['output_root']) / packet['run_id']; ordinary.mkdir(mode=0o700)
    slot = scratch / ('provider-' + packet['run_id']); slot.mkdir(mode=0o700)
    agent = AgentConfig(prompt_path=tmp_path / 'prompt', provider='codex', provider_args={'execution_mode':'exec'})
    wrapper = ProviderCommandWrapper(ProviderShortRetryConfig(max_attempts=1, initial_backoff_seconds=1,
        max_backoff_seconds=1, jitter=False))
    child_command = "printf 'ACPCHILD1|nonzero|2|n|10|20|0|0' >&2; exit 78"
    builder_source = os.environ.get('BUILDER_CHILD_PRODUCER_SOURCE')
    if outcome.startswith('producer_'):
        if not builder_source:
            pytest.skip('explicit Builder child producer source not supplied')
        import shlex
        producer_packet = tmp_path / 'producer-packet.json'; producer_packet.write_bytes(canonical(packet))
        producer = tmp_path / 'producer.py'
        producer.write_text('''import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import capabilities
p=json.loads(Path(sys.argv[2]).read_bytes())
scratch=Path(sys.argv[3])
os.environ['ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR']=str(scratch / ('provider-' + p['run_id']))
try:
 scenario=sys.argv[5]
 commands={'nonzero':[sys.executable,'-c','import sys;sys.stderr.write("bad");sys.exit(2)'],
  'timeout':[sys.executable,'-c','import time;time.sleep(10)'],
  'interrupted':[sys.executable,'-c','import os,signal,time;os.kill(os.getppid(),signal.SIGTERM);time.sleep(10)'],
  'spawn':[str(scratch / 'missing-child')],
  'combined':[sys.executable,'-c','import time;time.sleep(10)']}
 if scenario == 'combined':
  real_kill=os.killpg
  def fail_after_kill(pid,sig):
   real_kill(pid,sig)
   raise OSError('cleanup-secret')
  os.killpg=fail_after_kill
 capabilities._container_child(commands[scenario],{},str(scratch),.1 if scenario in ('timeout','combined') else 5,65536)
except capabilities.CodexChildFailure as error:
 if sys.argv[4] == 'marker': os.environ['ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR']='foreign'
 capabilities._record_container_child_failure(scratch,p,error)
 if error.marker: print(error.marker,file=sys.stderr)
 sys.exit(78)
''')
        child_command = ' '.join(map(shlex.quote, [sys.executable,str(producer),str(Path(builder_source) / 'tools/orchestration'),
            str(producer_packet),str(scratch),'marker' if outcome in ('producer_marker','producer_combined') else 'slot',
            outcome.removeprefix('producer_') if outcome in ('producer_timeout','producer_interrupted','producer_spawn','producer_combined') else 'nonzero']))
    command = wrapper.wrap(child_command, agent, slot) if outcome in ('child', 'child_file') or outcome.startswith('producer_') else wrapper.wrap("/usr/bin/python3 -c 'import select; select.select([], [], [])'" if outcome == 'timeout' else 'printf "connection refused\\n" >&2; exit 1', agent, slot)
    env = {**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[2] / 'src')}
    if outcome not in ('cancel', 'active', 'deadline'):
        argv = shlex.split(command)
        if outcome == 'timeout': argv[argv.index('--timeout-seconds') + 1] = '1'
        if outcome == 'producer_combined':
            # Exercise the Docker entrypoint while substituting the physical mount guard.
            module = 'issue_orchestrator.entrypoints.cli_tools.provider_runner'
            args = argv[argv.index(module) + 1:]
            shim = ('from pathlib import Path; from issue_orchestrator.execution import docker_provider_status as s; '
                    's.worker_slot=lambda value, run_dir: Path(value); '
                    'from issue_orchestrator.entrypoints.cli_tools.provider_runner import main; '
                    'import sys; sys.exit(main(sys.argv[1:]))')
            argv = [sys.executable, '-c', shim, *args]
            env['ISSUE_ORCHESTRATOR_CALLBACK_SCOPE'] = 'docker'
            env['ISSUE_ORCHESTRATOR_DOCKER_PROVIDER_DIR'] = str(slot)
        child = subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, timeout=15)
        assert child.returncode == (124 if outcome == 'timeout' else 78 if outcome in ('child', 'child_file') or outcome.startswith('producer_') else 1)
    if outcome == 'child_file':
        value = {'schema_version':1, 'kind':'builder-codex-child-diagnostic', 'run_id':packet['run_id'],
            'launch_sha256':sha256(canonical(packet)).hexdigest(), 'phase':'codex-child', 'reason':'nonzero',
            'exit_code':2, 'exception_type':None, 'stderr_bytes':3, 'stderr_sha256':sha256(b'bad').hexdigest(),
            'stderr_truncated':False, 'elapsed_ms':10, 'remaining_ms':20, 'own_timer_fired':False, 'secondary':[]}
        (slot / 'child-diagnostic.json').write_text(json.dumps(value)); (slot / 'child-diagnostic.json').chmod(0o600)
    descriptor = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    exec_id = '3'*64
    runner._provider_slot = (slot, descriptor, 'codex', False)  # noqa: SLF001
    runner._packet = packet  # noqa: SLF001
    runner._record = {  # noqa: SLF001
        'issue_number':42, 'session_name':'issue-42', 'daemon_id':packet['daemon_id'], 'run_id':packet['run_id'],
        'container_id':'2'*64, 'provider_exec_id':exec_id, 'launch_sha256':sha256(canonical(packet)).hexdigest(),
        'state':'exec-created', 'output_bytes':0, 'overflow':False, 'provider_exit_code':None, 'error':''}
    engine.exec_payloads[exec_id] = {}
    original_request = engine.request
    def request(method, route, payload=None):
        result = original_request(method, route, payload)
        if route == '/exec/' + exec_id + '/json':
            result['ExitCode'] = 124 if outcome == 'timeout' else 78 if outcome in ('child', 'child_file') or outcome.startswith('producer_') else 1
            if outcome == 'cancel': result['Running'] = cancel_child.poll() is None
            if outcome in ('active', 'active_status'): result['Running'] = True
        return result
    cancel_child = subprocess.Popen(['/usr/bin/python3', '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE) if outcome == 'cancel' else None
    def stop(_):
        if cancel_child is not None:
            cancel_child.terminate(); cancel_child.wait(timeout=5)
            raise OSError('sensitive-stop-detail')
        if receipt_recording_fails: launch_dir.chmod(0o500)
        raise OSError('sensitive-stop-detail')
    engine.request = request
    engine.stop = stop
    if status_recording_fails: run.chmod(0o500)
    try:
        if outcome in ('active', 'active_status'):
            os.close(descriptor); runner._provider_slot = None  # noqa: SLF001
            if outcome == 'active_status':
                from shutil import copyfile
                copyfile(slot / 'provider-status.json', run / 'provider-status.json')
            runner._save()  # noqa: SLF001
        elif outcome == 'deadline':
            os.close(descriptor); runner._provider_slot = None  # noqa: SLF001
            runner._deadline_stop()  # noqa: SLF001
        elif outcome == 'cancel':
            os.close(descriptor); runner._provider_slot = None  # noqa: SLF001
            runner._save()  # noqa: SLF001
            original_save = runner._save  # noqa: SLF001
            saves = 0
            def failing_save():
                nonlocal saves
                saves += 1
                if status_recording_fails and (saves == 1 or receipt_recording_fails):
                    raise OSError('sensitive-record-detail')
                original_save()
            monkeypatch.setattr(runner, '_save', failing_save)
            with pytest.raises(OSError, match='sensitive-stop-detail'):
                runner.kill_session(42, 'issue-42')
            assert cancel_child is not None and cancel_child.returncode is not None
        elif receipt_recording_fails:
            with pytest.raises(OSError): runner._run_provider()  # noqa: SLF001
        else:
            runner._run_provider()  # noqa: SLF001
    finally:
        run.chmod(0o700); launch_dir.chmod(0o700)
        if cancel_child is not None:
            if cancel_child.poll() is None: cancel_child.kill(); cancel_child.wait(timeout=5)
            if cancel_child.stdin: cancel_child.stdin.close()
    if corrupt_status:
        status_path = run / 'provider-status.json'
        if corrupt_status == 'malformed': status_path.write_text('{')
        else:
            payload = json.loads(status_path.read_text()); payload['provider'] = 'foreign'
            status_path.write_text(json.dumps(payload))
    from dataclasses import replace
    from datetime import datetime
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import asyncio
    from issue_orchestrator.control.original_delivery import OriginalDeliveryOwner
    from issue_orchestrator.domain.claim import Claim
    from issue_orchestrator.domain.original_delivery import DockerCustody
    from issue_orchestrator.entrypoints.mcp_original_delivery import original_delivery_result
    from issue_orchestrator.execution.original_delivery_docker import DockerOriginalCustody
    from tests.unit.test_original_delivery import custody
    digest = sha256(canonical(packet)).hexdigest()
    row = DockerCustody(schema_version=1, run_id=packet['run_id'], daemon_id=packet['daemon_id'],
        controller_container_id=packet['controller_container_id'], container_id='2'*64,
        provider_exec_id=exec_id, launch_sha256=digest)
    selected = replace(custody(), run_id=packet['run_id'], run_dir=str(run), worktree=packet['working_dir'],
        contract_sha256=packet['contract_sha256'], execution_backend='docker', docker_custody=(row,))
    claim = Claim(lease_id='fixture', claimant='fixture', issue_number=42, started_at=datetime(2026, 1, 1),
        expires_at=datetime(2099, 1, 1), priority=1, original=selected)
    claims = SimpleNamespace(original_claim=lambda _: (claim, 'a'*40))
    config = SimpleNamespace(repo=selected.repository, config_fingerprint=selected.config_fingerprint)
    if transport_fails:
        def unavailable(*_args, **_kwargs): raise OSError('sensitive-transport-detail')
        engine.request = unavailable
    observer = DockerPlugin(engine=engine)
    observer.template_path = runner.template_path
    backend = DockerOriginalCustody(observer)
    owner = OriginalDeliveryOwner(claims, MagicMock(), None, config, None, lambda:('',0,''),
        MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(), docker_custody=backend)
    class Api:
        async def original_delivery(self, issue_number, operation, payload):
            return owner.observe(issue_number)
    result = asyncio.run(original_delivery_result(Api(), Path('/unused'), 42, 'observe', None, running=True))
    assert not result.isError
    diagnostic = result.structuredContent['diagnostic']
    assert result.structuredContent['remote_released'] is False
    if outcome in ('active', 'active_status') or receipt_recording_fails and (transport_fails or status_recording_fails or corrupt_status):
        assert diagnostic is None
    else:
        assert diagnostic['primary'] == {'phase':'provider', 'reason':{'failure':'provider_transient', 'timeout':'provider_timeout', 'cancel':'provider_cancelled', 'deadline':'controller_deadline', 'child':'provider_nonzero', 'child_file':'provider_nonzero', 'producer_file':'provider_nonzero', 'producer_marker':'provider_nonzero', 'producer_timeout':'provider_nonzero', 'producer_interrupted':'provider_nonzero', 'producer_spawn':'provider_nonzero', 'producer_combined':'provider_nonzero'}[outcome]}
        expected = ([] if receipt_recording_fails else
            ([{'phase':'record', 'reason':'record_failed'}] if status_recording_fails else []) +
            [{'phase':'stop', 'reason':'stop_unverified'}])
        assert diagnostic['secondary'] == expected
        if outcome not in ('child', 'child_file') and not outcome.startswith('producer_'):
            assert 'child' not in diagnostic
        if outcome in ('child', 'child_file') or outcome.startswith('producer_'):
            expected_reason = {'producer_timeout':'timeout', 'producer_interrupted':'interrupted', 'producer_spawn':'spawn_failed', 'producer_combined':'timeout'}.get(outcome, 'nonzero')
            assert diagnostic['child']['reason'] == expected_reason
            if expected_reason == 'nonzero': assert diagnostic['child']['exit_code'] == 2
            assert diagnostic['child']['source'] == ('marker' if outcome in ('child', 'producer_marker', 'producer_combined') else 'slot')
            assert diagnostic['child']['secondary'] == (['record_failed', 'cleanup_failed'] if outcome == 'producer_combined' else ['record_failed'] if outcome in ('child', 'producer_marker') else [])
            if outcome.startswith('producer_'):
                sys.path.insert(0, str(Path(builder_source) / 'tools/orchestration'))
                import qualification_runner
                current = {'observation':{'original_delivery':result.structuredContent},
                    'owner':result.structuredContent['owner'], 'receipts':[{'run_id':packet['run_id'], 'launch_sha256':digest}]}
                with pytest.raises(qualification_runner.ProviderDiagnosticError) as caught:
                    qualification_runner.raise_provider_diagnostic(current)
                assert caught.value.diagnostic['child'] == diagnostic['child']
                import time
                operations = {name:lambda _:True for name in qualification_runner.PHASES}
                operations['observation'] = lambda _:qualification_runner.raise_provider_diagnostic(current)
                def fail_stop(_): raise OSError('stop-secret')
                operations['owner_stop'] = fail_stop
                def fail_record(event):
                    if event.get('state') == 'failed': raise OSError('record-secret')
                plan = qualification_runner.Plan('a'*64, ('fixture',), time.time()+8, 2, .1, (2,)*7)
                final = qualification_runner.run(plan, operations, {}, fail_record)
                assert final['failure_detail']['provider_diagnostic']['child'] == diagnostic['child']
                assert final['recording_failed'] and final['cleanup_failures'][0]['phase'] == 'owner_stop'
                assert 'stop-secret' not in json.dumps(final) and 'record-secret' not in json.dumps(final)
    assert 'connection refused' not in json.dumps(result.structuredContent)
    assert 'sensitive-stop-detail' not in json.dumps(result.structuredContent)


@pytest.mark.parametrize('prior', [None, {'phase':'provider', 'reason':'provider_auth'}])
def test_explicit_cancellation_preserves_existing_primary_and_reaps_child(launch, prior):
    import subprocess
    import sys
    runner, engine, packet, _ = launch
    child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE)
    try:
        runner._record = {  # noqa: SLF001
            'issue_number':42, 'session_name':'issue-42', 'run_id':packet['run_id'], 'daemon_id':packet['daemon_id'],
            'container_id':'2'*64, 'provider_exec_id':'3'*64, 'provider_exit_code':None,
            'launch_sha256':sha256(canonical(packet)).hexdigest(), 'state':'exec-created', 'error':''}
        if prior is not None:
            runner._record['diagnostic'] = {'run_id':packet['run_id'], 'launch_sha256':sha256(canonical(packet)).hexdigest(),  # noqa: SLF001
                'primary':prior, 'secondary':[]}
        engine.exec_payloads['3'*64] = {}
        original_request = engine.request
        def request(method, route, payload=None):
            actual = original_request(method, route, payload)
            if route == '/exec/' + '3'*64 + '/json': actual['Running'] = child.poll() is None
            return actual
        engine.request = request
        def stop(container):
            assert container == '2'*64
            child.terminate(); child.wait(timeout=5)
            engine.running = False
        engine.stop = stop
        runner.kill_session(42, 'issue-42')
        assert child.returncode is not None
        receipt = json.loads(runner.receipt_path().read_bytes())
        assert receipt['diagnostic']['primary'] == (prior or {'phase':'provider', 'reason':'provider_cancelled'})
    finally:
        if child.poll() is None: child.kill(); child.wait(timeout=5)
        if child.stdin: child.stdin.close()


def test_unobserved_provider_does_not_invent_cancellation(launch):
    runner, engine, packet, _ = launch
    runner._record = {  # noqa: SLF001
        'issue_number':42, 'session_name':'issue-42', 'run_id':packet['run_id'], 'daemon_id':packet['daemon_id'],
        'container_id':'2'*64, 'provider_exec_id':'3'*64, 'provider_exit_code':None,
        'launch_sha256':sha256(canonical(packet)).hexdigest(), 'state':'exec-created', 'error':''}
    original_request = engine.request
    def request(method, route, payload=None):
        if route == '/exec/' + '3'*64 + '/json': raise OSError('transport unavailable')
        return original_request(method, route, payload)
    engine.request = request
    runner.kill_session(42, 'issue-42')
    assert not engine.running
    receipt = json.loads(runner.receipt_path().read_bytes())
    assert receipt.get('diagnostic') is None


def test_controller_deadline_is_distinct_from_provider_timeout(launch):
    runner, engine, packet, _ = launch
    runner._record = {  # noqa: SLF001
        'issue_number':42, 'session_name':'issue-42', 'run_id':packet['run_id'], 'daemon_id':packet['daemon_id'],
        'container_id':'2'*64, 'provider_exec_id':'3'*64, 'provider_exit_code':None,
        'launch_sha256':sha256(canonical(packet)).hexdigest(), 'state':'exec-created', 'error':''}
    runner._deadline_stop()  # noqa: SLF001
    assert not engine.running
    receipt = json.loads(runner.receipt_path().read_bytes())
    assert receipt['diagnostic']['primary'] == {'phase':'provider', 'reason':'controller_deadline'}

@pytest.mark.parametrize('stop_fails', [False, True])
def test_startup_record_failure_still_attempts_owned_stop(launch, monkeypatch, stop_fails):
    runner, engine, packet, _ = launch
    original_save = runner._save  # noqa: SLF001
    stopped = []
    def fail_allocated_save():
        if runner._record and runner._record.get('container_id'):  # noqa: SLF001
            raise OSError('synthetic recording failure')
        original_save()
    def stop(container):
        stopped.append(container)
        if stop_fails: raise OSError('synthetic stop failure')
        engine.running = False
    monkeypatch.setattr(runner, '_save', fail_allocated_save)
    monkeypatch.setattr(engine, 'stop', stop)
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', secret_env=None) is False
    assert stopped == ['2' * 64]
    assert engine.running is stop_fails
    assert runner._record['error'] == 'launch-refused-or-uncertain'  # noqa: SLF001
    assert runner._record.get('diagnostic') is None  # noqa: SLF001


def test_provider_creation_waits_for_original_owner_before_activation(launch):
    runner, engine, packet, _ = launch
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    # The admitted implementation role is normally set by prepare_session.
    runner._require_original_owner = True  # noqa: SLF001
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    runner.on_orchestrator_shutdown()
    assert engine.starts == 0


def test_cancelled_unstarted_exec_retains_explicit_stop_wait_proof(launch):
    runner, engine, packet, _ = launch
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    runner._require_original_owner = True  # noqa: SLF001 - admitted role substituted
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    runner._record.update(original_binding='bound', original_fence='a'*40)  # noqa: SLF001 - original CAS substituted
    runner._save()  # noqa: SLF001
    runner.kill_session(42, 'issue-42')
    record = json.loads(runner.receipt_path().read_bytes())
    assert engine.starts == 0 and not engine.running
    assert record['start_intent'] == 'cancelled-before-start'
    assert record['never_started']['kind'] == 'docker-never-started'
    assert record['never_started']['before'] == record['never_started']['after'] == {
        'running':False, 'pid':0, 'exit_code':None}
    assert record['never_started']['stop_wait'] == 'completed'


def test_unstarted_exec_without_disposition_does_not_certify_release():
    from dataclasses import replace
    from types import SimpleNamespace
    from issue_orchestrator.domain.original_delivery import DockerCustody
    from issue_orchestrator.execution.original_delivery_docker import DockerOriginalCustody
    from tests.unit.test_original_delivery import custody

    # Shape and values are replayed from the actual never-started exec readback.
    observed = {'ID':'d8897ca0c6141934739d2f5dc8f0d14636bec4fea54774ea6599b04d1e315101',
        'ContainerID':'4cd659ef470710035774864aa41f7e9c7a7ac2cd1afbb1c250dd6f44282f4004',
        'Running':False, 'Pid':0, 'ExitCode':None}
    if source := os.environ.get('DOCKER_PRESTART_INSPECT_FIXTURE'):
        raw = Path(source).read_bytes()
        assert sha256(raw).hexdigest() == 'bbd1cf52a5de7fa5bcfc7c0ec2a8e3dcb566cea0801e74e71aaf931ab069d695'
        observed = json.loads(raw)
    row = DockerCustody(schema_version=1, run_id='run-1', daemon_id='daemon',
        controller_container_id='1'*64, container_id=observed['ContainerID'],
        provider_exec_id=observed['ID'], launch_sha256='a'*64)
    class Daemon:
        def request(self, method, route):
            if route == '/info': return {'ID':'daemon'}
            if route.startswith('/exec/'): return observed
            return {'Id':row.container_id, 'Config':{'Labels':{'io.builder.launch':row.launch_sha256}},
                    'State':{'Running':False}}
        def inspect_exec(self, exec_id): return {'status':200, 'value':observed}
    owner = replace(custody(), execution_backend='docker', docker_custody=(row,))
    with pytest.raises(ValueError):
        DockerOriginalCustody(SimpleNamespace(engine=Daemon())).quiescent(owner, offline=False)


def test_never_started_inspect_requires_exact_process_and_null_exit():
    from issue_orchestrator.execution.docker_worker_state import require_never_started_exec
    observed = {'ID':'d8897ca0c6141934739d2f5dc8f0d14636bec4fea54774ea6599b04d1e315101',
        'ContainerID':'4cd659ef470710035774864aa41f7e9c7a7ac2cd1afbb1c250dd6f44282f4004',
        'Running':False, 'Pid':0, 'ExitCode':None,
        'ProcessConfig':{'entrypoint':'/usr/bin/python3', 'arguments':['-I','-B','-c','pass'],
            'user':'1000:1000', 'privileged':False, 'tty':False}}
    if source := os.environ.get('DOCKER_PRESTART_INSPECT_FIXTURE'):
        raw = Path(source).read_bytes()
        assert sha256(raw).hexdigest() == 'bbd1cf52a5de7fa5bcfc7c0ec2a8e3dcb566cea0801e74e71aaf931ab069d695'
        observed = json.loads(raw)
    args = (observed['ContainerID'], observed['ID'], '1000:1000', ['/usr/bin/python3','-I','-B','-c','pass'])
    require_never_started_exec(observed, *args)
    for changed in ({'Running':True}, {'Pid':1}, {'ExitCode':0}, {'ID':'f'*64},
                    {'ProcessConfig':{**observed['ProcessConfig'], 'user':'0:0'}},
                    {'ProcessConfig':{**observed['ProcessConfig'], 'arguments':['-c','other']}}):
        with pytest.raises(ValueError):
            require_never_started_exec({**observed, **changed}, *args)


def test_docker_exec_handshake_finishes_before_output_stream_is_read(monkeypatch):
    from issue_orchestrator.execution.docker_engine import DockerEngine
    class Sock:
        def __init__(self): self.timeouts = []
        def settimeout(self, timeout): self.timeouts.append(timeout)
    class Response:
        status = 200
        def read(self, count): raise AssertionError('stream must not be consumed in handshake')
    class Connection:
        def __init__(self, path, timeout): self.sock = Sock(); self.timeout = timeout; self.closed = False
        def request(self, *args, **kwargs): pass
        def getresponse(self): return Response()
        def close(self): self.closed = True
    monkeypatch.setattr('issue_orchestrator.execution.docker_engine._UnixConnection', Connection)
    stream = DockerEngine().open_exec('a'*64, 120)
    assert stream.connection.timeout == 10 and 119 <= stream.connection.sock.timeouts[0] <= 120
    stream.close()
    assert stream.connection.closed


def test_lost_exec_start_ack_is_retained_and_never_certifies_no_start(launch, monkeypatch):
    from tests.unit.threading_helpers import wait_for_event
    runner, engine, packet, _ = launch
    entered = threading.Event()
    def lost_ack(exec_id, timeout):
        entered.set()
        raise TimeoutError('start acknowledgement unknown')
    monkeypatch.setattr(engine, 'open_exec', lost_ack)
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    wait_for_event(entered, 5, label='start request')
    runner.on_orchestrator_shutdown()
    record = json.loads(runner.receipt_path().read_bytes())
    assert record['start_intent'] == 'requested'
    assert 'never_started' not in record
    assert record['error'] == 'provider-unsettled-or-bound-exhausted'


def test_original_owner_accepts_only_matching_durable_never_started_proof(launch):
    from dataclasses import replace
    from shutil import copyfile
    from issue_orchestrator.domain.original_delivery import DockerCustody
    from issue_orchestrator.execution.original_delivery_docker import DockerOriginalCustody
    from tests.unit.test_original_delivery import custody
    runner, engine, packet, _ = launch
    runner.launch_path.chmod(0o600)
    runner.launch_path.write_bytes(canonical(packet))
    runner.launch_path.chmod(0o400)
    runner._require_original_owner = True  # noqa: SLF001 - admitted role substituted
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    runner._record.update(original_binding='bound', original_fence='a'*40)  # noqa: SLF001 - original CAS substituted
    runner._save()  # noqa: SLF001
    runner.kill_session(42, 'issue-42')
    record = json.loads(runner.receipt_path().read_bytes())
    directory = runner.launch_path.parent / packet['run_id']; directory.mkdir(mode=0o700)
    copyfile(runner.launch_path, directory / 'launch.json'); (directory / 'launch.json').chmod(0o400)
    copyfile(runner.receipt_path(), directory / 'docker-session.json'); (directory / 'docker-session.json').chmod(0o600)
    observer = DockerPlugin(launch_path=directory / 'launch.json', engine=engine)
    observer.template_path = directory.parent / 'template.json'
    backend = DockerOriginalCustody(observer)
    row = DockerCustody(**{key:record[key] for key in DockerCustody.__dataclass_fields__})
    original = replace(custody(), repository=packet['repository'], run_id=packet['run_id'],
        contract_sha256=packet['contract_sha256'], worktree=packet['working_dir'],
        run_dir=packet['engine_run_dir'], execution_backend='docker', docker_custody=(row,), cancelled=True)
    backend.quiescent(original, offline=False)
    assert backend.never_started(original)['provider_exec_id'] == row.provider_exec_id
    assert backend.never_started(replace(original, cancelled=False)) is None
    receipt = directory / 'docker-session.json'
    record['start_intent'] = 'requested'
    receipt.write_bytes(canonical(record))
    assert backend.never_started(original) is None
    with pytest.raises(ValueError): backend.quiescent(original, offline=False)


@pytest.mark.parametrize('wait', [{}, {'StatusCode':None}, {'StatusCode':False},
                                  {'StatusCode':137,'Error':{'Message':'wait failed'}}])
def test_docker_stop_requires_positive_wait_result(wait, monkeypatch):
    from issue_orchestrator.execution.docker_engine import DockerEngine
    engine = DockerEngine()
    def request(method, route, payload=None):
        if '/wait?' in route: return wait
        if route.endswith('/json'): return {'State':{'Running':False}}
        return {}
    monkeypatch.setattr(engine, 'request', request)
    with pytest.raises(ValueError): engine.stop('a'*64)


def test_restart_refuses_unbound_allocated_original_before_discovery(launch):
    runner, engine, packet, _ = launch
    runner._require_original_owner = True  # noqa: SLF001 - admitted role substituted
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    fresh = DockerPlugin(launch_path=runner.launch_path, engine=engine)
    with pytest.raises(ValueError, match='retained custody reconciliation'):
        fresh.on_orchestrator_startup()
    assert engine.starts == 0 and engine.running
    assert json.loads(fresh.receipt_path().read_bytes())['original_binding'] == 'pending'


def test_real_typed_implementation_preparation_defers_exec(launch, monkeypatch):
    import pluggy
    from issue_orchestrator.execution.session_output_adapter import FileSystemSessionOutput
    from issue_orchestrator.execution.session_runner_adapter import PluggySessionRunner
    from issue_orchestrator.infra.hooks.hookspec import TerminalSpec
    _, engine, packet, _ = launch
    root = engine.record_path.parent
    template_path = root / 'template.json'
    template = {**packet, 'run_id':'', 'engine_run_dir':'', 'command_sha256':'0'*64}
    intent = {key:value for key, value in template.items() if key not in {'contract_sha256','run_id','engine_run_dir','command_sha256'}}
    contract = {'role':'standard-implementation', 'execution':{'backend':'docker', 'docker_launch':{
        'template_path':str(template_path), 'intent_sha256':sha256(canonical(intent)).hexdigest()}}}
    contract_path = root / 'contract.json'; contract_path.write_bytes(canonical(contract)); contract_path.chmod(0o400)
    template['contract_sha256'] = sha256(canonical(contract)).hexdigest()
    template_path.write_bytes(canonical(template)); template_path.chmod(0o400)
    monkeypatch.setenv('ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE', str(template_path))
    monkeypatch.setenv('XORETS_EXECUTION_CONTRACT', str(contract_path))
    monkeypatch.setenv('XORETS_EXECUTION_DIGEST', template['contract_sha256'])
    plugin = DockerPlugin(engine=engine)
    pm = pluggy.PluginManager('issue_orchestrator'); pm.add_hookspecs(TerminalSpec); pm.register(plugin)
    runner = PluggySessionRunner(pm)
    assets = FileSystemSessionOutput().start_run(Path(packet['working_dir']), 'coding-1', issue_number=42)
    runner.prepare_session(assets, 'issue-42', 'echo safe')
    engine.packet = json.loads(plugin.launch_path.read_bytes()); engine.record_path = plugin.receipt_path()
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42')
    assert json.loads(plugin.receipt_path().read_bytes())['original_binding'] == 'pending'
    assert engine.starts == 0
    plugin.on_orchestrator_shutdown()


@pytest.mark.parametrize('missing_after_stop', [False, True])
def test_owner_retains_prestart_cancellation_and_public_proof(launch, first_model_owner, monkeypatch, missing_after_stop):
    import asyncio
    import sys
    from types import SimpleNamespace
    from issue_orchestrator.adapters.github.http_client import GitHubHttpClient, GitHubHttpConfig
    from issue_orchestrator.adapters.github.ref_claim_adapter import GitHubRefClaimAdapter
    from issue_orchestrator.control.original_delivery import OriginalDeliveryCommand
    from issue_orchestrator.control.issue_termination import terminate_every_session
    from issue_orchestrator.control.review_exchange_lifecycle import CoreIssueRuntimeOwners
    from issue_orchestrator.control.session_manager import SessionManager
    from issue_orchestrator.domain.validated_work_commands import ValidatedWorkDispositionBatch
    from issue_orchestrator.entrypoints.mcp_original_delivery import original_delivery_result
    from issue_orchestrator.execution.original_delivery_docker import DockerOriginalCustody

    fixture = None
    http = None
    try:
        owner, session, _, _ = first_model_owner
        claims = owner.claims
        lease_id = session.lease_id
        if os.environ.get('ENGINE_REAL_GIT_FIXTURE'):
            source = Path(os.environ['BUILDER_CHILD_PRODUCER_SOURCE']) / 'tools/orchestration'
            monkeypatch.syspath_prepend(str(source))
            from test_claim_fixture import ClaimFixtureTests
            fixture = ClaimFixtureTests(); fixture.setUp()
            fixture.public('POST', 'refs', {'ref':'refs/heads/master', 'sha':fixture.commit()})
            http = GitHubHttpClient(GitHubHttpConfig(repo='local/one', token='fixture', base_url=fixture.api.split('/repos/')[0]))
            claims = GitHubRefClaimAdapter(http, 'fixture', label_adapter=SimpleNamespace(add_label=lambda *_:None, remove_label=lambda *_:None))
            acquired = claims.attempt_claim(42); assert acquired.success
            lease_id = acquired.lease_id
            session.lease_id = lease_id
        owner.claims = claims; owner.config.repo = 'local/one'
        owner.state.pause_state = owner.state.pause_state.running()
        runner, engine, packet, _ = launch
        inspect = engine.inspect_exec
        if missing_after_stop:
            monkeypatch.setattr(engine, 'inspect_exec', lambda exec_id:
                {'status':404} if not engine.running else inspect(exec_id))
        run = session.run_assets
        packet.update(run_id=run.run_id, engine_run_dir=str(run.run_dir), contract_sha256='a'*64)
        root = runner.launch_path.parent
        folder = root / run.run_id; folder.mkdir(mode=0o700)
        path = folder / 'launch.json'; path.write_bytes(canonical(packet)); path.chmod(0o400)
        runner.launch_path = path; runner.template_path = root / 'template.json'
        runner._require_original_owner = True  # noqa: SLF001 - sealed role admission substituted
        engine.packet = packet; engine.record_path = runner.receipt_path()
        run.run_dir.mkdir(parents=True)
        run.manifest.path.write_text(json.dumps({'run_id':run.run_id, 'run_dir':str(run.run_dir),
            'session_name':run.identity.session_name, 'started_at':run.started_at, 'worktree':str(run.worktree_path),
            'agent_label':session.agent_label}))
        (run.run_dir / 'session-identity.json').write_text(json.dumps({'session_name':session.terminal_id,
            'issue_number':42, 'worktree':str(run.worktree_path), 'branch':session.branch_name,
            'agent':session.agent_label, 'session_key':session.key.stable_id(), 'task':session.key.kind.value}))
        monkeypatch.setattr('issue_orchestrator.execution.terminal_docker.model_projection_snapshot',
            lambda packet: ({}, {'role':'standard-implementation'}, {}))
        monkeypatch.setattr('issue_orchestrator.execution.terminal_docker._authority_environment', lambda packet: {'admitted':'fixture'})
        assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
        assert engine.starts == 0
        backend = DockerOriginalCustody(runner)
        owner.docker_custody = backend
        owner.quiescent = lambda original, offline: backend.quiescent(original, offline=offline)
        owner.verify_contract = backend.verify_contract
        owner.verify_session = backend.verify_session
        owner.termination_scope = backend.termination_scope
        before = claims.original_claim(42)[1]
        fence = owner.register_prestart(session)
        assert fence != before and claims.original_claim(42)[0].original is not None
        monkeypatch.setattr('issue_orchestrator.execution.terminal_docker.time.time_ns', lambda:packet['deadline_unix_ns'] + 1)
        with pytest.raises(ValueError, match='deadline'):
            runner.activate_session(run, session.terminal_id, fence)
        assert engine.starts == 0
        from unittest.mock import Mock
        manager = SessionManager(runner, Mock(), owner.config)
        core = CoreIssueRuntimeOwners(manager, owner.state.active_sessions, None, None, Mock(), Mock(), claims)
        owners = SimpleNamespace(core=core)
        owner.terminate = lambda issue: terminate_every_session(owners, issue, 'fixture-cancel',
            capture=lambda:ValidatedWorkDispositionBatch.no_work(issue, 'fixture-cancel'), observe=lambda _:None)
        command = OriginalDeliveryCommand('cancel', lease_id, fence, packet['contract_sha256'], run.run_id, 'cancel-fixture')
        released = owner.execute(42, command)
        assert owner.state.active_sessions == [] and not engine.running
        assert released['owner']['cancelled'] and released['remote_released']
        class Api:
            async def original_delivery(self, issue_number, operation, payload): return owner.observe(issue_number)
        public = asyncio.run(original_delivery_result(Api(), Path('/unused'), 42, 'observe', None, running=True))
        assert not public.isError and public.structuredContent['never_started']['provider_exec_id'] == '3'*64
        assert public.structuredContent['never_started']['stop_wait'] == 'completed'
        if missing_after_stop:
            assert public.structuredContent['never_started']['after'] == {'kind':'exact-exec-not-found','status':404}
        if builder_source := os.environ.get('BUILDER_CHILD_PRODUCER_SOURCE'):
            from unittest.mock import patch
            monkeypatch.syspath_prepend(str(Path(builder_source) / 'tools/orchestration'))
            import qualification_runner as builder
            observed = public.structuredContent
            public_owner = observed['owner']
            contract = {'repository':{'name':public_owner['repository']}, 'issue':{'number':42},
                'branch':{'name':public_owner['branch']}, 'execution':{'backend':'docker',
                    'workspace':public_owner['worktree'], 'agent_label':public_owner['agent'],
                    'logical_child':public_owner['logical_child'], 'session_name':public_owner['session_name'],
                    'docker_launch':{'template_path':str(runner.template_path)}},
                'supervised':{'correction':{'budget':{'max_rework_cycles':public_owner['max_cycles']}}}}
            row = {**public_owner['docker_custody'][0], 'contract_sha256':packet['contract_sha256']}
            independent_fence = claims.original_claim(42)[1]
            observation = {'original_delivery':observed, 'claim_ref_sha':independent_fence,
                'status':{'active_sessions':[]}, 'supervisor':{'state':'running'}}
            authority = SimpleNamespace(document={'subject':{'run':'fixture'},'worker':{'image_id':packet['image_id']}},
                engine_digest=packet['contract_sha256'], engine_contract=contract)
            result = {'released':True, 'receipts':[row], 'owner':public_owner, 'outer_sha256':'fixture',
                'engine_sha256':packet['contract_sha256'], 'observation':observation}
            lifecycle = Mock(); lifecycle.observe.return_value = result
            supervisor = Mock(); supervisor.drain.return_value = {'status':'drained'}; supervisor.stop.return_value = {'stopped':True}
            class BuilderDocker:
                def request(self, method, route):
                    value = engine.request(method, route)
                    if route == '/containers/' + row['container_id'] + '/json':
                        value['State'].update(Pid=0, Status='exited', OOMKilled=False, Error='')
                        value['RestartCount'] = 0
                    return value
                def inspect_exec(self, exec_id): return engine.inspect_exec(exec_id)
            with patch.object(builder, 'read_authority', return_value=authority), \
                    patch.object(builder, 'DockerControllerLifecycle', return_value=lifecycle), \
                    patch.object(builder, 'engine_stop_proof', return_value={'pid':42}):
                evidence = builder.verify_original_release(supervisor, 'repo', {}, 'path', 'sha',
                    authority.document['subject'], [row], BuilderDocker(), lambda event:None)
            assert evidence['containers'][0]['never_started'] == observed['never_started']
    finally:
        if http is not None: http.close()
        if fixture is not None: fixture.doCleanups()


def test_start_ack_serializes_with_cancel_without_locking_output_stream(launch, monkeypatch):
    from types import SimpleNamespace
    from tests.unit.threading_helpers import wait_for_event
    runner, engine, packet, _ = launch
    runner._require_original_owner = True  # noqa: SLF001 - admitted role substituted
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    monkeypatch.setattr('issue_orchestrator.execution.terminal_docker._authority_environment', lambda _: {'admitted':'fixture'})
    entered, acknowledge, reading, finish, cancel_entered = (threading.Event() for _ in range(5))
    operations = []
    class Stream:
        def consume(self, consume):
            reading.set()
            wait_for_event(finish, 5, label='stream finish')
        def close(self): pass
    def open_exec(exec_id, timeout):
        operations.append('post'); entered.set()
        wait_for_event(acknowledge, 5, label='start acknowledgement')
        operations.append('ack')
        return Stream()
    def stop(container_id):
        operations.append('stop'); engine.running = False
    monkeypatch.setattr(engine, 'open_exec', open_exec)
    monkeypatch.setattr(engine, 'stop', stop)
    failures = []
    def activate():
        try: runner.activate_session(SimpleNamespace(run_id=packet['run_id']), 'issue-42', 'a'*40)
        except Exception as error: failures.append(error)
    def cancel():
        cancel_entered.set()
        try: runner.kill_session(42, 'issue-42')
        except Exception as error: failures.append(error)
    starter = threading.Thread(target=activate); starter.start()
    wait_for_event(entered, 5, label='start POST')
    canceller = threading.Thread(target=cancel); canceller.start()
    wait_for_event(cancel_entered, 5, label='cancellation requested')
    acknowledge.set()
    starter.join(5); canceller.join(5)
    assert not starter.is_alive() and not canceller.is_alive() and not failures
    wait_for_event(reading, 5, label='provider stream')
    assert operations[:3] == ['post', 'ack', 'stop']
    assert json.loads(runner.receipt_path().read_bytes())['start_intent'] == 'requested'
    finish.set()
    runner.on_orchestrator_shutdown()


def test_start_intent_record_failure_never_posts_and_still_stops(launch, monkeypatch):
    from types import SimpleNamespace
    runner, engine, packet, _ = launch
    runner._require_original_owner = True  # noqa: SLF001 - admitted role substituted
    assert runner.create_session(42, 'echo safe', packet['working_dir'], None, 'issue-42', None)
    monkeypatch.setattr('issue_orchestrator.execution.terminal_docker._authority_environment', lambda _: {'admitted':'fixture'})
    save = runner._save  # noqa: SLF001
    def fail_intent():
        if runner._record.get('start_intent') == 'requested':  # noqa: SLF001
            raise OSError('synthetic recorder failure')
        save()
    monkeypatch.setattr(runner, '_save', fail_intent)
    with pytest.raises(RuntimeError, match='start intent'):
        runner.activate_session(SimpleNamespace(run_id=packet['run_id']), 'issue-42', 'a'*40)
    with pytest.raises(OSError): runner.kill_session(42, 'issue-42')
    assert engine.starts == 0 and not engine.running
    assert 'never_started' not in json.loads(runner.receipt_path().read_bytes())


def test_exec_start_ack_past_original_deadline_is_unknown(monkeypatch):
    from issue_orchestrator.execution.docker_engine import DockerEngine
    class Sock:
        def settimeout(self, timeout): pass
    class Connection:
        closed = False
        def __init__(self, path, timeout): self.sock = Sock()
        def request(self, *args, **kwargs): pass
        def getresponse(self): return type('Response', (), {'status':200})()
        def close(self): self.closed = True
    class Timer:
        def __init__(self, limit, callback): self.daemon = False
        def start(self): pass
        def cancel(self): pass
    times = iter((100.0, 106.0))
    monkeypatch.setattr('issue_orchestrator.execution.docker_engine._UnixConnection', Connection)
    monkeypatch.setattr('issue_orchestrator.execution.docker_engine.threading.Timer', Timer)
    monkeypatch.setattr('issue_orchestrator.execution.docker_engine.time.monotonic', lambda:next(times))
    with pytest.raises(TimeoutError): DockerEngine().open_exec('a'*64, 5)


@pytest.mark.parametrize(('status', 'accepted'), [(200, True), (404, True), (500, False)])
def test_exact_exec_inspection_preserves_only_expected_http_status(monkeypatch, status, accepted):
    from issue_orchestrator.execution.docker_engine import DockerEngine
    if status == 404 and (source := os.environ.get('DOCKER_POSTSTOP_FAILURE_FIXTURE')):
        raw = Path(source).read_bytes()
        assert sha256(raw).hexdigest() == 'a4d1473bcf435f6fd95165fb059a43219a39372acbc9f44b14ea21642ded2180'
        # Substitute only the captured HTTP status; the receipt is not an API response.
        assert json.loads(raw)['http_status'] == status
    class Response:
        def __init__(self): self.status = status
        def read(self, count): return b'{"ID":"' + b'a'*64 + b'"}'
    class Connection:
        def __init__(self, path, timeout): pass
        def request(self, method, route, **kwargs):
            assert method == 'GET' and route == '/v1.45/exec/' + 'a'*64 + '/json'
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr('issue_orchestrator.execution.docker_engine._UnixConnection', Connection)
    if not accepted:
        with pytest.raises(ValueError): DockerEngine().inspect_exec('a'*64)
    else:
        result = DockerEngine().inspect_exec('a'*64)
        assert result == ({'status':404} if status == 404 else {'status':200,'value':{'ID':'a'*64}})
    with pytest.raises(ValueError): DockerEngine().inspect_exec('../foreign')


def test_legacy_poststop_failure_is_not_a_typed_exec_inspection():
    from issue_orchestrator.execution.docker_never_started import after_stop
    legacy = {'exception_type':'ValueError', 'http_status':404, 'phase':'inspect', 'reason':'other', 'result':'NONPASS'}
    if source := os.environ.get('DOCKER_POSTSTOP_FAILURE_FIXTURE'):
        raw = Path(source).read_bytes()
        assert sha256(raw).hexdigest() == 'a4d1473bcf435f6fd95165fb059a43219a39372acbc9f44b14ea21642ded2180'
        legacy = json.loads(raw)
    record = {'daemon_id':'daemon', 'container_id':'b'*64, 'provider_exec_id':'c'*64, 'launch_sha256':'d'*64}
    class Daemon:
        def request(self, method, route):
            if route == '/info': return {'ID':'daemon'}
            return {'Id':record['container_id'], 'State':{'Running':False},
                'Config':{'Labels':{'io.builder.launch':record['launch_sha256']}}}
        def inspect_exec(self, exec_id): return legacy
    with pytest.raises(ValueError): after_stop(Daemon(), None, record)


def test_retained_poststop_preobservation_matches_exact_exec_validator():
    from issue_orchestrator.execution.docker_worker_state import require_never_started_exec
    observed = {'ContainerID':'d9225630ffe45009b2059869c7897472a4f96269abed5f3d361227a22aa3dca8',
        'ExitCode':None, 'ID':'276cb6e1ad7e17b73b4bddf474ed26fb1fc5ee639eb4357cc493e37af14bb6eb',
        'Pid':0, 'ProcessConfig':{'arguments':['-I','-B','-c','pass'], 'entrypoint':'/usr/bin/python3',
            'privileged':False, 'tty':False, 'user':'1000:1000'}, 'Running':False}
    if source := os.environ.get('DOCKER_POSTSTOP_PRE_FIXTURE'):
        raw = Path(source).read_bytes()
        assert sha256(raw).hexdigest() == 'f739c54048df02e09109cfdf3979cfd852fb5480e297476201f3fba7fbda9113'
        observed = json.loads(raw)
    require_never_started_exec(observed, observed['ContainerID'], observed['ID'], '1000:1000',
        ['/usr/bin/python3','-I','-B','-c','pass'])
