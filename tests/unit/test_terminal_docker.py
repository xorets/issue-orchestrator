"""The SessionRunner boundary refuses unsealed or repeated Docker launches."""
from hashlib import sha256
import json
import os
from pathlib import Path
import pytest
import time
import copy

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
        if route == "/containers/" + self.packet["container_name"] + "/json":
            raise ValueError("reserved container has not been created")
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
        engine.starts += 1
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
        engine.starts += 1
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


def test_finished_watcher_cannot_protect_a_running_worker(launch):
    plugin, engine, packet, calls = launch
    assert plugin.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
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
    assert runner.create_session(42, "echo safe", packet["working_dir"], None, "issue-42", secret_env=None)
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
    with pytest.raises(FileExistsError):
        runner.seal_first_model(run, receipt)
    with pytest.raises(ValueError, match='metadata bound'):
        runner.seal_first_model(run, {**receipt, 'oversized':'x'*1024})
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
