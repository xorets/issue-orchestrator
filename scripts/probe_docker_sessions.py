#!/usr/bin/env python3
"""Explicit cached-image, network-none non-model Docker transport primitive.

No image pull, model command, real dispatch, public network or deployment.
An ephemeral read-only workspace and bounded tmpfs are the only worker mounts.
Full raw evidence stays in the requested private evidence directory. This is
not integrated all-writer quota/network/agent acceptance.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time

repository = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repository / "src"))
from issue_orchestrator.execution.terminal_docker import DockerPlugin, canonical
from issue_orchestrator.execution.docker_engine import DockerEngine


def docker_cli(*args):
    """Every fixture Docker operation uses the same explicit local daemon."""
    return subprocess.check_output(
        ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args],
        timeout=15,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "DOCKER_CONFIG": "/nonexistent",
        },
    ).strip()


def validate_image(image):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        raise ValueError(
            "Non-model probe requires an immutable repository@sha256 image"
        )


def main():  # noqa: C901, PLR0912 - One bounded disposable lifecycle with unconditional cleanup.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tools",
        required=True,
        type=Path,
        help="Pinned Node/CLI paths and tool_files SHA256 mapping",
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Already cached immutable repository@sha256 reference",
    )
    parser.add_argument("--evidence-root", required=True, type=Path)
    args = parser.parse_args()
    validate_image(args.image)
    if subprocess.check_output(
        ["git", "-C", str(repository), "status", "--porcelain"], text=True
    ).strip():
        raise ValueError("Commit the candidate before collecting exact-source evidence")
    root = Path(
        tempfile.mkdtemp(prefix="builder27-transport-", dir=args.evidence_root)
    ).resolve()
    os.chmod(root, 0o755)
    control = root / "control"
    control.mkdir(mode=0o700)
    output = root / "output"
    output.mkdir(mode=0o700)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o755)
    image = args.image

    def checksum(p):
        with Path(p).open("rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()

    engine = DockerEngine()
    controller = None
    runner = None
    known = []
    result = {
        "source_commit": subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip(),
        "source_tree": subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], text=True
        ).strip(),
        "scope": "NON-MODEL TRANSPORT PRIMITIVE ONLY; NOT ADMISSION",
        "root": str(root),
    }
    try:
        info = engine.request("GET", "/info")
        img = engine.request("GET", "/images/" + image + "/json")
        controller = docker_cli(
            "run",
            "--pull=never",
            "-d",
            "--name",
            "builder27-controller-" + root.name,
            "--read-only",
            "--network",
            "none",
            "--memory",
            "32m",
            "--memory-swap",
            "32m",
            "--cpus",
            "1",
            "--pids-limit",
            "16",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "1000:1000",
            "--log-driver",
            "none",
            image,
            "/bin/sleep",
            "110",
        )
        known.append(controller)
        tools = json.loads(args.tools.read_bytes())
        for path, expected in tools["tool_files"].items():
            if checksum(path) != expected:
                raise ValueError("Tool closure changed")
        result["tool_material"] = {
            key: checksum(tools[key]) for key in ("node", "devcontainer_cli")
        }
        result["tool_material"]["tools_manifest_sha256"] = checksum(args.tools)
        result["tool_material"]["closure_sha256"] = hashlib.sha256(
            canonical(tools["tool_files"])
        ).hexdigest()
        result["image"] = image
        result["image_id"] = img["Id"]
        command = "printf 'builder27-canary\\n'; /bin/sh -c 'sleep 60 &'"
        packet = {
            "schema_version": 1,
            "repository": "local/nonmodel",
            "builder_run_id": "run-" + "a" * 32,
            "run_id": "20261017-120000Z-" + "b" * 32,
            "engine_run_dir": str(workspace / "run-assets"),
            "output_root": str(output),
            "session_name": "issue-27",
            "working_dir": str(workspace),
            "daemon_id": info["ID"],
            "controller_container_id": controller,
            "container_name": "builder27-worker-" + root.name,
            "contract_sha256": "1" * 64,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "image": image,
            "image_id": img["Id"],
            "network_id": "none",
            "deadline_unix_ns": time.time_ns() + 60_000_000_000,
            "limits": {
                "memory_bytes": 67108864,
                "swap_bytes": 67108864,
                "cpu_nano": 1000000000,
                "pids": 32,
                "max_output_bytes": 65536,
            },
            "user": "1000:1000",
            "read_only": True,
            "tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=4194304",
                "/run": "rw,noexec,nosuid,nodev,size=1048576",
                "/dev/shm": "rw,noexec,nosuid,nodev,size=1048576",
            },
            "mounts": [
                {"source": str(workspace), "target": str(workspace), "read_only": True}
            ],
            "hooks": {},
            "storage_policy_sha256": "2" * 64,
            "network_policy_sha256": "3" * 64,
            "devcontainer_config": str(control / "devcontainer.json"),
            "devcontainer_config_sha256": "4" * 64,
            "node": tools["node"],
            "node_sha256": checksum(tools["node"]),
            "devcontainer_cli": tools["devcontainer_cli"],
            "devcontainer_cli_sha256": checksum(tools["devcontainer_cli"]),
            "docker_cli": "/usr/bin/docker",
            "docker_cli_sha256": checksum("/usr/bin/docker"),
            "tool_files": tools["tool_files"],
        }
        args = [
            "--name",
            packet["container_name"],
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--log-driver=none",
            "--network",
            "none",
            "--memory",
            "67108864",
            "--memory-swap",
            "67108864",
            "--pids-limit",
            "32",
            "--cpus",
            "1.0",
        ]
        for target, options in sorted(packet["tmpfs"].items()):
            args += ["--tmpfs", target + ":" + options]
        config = {
            "image": image,
            "workspaceFolder": str(workspace),
            "containerUser": "1000:1000",
            "remoteUser": "1000:1000",
            "updateRemoteUserUID": False,
            "overrideCommand": True,
            "workspaceMount": "type=bind,source="
            + str(workspace)
            + ",target="
            + str(workspace)
            + ",readonly",
            "runArgs": args,
        }
        p = control / "devcontainer.json"
        p.write_bytes(canonical(config))
        p.chmod(0o400)
        packet["devcontainer_config_sha256"] = checksum(p)
        launch = control / "launch.json"
        launch.write_bytes(canonical(packet))
        launch.chmod(0o400)
        runner = DockerPlugin(launch_path=launch, engine=engine)
        result["created"] = runner.create_session(
            27, command, str(workspace), None, "issue-27", secret_env=None,
        )
        if result["created"]:
            import threading

            end = time.monotonic() + 65
            while time.monotonic() < end:
                current = json.loads(runner.receipt_path().read_bytes())
                if current.get("state") in {"stopped", "retained"}:
                    break
                threading.Event().wait(0.05)
            runner.on_orchestrator_shutdown()
        record = json.loads(runner.receipt_path().read_bytes())
        result["technical_report"] = record
        if record.get("container_id"):
            known.append(record["container_id"])
        result["output"] = runner.get_session_output(27, 10, "issue-27")
        result["primitive_pass"] = (
            record.get("state") == "stopped"
            and record.get("provider_exit_code") == 0
            and result["output"] == "builder27-canary"
        )
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)
    finally:
        cleanup = []
        if runner is not None:
            try:
                retained = json.loads(runner.receipt_path().read_bytes())
                if (
                    retained.get("container_id")
                    and retained["container_id"] not in known
                ):
                    known.append(retained["container_id"])
            except (OSError, ValueError):
                pass
        for cid in known:
            try:
                docker_cli("rm", "-f", cid)
            except Exception as exc:
                cleanup.append({"id": cid, "removed": False})
                continue
            try:
                engine.request("GET", "/containers/" + cid + "/json")
                absent = False
            except ValueError as exc:
                absent = str(exc).endswith("HTTP 404")
            cleanup.append({"id": cid, "removed": absent})
        result["cleanup"] = cleanup
        result["primitive_pass"] = result.get("primitive_pass", False) and all(
            item["removed"] for item in cleanup
        )
        result["evidence_allocation_bytes"] = sum(
            p.stat().st_size for p in root.rglob("*") if p.is_file()
        )
        result["artifact_sha256"] = {
            str(p.relative_to(root)): checksum(p)
            for p in root.rglob("*")
            if p.is_file()
        }
        (root / "result.json").write_bytes(canonical(result))
        print(
            json.dumps(
                {
                    "evidence_root": str(root),
                    "primitive_pass": result.get("primitive_pass", False),
                    "cleanup": cleanup,
                    "result_sha256": checksum(root / "result.json"),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
