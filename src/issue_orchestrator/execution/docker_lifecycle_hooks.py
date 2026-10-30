"""Run the admitted bounded Docker lifecycle phases."""
import threading
import time
import re

from .docker_launch_input import hook_argv


def run_hooks(engine, packet, record, output_directory, save, consume_output, deadline_stop):
    hooks = packet.get("hooks", {})
    phases = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand")
    if type(hooks) is not dict or set(hooks) - set(phases):
        raise ValueError("Unsupported Docker lifecycle phase")
    if not hooks:
        return
    output = output_directory / "docker-hook-output.log"
    with output.open("xb") as destination:
        for phase in phases:
            if phase not in hooks:
                continue
            argv = hook_argv(hooks[phase])
            payload = {"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False,
                "User": packet["user"], "WorkingDir": packet["working_dir"], "Cmd": argv, "Env": []}
            exec_id = engine.request("POST", f"/containers/{record['container_id']}/exec", payload)["Id"]
            if not re.fullmatch(r"[0-9a-f]{64}", exec_id):
                raise ValueError("Docker lifecycle exec identity is invalid")
            row = {"phase": phase, "exec_id": exec_id, "exit_code": None}
            record["hook_execs"].append(row)
            save()
            def consume(chunk: bytes) -> None:
                consume_output(packet, record, destination, chunk)
            remaining = (packet["deadline_unix_ns"] - time.time_ns()) / 1e9
            if remaining <= 0:
                raise ValueError("Docker lifecycle deadline exhausted")
            timer = threading.Timer(remaining, deadline_stop)
            timer.daemon = True
            timer.start()
            try:
                engine.start_exec(exec_id, consume, remaining)
            finally:
                timer.cancel()
            observed = engine.request("GET", f"/exec/{exec_id}/json")
            if observed.get("ContainerID") != record["container_id"] or observed.get("Running") is not False or observed.get("ExitCode") != 0:
                raise ValueError("Docker lifecycle failed or did not settle")
            row["exit_code"] = 0
            save()

