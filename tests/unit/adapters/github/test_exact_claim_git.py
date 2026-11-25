"""Exercise the exact ref update with real Git and a disposable remote."""

from __future__ import annotations

import errno
import fcntl
import os
import signal
import subprocess
import sys
import traceback
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from unittest.mock import Mock

import pytest

from issue_orchestrator.adapters.github import exact_claim_git, http_client
from issue_orchestrator.adapters.github.auth import GitHubAuth
from issue_orchestrator.adapters.github.errors import GitHubAuthError
from issue_orchestrator.adapters.github.exact_claim_git import ExactClaimGitError, append_claim_record
from issue_orchestrator.adapters.github.http_client import GitHubHttpClient, GitHubHttpConfig
from issue_orchestrator.adapters.github.tokens import StaticGitHubTokenProvider

REF = "refs/issue-orchestrator/claims/issue-42"
NEXT_RECORD = "updated claim record"
MESSAGE = "Update claim\n\nio-record-format: tree-blob-v1"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@dataclass(frozen=True)
class Remote:
    path: Path
    original: str
    ancestor: str

    @property
    def env(self) -> dict[str, str]:
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "remote.origin.url",
            "GIT_CONFIG_VALUE_0": str(self.path),
        }


@pytest.fixture
def remote(tmp_path: Path) -> Remote:
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        pytest.skip("The exact claim Git transport requires Linux pidfd support")
    worktree = tmp_path / "seed"
    worktree.mkdir()
    git(worktree, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    git(worktree, "config", "user.name", "Test")
    git(worktree, "config", "user.email", "test@example.invalid")
    (worktree / "record.json").write_text("ancestor", encoding="utf-8")
    git(worktree, "add", "record.json")
    git(worktree, "commit", "--quiet", "-m", "ancestor")
    ancestor = git(worktree, "rev-parse", "HEAD")
    (worktree / "record.json").write_text("original claim", encoding="utf-8")
    git(worktree, "commit", "--quiet", "-am", "original")
    original = git(worktree, "rev-parse", "HEAD")
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--quiet", "--bare", str(worktree), str(bare)], check=True)
    git(bare, "update-ref", REF, original)
    return Remote(bare, original, ancestor)


def append(remote: Remote) -> bool:
    return append_claim_record(remote.env, ref=REF, predecessor=remote.original,
                               record=NEXT_RECORD.encode(), message=MESSAGE)


def test_appends_only_one_direct_child_with_existing_record_format(remote: Remote) -> None:
    assert append(remote) is True
    successor = git(remote.path, "rev-parse", REF)
    assert git(remote.path, "show", "-s", "--format=%P", successor) == remote.original
    assert git(remote.path, "show", "-s", "--format=%B", successor) == MESSAGE
    assert git(remote.path, "show", f"{successor}:record.json") == NEXT_RECORD


@pytest.mark.parametrize("before", ["moved", "absent"])
def test_refuses_nonmatching_ref_without_remote_write(remote: Remote, before: str) -> None:
    if before == "moved":
        git(remote.path, "update-ref", REF, remote.ancestor)
    else:
        git(remote.path, "update-ref", "-d", REF)
    refs = git(remote.path, "show-ref")

    assert append(remote) is False
    assert git(remote.path, "show-ref") == refs


def test_server_compares_exact_old_ref_after_it_advertises_it(remote: Remote) -> None:
    # The received commit descends from the ancestor too. A fast-forward-only
    # check could accept the write if the ref moves back to that ancestor.
    hook = remote.path / "hooks/pre-receive"
    hook.write_text(
        "#!/bin/sh\n"
        "unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n"
        f"git update-ref {REF} {remote.ancestor} {remote.original}\n",
        encoding="utf-8",
    )
    os.chmod(hook, 0o700)

    with pytest.raises(ExactClaimGitError, match=r"Git push failed .*exit-status.*ref update unconfirmed") as raised:
        append(remote)
    assert raised.value.exit_status == 1
    assert raised.value.uncertain_update
    assert git(remote.path, "rev-parse", REF) == remote.ancestor


def test_timed_out_push_reaps_its_transport_and_leaves_ref_unchanged(remote: Remote, tmp_path: Path) -> None:
    lock, marker, fifo = (tmp_path / leaf for leaf in ("lock", "started", "wait"))
    os.mkfifo(fifo)
    helper = tmp_path / "hold-receive-pack"
    helper.write_text(
        "#!/usr/bin/python3\n"
        "import fcntl, os\n"
        "from pathlib import Path\n"
        f"with open({str(lock)!r}, 'wb') as held:\n"
        "    fcntl.flock(held, fcntl.LOCK_EX)\n"
        f"    Path({str(marker)!r}).touch()\n"
        f"    os.open({str(fifo)!r}, os.O_RDONLY)\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    env = {**remote.env, "GIT_CONFIG_COUNT": "2",
           "GIT_CONFIG_KEY_1": "remote.origin.receivepack", "GIT_CONFIG_VALUE_1": str(helper)}

    with pytest.raises(ExactClaimGitError, match=r"Git push failed .*timeout.*ref update unconfirmed") as raised:
        append_claim_record(env, ref=REF, predecessor=remote.original,
                            record=NEXT_RECORD.encode(), message=MESSAGE, timeout_seconds=2)

    assert raised.value.timed_out
    assert raised.value.elapsed_ms >= 2000
    assert marker.is_file()
    with lock.open("rb") as released:
        fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert git(remote.path, "rev-parse", REF) == remote.original


def test_engine_group_sigkill_stops_blocked_git_transport(remote: Remote, tmp_path: Path) -> None:
    lock, marker, unblock, late = (tmp_path / name for name in ("lock", "started", "unblock", "late"))
    helper = tmp_path / "hold-receive-pack"
    helper.write_text(
        "#!/usr/bin/python3\n"
        "import fcntl, time\n"
        "from pathlib import Path\n"
        f"with Path({str(lock)!r}).open('wb') as held:\n"
        "    fcntl.flock(held, fcntl.LOCK_EX)\n"
        f"    Path({str(marker)!r}).touch()\n"
        f"    while not Path({str(unblock)!r}).exists(): time.sleep(0.01)\n"
        f"    Path({str(late)!r}).touch()\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    env = {**remote.env, "GIT_CONFIG_COUNT": "2",
           "GIT_CONFIG_KEY_1": "remote.origin.receivepack", "GIT_CONFIG_VALUE_1": str(helper)}
    command = ("from issue_orchestrator.adapters.github.exact_claim_git import append_claim_record\n"
               f"append_claim_record({env!r}, ref={REF!r}, predecessor={remote.original!r}, "
               f"record={NEXT_RECORD.encode()!r}, message={MESSAGE!r}, timeout_seconds=30)")
    with subprocess.Popen([sys.executable, "-c", command], start_new_session=True) as engine:
        try:
            deadline = monotonic() + 10
            while not marker.is_file() and monotonic() < deadline:
                sleep(0.01)
            assert marker.is_file()
            os.killpg(engine.pid, signal.SIGKILL)
            assert engine.wait(timeout=5) == -signal.SIGKILL

            deadline = monotonic() + 5
            with lock.open("rb") as released:
                while True:
                    try:
                        fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        assert monotonic() < deadline, "orphan Git helper retained the lock"
                        sleep(0.01)
                unblock.touch()
        finally:
            if engine.poll() is None:
                os.killpg(engine.pid, signal.SIGKILL)
            unblock.touch()
    assert not late.exists()
    assert git(remote.path, "rev-parse", REF) == remote.original


def _wait_for_file(path: Path) -> None:
    deadline = monotonic() + 10
    while not path.is_file():
        assert monotonic() < deadline, f"fixture did not produce {path.name}"
        sleep(0.01)


def test_sigint_awaits_witness_before_removing_git_workspace(remote: Remote, tmp_path: Path) -> None:
    marker, lock, interrupt_done = (tmp_path / name for name in ("witness", "lock", "interrupted"))
    fifo = tmp_path / "wait"
    late = tmp_path / "late"
    os.mkfifo(fifo)
    helper = tmp_path / "hold-receive-pack"
    helper.write_text(
        "#!/usr/bin/python3\n"
        "import fcntl, os\n"
        "from pathlib import Path\n"
        f"with Path({str(lock)!r}).open('wb') as held:\n"
        "    fcntl.flock(held, fcntl.LOCK_EX)\n"
        f"    marker = Path({str(marker)!r})\n"
        "    pending = marker.with_suffix('.tmp')\n"
        "    pending.write_text(str(os.getsid(0)))\n"
        "    pending.replace(marker)\n"
        f"    os.open({str(fifo)!r}, os.O_RDONLY)\n"
        f"    Path({str(late)!r}).touch()\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    env = {**remote.env, "GIT_CONFIG_COUNT": "2",
           "GIT_CONFIG_KEY_1": "remote.origin.receivepack", "GIT_CONFIG_VALUE_1": str(helper)}
    command = ("from pathlib import Path\n"
               "from issue_orchestrator.adapters.github.exact_claim_git import append_claim_record\n"
               "try:\n"
               f"    append_claim_record({env!r}, ref={REF!r}, predecessor={remote.original!r}, "
               f"record={NEXT_RECORD.encode()!r}, message={MESSAGE!r}, timeout_seconds=30)\n"
               "except KeyboardInterrupt:\n"
               f"    Path({str(interrupt_done)!r}).touch()\n")
    engine_env = {**os.environ, "TMPDIR": str(tmp_path)}
    with subprocess.Popen([sys.executable, "-c", command], env=engine_env, start_new_session=True) as engine:
        try:
            _wait_for_file(marker)
            witness = int(marker.read_text())
            (repo,) = tmp_path.glob("io-expected-claim-*")
            os.kill(witness, signal.SIGSTOP)
            try:
                os.kill(engine.pid, signal.SIGINT)
                sleep(0.6)
                assert engine.poll() is None and not interrupt_done.exists()
                assert repo.is_dir()
            finally:
                os.kill(witness, signal.SIGCONT)
            assert engine.wait(timeout=5) == 0
        finally:
            if engine.poll() is None:
                os.killpg(engine.pid, signal.SIGKILL)

    assert interrupt_done.is_file() and not repo.exists()
    with lock.open("rb") as released:
        fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with pytest.raises(OSError) as no_reader:
        with os.fdopen(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK), "wb"):
            pytest.fail("Git helper survived to accept the late write trigger")
    assert no_reader.value.errno == errno.ENXIO and not late.exists()
    assert git(remote.path, "rev-parse", REF) == remote.original


@pytest.mark.parametrize(("operation", "cause"), [("fetch", "os-error"), ("push", "missing-acknowledgement")])
def test_failed_phase_excludes_raw_subprocess_details(remote: Remote, monkeypatch, operation: str, cause: str) -> None:
    run_git = exact_claim_git._run_git  # noqa: SLF001
    private_detail = "private-subprocess-detail"

    def inject_failure(argv, **kwargs):
        if argv[5] != operation:
            return run_git(argv, **kwargs)
        if operation == "fetch":
            raise OSError(private_detail)
        return 0, private_detail.encode()

    monkeypatch.setattr(exact_claim_git, "_run_git", inject_failure)

    with pytest.raises(ExactClaimGitError, match=f"Git {operation} failed") as raised:
        append(remote)

    error = raised.value
    assert error.cause == cause
    assert error.exit_status == (0 if operation == "push" else None)
    assert error.uncertain_update == (operation == "push")
    assert private_detail not in "".join(traceback.format_exception(error))
    assert git(remote.path, "rev-parse", REF) == remote.original


def test_cleanup_failure_preserves_primary_push_timeout(remote: Remote, tmp_path: Path, monkeypatch) -> None:
    run_git = exact_claim_git._run_git  # noqa: SLF001
    private_detail = "private-subprocess-detail"
    local_repo = tmp_path / "private-repo"
    local_repo.mkdir()

    class BrokenCleanup:
        name = str(local_repo)

        def cleanup(self):
            raise OSError("private-filesystem-detail")

    def inject_timeout(argv, **kwargs):
        if argv[5] == "push":
            raise subprocess.TimeoutExpired([private_detail], 1, stderr=private_detail.encode())
        return run_git(argv, **kwargs)

    monkeypatch.setattr(exact_claim_git, "TemporaryDirectory", lambda **_kwargs: BrokenCleanup())
    monkeypatch.setattr(exact_claim_git, "_run_git", inject_timeout)
    with pytest.raises(ExactClaimGitError) as raised:
        append(remote)

    error = raised.value
    assert error.phase == "push" and error.timed_out and error.uncertain_update
    assert error.cleanup_elapsed_ms is not None
    rendered = "".join(traceback.format_exception(error))
    assert "Git push failed" in rendered and "Git cleanup failed (OSError" in rendered
    assert private_detail not in rendered and "private-filesystem-detail" not in rendered
    assert git(remote.path, "rev-parse", REF) == remote.original


def test_witness_can_finish_stopping_after_cancel_pipe_failure(remote: Remote, monkeypatch, caplog) -> None:
    original = subprocess.TimeoutExpired(["private-command"], 0.2)
    run_git = exact_claim_git._run_git  # noqa: SLF001
    native_write = os.write

    def timeout(_process, _data, *, timeout):
        raise original

    def fail_cancellation(fd, data):
        if data == b"\0":
            raise OSError("private-stop-error")
        return native_write(fd, data)

    monkeypatch.setattr(subprocess.Popen, "communicate", timeout)
    monkeypatch.setattr(os, "write", fail_cancellation)
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        run_git(["/bin/sh", "-c", "sleep 2"], env={"PATH": os.defpath}, data=b"", timeout=0.2)

    assert raised.value is original
    assert "cancellation pipe failed (OSError)" in caplog.text
    assert "witness-git-deadline" in caplog.text
    assert "private-stop-error" not in caplog.text and "private-command" not in caplog.text


def _delay_witness_stop(tmp_path: Path, monkeypatch, setup: str = "") -> Path:
    stop_ready = tmp_path / "stop-ready"
    real_supervisor = exact_claim_git._SUPERVISOR  # noqa: SLF001
    supervisor = tmp_path / "supervisor-fixture.py"
    supervisor.write_text(
        "import errno, os, runpy, select, sys, time\n"
        "from pathlib import Path\n"
        "killpg = os.killpg\n"
        "limit = time.monotonic() + 5\n"
        f"{setup}"
        "def delayed_stop(pid, signal):\n"
        f"    marker = Path({str(stop_ready)!r})\n"
        "    if not marker.exists():\n"
        "        child = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)\n"
        "        temporary_marker = marker.with_suffix('.tmp')\n"
        "        temporary_marker.write_text(str(child.si_status) if child else 'running')\n"
        "        temporary_marker.replace(marker)\n"
        "    if time.monotonic() < limit and not select.select([int(sys.argv[2])], [], [], 0)[0]:\n"
        "        raise InterruptedError(errno.EINTR, 'private stop detail')\n"
        "    return killpg(pid, signal)\n"
        "os.killpg = delayed_stop\n"
        f"runpy.run_path({str(real_supervisor)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    communicate = subprocess.Popen.communicate

    def communicate_after_stop_begins(process, data, *, timeout):
        _wait_for_file(stop_ready)
        return communicate(process, data, timeout=timeout)

    monkeypatch.setattr(exact_claim_git, "_SUPERVISOR", supervisor)
    monkeypatch.setattr(subprocess.Popen, "communicate", communicate_after_stop_begins)
    return stop_ready


def test_witness_setup_fault_survives_later_deadline_and_stop_retry(remote: Remote, tmp_path: Path, monkeypatch) -> None:
    worker_started, lock = (tmp_path / name for name in ("started", "git-lock"))
    git_dir = tmp_path / "bin"
    git_dir.mkdir()
    git_program = git_dir / "git"
    git_program.write_text(
        "#!/usr/bin/python3\n"
        "import fcntl, time\n"
        "from pathlib import Path\n"
        f"with Path({str(lock)!r}).open('wb') as held:\n"
        "    fcntl.flock(held, fcntl.LOCK_EX)\n"
        f"    Path({str(worker_started)!r}).touch()\n"
        "    time.sleep(10)\n",
        encoding="utf-8",
    )
    git_program.chmod(0o700)
    stop_ready = _delay_witness_stop(
        tmp_path, monkeypatch,
        "def fail_child_watch(pid):\n"
        f"    while not Path({str(worker_started)!r}).is_file() and time.monotonic() < limit: time.sleep(0.01)\n"
        "    raise PermissionError(errno.EPERM, 'private watcher detail')\n"
        "os.pidfd_open = fail_child_watch\n",
    )
    with pytest.raises(ExactClaimGitError) as raised:
        exact_claim_git._checked_git(  # noqa: SLF001
            remote.path, "push", (), env={"PATH": f"{git_dir}:{os.defpath}"},
            data=b"", timeout=0.2, acknowledgement=None,
        )

    error = raised.value
    assert error.phase == "push" and error.cause == "witness-git-watch"
    assert not error.timed_out and error.settlement_timed_out and error.stop_retried
    assert error.uncertain_update and error.exit_status == 128 + signal.SIGKILL
    assert "caller deadline elapsed during settlement" in str(error)
    assert "witness group stop retried" in str(error)
    assert "private watcher detail" not in str(error) and "private stop detail" not in str(error)
    assert stop_ready.read_text() == "running"
    with lock.open("rb") as released:
        fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_git_nonzero_exit_survives_later_deadline_and_stop_retry(remote: Remote, tmp_path: Path, monkeypatch) -> None:
    stop_ready = _delay_witness_stop(tmp_path, monkeypatch)

    with pytest.raises(ExactClaimGitError) as raised:
        exact_claim_git._checked_git(  # noqa: SLF001
            remote.path, "push", ("--synthetic-invalid-option",), env={"PATH": os.defpath},
            data=b"", timeout=0.2, acknowledgement=None,
        )

    error = raised.value
    assert stop_ready.read_text() == "129"
    assert error.phase == "push" and error.cause == "exit-status" and error.exit_status == 129
    assert not error.timed_out and error.settlement_timed_out and error.stop_retried and error.uncertain_update
    assert "caller deadline elapsed during settlement" in str(error)
    assert "witness group stop retried" in str(error)
    assert "synthetic-invalid-option" not in str(error) and "private stop detail" not in str(error)


@pytest.mark.parametrize(("report", "status", "originating_cause"), [
    (b"owner-watch", 125, "witness-owner-watch"),
    (b"owner-ended", 125, None),
    (b"git-spawn", 125, "witness-git-spawn"),
    (b"git-watch|stop-retried", 137, "witness-git-watch"),
    (b"git-deadline|stop-retried", 137, None),
    (b"git-stopped|stop-retried", 137, None),
    (b"git-exited|stop-retried", 129, "exit-status"),
    (b"git-exited|stop-retried", 0, None),
    (b"git-exited", -signal.SIGKILL, None),
    (b"git-exited|malformed", 129, None),
    (b"", 1, None),
    (b"unrecognized", 1, None),
])
@pytest.mark.parametrize("timed_out", [False, True])
def test_settlement_only_promotes_verified_originating_failures(report, status, originating_cause, timed_out) -> None:
    interruption = subprocess.TimeoutExpired("fixture", 1) if timed_out else KeyboardInterrupt()
    witness = Mock()
    witness.wait.return_value = status
    with ExitStack() as descriptors:
        cancel_reader, cancel_writer = os.pipe()
        report_reader, report_writer = os.pipe()
        for fd in (cancel_reader, cancel_writer, report_reader, report_writer):
            descriptors.callback(os.close, fd)
        os.write(report_writer, report)
        if not report:
            # A witness exiting before publishing evidence closes its end.
            os.set_blocking(report_reader, False)

        if timed_out and originating_cause:
            with pytest.raises(exact_claim_git._WitnessFailure) as raised:  # noqa: SLF001
                exact_claim_git._cancel_witness(  # noqa: SLF001
                    witness, cancel_writer, report_reader, interruption=interruption,
                )
            assert raised.value.cause == originating_cause and raised.value.status == status
            assert raised.value.settlement_timed_out
            assert raised.value.stop_retried == report.endswith(b"|stop-retried")
        else:
            exact_claim_git._cancel_witness(  # noqa: SLF001
                witness, cancel_writer, report_reader, interruption=interruption,
            )
        assert os.read(cancel_reader, 1) == b"\0"
    witness.wait.assert_called_once_with()


@pytest.mark.parametrize("api_url", ["https://api.github.com", "https://api.github.com/"])
def test_claim_transport_uses_repo_token_without_changing_ordinary_git_auth(api_url: str) -> None:
    auth = GitHubAuth(token_provider=StaticGitHubTokenProvider("fixture-token"),
                      repo="local/example", source_descriptions=(), api_url=api_url)

    env = auth.exact_claim_git_env()

    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
    assert env["GIT_CONFIG_VALUE_1"] == env["GIT_CONFIG_VALUE_2"] == "https://github.com/local/example.git"
    assert auth.git_env_overrides(remote="origin") is None


@pytest.mark.parametrize("api_url", [
    "https://github.enterprise.example:8443/api/v3", "https://api.github.com:443", "https://api.github.com:bad",
    "https://guest@api.github.com", "https://api.github.com.evil.invalid", "http://api.github.com",
    "https://api.github.com/?not-canonical", "https://api.github.com//", " https://api.github.com",
    "https://[not-an-endpoint", "https://api.github.com/\n",
])
def test_claim_transport_refuses_other_origins_before_resolving_token(api_url: str) -> None:
    token = Mock(spec=StaticGitHubTokenProvider)
    auth = GitHubAuth(token_provider=token, repo="local/example", source_descriptions=(), api_url=api_url)

    with pytest.raises(GitHubAuthError, match="requires the canonical GitHub.com HTTPS API"):
        auth.exact_claim_git_env()

    token.get_token.assert_not_called()


def test_claim_transport_without_owner_lifetime_never_starts_git(remote: Remote, monkeypatch) -> None:
    monkeypatch.delattr(os, "pidfd_open")
    spawn = Mock()
    with monkeypatch.context() as isolated:
        isolated.setattr(exact_claim_git.subprocess, "Popen", spawn)
        with pytest.raises(ExactClaimGitError, match=r"Git init failed .*os-error"):
            append(remote)
        spawn.assert_not_called()


@pytest.mark.parametrize("replace_config_endpoint", [False, True])
def test_http_claim_requires_matching_canonical_rest_endpoint(monkeypatch, replace_config_endpoint: bool) -> None:
    token = Mock(spec=StaticGitHubTokenProvider)
    auth = GitHubAuth(token_provider=token, repo="local/example", source_descriptions=())
    config = GitHubHttpConfig(repo="local/example", auth=auth, base_url="https://enterprise.example:8443/api/v3")
    append_call = Mock()
    monkeypatch.setattr(http_client, "append_claim_record", append_call)
    client = GitHubHttpClient(config)
    try:
        if replace_config_endpoint:
            config.base_url = "https://api.github.com"
        with pytest.raises(GitHubAuthError, match="REST endpoint must be the canonical GitHub.com HTTPS API"):
            client.append_exact_claim(ref=REF, predecessor="a" * 40, record=NEXT_RECORD.encode(), message=MESSAGE)
    finally:
        client.close()

    token.get_token.assert_not_called()
    append_call.assert_not_called()


@pytest.mark.parametrize(("starts", "cause"), [(False, "witness-git-spawn"), (True, "exit-status")])
def test_witness_distinguishes_spawn_failure_from_git_exit(remote, tmp_path, monkeypatch, starts, cause):
    run_git = exact_claim_git._run_git  # noqa: SLF001
    private_detail = "private-witness-detail"

    def inject_command(argv, **kwargs):
        if argv[5] != "push":
            return run_git(argv, **kwargs)
        command = ["/bin/sh", "-c", f"printf {private_detail}; exit 1"] if starts else [str(tmp_path / private_detail)]
        return run_git(command, **kwargs)

    monkeypatch.setattr(exact_claim_git, "_run_git", inject_command)
    with pytest.raises(ExactClaimGitError) as raised:
        append(remote)

    assert raised.value.cause == cause
    assert raised.value.exit_status == (1 if starts else 125)
    assert raised.value.uncertain_update is starts
    assert private_detail not in "".join(traceback.format_exception(raised.value))
    assert git(remote.path, "rev-parse", REF) == remote.original
