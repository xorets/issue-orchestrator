"""Append one claim record using Git's exact-old-ref update."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Literal

from .errors import GitHubTransportError
from .ref_store import RECORD_PATH


_OID = re.compile(r"[0-9a-f]{40}")
_CLAIM_REF = re.compile(r"refs/issue-orchestrator/claims/issue-[1-9][0-9]*")
_SUPERVISOR = Path(__file__).with_name("_exact_claim_git_supervisor.py")
logger = logging.getLogger(__name__)
ClaimGitPhase = Literal[
    "prepare", "init", "ls-remote", "fetch", "rev-parse", "hash-object", "mktree", "commit-tree", "show", "push", "cleanup",
]
ClaimGitFailureCause = Literal[
    "os-error", "timeout", "exit-status", "missing-acknowledgement", "unexpected-parent",
    "witness-owner-watch", "witness-owner-ended", "witness-git-spawn", "witness-git-watch",
    "witness-git-deadline", "witness-status",
]
_WITNESS_FAILURES: dict[bytes, ClaimGitFailureCause] = {
    b"owner-watch": "witness-owner-watch",
    b"owner-ended": "witness-owner-ended",
    b"git-spawn": "witness-git-spawn",
    b"git-watch": "witness-git-watch",
    b"git-deadline": "witness-git-deadline",
}
_ORIGINATING_WITNESS_FAILURES = ("witness-owner-watch", "witness-git-spawn", "witness-git-watch", "exit-status")


class ExactClaimGitError(GitHubTransportError):
    """Retain the safe facts about a failed Git phase, never subprocess output."""

    def __init__(self, phase: ClaimGitPhase, cause: ClaimGitFailureCause, *, elapsed_ms: int,
                 exit_status: int | None = None, settlement_timed_out: bool = False,
                 stop_retried: bool = False) -> None:
        self.phase = phase
        self.cause = cause
        self.elapsed_ms = elapsed_ms
        self.exit_status = exit_status
        self.timed_out = cause in ("timeout", "witness-git-deadline")
        self.settlement_timed_out = settlement_timed_out
        self.stop_retried = stop_retried
        self.uncertain_update = phase == "push" and cause not in (
            "witness-owner-watch", "witness-owner-ended", "witness-git-spawn",
        )
        self.cleanup_elapsed_ms: int | None = None
        details = [f"elapsed_ms={elapsed_ms}"]
        if exit_status is not None:
            details.append(f"exit_status={exit_status}")
        if self.uncertain_update:
            details.append("ref update unconfirmed")
        if settlement_timed_out:
            details.append("caller deadline elapsed during settlement")
        if stop_retried:
            details.append("witness group stop retried")
        super().__init__(f"Exact claim Git {phase} failed ({type(self).__name__}, {cause}, {', '.join(details)})")

    def record_cleanup_failure(self, elapsed_ms: int) -> None:
        self.cleanup_elapsed_ms = elapsed_ms
        self.args = (f"{self} [Exact claim Git cleanup failed (OSError, elapsed_ms={elapsed_ms})]",)


class _WitnessFailure(Exception):
    def __init__(self, cause: ClaimGitFailureCause, status: int, *, stop_retried: bool) -> None:
        self.cause: ClaimGitFailureCause = cause
        self.status = status
        self.stop_retried = stop_retried
        self.settlement_timed_out = False
        super().__init__(cause)


def _verify_witness_report(report_fd: int, status: int, *, interrupted: bool = False) -> None:
    try:
        report = os.read(report_fd, 64)
    except OSError:
        report = b""
    report, separator, secondary = report.partition(b"|")
    stop_retried = secondary == b"stop-retried"
    if separator and not stop_retried:
        report = b""
    if stop_retried:
        logger.warning("Exact claim Git witness retried group stop (OSError)")
    if report == b"git-exited":
        if interrupted and status > 0:
            raise _WitnessFailure("exit-status", status, stop_retried=stop_retried)
    elif not (interrupted and report == b"git-stopped"):
        raise _WitnessFailure(_WITNESS_FAILURES.get(report, "witness-status"), status, stop_retried=stop_retried)


def _cancel_witness(witness: subprocess.Popen[bytes], writer_fd: int, report_fd: int, *,
                    interruption: BaseException) -> None:
    notified = False
    while True:
        try:
            if not notified:
                try:
                    os.write(writer_fd, b"\0")
                except BrokenPipeError:
                    pass
                except OSError:
                    logger.warning("Exact claim Git cancellation pipe failed (OSError)")
                notified = True
            status = witness.wait()
        except KeyboardInterrupt:
            continue
        break
    # Popen's automatic wait is intentionally short on KeyboardInterrupt.
    # The private repo must outlive the witness and its transport group.
    try:
        _verify_witness_report(report_fd, status, interrupted=True)
    except _WitnessFailure as failure:
        if isinstance(interruption, subprocess.TimeoutExpired) and failure.cause in _ORIGINATING_WITNESS_FAILURES:
            # The witness established the failure before stopping the group.
            failure.settlement_timed_out = True
            raise failure from None
        logger.warning("Exact claim Git witness settlement reported %s (exit_status=%d)", failure.cause, failure.status)


def _run_git(argv: list[str], *, env: dict[str, str], data: bytes, timeout: float) -> tuple[int, bytes]:
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        raise OSError("Exact claim Git requires Linux pidfd support")
    with ExitStack() as descriptors:
        owner_fd = os.pidfd_open(os.getpid())
        descriptors.callback(os.close, owner_fd)
        cancel_fd, writer_fd = os.pipe()
        descriptors.callback(os.close, cancel_fd)
        descriptors.callback(os.close, writer_fd)
        report_fd, report_writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        descriptors.callback(os.close, report_fd)
        report_output = descriptors.enter_context(os.fdopen(report_writer, "wb"))
        command = [sys.executable, "-I", "-S", str(_SUPERVISOR), str(owner_fd), str(cancel_fd),
                   str(report_writer), str(timeout), *argv]
        with subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, start_new_session=True,
                              pass_fds=(owner_fd, cancel_fd, report_writer)) as witness:
            try:
                report_output.close()
                stdout, _ = witness.communicate(data, timeout=timeout)
            except BaseException as interruption:
                _cancel_witness(witness, writer_fd, report_fd, interruption=interruption)
                raise
            status = witness.wait()
            _verify_witness_report(report_fd, status)
            return status, stdout.strip()


@contextmanager
def _private_claim_repo() -> Iterator[Path]:
    started = monotonic()
    try:
        directory = TemporaryDirectory(prefix="io-expected-claim-")
    except OSError:
        raise ExactClaimGitError("prepare", "os-error", elapsed_ms=int((monotonic() - started) * 1000)) from None

    primary: BaseException | None = None
    try:
        yield Path(directory.name)
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_started = monotonic()
        try:
            directory.cleanup()
        except OSError:
            elapsed_ms = int((monotonic() - cleanup_started) * 1000)
            if primary is None:
                raise ExactClaimGitError("cleanup", "os-error", elapsed_ms=elapsed_ms) from None
            if isinstance(primary, ExactClaimGitError):
                primary.record_cleanup_failure(elapsed_ms)
            else:
                logger.warning("Exact claim Git cleanup failed (OSError, elapsed_ms=%d)", elapsed_ms)


def _checked_git(repo: Path, phase: ClaimGitPhase, args: tuple[str, ...], *, env: dict[str, str],
                 data: bytes, timeout: float, acknowledgement: bytes | None) -> bytes:
    started = monotonic()

    def failure(cause: ClaimGitFailureCause, status: int | None = None) -> ExactClaimGitError:
        return ExactClaimGitError(phase, cause, elapsed_ms=int((monotonic() - started) * 1000), exit_status=status)

    try:
        status, output = _run_git(
            ["git", "-C", str(repo), "-c", "http.followRedirects=false", phase, *args],
            env=env, data=data, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise failure("timeout") from None
    except _WitnessFailure as error:
        raise ExactClaimGitError(phase, error.cause, elapsed_ms=int((monotonic() - started) * 1000),
                                 exit_status=error.status, settlement_timed_out=error.settlement_timed_out,
                                 stop_retried=error.stop_retried) from None
    except OSError:
        raise failure("os-error") from None
    if status:
        raise failure("exit-status", status)
    if acknowledgement is not None and not any(line.startswith(acknowledgement) for line in output.splitlines()):
        # An up-to-date response is not a successful acquisition by this call.
        raise failure("missing-acknowledgement", status)
    return output


def append_claim_record(
    git_auth_env: dict[str, str],
    *,
    ref: str,
    predecessor: str,
    record: bytes,
    message: str,
    timeout_seconds: float = 20.0,
) -> bool:
    """Append a direct child when the server still holds the exact predecessor.

    An explicit lease makes receive-pack compare the old OID during its ref
    update. Creating and checking a single direct child prevents this path from
    rewriting history, even though Git's lease flag also permits that use.
    """
    if not _CLAIM_REF.fullmatch(ref) or not _OID.fullmatch(predecessor):
        raise ValueError("Exact claim ref and predecessor OID required")
    isolated_env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "issue-orchestrator",
        "GIT_AUTHOR_EMAIL": "issue-orchestrator@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "issue-orchestrator",
        "GIT_COMMITTER_EMAIL": "issue-orchestrator@users.noreply.github.com",
    }
    with _private_claim_repo() as repo:
        def git(phase: ClaimGitPhase, *args: str, data: bytes = b"", remote: bool = False,
                acknowledgement: bytes | None = None) -> bytes:
            env = {**isolated_env, **git_auth_env} if remote else isolated_env
            return _checked_git(repo, phase, args, env=env, data=data, timeout=timeout_seconds,
                                acknowledgement=acknowledgement)

        git("init", "--bare", "--quiet", "--object-format=sha1", "--template=")
        # A missing ref makes fetch fail. Listing first makes absence and an
        # already moved ref ordinary refusals before fetching an object.
        selected = git("ls-remote", "--refs", "origin", ref, remote=True)
        if selected != f"{predecessor}\t{ref}".encode("ascii"):
            return False
        git("fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", ref, remote=True)
        if git("rev-parse", "FETCH_HEAD^{commit}") != predecessor.encode("ascii"):
            return False
        blob = git("hash-object", "-w", "--stdin", data=record)
        tree_entry = b"100644 blob " + blob + f"\t{RECORD_PATH}\n".encode("ascii")
        tree = git("mktree", data=tree_entry).decode("ascii")
        candidate = git("commit-tree", tree, "-p", predecessor, data=message.encode()).decode("ascii")
        parent_check_started = monotonic()
        if not _OID.fullmatch(candidate) or git("show", "-s", "--format=%P", candidate) != predecessor.encode("ascii"):
            raise ExactClaimGitError("show", "unexpected-parent",
                                     elapsed_ms=int((monotonic() - parent_check_started) * 1000))
        update = f" \t{candidate}:{ref}\t".encode("ascii")
        git("push", "--porcelain", f"--force-with-lease={ref}:{predecessor}", "origin",
            f"{candidate}:{ref}", remote=True, acknowledgement=update)
        return True
