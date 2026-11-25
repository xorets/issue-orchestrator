"""Stop Git and its transport helpers when the Engine or the command ends."""

import os
import selectors
import signal
import subprocess
import sys
from contextlib import suppress
from time import monotonic, sleep


def _watch_git(ready: selectors.BaseSelector, argv: list[str], deadline: float) -> tuple[int, bytes]:
    # Git and its helpers share a group inside the witness's private session.
    try:
        git = subprocess.Popen(argv, process_group=0, close_fds=True)
    except OSError:
        return 125, b"git-spawn"

    try:
        try:
            child_fd = os.pidfd_open(git.pid)
            try:
                ready.register(child_fd, selectors.EVENT_READ, "git")
                events = ready.select(timeout=max(0, deadline - monotonic()))
            finally:
                os.close(child_fd)
        except OSError:
            report = b"git-watch"
        else:
            report = _report_events(events)
    finally:
        # Retain the child's PID until stopping its group, including any
        # helper still running after the main Git process has exited.
        status, stop_retried = _stop_git(git)
    if stop_retried:
        report += b"|stop-retried"
    return (status if status >= 0 else 128 - status), report


def _stop_git(git: subprocess.Popen[bytes]) -> tuple[int, bool]:
    retried = False
    while True:
        try:
            with suppress(ProcessLookupError):
                os.killpg(git.pid, signal.SIGKILL)
        except OSError:
            # A transient stop fault cannot certify the group has settled.
            retried = True
            sleep(0.01)
            continue
        return git.wait(), retried


def _report_events(events: list[tuple[selectors.SelectorKey, int]]) -> bytes:
    if not events:
        return b"git-deadline"
    if any(key.data == "stop" for key, _ in events):
        return b"git-stopped"
    return b"git-exited"


def supervise(owner_fd: int, cancel_fd: int, argv: list[str], timeout: float) -> tuple[int, bytes]:
    deadline = monotonic() + timeout
    try:
        ready = selectors.DefaultSelector()
    except OSError:
        return 125, b"owner-watch"
    # Monitor the owner in the same selector from before Git starts until the
    # last group signal is sent.
    with ready:
        try:
            ready.register(owner_fd, selectors.EVENT_READ, "stop")
            ready.register(cancel_fd, selectors.EVENT_READ, "stop")
            owner_ended = bool(ready.select(timeout=0))
        except OSError:
            return 125, b"owner-watch"
        if owner_ended:
            return 125, b"owner-ended"
        return _watch_git(ready, argv, deadline)


if __name__ == "__main__":
    result, report = supervise(int(sys.argv[1]), int(sys.argv[2]), sys.argv[5:], float(sys.argv[4]))
    with suppress(BrokenPipeError):
        os.write(int(sys.argv[3]), report)
    raise SystemExit(result)
