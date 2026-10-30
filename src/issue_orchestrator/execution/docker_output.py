"""Controller-only Docker output custody and bounded per-run allocation."""
from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import time
from uuid import uuid4


def private_directory(path: Path, *, create: bool = False) -> Path:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Docker ordinary output directory is not private and canonical")
    return path


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


@contextmanager
def bounded_output(root: Path, size: int, limit: int, deadline_unix_ns: int):
    """Serialize actual output allocation across live and observer instances."""
    import fcntl
    descriptor = os.open(private_directory(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if time.time_ns() >= deadline_unix_ns:
            raise ValueError("Docker output allocation deadline exhausted")
        used = 0
        for name in ("docker-output.log", "docker-hook-output.log"):
            try:
                info = (root / name).lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Docker output custody changed")
            used += info.st_size
        evidence = root / "builder-first-model"
        if evidence.exists():
            used += first_model_evidence_size(private_directory(evidence))
        if used + size > limit:
            raise ValueError("Docker aggregate output bound exhausted")
        yield
    finally:
        os.close(descriptor)
