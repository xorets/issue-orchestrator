"""Immutable controller launch inputs shared by Docker execution boundaries."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat


def sealed_bytes(path: Path, *, expected: str | None = None, limit: int = 1024 * 1024) -> bytes:
    """Read the controller's sealed input without following a replacement link."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("Docker launch input path is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400):
            raise ValueError("Docker launch input is not a sealed owned file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(limit + 1)
        if len(raw) > limit or expected is not None and sha256(raw).hexdigest() != expected:
            raise ValueError("Docker launch input digest/size changed")
        return raw
    finally:
        os.close(descriptor)


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


