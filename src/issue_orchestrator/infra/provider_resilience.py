"""Provider resilience status helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..ports.provider_resilience import ProviderStatus


PROVIDER_STATUS_FILE = "provider-status.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_provider_status(run_dir: Path, status: ProviderStatus) -> Path:
    """Write provider status JSON to the session run directory."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / PROVIDER_STATUS_FILE
    path.write_text(json.dumps(status.to_dict(), indent=2, sort_keys=True))
    return path


def read_provider_status(run_dir: Path) -> ProviderStatus | None:
    """Read provider status JSON from the session run directory."""
    path = run_dir / PROVIDER_STATUS_FILE
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    return ProviderStatus.from_dict(data)
