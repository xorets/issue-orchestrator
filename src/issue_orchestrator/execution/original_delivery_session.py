"""Verify independently written native assets against the engine's typed session."""
import json

from ..domain.models import Session


def require_native_session_assets(session: Session) -> None:
    run = session.run_assets
    manifest = json.loads(run.manifest.path.read_bytes())
    identity = json.loads((run.run_dir/'session-identity.json').read_bytes())
    if (manifest.get('run_id'), manifest.get('run_dir'), manifest.get('session_name'),
            manifest.get('started_at'), manifest.get('worktree'), manifest.get('agent_label')) != (
            run.run_id, str(run.run_dir), run.identity.session_name, run.started_at,
            str(run.worktree_path), session.agent_label):
        raise ValueError('Native original run manifest changed')
    if (identity.get('session_name'), identity.get('issue_number'), identity.get('worktree'),
            identity.get('branch'), identity.get('agent'), identity.get('session_key'), identity.get('task')) != (
            session.terminal_id, session.issue.number, str(run.worktree_path), session.branch_name,
            session.agent_label, session.key.stable_id(), session.key.kind.value):
        raise ValueError('Native original session identity changed')
