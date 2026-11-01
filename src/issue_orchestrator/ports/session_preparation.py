"""Trusted terminal preparation after typed allocation and command assembly."""
from typing import Protocol, runtime_checkable
from ..domain.session_run import SessionRunAssets


@runtime_checkable
class SessionPreparation(Protocol):
    def prepare_session(self, run: SessionRunAssets, session_name: str, command: str) -> None: ...
    def activation_pending(self, session_name: str) -> bool: ...


class NoSessionPreparation:
    def prepare_session(self, run: SessionRunAssets, session_name: str, command: str) -> None:
        pass

    def activation_pending(self, session_name: str) -> bool:
        return False


NO_SESSION_PREPARATION = NoSessionPreparation()
