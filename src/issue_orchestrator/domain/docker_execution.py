"""Technical terminal facts; Builder determines task completion separately."""
from enum import StrEnum


class DockerSessionState(StrEnum):
    RESERVED = "reserved"
    CREATED = "created"
    EXEC_CREATED = "exec-created"
    STARTING = "starting"
    STOPPED = "stopped"
    RETAINED = "retained"
