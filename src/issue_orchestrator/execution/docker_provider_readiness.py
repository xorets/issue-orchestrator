"""Selected Docker local auth probes, isolated from ambient controller auth."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import time
from uuid import uuid4

from ..ports.command_runner import CommandResult, CommandRunner, OutputNewlines
from ..ports.provider_credentials import ProviderCredentials
from .docker_launch_input import canonical, sealed_bytes
from .docker_worker_authority import docker_model_auth_requested, model_projection_snapshot, MODEL_AUTH_ENV
from .terminal_docker import private_directory, run_cli_capture


class DockerReadinessRefused(ValueError):
    """A selected model probe must refuse rather than inherit ambient auth."""


class DockerAuthProbeRunner:
    """Only local `codex login status`, under a hard output/deadline bound."""
    def __init__(self, environment: dict[str, str], deadline: int, output_limit: int):
        self.environment, self.deadline, self.output_limit = environment, deadline, output_limit

    def run(self, command: str | list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
            timeout_seconds: int | None = None, shell: bool = False,
            newlines: OutputNewlines = OutputNewlines.TRANSLATED) -> CommandResult:
        if command != ['codex','login','status'] or cwd is not None or env is not None or shell:
            raise ValueError('Docker readiness permits only the existing local Codex status probe')
        timeout = min(timeout_seconds or 15, 15, (self.deadline-time.time_ns())/1e9)
        executable = shutil.which('codex', path=self.environment['PATH'])
        if not executable or timeout <= 0:
            raise ValueError('Docker local auth probe executable/deadline unavailable')
        stdout,stderr,exit_code = run_cli_capture([executable,'login','status'], environment=self.environment,
            timeout=timeout, output_limit=self.output_limit)
        return CommandResult(exit_code,newlines.decode(stdout,errors='replace'),newlines.decode(stderr,errors='replace'))


@contextmanager
def docker_readiness_context(provider: str, ordinary_runner: CommandRunner, credentials: ProviderCredentials,
                             *, runner_factory=DockerAuthProbeRunner):
    """Verify selected authority before resolving one secret and creating private auth."""
    try:
        selected = docker_model_auth_requested()
    except (OSError, ValueError, KeyError, TypeError):
        raise DockerReadinessRefused('Selected Docker readiness authority refused') from None
    if not selected:
        yield ordinary_runner
        return
    try:
        with admitted_readiness_context(provider, credentials, runner_factory) as runner:
            yield runner
    except (OSError, ValueError, KeyError, TypeError):
        raise DockerReadinessRefused('Selected Docker private authentication probe refused') from None


@contextmanager
def admitted_readiness_context(provider: str, credentials: ProviderCredentials, runner_factory):
    packet,root = readiness_task(provider)
    secret = dict(credentials.session_env(provider,docker=True)).get(MODEL_AUTH_ENV)
    if not isinstance(secret,str) or not 0 < len(secret.encode()) <= min(65536,packet['limits']['max_output_bytes']):
        raise ValueError('Docker readiness requires one bounded explicit model auth secret')
    value = json.loads(secret)
    if not isinstance(value,dict) or not value:
        raise ValueError('Docker readiness auth must be a nonempty JSON object')
    raw = canonical(value)
    output_limit = min(65536,packet['limits']['max_output_bytes']-len(raw))
    if output_limit <= 0:
        raise ValueError('Docker readiness metadata/output allocation exhausted')
    available = os.statvfs(root)
    if available.f_bavail * available.f_frsize < len(raw) + output_limit + 8192:
        raise ValueError('Docker readiness task allocation exhausted')
    home = private_directory(root/('provider-readiness-'+uuid4().hex),create=True)
    descriptor = os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    created = False
    identity = os.fstat(descriptor)
    try:
        fd = os.open('auth.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=descriptor)
        created = True
        with os.fdopen(fd,'wb') as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError('Docker readiness auth custody differs')
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(descriptor)
        environment = {'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(home),'CODEX_HOME':str(home)}
        yield runner_factory(environment,packet['deadline_unix_ns'],output_limit)
    finally:
        try:
            if created:
                os.unlink('auth.json',dir_fd=descriptor)
            current = home.lstat()
            if (current.st_dev,current.st_ino) != (identity.st_dev,identity.st_ino):
                raise ValueError('Docker readiness runtime identity changed')
            home.rmdir()
        finally:
            os.close(descriptor)


def readiness_task(provider: str) -> tuple[dict, Path]:
    """The selected private task allocation, verified before any credential lookup."""
    if provider != 'codex':
        raise ValueError('Docker model readiness requires the selected Codex provider')
    template = Path(os.environ['ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE'])
    packet = json.loads(sealed_bytes(template))
    outer,inner,projection = model_projection_snapshot(packet)
    if (inner['role'] not in {'standard-implementation','standard-review'} or
            type(packet.get('deadline_unix_ns')) is not int or packet['deadline_unix_ns'] <= time.time_ns() or
            packet.get('output_root') != '/srv/builder/tasks/'+packet['builder_run_id']+'/controller-output'):
        raise ValueError('Docker readiness task/role/deadline differs from selected authority')
    root = Path(packet['output_root'])
    if any(root.is_relative_to(Path(row[key])) or Path(row[key]).is_relative_to(root)
            for row in packet['mounts'] for key in ('source','target')):
        raise ValueError('Docker readiness output overlaps worker mounts')
    private_directory(root)
    return packet,root
