"""Selected Docker local auth probes, isolated from ambient controller auth."""
from contextlib import contextmanager
from hashlib import sha256
import re
import json
import os
from pathlib import Path
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
    def __init__(self, environment: dict[str, str], deadline: int, output_limit: int, executable: Path):
        self.environment, self.deadline, self.output_limit = environment, deadline, output_limit
        self.executable = executable

    def run(self, command: str | list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
            timeout_seconds: int | None = None, shell: bool = False,
            newlines: OutputNewlines = OutputNewlines.TRANSLATED) -> CommandResult:
        if command != ['codex','login','status'] or cwd is not None or env is not None or shell:
            raise ValueError('Docker readiness permits only the existing local Codex status probe')
        timeout = min(timeout_seconds or 15, 15, (self.deadline-time.time_ns())/1e9)
        if timeout <= 0:
            raise ValueError('Docker local auth probe executable/deadline unavailable')
        stdout,stderr,exit_code = run_cli_capture([str(self.executable),'login','status'], environment=self.environment,
            timeout=timeout, output_limit=self.output_limit)
        if exit_code != 0:
            raise DockerReadinessRefused('Selected Docker local auth status failed')
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
    packet,root,executable = readiness_task(provider)
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
        yield runner_factory(environment,packet['deadline_unix_ns'],output_limit,executable)
    finally:
        try:
            if created:
                os.unlink('auth.json',dir_fd=descriptor)
            current = home.lstat()
            if (current.st_dev,current.st_ino) != (identity.st_dev,identity.st_ino):
                raise ValueError('Docker readiness runtime identity changed')
            _clear_private_home(descriptor, identity)
            current = home.lstat()
            if (current.st_dev,current.st_ino) != (identity.st_dev,identity.st_ino):
                raise ValueError('Docker readiness runtime identity changed')
            home.rmdir()
        finally:
            os.close(descriptor)


class _PrivateHomeCleaner:
    """Bounded descriptor-relative cleanup of a private readiness home."""
    def __init__(self, identity: os.stat_result):
        self.identity = identity
        self.remaining = 256

    def clear(self, fd: int, depth: int) -> None:
        if depth > 8:
            raise ValueError('Docker readiness cache nesting exceeded')
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                self.remaining -= 1
                if self.remaining < 0:
                    raise ValueError('Docker readiness cache entry limit exceeded')
                names.append(entry.name)
        for name in names:
            self._remove(fd, name, depth)

    def _remove(self, fd: int, name: str, depth: int) -> None:
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if before.st_uid != self.identity.st_uid or before.st_dev != self.identity.st_dev:
            raise ValueError('Docker readiness cache ownership changed')
        if stat.S_ISDIR(before.st_mode):
            self._remove_directory(fd, name, depth, before)
        elif stat.S_ISLNK(before.st_mode) or stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            self._verify_identity(fd, name, before, 'entry')
            os.unlink(name, dir_fd=fd)
        else:
            raise ValueError('Docker readiness cache contains unexpected entry')

    @staticmethod
    def _verify_identity(fd: int, name: str, before: os.stat_result, kind: str) -> None:
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Docker readiness cache ' + kind + ' changed')

    def _remove_directory(self, fd: int, name: str, depth: int, before: os.stat_result) -> None:
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            actual = os.fstat(child)
            if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('Docker readiness cache directory changed')
            self.clear(child, depth + 1)
            self._verify_identity(fd, name, actual, 'directory')
            os.rmdir(name, dir_fd=fd)
        finally:
            os.close(child)


def _clear_private_home(directory_fd: int, identity: os.stat_result) -> None:
    _PrivateHomeCleaner(identity).clear(directory_fd, 0)


def readiness_task(provider: str) -> tuple[dict, Path, Path]:
    """The selected private task allocation, verified before any credential lookup."""
    if provider != 'codex':
        raise ValueError('Docker model readiness requires the selected Codex provider')
    template = Path(os.environ['ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE'])
    packet = json.loads(sealed_bytes(template))
    _,inner,_ = model_projection_snapshot(packet)
    if (inner['role'] not in {'standard-implementation','standard-review'} or
            type(packet.get('deadline_unix_ns')) is not int or packet['deadline_unix_ns'] <= time.time_ns() or
            packet.get('output_root') != '/srv/builder/tasks/'+packet['builder_run_id']+'/controller-output'):
        raise ValueError('Docker readiness task/role/deadline differs from selected authority')
    root = Path(packet['output_root'])
    if any(root.is_relative_to(Path(row[key])) or Path(row[key]).is_relative_to(root)
            for row in packet['mounts'] for key in ('source','target')):
        raise ValueError('Docker readiness output overlaps worker mounts')
    private_directory(root)
    executable = selected_codex(inner)
    if packet['deadline_unix_ns'] <= time.time_ns():
        raise ValueError('Docker readiness deadline exhausted while authenticating executable')
    return packet,root,executable


def selected_codex(inner: dict) -> Path:
    """Select raw CLI bytes from sealed authority, never the PATH's ACP wrapper."""
    capability = inner['capabilities']
    expected = capability.get('codex_sha256')
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Docker readiness selected Codex digest is unavailable')
    executable = Path(capability['capability_bundle']) / 'toolchain/codex'
    if not executable.is_absolute() or executable.resolve(strict=True) != executable:
        raise ValueError('Docker readiness selected Codex path is not canonical')
    for parent in executable.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Docker readiness selected Codex ancestry is not protected')
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                before.st_mode & 0o222 or not before.st_mode & 0o111 or not 0 < before.st_size <= 512 * 1024**2):
            raise ValueError('Docker readiness selected Codex is not an immutable executable')
        digest = sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise ValueError('Docker readiness selected Codex short read')
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (os.read(fd, 1) or any(getattr(before, name) != getattr(after, name) for name in fields) or
                digest.hexdigest() != expected):
            raise ValueError('Docker readiness selected Codex identity or digest changed')
    finally:
        os.close(fd)
    return executable
