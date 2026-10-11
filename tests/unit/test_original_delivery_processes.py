"""Actual Linux children must be gone; a mock termination is insufficient."""
import os
import select
import signal
import subprocess
import sys
from dataclasses import replace

import pytest

from issue_orchestrator.domain.original_delivery import OriginalDelivery
from issue_orchestrator.execution.original_delivery_processes import capture_original_processes, engine_identity, require_original_quiescent


def test_changed_cwd_sigterm_resistant_worker_blocks_terminal_custody(tmp_path):
    owned = tmp_path/'owned'
    owned.mkdir()
    retained = owned/'unpublished.txt'
    retained.write_text('retain original work')
    foreign = tmp_path/'foreign'
    foreign.mkdir()
    host, pid, birth = engine_identity()
    owner = OriginalDelivery(repository='test/repo', config_fingerprint='config', contract_sha256='a'*64,
        run_id='original', session_name='issue-42', native_phase_name='coding-1', logical_child='code:42', started_at='start', branch='delivery', worktree=str(owned),
        run_dir=str(owned/'run'), agent='agent:web', engine_host=host, engine_pid=pid, engine_birth=birth, max_cycles=1)
    # SIGALRM caps leaked fixtures even when pytest dies before its finally block.
    script = "import signal,sys; signal.alarm(30); signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); signal.pause()"
    child = subprocess.Popen([sys.executable, '-c', script], cwd=foreign, start_new_session=True,
        env={**os.environ, 'ISSUE_ORCHESTRATOR_RUN_DIR':owner.run_dir}, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout is not None
        assert select.select([child.stdout], [], [], 5)[0], 'actual child readiness timeout'
        assert child.stdout.readline().strip() == 'ready'
        owner = replace(owner, process_roots=capture_original_processes(owner))
        with pytest.raises(ValueError, match='remains'):
            require_original_quiescent(owner, offline=False)
        child.send_signal(signal.SIGTERM)
        assert child.poll() is None
        with pytest.raises(ValueError, match='remains'):
            require_original_quiescent(owner, offline=False)
        child.kill()
        child.wait(timeout=5)
        require_original_quiescent(owner, offline=False)
        assert retained.read_text() == 'retain original work'
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        if child.stdout is not None:
            child.stdout.close()


def test_retained_session_finds_scrubbed_detached_descendant_after_root_exit(tmp_path):
    from dataclasses import replace
    from issue_orchestrator.execution.agent_runner import agent_session_has_live_processes, terminate_agent_session
    from issue_orchestrator.execution.original_delivery_processes import capture_original_processes
    owned = tmp_path/'owned'
    owned.mkdir()
    foreign = tmp_path/'foreign'
    foreign.mkdir()
    retained = owned/'evidence.txt'
    retained.write_text('custody stays')
    host, pid, birth = engine_identity()
    owner = OriginalDelivery(repository='test/repo', config_fingerprint='config', contract_sha256='a'*64,
        run_id='original', session_name='issue-42', native_phase_name='coding-1', logical_child='code:42', started_at='start', branch='delivery', worktree=str(owned),
        run_dir=str(owned/'run'), agent='agent:web', engine_host=host, engine_pid=pid, engine_birth=birth, max_cycles=1)
    descendant = "import os,signal; signal.alarm(30); os.setpgid(0,0); signal.signal(signal.SIGTERM,signal.SIG_IGN); print('descendant-ready',flush=True); signal.pause()"
    script = "import signal,subprocess,sys; signal.alarm(30); print('root-ready',flush=True); sys.stdin.readline(); subprocess.Popen([sys.executable,'-c',sys.argv[1]],env={});"
    root = subprocess.Popen([sys.executable, '-c', script, descendant], cwd=foreign, start_new_session=True,
        env={**os.environ, 'ISSUE_ORCHESTRATOR_RUN_DIR':owner.run_dir}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    other = subprocess.Popen([sys.executable, '-c', "import signal; signal.alarm(30); signal.pause()"], cwd=foreign, start_new_session=True)
    try:
        assert root.stdout is not None and root.stdin is not None
        assert select.select([root.stdout], [], [], 5)[0]
        assert root.stdout.readline().strip() == 'root-ready'
        owner = replace(owner, process_roots=capture_original_processes(owner))
        assert any(item[1] == root.pid for item in owner.process_roots)
        root.stdin.write('spawn\n')
        root.stdin.flush()
        assert select.select([root.stdout], [], [], 5)[0]
        assert root.stdout.readline().strip() == 'descendant-ready'
        root.wait(timeout=5)
        assert agent_session_has_live_processes(root.pid)
        with pytest.raises(ValueError, match='descendant'):
            require_original_quiescent(owner, offline=False)
        terminate_agent_session(root.pid)
        assert not agent_session_has_live_processes(root.pid)
        require_original_quiescent(owner, offline=False)
        assert other.poll() is None
        assert retained.read_text() == 'custody stays'
    finally:
        terminate_agent_session(root.pid)
        root.wait(timeout=5)
        other.kill()
        other.wait(timeout=5)
        if root.stdin is not None:
            root.stdin.close()
        if root.stdout is not None:
            root.stdout.close()


def test_reused_root_and_session_numbers_do_not_authorize_foreign_termination(tmp_path):
    from dataclasses import replace
    from issue_orchestrator.execution.original_delivery_processes import process_birth, require_original_termination_scope
    owned = tmp_path/'owned'
    owned.mkdir()
    foreign = tmp_path/'foreign'
    foreign.mkdir()
    host,pid,birth=engine_identity()
    owner=OriginalDelivery(repository='test/repo',config_fingerprint='config',contract_sha256='a'*64,
        run_id='original',session_name='issue-42',native_phase_name='coding-1',logical_child='code:42',started_at='start',
        branch='delivery',worktree=str(owned),run_dir=str(owned/'run'),agent='agent:web',engine_host=host,
        engine_pid=pid,engine_birth=birth,max_cycles=1)
    child=subprocess.Popen([sys.executable,'-c',"import signal; signal.alarm(30); signal.pause()"],cwd=foreign,start_new_session=True)
    try:
        observed_birth=process_birth(child.pid)
        assert observed_birth is not None
        owner=replace(owner,process_roots=(('original',child.pid,'stale-'+observed_birth,child.pid,'stale-'+observed_birth),))
        require_original_quiescent(owner,offline=False)
        with pytest.raises(ValueError,match='foreign process'):
            require_original_termination_scope(owner,'original')
        assert child.poll() is None
    finally:
        child.kill()
        child.wait(timeout=5)


def test_orphan_run_marker_cannot_register_current_engine_worker_custody(tmp_path):
    from issue_orchestrator.execution.agent_runner import terminate_agent_session
    from issue_orchestrator.execution.original_delivery_processes import capture_original_processes
    host, pid, birth = engine_identity()
    owner = OriginalDelivery(repository='test/repo', config_fingerprint='config', contract_sha256='a'*64,
        run_id='original',session_name='issue-42',native_phase_name='coding-1',logical_child='code:42',started_at='start',
        branch='delivery',worktree=str(tmp_path),run_dir=str(tmp_path/'run'),agent='agent:web',
        engine_host=host,engine_pid=pid,engine_birth=birth,max_cycles=1)
    worker = "import signal; signal.alarm(30); print('ready',flush=True); signal.pause()"
    script = "import signal,subprocess,sys; signal.alarm(30); child=subprocess.Popen([sys.executable,'-c',sys.argv[1]],start_new_session=True); print(child.pid,flush=True)"
    previous = subprocess.Popen([sys.executable,'-c',script,worker],cwd=tmp_path,start_new_session=True,
        env={**os.environ,'ISSUE_ORCHESTRATOR_RUN_DIR':owner.run_dir},stdout=subprocess.PIPE,text=True)
    orphan_pid = None
    try:
        assert previous.stdout is not None
        lines = [previous.stdout.readline().strip(), previous.stdout.readline().strip()]
        assert 'ready' in lines
        orphan_pid = int(next(line for line in lines if line != 'ready'))
        previous.wait(timeout=5)
        with pytest.raises(ValueError,match='current engine process tree'):
            capture_original_processes(owner)
        with pytest.raises(ValueError,match='root custody is unknown'):
            require_original_quiescent(owner,offline=False)
    finally:
        if orphan_pid is not None:
            terminate_agent_session(orphan_pid)
        if previous.poll() is None:
            previous.kill()
        previous.wait(timeout=5)
        if previous.stdout is not None:
            previous.stdout.close()
