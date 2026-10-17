# Docker session source candidate

This backend extends the existing `SessionRunner`/Pluggy terminal seam for
[Builder #27](https://github.com/xorets/builder/issues/27). It is an opt-in source
candidate, not installed runtime acceptance or permission to run a model. Native
remains the default. Select the explicit class path
`issue_orchestrator.execution.terminal_docker:DockerPlugin` only with separately
admitted immutable Docker inputs.

## Preparation and execution

The existing session launcher allocates `SessionRunAssets` and assembles its
provider command before the optional `SessionPreparation` port runs. The Docker
implementation reads `ISSUE_ORCHESTRATOR_DOCKER_TEMPLATE`, a controller-owned
0400 file outside worker mounts. Its contract must be inherited through the
existing `XORETS_EXECUTION_CONTRACT`/`XORETS_EXECUTION_DIGEST` seal. The contract's
`execution.backend` is `docker`; `execution.docker_launch` binds `template_path`
and `intent_sha256`. Intent is canonical sorted, indented JSON with a trailing
newline, excluding `contract_sha256`, `run_id`, `engine_run_dir`, and
`command_sha256` to avoid a circular digest.

Preparation fills only the empty engine run ID/directory and zero command
digest placeholders. Builder's `builder_run_id` remains separate from the
engine's `YYYYMMDD-HHMMSSZ-<UUID hex>` run ID. The exact session/worktree/contract
must match. Preparation writes an exclusive 0400 launch under a private 0700
per-engine-run directory; it does not replace prior launches or grant a new
deadline. Correction needs a separately admitted matching template and the
original owner's remaining correction budget.

The standard pinned Dev Container CLI receives only the generated configuration
whose exact fixed create arguments, tools and image are checked before `up`.
Host initialization, build inputs and implicit image volumes are refused. The
returned container is checked against exact daemon/image/name/mount/user,
network, read-only root, no capabilities, no-new-privileges, no logging and
memory/swap/CPU/PID bounds before any admitted project hook or provider runs.
Lifecycle hooks run by Docker exec inside that verified worker; `postAttach`
and interactive input are unsupported in this first noninteractive backend.

The provider command is never evaluated in the service shell. Docker exec-create
returns an immutable ID, recorded durably before exec-start. Credentials travel
only in the Unix Docker API request, separately from command argv. Provider
retries are capped at one attempt on the prepared Docker path. Raw hook/provider
output shares a byte bound and global deadline; Docker's task log driver is
disabled. Provider exit and complete-container stop are separate observations.
No automatic container removal discards evidence.

CLI user/session scratch lives under bounded `/tmp`; system patch markers stay
on the immutable root at `/var/devcontainer`. The selected CLI skips system
environment/profile patching when it cannot create those markers. A writable
system-marker directory instead causes it to attempt `/etc/environment` changes
and is incompatible with this read-only root. Login-shell environment probing
is explicitly disabled. CLI diagnostics are capped and retained privately.

## Custody and recovery

The existing remote original claim gains the `execution_backend` discriminator
and typed versioned `docker_custody` history. Each row binds engine run, daemon,
controller container, worker container, provider exec and full launch digest.
Old Native claim records remain readable; unknown backends, mixed PID/Docker
proof, changed IDs and unknown/missing Docker objects refuse.

Original register/track/correction operations use the same fenced claim owner.
The Docker custody adapter is selected in both serving and offline composition;
PID namespaces never substitute for worker termination. Offline adoption requires
the recorded old controller and all recorded workers to be demonstrably stopped.
The trusted persistent singleton remains Builder's responsibility.

An exclusive reservation survives uncertain create/start acknowledgement.
Restart stops the exact tracked worker and retains an unknown provider result;
it never starts an exec again. Lost CLI create acknowledgement is resolved by
the reserved container name plus exact launch label before an immutable ID can
authorize stop. A wrong daemon/foreign label cannot authorize termination.
`public_receipt()` projects exact technical Docker identities for Builder;
`docker-session.json` separately retains exit/overflow/stop/error facts.

## Explicit callback addressing and remaining gates

Native callback addressing remains loopback. Trusted deployment may set
`ISSUE_ORCHESTRATOR_CALLBACK_BIND` and `ISSUE_ORCHESTRATOR_CALLBACK_HOST`;
the runtime endpoint publishes the actual bound port and passes a validated
`ISSUE_ORCHESTRATOR_API_ORIGIN` to all agent callback clients. Existing route
allowlists and run completion capabilities remain authoritative. Reaching an
origin is not evidence that cross-run callback authorization passed.

This source does not provision storage quotas, daemon capacity accounting,
private-network protection, image/tool installation, credentials or provider
mount projections. Builder admission must prove every persistent writer's hard
byte/inode quota, bounded temporary writes, private/host/cross-task network
denial, public egress and callback scope before real sessions. Resource/network
policy hashes in a packet identify the subject; they are not proof of installed
enforcement. Host #167/#169 own those prerequisites and exact-image activation.
Native qualification does not qualify Docker, and no model, real dispatch,
deployment or full legacy acceptance matrix is implied by unit tests.

For an explicitly authorized cheap transport check, the committed
`scripts/probe_docker_sessions.py` accepts an already cached digest image, pinned
Node/CLI paths plus `tool_files` SHA256 mapping in `--tools`, and an existing
private `--evidence-root`. It refuses a dirty source checkout. The fixed fixture
uses network `none`, an inert disposable controller, a read-only canary workspace,
bounded temporary files and a short deadline. It records source/tree/material
identities, a technical report, capped logs, artifact digests and independent
container-removal observations. It does not exercise model/provider projection,
Git tooling, public egress, callbacks or persistent quota acceptance. Failed
development probes must remain separate evidence from a committed-source pass.
