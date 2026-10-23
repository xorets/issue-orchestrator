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
Image references may be a registry `repository@sha256` manifest digest or an
exact local `sha256:<image ID>` whose selected value equals inspected `Id`.
Tags and fabricated registry digests are not accepted.
Lifecycle hooks run by Docker exec inside that verified worker; `postAttach`
and interactive input are unsupported in this first noninteractive backend.

The provider command is never evaluated in the service shell. Docker exec-create
returns an immutable ID, recorded durably before exec-start. Credentials travel
only in the Unix Docker API request, separately from command argv. The terminal
hook spec and both built-in implementations require the nullable `secret_env`
argument because Pluggy forwards only required implementation arguments. Public
session facades supply `None` when absent; plugins that omit this argument remain
compatible. Provider retries are capped at one attempt on the prepared Docker
path. Raw hook/provider
output shares a byte bound and global deadline; Docker's task log driver is
disabled. Provider exit and complete-container stop are separate observations.
No automatic container removal discards evidence.

The required sealed `output_root` separates ordinary controller writes from
settlement. Builder projects exactly
`/srv/builder/tasks/<builder_run_id>/controller-output` for a full worker;
the network-none source primitive supplies an explicit private absolute root.
There is no implicit legacy path. The root must already exist, be canonical,
controller-owned mode0700, and overlap neither worker mount sources/targets
(in either ancestry direction, including read-only mounts) nor the launch/template
parent. The engine creates one private child named by the allocated engine run ID.
Raw provider/hook output, capped CLI diagnostics, and CLI `HOME`/`TMPDIR` children
live there. The existing launch, active-run selector and atomic custody receipt
stay under the template parent; host acceptance must prove the selected ordinary
and settlement paths have their declared finite byte/inode allocations. Ordinary
output exhaustion stops the exact worker and retains the unknown provider result
in the settlement receipt. Restored output reads the same sealed root and run;
restart never replays exec. Session-run projections inside the worker worktree
remain ordinary task data and do not confer custody.

CLI **worker-side** user/session scratch lives under bounded `/tmp`; system patch markers stay
on the immutable root at `/var/devcontainer`. The selected CLI skips system
environment/profile patching when it cannot create those markers. A writable
system-marker directory instead causes it to attempt `/etc/environment` changes
and is incompatible with this read-only root. Login-shell environment probing
is explicitly disabled. CLI diagnostics are capped and retained privately.

The optional sealed `control_manifest` contains only `fetched_unix_ns` and
`manifest`, the genuine policy object fetched by the trusted outer operator from
`https://containers.dev/static/devcontainer-control-manifest.json`. Retain the
fetch URL, timestamp and response digest in the operation provenance; shape
validation cannot establish remote authenticity. Both policy arrays
`disallowedFeatures` and `featureAdvisories` and their required string fields
must be present. Empty upstream arrays are valid; the engine never synthesizes
empty policy or strips denial/advisory rows. Canonical policy is bounded to
64KiB. The whole envelope participates in immutable intent and launch hashes.

The engine refuses future timestamps and inputs at least 300 seconds old,
rechecks freshness when seeding its freshly private per-run
`TMPDIR/devcontainercli-<actual-account-name>/control-manifest.json`, and sets
mtime to the original fetch time. It never renews stale policy by copying it.
The pinned CLI uses that cache while fresh and retains its own stale-cache
refresh behavior; `--user-data-folder` does not select this cache. No downloader
or altered CLI is introduced. Omission preserves the existing CLI lookup path.
The test policy fixture records public upstream content captured on 2026-10-20;
its test timestamps are controlled inputs, not evidence of current live policy.

CLI spawn refuses an exhausted global deadline. The process-group timeout still
kills CLI descendants, and an expired packet after CLI completion refuses hooks
and provider exec, retaining and stopping any identified worker. These source
checks do not prove cancellation of a request already in flight to Docker's
daemon; uncertain create acknowledgment retains the existing reservation and
requires independent exact-ID recovery. They do not prove original-owner release.

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
Ordinary discovery preserves a provider still owned by the same live in-process
watcher and its exact record object, after the existing daemon/container identity
checks. A persisted receipt alone cannot establish that ownership. A fresh plugin
instance or a finished watcher retains the restart behavior: stop the exact tracked
worker and retain an unknown provider result; never start an exec again. Lost CLI create acknowledgement is resolved by
the reserved container name plus exact launch label before an immutable ID can
authorize stop. A wrong daemon/foreign label cannot authorize termination.
`public_receipt()` projects exact technical Docker identities for Builder;
`docker-session.json` separately retains exit/overflow/stop/error facts.

## Explicit callback addressing and remaining gates

The launch packet's sealed `network` selects `worker_ipv4`, `controller_ipv4`,
canonical RFC1918 `subnet`, `gateway`, safe `br-` interface `bridge_name`, and one
to three unique public IPv4 `dns` servers. The generated create intent fixes the
worker IP, DNS and `net.ipv6.conf.all.disable_ipv6=1`. Full `worker_authority`
projection requires this descriptor; only the isolated `network_id:none`
source primitive may omit it.

Before create and again before hooks/provider exec, the existing Docker
transport verifies the exact selected local bridge, subnet/gateway, IPv6 off,
non-internal mode, bridge interface and ICC on, plus the controller's selected
IPv4 membership. Created worker inspection requires exactly one selected IPv4
endpoint, matching DNS, and the fixed IPv6 sysctl. No bridge/firewall is
configured here. These readbacks and the sealed firewall-policy hash do not
prove egress filtering or DNS forwarding; actual-host #169 acceptance remains
separate. See Docker's [network flags](https://docs.docker.com/reference/cli/docker/container/run/)
and [bridge options](https://docs.docker.com/engine/network/drivers/bridge/#options).
ICC on is not an isolation claim: a separately qualified native bridge-family
fence must deny other switched traffic. This avoids Docker's ICC-off path that
can load `br_netfilter` and enable host-wide bridge filtering; the selected
daemon's userland proxy must remain enabled. Admission remains closed.

Native callback addressing remains loopback. Trusted deployment may set
`ISSUE_ORCHESTRATOR_CALLBACK_BIND` and `ISSUE_ORCHESTRATOR_CALLBACK_HOST`;
both the Control API server and web dashboard honor the selected binding.
An explicit non-loopback binding leaves occupied-port failure to the server
instead of trying to terminate other listeners. For an automatically assigned
port, start paused, verify the published bound endpoint, and install the exact
network exception before attaching a worker. Restart requires re-verification.
The runtime endpoint publishes the actual bound port and passes a validated
`ISSUE_ORCHESTRATOR_API_ORIGIN` to all agent callback clients. The Docker server
and dashboard select an authenticated callback scope admitting only completion
submissions and exact issue-resume routes, with existing per-run capabilities.
Host Git preflight, review exchange and all operator routes refuse that token;
workers cannot choose a host worktree and execute its Git hooks through the
service. Managed `coding-done` already delegates publication to the controller;
direct Docker preflight/exchange helpers report unsupported rather than a pass.

An optional `worker_authority` packet descriptor binds exact canonical outer
Builder and inner engine authority file paths. Both files require exact
read-only mounts with no writable ancestor. The backend verifies the outer
envelope's inner checksum, mirrored subject, image and packet intent, then
derives the worker's `XORETS_EXECUTION_CONTRACT` and digest from those sealed
bytes. The path-only descriptor avoids a checksum cycle. Provider secrets
cannot replace these seals or inject controller/GitHub credentials. The existing
scoped callback token and exact allocation-owned completion
capability cross separately in the private Unix exec payload. The trusted
launcher rejects provider overrides and resolves the capability from its typed
run; Docker commands require that injected value instead of reading a controller
capability file. Neither secret enters command text, launch packets or public
receipts, and ambient controller environment is not copied. Docker rework
remains explicitly unsupported until its separate spawn seam carries that
allocation authority; synthetic acceptance keeps its correction budget at zero.
Builder v1 outer seals retain their non-model semantics and reject admission
proof projections. A v2 outer seal adds exact installed acceptance and finite
run authorization descriptors. Its packet projects only their public paths:
`/srv/builder/admission/acceptances/<sha256>.json` and
`/srv/builder/admission/authorizations/<builder_run_id>.json`. These paths join
the outer descriptors and immutable launch intent without embedding a grant's
own hash in the launch intent. Each requires an isolated exact read-only file
mount, protected root ancestry and bounded immutable root-owned canonical bytes
matching the outer digest. Writable overlaps or directory projections refuse.
Builder owns acceptance/model policy evaluation; this adapter authenticates
those already selected public bytes and the original authority subject.

Only the selected v2 Codex path asks the existing provider credential port for
`XORETS_DOCKER_MODEL_AUTH_JSON`. Before that single named keyring/environment
lookup, the adapter authenticates the current sealed template, active inner
contract, root authorization's delivery/run/acceptance identity and exact
worker projection. Native and v1 provider credential behavior stays unchanged;
no host login file is read or mounted. Missing credentials refuse.

The private Docker exec environment carries that bounded nonempty JSON object
separately from generated `XORETS_DOCKER_LAUNCH_JSON` and
`XORETS_DOCKER_PROJECTION_JSON` copies. The latter are canonical public transport
copies of the actual assigned packet and authenticated projection; provider
credentials cannot override them. The projection must bind the selected
image/worker manifest, baked role home and bounded task runtime root. Builder's
worker launcher revalidates its full grant before materializing temporary auth
and removes the secret from its child environment. Callback/completion authority
still comes from their existing owners, never from these public copies.
A primitive without the worker-authority descriptor receives no execution
authority. These source checks grant no model admission.
Native keeps its previous callback allowlist. Reaching an origin alone does
not establish cross-run authorization or network qualification.

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

## Model preflight and private readiness

The internal Docker worker protocol uses `POST /api/docker/first-model` with
exact `run_id`, `contract_sha256`, and `launch_sha256` fields. Both the scoped
Docker callback bearer and the same active allocation's completion capability
are required. The owner authenticates the current finite root grant and live
worker/provider custody before requesting the existing OPERATOR planner pause;
startup, incident, and other existing pause reasons cannot be overwritten. The
response binds the committed barrier and original fence to the assigned packet.
Each receipt is sealed mode0400 under
`output_root/<engine_run_id>/builder-first-model/receipt-<UUID hex>.json`, outside
worker mounts. All immutable receipts and provider output share the existing
output-byte bound, together with lifecycle hook output. Each allocation checks
the actual retained log and immutable receipt sizes under one per-run directory
lock, held through the write. Contention refuses immediately, and acquisition
rechecks the original sealed deadline. Serving and offline custody observers
keep their own selected-run state and never save a cached session record when sealing
evidence; provider settlement remains owned by the live terminal adapter.

Independent review uses its own engine, allocation, checkout, role, and root
grant. Its receipt adds the exact root-granted `review_parent`; worker/launch
fields describe the reviewer while `original_delivery` describes the original
implementation. The producer checks that the original worker/provider has
successfully stopped and never registers a second original claim. The barrier
in this receipt describes the reviewer; the trusted parent preflight owns the
original engine's OPERATOR pause requirement. The grant's fence selects one
immutable claim anchor. REVIEW authenticates that commit directly and accepts
only a nondecreasing expiry renewal of the same complete claim and original
owner; its receipt reports the independently observed current fence. Missing
anchor history, changed lease, cancellation, or any other original mutation
refuses without registration or a new claim. Stopped-parent inspection first
requires the exact terminal container with PID0 and successful settled provider.
It retains exact image/configuration/resources/mounts/bridge/static IPAM checks,
while accepting lifecycle-cleared operational endpoint addresses as described by
[Moby's cleanup owner](https://github.com/moby/moby/blob/v28.5.2/daemon/container_operations.go#L565).
The live worker's endpoint checks remain unchanged. This source behavior still
requires exact-image host verification; an upstream lifecycle contract does not
establish this host's runtime acceptance.

Before worker creation, Docker readiness checks only the explicitly named
`XORETS_DOCKER_MODEL_AUTH_JSON` secret after authenticating the selected v2
template, grant, role, and projection. It creates an exclusive private home in
the existing controller task output allocation, writes mode0600 `auth.json`, and
runs only the existing local `codex login status` probe with a clean environment.
The existing Codex parser produces readiness; the probe has finite output and
time bounds and removes the private auth in `finally`. Failure to authenticate
the selected context is nonlaunchable. Native and nonmodel v1 use their existing
readiness path. No host auth file is mounted or copied.
