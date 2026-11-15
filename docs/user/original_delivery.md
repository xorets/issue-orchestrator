# Original delivery custody

This public boundary supports a supervised, explicitly selected Issue whose
original implementation was registered before its first inference. It uses the
existing issue claim ref, original native session, configuration authority
ceiling, and `max_rework_cycles` budget. An HTTP acknowledgment, local queue row,
old process ID, or an absent worker does not establish current remote authority.

The owning implementation is [Builder #8](https://github.com/xorets/builder/issues/8).
The accepted source predecessor is
`xorets/issue-orchestrator@b9b4ca9aefc49e3da50e8b0b59e2347ffb905986`.
Its original failing compositions remain historical qualification evidence.
The owner conditionally authorized source-only adoption of an exact successor
revision after required qualification and independent Standards and Spec reviews
pass. This source API does not constitute installed Ubuntu acceptance or a real
delivery, and does not authorize production activation or human merge.

Builder's selected Docker marker can inherit a schema-5 inner contract with a
version-1 current-state retry identity. The original-owner and worker-authority
readers verify its request/content digest, generation, Builder run identity and
Docker backend, while preserving the same sealed grant, configuration, custody
and correction limits. Schema-4 contracts retain their original interpretation;
a current request cannot be relabeled as legacy authority. This compatibility
change grants no model allowance, installation, activation or merge authority.

## Public commands

MCP exposes `orchestrator.original_delivery(issue_number, operation, payload)`.
The same authenticated engine HTTP boundary exposes
`GET /api/original-delivery/{issue_number}` and
`POST /api/original-delivery/{issue_number}/{operation}`. The trusted controller
uses these commands; model capability profiles must not expose control-plane
commands merely because an additional engine tool exists.

`orchestrator.original_delivery_history` verifies at most 256 ordered receipt
fences and timestamps against an independently selected review parent and stable
current ref. The trusted controller authenticates the sealed parent and receipt
source before calling it. The proof compares authenticated full claim snapshots;
it does not prove Git commit ancestry or protect against a compromised controller
receipt store. It returns only the current fence and a canonical input digest.
Large histories may exceed the trusted controller's bounded MCP call and fail closed.

Every mutation requires `lease_id`, `fence`, `contract_sha256`, `run_id`, and a
bounded `request_id`. `fence` is the current remote claim commit SHA returned by
observe. `run_id` is the original native engine run, distinct from a controller's
execution-contract generation ID. Unknown fields and malformed identity values
are refused. Mutations accept only the operation values below, validated
before transport or owner activity; arbitrary path fragments and unknown values
are refused. Omitted observation payloads remain read-only. After a stale fence
or lost acknowledgment, observe the remote record before retrying; a successful
historical acknowledgment is not authority.

| Operation | Additional inputs and behavior |
| --- | --- |
| `observe` | Returns current remote lease, claimant, fence, expiry, original owner record, and explicit `remote_released`. Reads do not grant authority. |
| `register` | Requires current OPERATOR hold, one active initial implementation, exact native `session_name` (terminal ID) and `started_at`, current lease, independently matching native manifest and session identity, sealed launch-inherited contract, and observed worker roots in the current engine's PID/birth process tree. Existing nonzero rework labels cannot be reset into a fresh budget. |
| `handoff` | Requires exact open PR `pr_number`, `head_sha`, and `base_sha`, original branch, a clean published workspace, and positively quiescent original workers. Updates the same retained owner record. |
| `correct` | Requires that exact handoff and bounded nonempty `feedback`. Atomically admits a request and consumes one cycle in the remote CAS cell before Git preparation. Cancellation, stale ownership, pending prior correction, unpublished work, or exhaustion refuses. |
| `launch` | Requires the admitted `request_id` and exact published PR/head/base. The native launcher rechecks current engine custody and cancellation and commits a one-shot reservation before Git. It binds the native correction run before spawn. Duplicate launch observes the existing reservation/run and never launches again. |
| `track` | Binds observed worker roots for the exact currently active correction run and admitted request. It cannot invent a run or session. |
| `resume` | Explicit restart custody, preserving original run/session/contract/budget, canceled intent, admitted history, and process roots. Requires the old engine and supported workers positively gone and the same sealed configuration/contract. Records previous engine identities; cancellation refuses restart correction. |
| `cancel` | Persists cancellation intent before termination and preserves it in the terminal record. A partial stop or unreadable owned process leaves the remote claim retained. |
| `retire` | Offline cancelled Docker original only. Requires `recovery_evidence_path` and `recovery_evidence_sha256`, positive current containment, preserved evidence and unchanged-owner CAS. Records reservation recovery while keeping `released=false`; no task success, historical release certificate or fresh launch authority is inferred. |
| `reconcile` | Reconciles only the exact fenced original after positive worker quiescence. Writes a released tombstone through non-force remote CAS, preserving original evidence and allowing legitimate successor claim acquisition. |

Observe's `owner` contains the original native terminal `session_name` and
physical `native_phase_name` separately. For example, `issue-42` is the original
terminal while its native run manifest can name `coding-1`. Neither is inferred
from the other's spelling. `correction_runs` retains rows in the order
`[request_id, native_run_id, run_dir, terminal_id, started_at, native_phase_name]`.
`launches` records every consumed native launch reservation, so an older replay
cannot launch again or increment another correction cycle. A reserved launch
without a confirmed native run is explicit incomplete evidence and cannot be
replayed to prepare another workspace. `process_roots` records
`[native_run_id, pid, birth, session_id, session_leader_birth]`; numeric PID or
session-ID reuse is foreign ownership, never termination authority.

The original workspace check retains untracked engine review feedback under
`.issue-orchestrator/review-feedback/` without treating it as unpublished source.
Tracked changes, other untracked work, and failed Git enumeration still refuse
handoff or correction. Mutable checkout runtime-ignore patterns cannot grant
this exemption. The check does not delete, hide, or rewrite retained feedback.
Before admission it also proves HEAD and actual tracked bytes, types and modes
against the published commit. Hidden index flags (`assume-unchanged` or
`skip-worktree`) and unreadable tracked content refuse; a clean Git status is
insufficient. Checkout filters that transform tracked blob bytes also refuse.
No checkout contents or index flags are changed by this proof.
Admitted original corrections reuse the exact published branch through the
existing preserving-worktree contract: preparation neither rebases/resets the
branch nor cleans prior feedback. Earlier cycle feedback bytes and modes stay
intact while the new cycle writes its own feedback file. Unsafe reuse refuses
destructive recreation.

## Custody and qualification

Registration verifies the canonical nonsymlink, current-user, single-link,
mode-0400 file inherited as `XORETS_EXECUTION_CONTRACT`, and its exact bytes against
`XORETS_EXECUTION_DIGEST` and the request digest. The schema-4 contract binds the
repository, original workspace, agent, terminal, branch, originating capability
ceiling, configuration hash, and engine-observed correction budget. Callers
cannot supply a different ceiling or a new counter. Rework-cycle labels project
the remote grant; ordinary rework consumers cannot substitute their own grant or
fall back to initial coding.

Registered handoffs retain the original remote lease after native completion.
The original engine renews its explicitly registered custody. A restarted engine
must resume the original fence explicitly. Remote release is the positively read
`released` record, not ref absence or the disappearance of a PID. The advisory
`io:claimed` label is never a release oracle. Ordinary unregistered completion
uses the existing release contract and reports release only after observation.

When the selected engine is inactive, MCP permits observe, cancel, reconcile and guarded retirement. Cancel and
reconcile require the explicitly configured original remote claimant. For legacy
observe/retire only, a missing claimant may be resolved from the original remote
record when its repository/configuration and original PID-derived claimant match. It starts
no engine or model. Reconciliation requires the original engine's exact PID/birth
to be gone on the same host, then checks owned run/workspace processes and
retained worker/session identities. Supported descendants remain visible after
changing cwd or stripping their environment. Owned unreadable observations,
unknown worker roots, foreign host, or failed remote CAS refuse. Unrelated
protected processes do not grant custody and are not termination targets.

Terminal reconciliation retains files, unpublished work, native handoff assets,
and evidence; it does not clean a workspace or activate a replacement payload.
Live serving engines validate the original PID/birth identity before any
explicit or label-triggered cancellation intent write. A foreign live engine
cannot change intent, fence or budget merely by sharing repository/configuration
and claimant. Explicit restart proves the old custody quiescent before it can
record cancellation or resume; legitimate cancellation still persists before
terminal process activity, including incomplete offline reconciliation.
Candidate qualification must separately demonstrate real worker termination,
remote before/after observations, foreign-Issue and other-engine isolation,
restart and acknowledgment recovery, cancellation races, and drain-before-swap
with unchanged old payloads. Required skipped, partial, unavailable, or stale
evidence is NON-PASS. The locked tuple remains engine 0.10.0, MCP 1.28.1,
CPython 3.14.7, Codex CLI 0.157.1, lock SHA-256
`f6ce4b992ef6975e0134a06171f7cefa7d6a7d22d8bf352bca14ccac6f462cf9`;
record the exact selected source commit and staged payload identities alongside
qualification before adoption.

The quality ratchet accepts only two focused keys for this boundary:
`control_policy_branch_sites:src/issue_orchestrator/control/original_delivery.py`
records the centralized original-owner lifecycle policy, and
`oversized_control_hotspots:src/issue_orchestrator/infra/orchestrator.py`
records the existing facade's serialized delegation, completion claim wiring,
and retained-lease renewal. The owner keeps these decisions together; the facade
delegates rather than duplicating authority policy. Public input/output contracts
and native launch complexity remain enforced without new suppressions.

## Abandoned Docker reservation recovery

The trusted operator preserves the failed result, spent accounting, original
claim Git bundle, task archive and task Git bundle before requesting `retire`.
Recovery never overwrites original stop/wait receipts or changes an UNKNOWN
historical release into a certificate. A stopped worker and controller prevent
those exact containers from executing now; future runtime admission remains
subject to its separate original authority and current configuration checks.

The evidence is a canonical, single-link, current-user mode-0400 JSON file,
limited to 64KiB, with exactly `schema_version: 1`,
`kind: original-reservation-recovery`, `lease_id`, `previous_fence`, the complete
`owner` observed before retirement, `stopped` from the custody owner's
`recovery_snapshot`, and `preserved`. The latter contains exactly `claim_bundle`,
`task_archive`, `git_bundle`, each an absolute canonical `path` and its `sha256`.
The trusted operator is responsible for selecting complete matching archives
and verifying their contents using the existing preservation procedures; these
paths are evidence references, not worker-provided proof of archive completeness.
The owner verifies file custody and hashes, then rereads exact daemon/worker/
controller stopped generations before remote CAS. Live or restarted containers,
changed claim/configuration, incomplete custody, missing or changed preservation
and failed CAS refuse without retiring the reservation. Exec metadata is not
needed to establish current container containment; normal release reconciliation
still requires its positive original settlement proof.

The retained claim records `reservation_recovery` with request, prior fence and
evidence identity. Scheduling sees no active reservation; the immutable prior
Git commits retain the failed original. Re-observe after lost acknowledgement;
an identical recovery request returns its recorded disposition. A different
request cannot rewrite it. Later cleanup and independent restoration verification
remain separate, using existing supported controls and original baseline.
