"""Provider circuit breaker ports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Protocol


class ProviderErrorType(str, Enum):
    TRANSIENT = "transient"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    QUOTA = "quota"
    FATAL = "fatal"

    @property
    def requires_human_intervention(self) -> bool:
        """Whether a session must not retry this failure in process.

        The distinction the retry ladder turns on. A transient outage and an
        ordinary rate limit can heal during a short retry; an expired
        credential or an exhausted capacity meter cannot. The circuit later
        applies the lane's billing fact: prepaid quota receives a refill
        deadline, while metered quota requires external recovery evidence.
        Call sites that mean "a human must fix this" branch on this predicate
        rather than on ``is AUTH``, so adding a second non-retryable cause
        does not silently reinstate the retry-until-the-wall-clock behaviour
        that AUTH was given its own window to prevent (#6999).
        """
        return self in (ProviderErrorType.AUTH, ProviderErrorType.QUOTA)


@dataclass(frozen=True)
class ProviderStatus:
    provider: str | None
    error_type: ProviderErrorType | None
    attempts: int
    succeeded: bool
    exit_code: int | None
    timed_out: bool
    last_error_summary: str | None
    last_attempt_at: str
    quota_heals_on_timer: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "error_type": self.error_type.value if self.error_type else None,
            "attempts": self.attempts,
            "succeeded": self.succeeded,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "last_error_summary": self.last_error_summary,
            "last_attempt_at": self.last_attempt_at,
            "quota_heals_on_timer": self.quota_heals_on_timer,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProviderStatus":
        try:
            last_attempt_at = data["last_attempt_at"]
        except KeyError as exc:
            raise ValueError(
                "provider status must include last_attempt_at"
            ) from exc
        if not isinstance(last_attempt_at, str):
            raise ValueError("provider status last_attempt_at must be a string")
        error_type = data.get("error_type")
        parsed_error_type = None
        if error_type:
            try:
                parsed_error_type = ProviderErrorType(str(error_type))
            except ValueError:
                parsed_error_type = None
        return cls(
            provider=data.get("provider"),
            error_type=parsed_error_type,
            attempts=int(data.get("attempts", 1)),
            succeeded=bool(data.get("succeeded", False)),
            exit_code=data.get("exit_code"),
            timed_out=bool(data.get("timed_out", False)),
            last_error_summary=data.get("last_error_summary"),
            last_attempt_at=last_attempt_at,
            quota_heals_on_timer=bool(data.get("quota_heals_on_timer", False)),
        )


    @classmethod
    def from_worker_payload(cls, data: object, exit_code: int, lane: str, heals: bool) -> "ProviderStatus":
        """Validate bounded untrusted provider results before they affect a circuit."""
        fields = {'provider', 'error_type', 'attempts', 'succeeded', 'exit_code', 'timed_out', 'last_error_summary',
            'last_attempt_at', 'quota_heals_on_timer'}
        if (type(data) is not dict or set(data) != fields or type(data['attempts']) is not int or data['attempts'] != 1 or
                type(data['succeeded']) is not bool or type(data['timed_out']) is not bool or
                type(data['quota_heals_on_timer']) is not bool or
                type(data['provider']) is not str or len(data['provider']) > 128 or
                data['error_type'] is not None and data['error_type'] not in {x.value for x in ProviderErrorType} or
                data['last_error_summary'] is not None and (type(data['last_error_summary']) is not str or len(data['last_error_summary']) > 303) or
                type(data['last_attempt_at']) is not str or len(data['last_attempt_at']) > 64 or
                data['exit_code'] is not None and type(data['exit_code']) is not int or
                (data['exit_code'] if data['exit_code'] is not None else 124 if data['timed_out'] else 1) != exit_code):
            raise ValueError('Docker provider status shape or exec result differs')
        try:
            observed = datetime.fromisoformat(data['last_attempt_at'])
        except ValueError as exc:
            raise ValueError('Docker provider status timestamp differs') from exc
        if (type(exit_code) is not int or observed.utcoffset() is None or data['succeeded'] != (exit_code == 0) or
                data['succeeded'] and data['error_type'] is not None):
            raise ValueError('Docker provider status outcome differs')
        result = cls.from_dict(data)
        if result.provider != lane or result.quota_heals_on_timer is not heals:
            raise ValueError('Docker provider status belongs to another lane')
        return result


@dataclass(frozen=True)
class ProviderCircuitState:
    """Persisted circuit state, with one deadline per independent cause.

    A credential outage and a service outage are unrelated facts about a
    provider, and each has its own validity window. Collapsing them into a
    single ``open_until`` meant retiring one silently released the other: a
    ``READY`` credential probe says nothing about a 429/5xx outage, but would
    have re-opened launches into it (#6999 F3). An exhausted balance is a third
    such fact, independent of both: credits are not restored by a service
    recovering, nor by a login being renewed. Every dimension is stored, and
    "is the circuit open" is *derived* from them.
    """

    provider: str
    consecutive_outages: int
    last_error_summary: str | None
    updated_at: datetime
    # Deadline for the escalating transient ladder (429/5xx/transport).
    transient_open_until: datetime | None = None
    # Observation watermark for transient state. Success may arrive out of
    # attempt order and can retire only an outage older than itself.
    transient_observed_at: datetime | None = None
    # Deadline for the human-fixable credential outage. Its own (long) window,
    # cleared the moment the probe confirms re-authentication.
    auth_open_until: datetime | None = None
    # Auth failures are counted separately from transient outages: a credential
    # outage is human-fixable and must trip the circuit on its own threshold,
    # not be diluted by unrelated network blips (#6999).
    consecutive_auth_failures: int = 0
    # Identity of the last provider-readiness *sample* counted against this
    # circuit. One physical credential probe gates many launches in a tick, and
    # every one of them reports the same result; the circuit counts that sample
    # exactly once so a configured threshold > 1 still means "more than one
    # observation" (#6999 F2).
    last_auth_sample_id: str = ""
    # Deadline for an exhausted balance or usage allowance. A third dimension
    # rather than a reuse of the auth window, because the two recover on
    # different signals: a readiness probe confirming a valid login proves
    # nothing about restored credits, while a successful provider call does.
    # Clearing the auth window must therefore not release a quota outage.
    quota_open_until: datetime | None = None
    consecutive_quota_failures: int = 0
    # Observation watermark for the quota dimension. Completion effects can be
    # applied out of attempt order, so recovery evidence must be newer than the
    # exhaustion fact it retires.
    quota_observed_at: datetime | None = None
    # Whether the exhausted allowance returns merely because its deadline
    # elapsed. Subscription meters refill on a clock; a pay-as-you-go balance
    # does not. False is the fail-safe default for rows written before billing
    # was observed: keeping free capacity parked is cheaper than spending money
    # the operator did not authorize.
    quota_heals_on_timer: bool = False

    @property
    def metered_quota_is_open(self) -> bool:
        """Whether a metered exhaustion fact still requires human recovery."""
        return (
            not self.quota_heals_on_timer
            and self.quota_observed_at is not None
            and self.consecutive_quota_failures > 0
        )

    @property
    def open_until(self) -> datetime | None:
        """The latest deadline across all causes, or ``None`` if none are set.

        The aggregate the circuit is judged on: a provider is unavailable while
        *any* cause is still within its own window.
        """
        deadlines = [
            deadline
            for deadline in (
                self.transient_open_until,
                self.auth_open_until,
                self.quota_open_until,
            )
            if deadline is not None
        ]
        return max(deadlines) if deadlines else None


@dataclass(frozen=True)
class ProviderEvidenceWatermarks:
    """Durable chronology for provider-call evidence.

    This ledger is deliberately separate from :class:`ProviderCircuitState`.
    A confirmed healthy provider has no active circuit row, but its success
    observation must survive so a late, older failure cannot reopen the
    circuit after completion effects drain out of order.
    """

    provider: str
    success_observed_at: datetime | None = None
    transient_failure_observed_at: datetime | None = None
    quota_failure_observed_at: datetime | None = None


@dataclass(frozen=True)
class ProviderCircuitStatus:
    """Derived, point-in-time read model of a provider's circuit.

    Unlike the persisted :class:`ProviderCircuitState`, this carries the
    *interpreted* status the circuit owner computes against a clock:
    whether the circuit is open right now and how much cooldown remains.
    UI/observation layers consume this instead of re-deriving "is open"
    from ``open_until`` (that policy lives once, on the manager).
    """

    provider: str
    is_open: bool
    open_until: datetime | None
    cooldown_remaining_seconds: int
    consecutive_outages: int
    last_error_summary: str | None
    updated_at: datetime

    @property
    def timed_retry_seconds(self) -> int | None:
        """Cooldown remaining only when this open circuit has a deadline."""
        if not self.is_open or self.open_until is None:
            return None
        return self.cooldown_remaining_seconds


class ProviderCircuitStatusReader(Protocol):
    """Narrow read port: the interpreted status of every tracked circuit.

    The only surface presentation code is allowed to depend on for provider
    circuit state. Implemented by the circuit owner
    (``control.provider_resilience.ProviderResilienceManager``), so the
    dashboard projection depends on *behaviour* ("give me the interpreted
    status") rather than on the orchestrator's dependency-container layout.
    """

    def snapshot(self, now: datetime | None = None) -> list[ProviderCircuitStatus]:
        ...


@dataclass(frozen=True)
class StaticProviderCircuitStatusReader:
    """A reader that returns a fixed, explicitly supplied status list.

    Deliberately *not* a fallback: it exists so the two places that genuinely
    have no circuit owner to read must name that fact in the type system —
    the pre-boot dashboard page (no orchestrator is installed yet) and tests
    that inject an explicit circuit state. A misconfigured production
    orchestrator can never silently resolve to this, because the orchestrator
    facade exposes its resilience owner as a required property.
    """

    statuses: tuple[ProviderCircuitStatus, ...] = ()

    def snapshot(self, now: datetime | None = None) -> list[ProviderCircuitStatus]:
        del now  # a fixed status list has no clock to interpret against
        return list(self.statuses)


# The explicit "there is no circuit owner to read" reader. Distinct from a
# healthy-but-empty read only in intent; both render as "no outage", which is
# correct when no orchestrator is running at all.
NO_PROVIDER_CIRCUIT_STATUS: StaticProviderCircuitStatusReader = (
    StaticProviderCircuitStatusReader()
)


class ProviderCircuitStore(Protocol):
    """Persistence for active circuits and their durable evidence ledger."""

    def get(self, provider: str) -> ProviderCircuitState | None:
        ...

    def list_all(self) -> list[ProviderCircuitState]:
        ...

    def save(self, state: ProviderCircuitState) -> None:
        ...

    def delete(self, provider: str) -> None:
        ...

    def get_evidence(self, provider: str) -> ProviderEvidenceWatermarks | None:
        ...

    def save_reduction(
        self,
        evidence: ProviderEvidenceWatermarks,
        state: ProviderCircuitState | None,
    ) -> None:
        """Atomically persist evidence and its resulting active circuit state."""
        ...


class InMemoryProviderCircuitStore:
    """In-memory store for tests."""

    def __init__(self) -> None:
        self._states: dict[str, ProviderCircuitState] = {}
        self._evidence: dict[str, ProviderEvidenceWatermarks] = {}

    def get(self, provider: str) -> ProviderCircuitState | None:
        return self._states.get(provider)

    def list_all(self) -> list[ProviderCircuitState]:
        return list(self._states.values())

    def save(self, state: ProviderCircuitState) -> None:
        self._states[state.provider] = state

    def delete(self, provider: str) -> None:
        self._states.pop(provider, None)

    def get_evidence(self, provider: str) -> ProviderEvidenceWatermarks | None:
        return self._evidence.get(provider)

    def save_reduction(
        self,
        evidence: ProviderEvidenceWatermarks,
        state: ProviderCircuitState | None,
    ) -> None:
        self._evidence[evidence.provider] = evidence
        if state is None:
            self._states.pop(evidence.provider, None)
        else:
            self._states[state.provider] = state
