"""Offline remote ports, with transport lifetime owned by this adapter boundary."""
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from ..adapters.github.github_adapter import GitHubAdapter
from ..adapters.github.ref_claim_adapter import GitHubRefClaimAdapter
from ..domain.lease_config import LeaseConfig
from ..ports.original_delivery import OriginalDeliveryClaims
from ..ports.repository_host import RepositoryHost

if TYPE_CHECKING:
    from ..infra.config import Config


@contextmanager
def original_delivery_ports(config: Config, lease_config: LeaseConfig, *,
                            recovery_issue: int | None = None) -> Iterator[tuple[OriginalDeliveryClaims, RepositoryHost]]:
    claimant_id = config.claims.claimant_id
    if not claimant_id and recovery_issue is None:
        raise ValueError("Original custody requires an explicit claimant identity")
    repository = GitHubAdapter(repo=config.repo, config=config)
    try:
        if not claimant_id:
            assert recovery_issue is not None
            claim = GitHubRefClaimAdapter.read_original_record(repository.http_client, recovery_issue)
            original = claim.original
            assert original is not None
            first_pid = original.engine_history[0][1] if original.engine_history else original.engine_pid
            if ((original.repository, original.config_fingerprint) != (config.repo, config.config_fingerprint) or
                    claim.claimant != f'orchestrator-{first_pid}'):
                raise ValueError('Legacy recovery claimant/configuration does not match original custody')
            claimant_id = claim.claimant
        claims = GitHubRefClaimAdapter(repository.http_client, claimant_id, lease_config,
            label_adapter=repository)
        yield claims, repository
    finally:
        repository.http_client.close()
