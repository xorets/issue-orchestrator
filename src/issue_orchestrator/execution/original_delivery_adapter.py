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
def original_delivery_ports(config: Config, lease_config: LeaseConfig) -> Iterator[tuple[OriginalDeliveryClaims, RepositoryHost]]:
    claimant_id = config.claims.claimant_id
    if not claimant_id:
        raise ValueError("Original custody requires an explicit claimant identity")
    repository = GitHubAdapter(repo=config.repo, config=config)
    try:
        claims = GitHubRefClaimAdapter(repository.http_client, claimant_id, lease_config,
            label_adapter=repository)
        yield claims, repository
    finally:
        repository.http_client.close()
