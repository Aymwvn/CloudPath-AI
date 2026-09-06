"""
CloudProvider abstraction (ARCHITECTURE.md Section 24).

AWSProvider implements this first. Azure/GCP providers are stubbed later
under providers/azure and providers/gcp with the SAME interface, so the
engine layer (graph/iam/network/attack_paths/risk) never needs provider-
specific branching.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from engine.models import ScanResult


class CloudProvider(ABC):
    """Every cloud provider (AWS, Azure, GCP...) implements this contract."""

    @abstractmethod
    def discover_assets(self) -> ScanResult:
        """Read-only discovery of all in-scope resources for this account."""
        raise NotImplementedError

    @abstractmethod
    def discover_relationships(self, scan: ScanResult) -> ScanResult:
        """Derive graph edges (trust, network, containment) from raw assets.

        Takes the ScanResult from discover_assets and returns it enriched
        with Relationship objects. IAM-specific and network-specific edges
        are added later by engine.iam / engine.network, not here — this
        method only wires up the "obvious" structural relationships
        (e.g. EC2 RUNS_AS instance role, subnet CONTAINS EC2).
        """
        raise NotImplementedError
