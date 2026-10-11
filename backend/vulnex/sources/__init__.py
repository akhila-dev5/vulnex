"""Public vulnerability intelligence sources used by VULNEX.

The advisory sources (OSV, NVD, MITRE, Red Hat, GitHub Advisories) are queried
live during a scan. ``VulnerabilityDataSource`` is different: it reads a
pre-computed inventory published by the separate ``akhila-dev5/VulnerabilityData``
repository over raw.githubusercontent.com, with no API key.
"""

from .vulnerabilitydata import FeedError, VulnerabilityDataSource

__all__ = ["VulnerabilityDataSource", "FeedError"]
