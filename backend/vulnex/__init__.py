"""VULNEX — Azure Linux CVE scanner and security dashboard.

VULNEX collects real package metadata from the Azure Linux RPM spec
repositories, matches it against public vulnerability intelligence, verifies
each finding against distro backport patches, and serves the results through a
FastAPI dashboard.
"""

__version__ = "1.0.0"
