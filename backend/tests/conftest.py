"""Shared test setup."""

import pytest

from vulnex import cache


@pytest.fixture(autouse=True)
def _fresh_response_cache():
    """The API caches reads for a minute; tests that seed the database directly must not see another test's answers."""
    cache.clear()
    yield
    cache.clear()
