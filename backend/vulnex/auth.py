"""Authentication for the VULNEX console.

Two credentials exist, for two kinds of caller:

* a human **admin**, who signs in with email + password, or with GitHub (any
  account whose login is on the allow-list), and then presents the opaque session
  token this module mints;
* the **automation** machine identity, which presents one static key and may only
  set the GitHub CVE pull request.

Sessions live in memory on purpose: the tool has no user table, a restart is a
deployment event, and a token is worthless once the process is gone. Passwords
are stored as PBKDF2-SHA256 hashes (``python -m vulnex.cli hash-password``), never
as plaintext, and neither the hash nor the password is ever served by the API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlencode

import requests

from . import config

__all__ = [
    "hash_password",
    "verify_password",
    "password_login",
    "SessionStore",
    "sessions",
    "new_oauth_state",
    "consume_oauth_state",
    "github_authorize_url",
    "github_exchange",
    "github_login_allowed",
]

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 240_000
_SALT_BYTES = 16

_GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
_GITHUB_USER = "https://api.github.com/user"


# -- passwords --------------------------------------------------------------
def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """``pbkdf2_sha256$iterations$salt$hash`` — safe to keep in the environment."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "$".join(
        (
            _ALGO,
            str(iterations),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of a password against a stored PBKDF2 hash."""
    if not password or not encoded:
        return False
    try:
        algo, iterations, salt_b64, digest_b64 = encoded.split("$")
        if algo != _ALGO:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(computed, expected)


def password_login(email: str, password: str) -> bool:
    """Validate an admin email + password against the configured credential."""
    if not config.password_login_configured():
        return False
    if (email or "").strip().lower() != config.ADMIN_EMAIL:
        return False
    if config.ADMIN_PASSWORD_HASH:
        return verify_password(password, config.ADMIN_PASSWORD_HASH)
    return hmac.compare_digest(password or "", config.ADMIN_PASSWORD)


# -- sessions ---------------------------------------------------------------
class SessionStore:
    """In-memory admin sessions with expiry."""

    def __init__(self, ttl: int | None = None) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._tokens: dict[str, dict[str, Any]] = {}

    @property
    def ttl(self) -> int:
        return self._ttl if self._ttl is not None else config.SESSION_TTL

    def create(self, identity: dict, method: str) -> tuple[str, dict]:
        token = secrets.token_urlsafe(32)
        payload = {
            "role": config.ROLE_ADMIN,
            "method": method,
            "identity": identity,
            "expires_at": time.time() + self.ttl,
        }
        with self._lock:
            self._tokens[token] = payload
        return token, payload

    def get(self, token: str | None) -> dict | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            for key in [k for k, v in self._tokens.items() if v["expires_at"] <= now]:
                self._tokens.pop(key, None)
            return self._tokens.get(token)

    def drop(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            return self._tokens.pop(token, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


sessions = SessionStore()


# -- GitHub OAuth -----------------------------------------------------------
# Short-lived pending ``state`` values so the callback cannot be forged.
_STATE_TTL = 600
_states: dict[str, float] = {}
_states_lock = threading.Lock()


def new_oauth_state() -> str:
    state = secrets.token_urlsafe(24)
    now = time.time()
    with _states_lock:
        for key in [k for k, exp in _states.items() if exp <= now]:
            _states.pop(key, None)
        _states[state] = now + _STATE_TTL
    return state


def consume_oauth_state(state: str | None) -> bool:
    if not state:
        return False
    with _states_lock:
        expiry = _states.pop(state, None)
    return bool(expiry and expiry > time.time())


def github_authorize_url(redirect_uri: str, state: str) -> str:
    """The GitHub consent URL, scoped to reading the signed-in account."""
    query = urlencode(
        {
            "client_id": config.GITHUB_OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": "read:user",
            "state": state,
            "allow_signup": "false",
        }
    )
    return f"{_GITHUB_AUTHORIZE}?{query}"


def github_exchange(code: str, redirect_uri: str) -> dict | None:
    """Swap an OAuth code for the GitHub account, or ``None`` when it fails."""
    if not config.github_login_configured():
        return None
    try:
        token_resp = requests.post(
            _GITHUB_TOKEN,
            data={
                "client_id": config.GITHUB_OAUTH_CLIENT_ID,
                "client_secret": config.GITHUB_OAUTH_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
            timeout=config.HTTP_TIMEOUT,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
        if not access_token:
            return None
        user_resp = requests.get(
            _GITHUB_USER,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": config.user_agent(),
            },
            timeout=config.HTTP_TIMEOUT,
        )
        user_resp.raise_for_status()
        return user_resp.json()
    except Exception:  # network / bad code / revoked app are all "not signed in"
        return None


def github_login_allowed(login: str | None) -> bool:
    """Only the configured GitHub account may sign in as admin."""
    return bool(login) and login.strip().lower() == config.ADMIN_GITHUB
