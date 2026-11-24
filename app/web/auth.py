"""Analyst accounts, sessions, CSRF tokens and login throttling.

* **Passwords** are hashed with argon2id (``argon2-cffi`` defaults). A login for an unknown
  address still runs one hash verification, so response time does not reveal which
  addresses have accounts.
* **Sessions** are server-side. The browser holds an opaque random token in an HttpOnly,
  SameSite=Lax cookie (``__Host-`` prefixed and Secure over HTTPS); Redis maps
  ``session:{sha256(token)}`` to the user, with an idle timeout and an absolute lifetime.
  Logging in issues a new token (no session fixation); logging out deletes it.
* **CSRF**: every browser gets the cookie, even before logging in, and every unsafe
  request must carry ``HMAC(SECRET_KEY, cookie)`` in a form field or the ``X-CSRF-Token``
  header (htmx). Another site can make the browser send the cookie but cannot read it,
  so it cannot compute the token.
* **Throttling**: 5 failed logins for one account within 15 minutes lock that account for
  15 minutes (the plan's rule); a looser per-address limit slows down password spraying.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from redis import Redis

MIN_PASSWORD_LENGTH = 12
COOKIE_NAME = "pt_session"
SECURE_COOKIE_NAME = "__Host-pt_session"  # only accepted over HTTPS, never by subdomains
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32)

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(16))


def verify_password(password_hash: str | None, password: str) -> bool:
    """Check a password; with no account (``None``) still spend the same time, then fail."""
    try:
        return _hasher.verify(password_hash or _dummy_hash(), password) and bool(password_hash)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problem(password: str, email: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"the password must have at least {MIN_PASSWORD_LENGTH} characters"
    if password.strip().lower() == email.strip().lower():
        return "the password must not be the email address"
    return None


# --------------------------------------------------------------------------- tokens


def new_token() -> str:
    return secrets.token_urlsafe(32)


def is_token(value: str | None) -> bool:
    return bool(value and _TOKEN.match(value))


def csrf_token(secret: str, browser_token: str) -> str:
    return hmac.new(secret.encode(), b"csrf:" + browser_token.encode(), hashlib.sha256).hexdigest()


def csrf_valid(secret: str, browser_token: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(csrf_token(secret, browser_token), str(supplied))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --------------------------------------------------------------------------- sessions


class SessionStore:
    """Server-side sessions in Redis; the cookie only holds a random token."""

    def __init__(
        self,
        redis: Redis,
        idle_seconds: int,
        max_age_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._redis = redis
        self._idle = idle_seconds
        self._max_age = max_age_seconds
        self._clock = clock

    @staticmethod
    def _key(token: str) -> str:
        return f"session:{_digest(token)}"  # a Redis dump holds no usable session tokens

    def create(self, user_id: uuid.UUID) -> str:
        token = new_token()
        payload = json.dumps({"user_id": str(user_id), "created": self._clock()})
        self._redis.set(self._key(token), payload, ex=self._idle)
        return token

    def user_id(self, token: str) -> uuid.UUID | None:
        """The session's user, or ``None``. A valid session's idle timer restarts."""
        if not is_token(token):
            return None
        key = self._key(token)
        raw = self._redis.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            created = float(data["created"])
            user_id = uuid.UUID(data["user_id"])
        except (ValueError, KeyError, TypeError):
            self._redis.delete(key)
            return None
        if self._clock() - created > self._max_age:
            self._redis.delete(key)
            return None
        self._redis.expire(key, self._idle)
        return user_id

    def delete(self, token: str) -> None:
        if is_token(token):
            self._redis.delete(self._key(token))


# --------------------------------------------------------------------------- throttling


@dataclass(frozen=True)
class Limit:
    failures: int
    window_seconds: int
    lock_seconds: int


ACCOUNT_LIMIT = Limit(failures=5, window_seconds=15 * 60, lock_seconds=15 * 60)  # the plan's
ADDRESS_LIMIT = Limit(failures=30, window_seconds=15 * 60, lock_seconds=15 * 60)


class LoginThrottle:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def _keys(self, kind: str, subject: str) -> tuple[str, str]:
        digest = _digest(subject.lower())
        return f"login:fail:{kind}:{digest}", f"login:lock:{kind}:{digest}"

    def locked(self, email: str, address: str) -> bool:
        return bool(
            self._redis.exists(self._keys("account", email)[1], self._keys("address", address)[1])
        )

    def failure(self, email: str, address: str) -> bool:
        """Count a failed login; ``True`` if this locked the account or the address."""
        locked = False
        for kind, subject, limit in (
            ("account", email, ACCOUNT_LIMIT),
            ("address", address, ADDRESS_LIMIT),
        ):
            counter, lock = self._keys(kind, subject)
            with self._redis.pipeline() as pipe:
                pipe.incr(counter)
                pipe.expire(counter, limit.window_seconds, nx=True)
                count, _ = pipe.execute()
            if int(count) >= limit.failures:
                self._redis.set(lock, "1", ex=limit.lock_seconds)
                self._redis.delete(counter)
                locked = True
        return locked

    def success(self, email: str) -> None:
        self._redis.delete(self._keys("account", email)[0])
