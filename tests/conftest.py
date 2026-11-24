"""Shared fixtures. Tests never read the developer's environment, .env or network."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from app.config import (
    EXAMPLE_SETTINGS_FILE,
    SETTINGS_FILE_ENV,
    Policy,
    Settings,
    get_settings,
    load_policy_data,
)

# Variables Settings would pick up from the environment.
_SETTINGS_ENV = [name.upper() for name in Settings.model_fields] + [SETTINGS_FILE_ENV]


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _SETTINGS_ENV:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def example_policy() -> Policy:
    return Policy.model_validate(load_policy_data(EXAMPLE_SETTINGS_FILE))


@pytest.fixture
def make_settings(example_policy: Policy) -> Callable[..., Settings]:
    """Build Settings without touching .env; keyword arguments override fields."""

    def factory(**overrides: Any) -> Settings:
        overrides.setdefault("policy", example_policy)
        return Settings(_env_file=None, **overrides)

    return factory
