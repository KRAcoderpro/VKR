"""Configuration loader for TLS-PinEval (V2 §4).

Loads config/default.yaml and optionally merges a user-supplied override
file on top.  Returns a plain dict so callers can read settings without
importing any config-specific types.

PyYAML is used when available; if not installed, an empty dict is returned
(all callers must therefore handle missing keys with .get() and a default).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "default.yaml"


def load_config(override_path: Path | None = None) -> dict[str, Any]:
    """Return merged configuration dict.

    Args:
        override_path: Optional path to a YAML file with partial overrides.
                       Values here take precedence over defaults.

    Returns:
        Merged configuration dict.  Empty dict on PyYAML import failure.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return {}

    cfg: dict[str, Any] = {}

    if _DEFAULT_CONFIG.is_file():
        with _DEFAULT_CONFIG.open(encoding="utf-8") as fh:
            defaults = yaml.safe_load(fh) or {}
        _deep_merge(cfg, defaults)

    if override_path is not None:
        with override_path.open(encoding="utf-8") as fh:
            overrides = yaml.safe_load(fh) or {}
        _deep_merge(cfg, overrides)

    return cfg


def get(cfg: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Traverse nested dict by dot-path keys and return value or default.

    Example:
        get(cfg, "analysis", "bypass_timeout", default=15)
    """
    node: Any = cfg
    for key in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(key, default)
    return node


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Merge *override* into *base* in place (recursive for nested dicts)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
