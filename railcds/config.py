"""Configuration loading for RAIL.

A thin, typed wrapper around the YAML file in ``config/rail.yaml`` so the rest of
the code accesses tunables through attributes instead of dictionary lookups.
Paths in the config are resolved relative to the project root (the directory
that contains ``config/``) unless they are already absolute.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml


def project_root() -> Path:
    """Return the RAIL project root (the parent of the ``railcds`` package)."""
    return Path(__file__).resolve().parent.parent


@dataclass
class Config:
    """Parsed RAIL configuration with helpers to resolve relative paths."""

    raw: Dict[str, Any]
    root: Path = field(default_factory=project_root)

    # -- generic access -----------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    def resolve(self, path_str: str) -> Path:
        """Resolve a config path relative to the project root."""
        p = Path(os.path.expanduser(path_str))
        return p if p.is_absolute() else (self.root / p)

    # -- typed section accessors -------------------------------------------
    @property
    def inspection(self) -> Dict[str, Any]:
        return self.raw["inspection"]

    @property
    def integrity(self) -> Dict[str, Any]:
        return self.raw["integrity"]

    @property
    def anchoring(self) -> Dict[str, Any]:
        return self.raw["anchoring"]

    @property
    def fec(self) -> Dict[str, Any]:
        return self.raw["fec"]

    @property
    def transport(self) -> Dict[str, Any]:
        return self.raw["transport"]

    @property
    def crypto(self) -> Dict[str, Any]:
        return self.raw["crypto"]

    @property
    def audit(self) -> Dict[str, Any]:
        return self.raw["audit"]

    @property
    def policy_id(self) -> str:
        return self.raw["policy"]["id"]


def _apply_env_overrides(raw: Dict[str, Any]) -> None:
    """Let a few env vars override transport settings (handy for containers)."""
    t = raw.setdefault("transport", {})
    env_map = {
        "RAIL_SEND_HOST": ("send_host", str),
        "RAIL_SEND_PORT": ("send_port", int),
        "RAIL_BIND_HOST": ("bind_host", str),
        "RAIL_BIND_PORT": ("bind_port", int),
    }
    for env, (key, cast) in env_map.items():
        val = os.environ.get(env)
        if val is not None:
            t[key] = cast(val)


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load ``config/rail.yaml`` (or an explicit path) into a :class:`Config`."""
    root = project_root()
    cfg_path = Path(path) if path else (root / "config" / "rail.yaml")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    _apply_env_overrides(raw)
    return Config(raw=raw, root=root)
