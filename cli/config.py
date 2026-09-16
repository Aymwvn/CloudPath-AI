"""
cli/config.py — persists CLI session state (API URL + auth token) to
~/.cloudpath/config.json, matching how aws-cli/gh cli persist a login
session between invocations rather than requiring credentials on every
single command.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

CONFIG_DIR = Path.home() / ".cloudpath"
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class CLIConfig:
    api_url: str = "http://localhost:8000"
    access_token: str | None = None
    username: str | None = None
    role: str | None = None


def load_config() -> CLIConfig:
    if not CONFIG_FILE.exists():
        return CLIConfig()
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return CLIConfig(**data)
    except (json.JSONDecodeError, TypeError):
        # a corrupted config file shouldn't crash every CLI invocation —
        # treat it the same as "not logged in yet"
        return CLIConfig()


def save_config(config: CLIConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(asdict(config), indent=2))
    # config contains an access token — restrict to owner read/write only
    CONFIG_FILE.chmod(0o600)


def clear_config() -> None:
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
