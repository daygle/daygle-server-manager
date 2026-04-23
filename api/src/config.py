from __future__ import annotations

from pathlib import Path

DEFAULTS = {
    "SESSION_SECRET": "change-me-in-production",
    "DATABASE_URL": "postgresql+psycopg2://daygle_server_manager:change_me@db:5432/daygle_server_manager",
    "SSH_KEYS_PATH": "/ssh_keys/id_rsa",
    "SMTP_HOST": "localhost",
    "SMTP_PORT": "25",
    "SMTP_USERNAME": "",
    "SMTP_PASSWORD": "",
    "SMTP_USE_TLS": "false",
    "SMTP_FROM": "daygle-server-manager@localhost",
}


def _read_conf() -> dict[str, str]:
    conf_candidates = [
        Path("/config/daygle_server_manager.conf"),
        Path("/app/daygle_server_manager.conf"),
    ]

    values: dict[str, str] = {}
    for conf_path in conf_candidates:
        if not conf_path.exists():
            continue

        for raw_line in conf_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        break

    return values


_CONF = _read_conf()


def get_setting(name: str, fallback: str | None = None) -> str:
    if name in _CONF:
        return _CONF[name]
    if name in DEFAULTS:
        return DEFAULTS[name]
    if fallback is not None:
        return fallback
    raise KeyError(f"Missing required config key: {name}")
