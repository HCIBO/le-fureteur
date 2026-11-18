from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Config:
    data_dir: Path
    database_url: str
    secret_key: str
    cookie_secure: bool
    max_upload_mb: int
    session_hours: int = 12

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "targets"

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"


def _secret(data_dir: Path) -> str:
    env = os.environ.get("SCAKIT_SECRET_KEY")
    if env:
        return env
    p = data_dir / "secret.key"
    if not p.exists():
        p.write_text(secrets.token_urlsafe(48))
        p.chmod(0o600)
    return p.read_text().strip()


@lru_cache
def get_config() -> Config:
    data = Path(os.environ.get("SCAKIT_DATA_DIR", Path.home() / ".local/share/scakit-server")).expanduser()
    data.mkdir(parents=True, exist_ok=True)
    for sub in ("targets", "scans"):
        (data / sub).mkdir(exist_ok=True)
    return Config(
        data_dir=data,
        database_url=os.environ.get("SCAKIT_DATABASE_URL", f"sqlite:///{data / 'scakit.db'}"),
        secret_key=_secret(data),
        cookie_secure=os.environ.get("SCAKIT_COOKIE_SECURE", "0") == "1",
        max_upload_mb=int(os.environ.get("SCAKIT_MAX_UPLOAD_MB", "2048")),
    )
