"""Configuration : secrets via variables d'environnement, réglages métier via TOML.

Aucun secret ne doit être écrit dans le code ni dans config/triage.toml.
Voir .env.example pour la liste des variables.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_TRIAGE_CONFIG = Path(__file__).resolve().parent.parent / "config" / "triage.toml"


def _env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class FlareSettings:
    api_key: str
    tenant_id: int | None = None
    base_url: str = "https://api.flare.io"
    page_size: int = 10                 # max autorisé par /firework/v4/events/tenant/_search
    fetch_details: bool = True          # 1 appel détail par événement (doc Flare)
    min_severity: str | None = None     # filtre côté API (>=), ex. "low"
    event_types: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "FlareSettings":
        tenant = _env("FLARE_TENANT_ID")
        types = _env("FLARE_EVENT_TYPES", "") or ""
        return cls(
            api_key=_env("FLARE_API_KEY", required=True) or "",
            tenant_id=int(tenant) if tenant else None,
            base_url=_env("FLARE_BASE_URL", "https://api.flare.io") or "https://api.flare.io",
            fetch_details=_env_bool("FLARE_FETCH_DETAILS", True),
            min_severity=_env("FLARE_MIN_SEVERITY") or None,
            event_types=[t.strip() for t in types.split(",") if t.strip()],
        )


@dataclass
class JiraSettings:
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Task"
    dry_run: bool = True                # par défaut on n'envoie RIEN à JIRA

    @classmethod
    def from_env(cls) -> "JiraSettings":
        dry_run = _env_bool("JIRA_DRY_RUN", True)
        return cls(
            base_url=_env("JIRA_BASE_URL", required=not dry_run) or "",
            email=_env("JIRA_EMAIL", required=not dry_run) or "",
            api_token=_env("JIRA_API_TOKEN", required=not dry_run) or "",
            project_key=_env("JIRA_PROJECT_KEY", "CTI") or "CTI",
            issue_type=_env("JIRA_ISSUE_TYPE", "Task") or "Task",
            dry_run=dry_run,
        )


@dataclass
class AppSettings:
    state_db: Path = Path("data/state.sqlite")

    @classmethod
    def from_env(cls) -> "AppSettings":
        return cls(state_db=Path(_env("CTI_STATE_DB", "data/state.sqlite") or "data/state.sqlite"))


def load_triage_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else Path(_env("CTI_TRIAGE_CONFIG", str(DEFAULT_TRIAGE_CONFIG)) or DEFAULT_TRIAGE_CONFIG)
    with p.open("rb") as fh:
        return tomllib.load(fh)
