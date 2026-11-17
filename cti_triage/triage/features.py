"""Extraction de caractéristiques numériques pour le scoring, l'apprentissage
supervisé et la détection d'anomalies. Le vecteur a un ordre fixe
(`FEATURE_NAMES`) pour rester compatible avec un modèle sauvegardé."""

from __future__ import annotations

import math
from datetime import datetime, timezone

from ..models import Category, NormalizedEvent, Severity

CATEGORIES = [c.value for c in Category]
SEVERITIES = [s.value for s in Severity]

FEATURE_NAMES: list[str] = (
    [f"cat={c}" for c in CATEGORIES]
    + ["severity_rank", "freshness", "log_age_days", "risk_score",
       "credential_valid", "credential_invalid", "has_password_plain", "has_password_hash",
       "has_session_cookies", "contains_secrets", "n_identifiers", "critical_identifier",
       "known_actor", "has_actor", "log_volume", "n_emails", "desc_len_log"]
)


def freshness(ev: NormalizedEvent, half_life_days: float, now: datetime | None = None) -> tuple[float, float]:
    """Fraîcheur ∈ ]0,1] (décroissance exponentielle) et âge en jours."""
    now = now or datetime.now(timezone.utc)
    ref = ev.created_at or ev.matched_at
    if ref is None:
        return 1.0, 0.0
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    age = max(0.0, (now - ref).total_seconds() / 86400)
    return math.exp(-math.log(2) * age / max(half_life_days, 1e-6)), age


def _matches_any(values: list[str], patterns: list[str]) -> bool:
    low = [v.lower() for v in values]
    return any(p.lower() in v for p in patterns for v in low)


def extract(ev: NormalizedEvent, ctx: dict, now: datetime | None = None) -> dict[str, float]:
    a = ev.attributes
    fresh, age = freshness(ev, ctx.get("half_life_days", 30), now)
    ident_pool = ev.identifiers + a.get("emails", [])
    actor = str(a.get("actor", ""))

    f: dict[str, float] = {f"cat={c}": 0.0 for c in CATEGORIES}
    f[f"cat={ev.category.value}"] = 1.0
    f.update({
        "severity_rank": ev.severity.rank / 4,
        "freshness": fresh,
        "log_age_days": math.log1p(age),
        "risk_score": (ev.risk_score or 0) / 100,
        "credential_valid": 1.0 if a.get("credential_valid") is True else 0.0,
        "credential_invalid": 1.0 if a.get("credential_valid") is False else 0.0,
        "has_password_plain": 1.0 if a.get("has_password") and not a.get("password_is_hash") else 0.0,
        "has_password_hash": 1.0 if a.get("has_password") and a.get("password_is_hash") else 0.0,
        "has_session_cookies": 1.0 if a.get("has_session_cookies") else 0.0,
        "contains_secrets": 1.0 if a.get("contains_secrets") else 0.0,
        "n_identifiers": math.log1p(len(ev.identifiers)),
        "critical_identifier": 1.0 if _matches_any(ident_pool, ctx.get("critical_identifiers", [])) else 0.0,
        "known_actor": 1.0 if actor and _matches_any([actor], ctx.get("actor_watchlist", [])) else 0.0,
        "has_actor": 1.0 if actor else 0.0,
        "log_volume": math.log1p(float(a.get("volume") or 0)),
        "n_emails": math.log1p(len(a.get("emails", []))),
        "desc_len_log": math.log1p(len(ev.description)),
    })
    return f


def vectorize(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
