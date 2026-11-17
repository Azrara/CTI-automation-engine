"""Modèles de données internes du moteur (indépendants du format Flare)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    """Grandes catégories métier utilisées pour l'organisation et les stats."""

    CREDENTIAL_EXPOSURE = "credential_exposure"   # fuites d'identifiants, combos
    INFECTED_DEVICE = "infected_device"           # stealer logs, bots
    DATA_LEAK = "data_leak"                       # ransomleak, leaks, buckets ouverts
    SOURCE_CODE_SECRET = "source_code_secret"     # secrets / code exposé
    BRAND_IMPERSONATION = "brand_impersonation"   # lookalikes, faux profils
    FINANCIAL_FRAUD = "financial_fraud"           # cartes, listings de marché
    THREAT_ACTOR_CHATTER = "threat_actor_chatter" # forums, chats, blogs, pastes
    ATTACK_SURFACE = "attack_surface"             # services exposés, domaines
    OTHER = "other"


class Decision(str, Enum):
    NOTIFY = "notify"        # envoyé au client (JIRA)
    REVIEW = "review"        # zone grise : revue analyste
    SUPPRESS = "suppress"    # bruit


@dataclass
class NormalizedEvent:
    uid: str
    source_type: str                 # type Flare normalisé (ex. stealer_log)
    category: Category
    severity: Severity
    title: str
    description: str = ""
    created_at: datetime | None = None   # estimated_created_at
    matched_at: datetime | None = None
    tenant_id: str | None = None
    identifiers: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    risk_score: int | None = None       # header.risk.score (détail v2) si dispo
    status: str | None = None           # open / ignored / remediated
    # Attributs extraits utiles au triage (ex. credential_valid, has_password,
    # domain, actor, site, nb_records...). Rempli par le normaliseur.
    attributes: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["created_at"] = self.created_at.isoformat() if self.created_at else None
        d["matched_at"] = self.matched_at.isoformat() if self.matched_at else None
        if not include_raw:
            d.pop("raw", None)
        return d


@dataclass
class TriageResult:
    event: NormalizedEvent
    decision: Decision
    score: float                     # probabilité calibrée [0, 1] que l'alerte soit "à notifier"
    reasons: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)
    duplicate_of: str | None = None
    cluster_id: str | None = None
