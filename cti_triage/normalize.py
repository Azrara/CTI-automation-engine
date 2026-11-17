"""Normalisation des événements Flare vers `NormalizedEvent`.

Le flux v4 (`metadata.type`) et le détail (v2 `activity`, v4 `event_type`)
n'utilisent pas tous les mêmes noms de types : on les ramène à un type
canonique, puis à une grande catégorie métier (`Category`).

L'extraction d'attributs est volontairement défensive : le schéma détaillé
varie selon le type d'événement. À affiner type par type avec des
exemples réels du tenant.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .models import Category, NormalizedEvent, Severity

# Alias -> type canonique (noms du flux v4, du détail v4 et du détail v2).
TYPE_ALIASES: dict[str, str] = {
    "driller_source_code": "source_code",
    "source_code_files": "source_code",
    "driller_google": "google",
    "driller_forum_post": "forum_post",
    "driller_forum_topic": "forum_topic",
    "stack_exchange": "forum_post",
    "cc": "financial_data",
    "credit_card": "financial_data",
    "social_media_account": "social_media",
    "leaked_credential": "leak",
    "bot": "infected_device",
    "stealer_log": "stealer_log",
    "infected_devices": "infected_device",
    "blog_post": "blog_content",
    "forum_profile": "profile",
    "seller": "profile",
    "bucket_object": "bucket",
    "buckets": "bucket",
    "docker_image": "source_code",
    "docker_repository": "source_code",
}

CATEGORY_BY_TYPE: dict[str, Category] = {
    # Identifiants
    "leak": Category.CREDENTIAL_EXPOSURE,
    "valid_credential": Category.CREDENTIAL_EXPOSURE,
    "invalid_credential": Category.CREDENTIAL_EXPOSURE,
    "mitigated_credential": Category.CREDENTIAL_EXPOSURE,
    # Postes infectés
    "stealer_log": Category.INFECTED_DEVICE,
    "infected_device": Category.INFECTED_DEVICE,
    # Fuites de données
    "ransomleak": Category.DATA_LEAK,
    "bucket": Category.DATA_LEAK,
    # Code / secrets
    "source_code": Category.SOURCE_CODE_SECRET,
    "source_code_secret": Category.SOURCE_CODE_SECRET,
    # Usurpation de marque
    "lookalike": Category.BRAND_IMPERSONATION,
    "social_media": Category.BRAND_IMPERSONATION,
    # Fraude financière
    "financial_data": Category.FINANCIAL_FRAUD,
    "listing": Category.FINANCIAL_FRAUD,
    # Bavardage d'acteurs malveillants
    "forum_post": Category.THREAT_ACTOR_CHATTER,
    "forum_topic": Category.THREAT_ACTOR_CHATTER,
    "forum_content": Category.THREAT_ACTOR_CHATTER,
    "blog_content": Category.THREAT_ACTOR_CHATTER,
    "chat_message": Category.THREAT_ACTOR_CHATTER,
    "paste": Category.THREAT_ACTOR_CHATTER,
    "profile": Category.THREAT_ACTOR_CHATTER,
    "google": Category.THREAT_ACTOR_CHATTER,
    # Surface d'attaque
    "domain": Category.ATTACK_SURFACE,
    "service": Category.ATTACK_SURFACE,
}


def canonical_type(raw_type: str | None) -> str:
    t = (raw_type or "unknown").strip().lower()
    if t.startswith("lookalike"):
        return "lookalike"
    return TYPE_ALIASES.get(t, t)


def categorize(source_type: str) -> Category:
    return CATEGORY_BY_TYPE.get(source_type, Category.OTHER)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _walk(obj: Any, depth: int = 0):
    """Parcourt récursivement (clé, valeur) d'un JSON imbriqué."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:200]:
            yield from _walk(v, depth + 1)


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_attributes(source_type: str, item: dict, detail: dict) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    keys_seen: dict[str, Any] = {}
    for k, v in _walk(detail or {}):
        keys_seen.setdefault(str(k).lower(), v)

    # Identifiants
    if source_type == "valid_credential":
        attrs["credential_valid"] = True
    elif source_type in ("invalid_credential", "mitigated_credential"):
        attrs["credential_valid"] = False
    for key in ("password", "hash", "passwd"):
        if keys_seen.get(key):
            attrs["has_password"] = True
            attrs["password_is_hash"] = key == "hash"
            break

    # Stealer logs : cookies / sessions = risque de prise de session (MFA bypass)
    if source_type in ("stealer_log", "infected_device"):
        for key in ("cookies", "session_cookies", "cookie_count"):
            if keys_seen.get(key):
                attrs["has_session_cookies"] = True
                break

    # Secrets dans le code
    if source_type in ("source_code", "source_code_secret") or keys_seen.get("contains_secrets"):
        attrs["contains_secrets"] = bool(keys_seen.get("contains_secrets") or source_type == "source_code_secret")

    # Acteur / site / volumétrie
    for key in ("actor", "author", "username", "group", "ransomware_group"):
        if isinstance(keys_seen.get(key), str):
            attrs.setdefault("actor", keys_seen[key])
    for key in ("site", "source", "forum", "site_name"):
        if isinstance(keys_seen.get(key), str):
            attrs.setdefault("site", keys_seen[key])
    for key in ("nb_records", "record_count", "count", "size"):
        if isinstance(keys_seen.get(key), (int, float)):
            attrs.setdefault("volume", keys_seen[key])

    # Données de l'item de flux (v4)
    highlights = item.get("highlights") or {}
    text = " ".join(str(x) for x in (highlights.get("title"), highlights.get("description")) if x)
    emails = sorted(set(_EMAIL_RE.findall(text)))
    if emails:
        attrs["emails"] = emails[:20]
    return attrs


def normalize(item: dict, tenant_id: str | None = None) -> NormalizedEvent:
    """Transforme un item du flux v4 (éventuellement enrichi de `_detail`)."""
    meta = item.get("metadata") or {}
    detail = item.get("_detail") or {}
    header = detail.get("header") or {}
    tmeta = item.get("tenant_metadata") or {}
    highlights = item.get("highlights") or {}

    raw_type = meta.get("type") or detail.get("event_type") or (detail.get("metadata") or {}).get("type")
    source_type = canonical_type(raw_type)

    sev = tmeta.get("severity") or {}
    severity_value = (sev.get("override") if isinstance(sev, dict) else None) or meta.get("severity") \
        or (sev.get("original") if isinstance(sev, dict) else None)

    risk = (header.get("risk") or {}).get("score") if isinstance(header.get("risk"), dict) else None

    title = highlights.get("title") or header.get("title") or f"{source_type} event"
    if isinstance(title, list):
        title = " ".join(map(str, title))
    description = highlights.get("description") or ""
    if isinstance(description, list):
        description = " … ".join(map(str, description))

    status = None
    if header.get("remediated_at"):
        status = "remediated"
    elif header.get("ignored_at"):
        status = "ignored"

    return NormalizedEvent(
        uid=str(meta.get("uid") or item.get("uid")),
        source_type=source_type,
        category=categorize(source_type),
        severity=Severity.parse(severity_value),
        title=str(title)[:500],
        description=str(description)[:4000],
        created_at=_parse_dt(meta.get("estimated_created_at")),
        matched_at=_parse_dt(meta.get("matched_at")),
        tenant_id=tenant_id,
        identifiers=[str(i.get("name")) for i in item.get("identifiers") or [] if isinstance(i, dict)],
        tags=list(tmeta.get("tags") or header.get("tags") or []),
        risk_score=int(risk) if isinstance(risk, (int, float)) else None,
        status=status,
        attributes=extract_attributes(source_type, item, detail),
        raw=item,
    )
