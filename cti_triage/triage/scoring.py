"""Modèle expert : accumulation d'évidence en log-odds (type Bayes naïf /
"weight of evidence") sur des critères multi-critères (impact, exploitabilité,
fiabilité de la source, criticité de l'actif, fraîcheur, contexte).

p = sigmoid(base + Σ w_i · x_i)

Avantages : interprétable (chaque terme est une raison affichée dans JIRA),
fonctionne à froid sans données labellisées, et produit une probabilité
qui se mélange naturellement avec le modèle supervisé (learner.py).
"""

from __future__ import annotations

import math

from ..models import NormalizedEvent


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1 / (1 + math.exp(-x))
    e = math.exp(x)
    return e / (1 + e)


def logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def expert_log_odds(ev: NormalizedEvent, feats: dict[str, float], cfg: dict,
                    *, is_duplicate: bool = False, in_burst: bool = False,
                    novelty: float = 0.0) -> tuple[float, dict[str, float]]:
    w = cfg["weights"]
    sig = w["signals"]
    comp: dict[str, float] = {"base": cfg["prior"]["base_log_odds"]}

    comp["category"] = w["category"].get(ev.category.value, 0.0)
    comp["severity"] = w["severity"].get(ev.severity.value, 0.0)

    rel = cfg.get("source_reliability", {})
    comp["source_reliability"] = rel.get(ev.source_type, rel.get("default", 0.0))

    if feats["credential_valid"]:
        comp["credential_valid"] = sig["credential_valid"]
    if feats["credential_invalid"]:
        comp["credential_invalid"] = sig["credential_invalid"]
    if feats["has_password_plain"]:
        comp["password_plain"] = sig["has_password_plain"]
    if feats["has_password_hash"]:
        comp["password_hash"] = sig["has_password_hash"]
    if feats["has_session_cookies"]:
        comp["session_cookies"] = sig["has_session_cookies"]
    if feats["contains_secrets"]:
        comp["secrets"] = sig["contains_secrets"]
    if feats["critical_identifier"]:
        comp["critical_identifier"] = sig["critical_identifier"]
    if feats["known_actor"]:
        comp["known_actor"] = sig["known_actor"]
    if in_burst:
        comp["burst"] = sig["burst"]
    if novelty > 0:
        comp["novelty"] = sig["novelty"] * novelty
    if is_duplicate:
        comp["duplicate"] = sig["duplicate"]

    comp["staleness"] = sig["old_event"] * (1 - feats["freshness"])

    # Score de risque Flare (si présent dans le détail v2) : léger ajustement.
    if feats["risk_score"]:
        comp["flare_risk"] = (feats["risk_score"] - 0.5) * 1.0

    total = sum(comp.values())
    return total, {k: round(v, 3) for k, v in comp.items() if v}


REASON_LABELS = {
    "category": "impact de la catégorie",
    "severity": "sévérité Flare",
    "source_reliability": "fiabilité de la source",
    "credential_valid": "identifiant validé",
    "credential_invalid": "identifiant invalide",
    "password_plain": "mot de passe en clair",
    "password_hash": "hash de mot de passe",
    "session_cookies": "cookies de session volés (contournement MFA possible)",
    "secrets": "secrets exposés dans du code",
    "critical_identifier": "actif critique du client",
    "known_actor": "acteur suivi (watchlist)",
    "burst": "pic de volume dans la catégorie",
    "novelty": "événement atypique (anomalie)",
    "duplicate": "doublon d'un événement déjà traité",
    "staleness": "événement ancien",
    "flare_risk": "score de risque Flare",
    "ml": "modèle appris sur les retours analystes",
}


def explain(components: dict[str, float], top: int = 5) -> list[str]:
    items = [(k, v) for k, v in components.items() if k != "base"]
    items.sort(key=lambda kv: -abs(kv[1]))
    return [f"{'+' if v > 0 else '−'} {REASON_LABELS.get(k, k)} ({v:+.2f})" for k, v in items[:top]]
