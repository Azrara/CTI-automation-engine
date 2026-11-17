"""Statistiques et analytics sur les événements normalisés et les décisions."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from typing import Iterable

from .models import Decision, NormalizedEvent, TriageResult


def _day(ev: NormalizedEvent) -> str | None:
    dt = ev.matched_at or ev.created_at
    return dt.date().isoformat() if dt else None


def event_stats(events: Iterable[NormalizedEvent]) -> dict:
    events = list(events)
    by_cat = Counter(e.category.value for e in events)
    by_sev = Counter(e.severity.value for e in events)
    by_type = Counter(e.source_type for e in events)
    by_ident = Counter(i for e in events for i in e.identifiers)
    by_actor = Counter(e.attributes.get("actor") for e in events if e.attributes.get("actor"))
    per_day: dict[str, Counter] = defaultdict(Counter)
    latencies_h: list[float] = []
    for e in events:
        d = _day(e)
        if d:
            per_day[d][e.category.value] += 1
        if e.created_at and e.matched_at:
            latencies_h.append((e.matched_at - e.created_at).total_seconds() / 3600)

    return {
        "total": len(events),
        "by_category": dict(by_cat.most_common()),
        "by_severity": dict(by_sev.most_common()),
        "by_source_type": dict(by_type.most_common()),
        "top_identifiers": by_ident.most_common(10),
        "top_actors": by_actor.most_common(10),
        "per_day": {d: dict(c) for d, c in sorted(per_day.items())},
        "detection_latency_hours": _summary(latencies_h),
        "bursts": detect_bursts(per_day),
    }


def _summary(values: list[float]) -> dict:
    if not values:
        return {}
    values = sorted(values)
    return {
        "n": len(values),
        "median": round(statistics.median(values), 2),
        "p90": round(values[min(len(values) - 1, int(0.9 * len(values)))], 2),
        "max": round(values[-1], 2),
    }


def detect_bursts(per_day: dict[str, Counter], z_threshold: float = 3.0, min_days: int = 7) -> list[dict]:
    """Pics de volume par catégorie : z-score robuste (médiane / MAD).
    Un pic de fuites d'identifiants ou de lookalikes est souvent le signe
    d'une campagne en cours, à remonter même si chaque événement est faible."""
    days = sorted(per_day)
    if len(days) < min_days:
        return []
    cats = {c for counter in per_day.values() for c in counter}
    bursts = []
    for cat in cats:
        series = [per_day[d].get(cat, 0) for d in days]
        med = statistics.median(series)
        mad = statistics.median(abs(x - med) for x in series) or 1.0
        for d, x in zip(days, series):
            z = 0.6745 * (x - med) / mad
            if z >= z_threshold:
                bursts.append({"day": d, "category": cat, "count": x, "robust_z": round(z, 2)})
    return sorted(bursts, key=lambda b: -b["robust_z"])


def triage_stats(results: Iterable[TriageResult]) -> dict:
    results = list(results)
    n = len(results)
    by_dec = Counter(r.decision.value for r in results)
    dupes = sum(1 for r in results if r.duplicate_of)
    by_cat_dec: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        by_cat_dec[r.event.category.value][r.decision.value] += 1
    notified = by_dec.get(Decision.NOTIFY.value, 0)
    return {
        "total": n,
        "by_decision": dict(by_dec),
        "duplicates": dupes,
        "noise_reduction_ratio": round(1 - notified / n, 3) if n else None,
        "by_category_decision": {c: dict(v) for c, v in by_cat_dec.items()},
        "score_histogram": _histogram([r.score for r in results]),
    }


def _histogram(scores: list[float], bins: int = 10) -> list[int]:
    h = [0] * bins
    for s in scores:
        h[min(bins - 1, max(0, math.floor(s * bins)))] += 1
    return h
