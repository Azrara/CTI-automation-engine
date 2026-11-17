"""Orchestration : ingestion → normalisation → triage → export JIRA → stats."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .analytics import event_stats, triage_stats
from .jira.client import JiraExporter
from .models import Decision, NormalizedEvent, TriageResult
from .normalize import normalize
from .storage import StateStore
from .triage.engine import TriageEngine
from .triage.features import extract, vectorize
from .triage.learner import LogisticLearner

log = logging.getLogger(__name__)

MODEL_PATH = Path("data/model.json")


@dataclass
class RunReport:
    results: list[TriageResult] = field(default_factory=list)
    exported: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "events": event_stats(r.event for r in self.results),
            "triage": triage_stats(self.results),
            "jira_issues": self.exported,
        }


def load_history(store: StateStore) -> list[NormalizedEvent]:
    """Recharge l'historique normalisé (pour pics de volume et anomalies)."""
    from datetime import datetime

    from .models import Category, Severity

    out = []
    for d in store.load_events():
        out.append(NormalizedEvent(
            uid=d["uid"], source_type=d["source_type"], category=Category(d["category"]),
            severity=Severity.parse(d["severity"]), title=d.get("title", ""),
            description=d.get("description", ""),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else None,
            matched_at=datetime.fromisoformat(d["matched_at"]) if d.get("matched_at") else None,
            identifiers=d.get("identifiers", []), tags=d.get("tags", []),
            risk_score=d.get("risk_score"), status=d.get("status"),
            attributes=d.get("attributes", {})))
    return out


def run(raw_items: Iterable[dict], store: StateStore, cfg: dict, exporter: JiraExporter | None,
        tenant_id: str | None = None) -> RunReport:
    learner = LogisticLearner.load(MODEL_PATH)
    engine = TriageEngine(cfg, store, learner=learner, history=load_history(store))
    report = RunReport()
    for item in raw_items:
        ev = normalize(item, tenant_id)
        res = engine.triage(ev)
        report.results.append(res)
        if res.decision == Decision.NOTIFY and exporter is not None:
            key = exporter.export(res)
            if key:
                report.exported[ev.uid] = key
    return report


def train(store: StateStore, cfg: dict) -> LogisticLearner | None:
    """Réentraîne le modèle supervisé sur les retours analystes stockés."""
    from .triage.engine import TriageEngine as _E

    lcfg = cfg.get("learning", {})
    labelled = list(store.labelled_events())
    if len(labelled) < lcfg.get("min_labels", 30):
        log.info("seulement %d labels (< %d) : pas d'entraînement", len(labelled), lcfg.get("min_labels", 30))
        return None
    ctx = _E(cfg, store).ctx
    hist = {e.uid: e for e in load_history(store)}
    X, y = [], []
    for payload, label in labelled:
        ev = hist.get(payload["uid"])
        if ev:
            X.append(vectorize(extract(ev, ctx)))
            y.append(label)
    model = LogisticLearner(lr=lcfg.get("learning_rate", 0.05), l2=lcfg.get("l2", 1e-3),
                            epochs=lcfg.get("epochs", 30)).fit(X, y)
    model.save(MODEL_PATH)
    return model
