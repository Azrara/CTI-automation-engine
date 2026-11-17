"""Moteur de triage en cascade.

1. Règles dures      : statut remediated/ignored, types toujours/jamais notifiés.
2. Déduplication      : empreinte exacte puis SimHash (quasi-doublons).
3. Contexte           : pics de volume par catégorie (analytics.detect_bursts).
4. Anomalie           : Isolation Forest sur l'historique du tenant.
5. Score expert       : log-odds multi-critères, interprétable.
6. Score appris       : régression logistique sur les retours analystes,
                        mélangée au score expert selon le nombre de labels.
7. Décision           : NOTIFY / REVIEW / SUPPRESS selon des seuils.
"""

from __future__ import annotations

from datetime import datetime

from ..models import Decision, NormalizedEvent, TriageResult
from ..storage import StateStore
from . import dedup
from .anomaly import IsolationForest
from .features import extract, vectorize
from .learner import LogisticLearner, blend
from .scoring import expert_log_odds, explain, sigmoid


class TriageEngine:
    def __init__(self, cfg: dict, store: StateStore, learner: LogisticLearner | None = None,
                 history: list[NormalizedEvent] | None = None, now: datetime | None = None):
        self.cfg = cfg
        self.store = store
        self.learner = learner
        self.now = now
        ctx = cfg.get("context", {})
        self.ctx = {
            "critical_identifiers": ctx.get("critical_identifiers", []),
            "actor_watchlist": ctx.get("actor_watchlist", []),
            "half_life_days": cfg.get("freshness", {}).get("half_life_days", 30),
        }
        self.burst_keys: set[tuple[str, str]] = set()
        self.forest: IsolationForest | None = None
        if history:
            self.fit_context(history)

    # -- contexte historique ---------------------------------------------
    def fit_context(self, history: list[NormalizedEvent]) -> None:
        from ..analytics import event_stats

        stats = event_stats(history)
        self.burst_keys = {(b["day"], b["category"]) for b in stats["bursts"]}
        an = self.cfg.get("anomaly", {})
        if an.get("enabled", True) and len(history) >= an.get("min_history", 200):
            X = [vectorize(extract(e, self.ctx, self.now)) for e in history]
            self.forest = IsolationForest(an.get("n_trees", 100), an.get("sample_size", 256)).fit(X)

    # -- triage d'un événement -------------------------------------------
    def triage(self, ev: NormalizedEvent, persist: bool = True) -> TriageResult:
        rules = self.cfg.get("context", {})
        th = self.cfg["thresholds"]

        # 1. Règles dures
        if ev.status in rules.get("suppress_status", []):
            return self._finish(ev, Decision.SUPPRESS, 0.0, [f"statut Flare : {ev.status}"], {}, None, persist)
        if ev.source_type in rules.get("never_notify_types", []):
            return self._finish(ev, Decision.SUPPRESS, 0.0, [f"type exclu : {ev.source_type}"], {}, None, persist)

        # 2. Déduplication
        fp = dedup.fingerprint(ev)
        sh = dedup.simhash(ev)
        dup_of = self.store.find_by_fingerprint(fp, ev.uid)
        if dup_of is None:
            dup_of = dedup.find_near_duplicate(
                sh, [c for c in self.store.recent_simhashes(ev.category.value) if c[0] != ev.uid],
                self.cfg.get("dedup", {}).get("simhash_max_hamming", 3))
        if persist:
            self.store.save_event(ev.uid, ev.category.value, ev.source_type, ev.severity.value, fp, sh,
                                  ev.created_at.isoformat() if ev.created_at else None, ev.to_dict())

        # 3-4. Contexte et anomalie
        feats = extract(ev, self.ctx, self.now)
        x = vectorize(feats)
        day = (ev.matched_at or ev.created_at)
        in_burst = bool(day and (day.date().isoformat(), ev.category.value) in self.burst_keys)
        novelty = self.forest.novelty(x) if self.forest else 0.0

        # 5. Score expert
        lo, comp = expert_log_odds(ev, feats, self.cfg, is_duplicate=dup_of is not None,
                                   in_burst=in_burst, novelty=novelty)
        p_expert = sigmoid(lo)

        # 6. Score appris
        lcfg = self.cfg.get("learning", {})
        p_ml = None
        if self.learner and self.learner.n_labels >= lcfg.get("min_labels", 30):
            p_ml = self.learner.predict_proba(x)
        p, alpha = blend(p_expert, p_ml, self.learner.n_labels if self.learner else 0, lcfg.get("blend_k", 200))
        if p_ml is not None:
            comp["ml"] = round(alpha, 3)
            comp["p_ml"] = round(p_ml, 3)
        comp["p_expert"] = round(p_expert, 3)

        # 7. Décision
        if ev.source_type in rules.get("always_notify_types", []) and dup_of is None:
            decision = Decision.NOTIFY
        elif p >= th["notify"]:
            decision = Decision.NOTIFY
        elif p >= th["review"]:
            decision = Decision.REVIEW
        else:
            decision = Decision.SUPPRESS
        if dup_of is not None:
            decision = Decision.SUPPRESS      # rattaché à l'original, déjà traité

        reasons = explain({k: v for k, v in comp.items() if not k.startswith("p_") and k != "ml"})
        return self._finish(ev, decision, p, reasons, comp, dup_of, persist)

    def _finish(self, ev, decision, score, reasons, comp, dup_of, persist) -> TriageResult:
        if persist:
            if not self.store.has_event(ev.uid):
                fp, sh = dedup.fingerprint(ev), dedup.simhash(ev)
                self.store.save_event(ev.uid, ev.category.value, ev.source_type, ev.severity.value, fp, sh,
                                      ev.created_at.isoformat() if ev.created_at else None, ev.to_dict())
            self.store.save_decision(ev.uid, decision.value, score, reasons, comp, dup_of)
        return TriageResult(event=ev, decision=decision, score=round(score, 4), reasons=reasons,
                            components=comp, duplicate_of=dup_of)
