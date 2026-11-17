"""Apprentissage à partir des retours analystes (human-in-the-loop).

- Régression logistique L2 entraînée par descente de gradient, avec
  pondération des classes (les vrais positifs sont rares).
- Sélection active (uncertainty sampling) : on propose en priorité aux
  analystes les événements dont la probabilité est proche de 0,5, ce qui
  maximise le gain d'information par label (Settles 2009 ; AI², Veeramachaneni
  et al. 2016).

Quand le volume de labels le permet (quelques milliers), remplacer par un
gradient boosting (XGBoost / LightGBM) calibré (isotonique ou Platt) : voir
docs/triage-model.md. L'interface `predict_proba` reste la même.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

from .features import FEATURE_NAMES
from .scoring import logit, sigmoid


class LogisticLearner:
    def __init__(self, n_features: int = len(FEATURE_NAMES), lr: float = 0.05,
                 l2: float = 1e-3, epochs: int = 30, seed: int = 7):
        self.w = [0.0] * n_features
        self.b = 0.0
        self.lr, self.l2, self.epochs = lr, l2, epochs
        self.rng = random.Random(seed)
        self.n_labels = 0

    def fit(self, X: list[list[float]], y: list[int]) -> "LogisticLearner":
        n = len(y)
        self.n_labels = n
        if n == 0:
            return self
        pos = sum(y) or 1
        neg = (n - sum(y)) or 1
        cw = {1: n / (2 * pos), 0: n / (2 * neg)}
        idx = list(range(n))
        for _ in range(self.epochs):
            self.rng.shuffle(idx)
            for i in idx:
                p = sigmoid(self.b + sum(wj * xj for wj, xj in zip(self.w, X[i])))
                g = (p - y[i]) * cw[y[i]]
                for j, xj in enumerate(X[i]):
                    self.w[j] -= self.lr * (g * xj + self.l2 * self.w[j])
                self.b -= self.lr * g
        return self

    def predict_proba(self, x: list[float]) -> float:
        return sigmoid(self.b + sum(wj * xj for wj, xj in zip(self.w, x)))

    def top_weights(self, k: int = 10) -> list[tuple[str, float]]:
        pairs = list(zip(FEATURE_NAMES, self.w))
        pairs.sort(key=lambda p: -abs(p[1]))
        return [(n, round(w, 3)) for n, w in pairs[:k]]

    # -- persistance locale ---------------------------------------------
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"features": FEATURE_NAMES, "w": self.w, "b": self.b,
                                          "n_labels": self.n_labels}))

    @classmethod
    def load(cls, path: str | Path) -> "LogisticLearner | None":
        p = Path(path)
        if not p.exists():
            return None
        data = json.loads(p.read_text())
        if data.get("features") != FEATURE_NAMES:
            return None          # schéma de features changé : réentraîner
        m = cls()
        m.w, m.b, m.n_labels = data["w"], data["b"], data.get("n_labels", 0)
        return m


def uncertainty_rank(probas: dict[str, float], k: int = 20) -> list[str]:
    """Uids à faire labelliser en priorité (les plus incertains)."""
    return [uid for uid, _ in sorted(probas.items(), key=lambda kv: abs(kv[1] - 0.5))[:k]]


def blend(p_expert: float, p_ml: float | None, n_labels: int, k: float) -> tuple[float, float]:
    """Mélange en log-odds ; le poids du modèle appris croît avec n_labels."""
    if p_ml is None or n_labels <= 0:
        return p_expert, 0.0
    alpha = n_labels / (n_labels + k)
    return sigmoid((1 - alpha) * logit(p_expert) + alpha * logit(p_ml)), alpha
