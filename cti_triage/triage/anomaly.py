"""Isolation Forest (Liu, Ting & Zhou, ICDM 2008) en Python pur.

Sert à repérer les événements atypiques par rapport à l'historique du
tenant (ex. un stealer log sur un domaine jamais vu, un volume inhabituel).
Score s(x) = 2^(-E[h(x)] / c(n)) ∈ ]0,1] ; > 0.6 est généralement anormal.
On renvoie une "nouveauté" ramenée à [0,1] : max(0, (s - 0.5) * 2).

Remplaçable par sklearn.ensemble.IsolationForest si scikit-learn est installé.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass


def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n


@dataclass
class _Node:
    size: int
    feature: int = -1
    split: float = 0.0
    left: "_Node | None" = None
    right: "_Node | None" = None


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int = 42):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.rng = random.Random(seed)
        self.trees: list[_Node] = []
        self._psi = 0

    def fit(self, X: list[list[float]]) -> "IsolationForest":
        if not X:
            return self
        self._psi = min(self.sample_size, len(X))
        limit = math.ceil(math.log2(max(self._psi, 2)))
        self.trees = [self._build(self.rng.sample(X, self._psi), 0, limit) for _ in range(self.n_trees)]
        return self

    def _build(self, X: list[list[float]], depth: int, limit: int) -> _Node:
        if depth >= limit or len(X) <= 1:
            return _Node(size=len(X))
        dims = [j for j in range(len(X[0])) if min(r[j] for r in X) < max(r[j] for r in X)]
        if not dims:
            return _Node(size=len(X))
        j = self.rng.choice(dims)
        lo, hi = min(r[j] for r in X), max(r[j] for r in X)
        split = self.rng.uniform(lo, hi)
        left = [r for r in X if r[j] < split]
        right = [r for r in X if r[j] >= split]
        return _Node(size=len(X), feature=j, split=split,
                     left=self._build(left, depth + 1, limit),
                     right=self._build(right, depth + 1, limit))

    def _path(self, x: list[float], node: _Node, depth: int) -> float:
        if node.left is None or node.right is None:
            return depth + _c(node.size)
        nxt = node.left if x[node.feature] < node.split else node.right
        return self._path(x, nxt, depth + 1)

    def score(self, x: list[float]) -> float:
        if not self.trees:
            return 0.5
        mean_h = sum(self._path(x, t, 0) for t in self.trees) / len(self.trees)
        return 2 ** (-mean_h / max(_c(self._psi), 1e-9))

    def novelty(self, x: list[float]) -> float:
        return max(0.0, min(1.0, (self.score(x) - 0.5) * 2))
