"""Déduplication exacte (empreinte) et quasi-doublons (SimHash, Charikar 2002).

Flare remonte souvent la même fuite plusieurs fois (re-post sur un autre
forum, même combo dans un nouveau dump, même lookalike sous plusieurs
angles). Ces répétitions sont la première source de bruit.
"""

from __future__ import annotations

import hashlib
import re

from ..models import NormalizedEvent

_TOKEN_RE = re.compile(r"[a-z0-9@._-]{2,}")


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower()).strip()


def fingerprint(ev: NormalizedEvent) -> str:
    """Empreinte exacte : même catégorie + mêmes entités clés."""
    parts = [
        ev.category.value,
        ev.source_type,
        ",".join(sorted(ev.identifiers)),
        ",".join(ev.attributes.get("emails", [])),
        str(ev.attributes.get("actor", "")).lower(),
        _norm_text(ev.title)[:200],
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _features(ev: NormalizedEvent) -> list[str]:
    text = _norm_text(f"{ev.title} {ev.description}")
    tokens = _TOKEN_RE.findall(text)
    shingles = [" ".join(tokens[i:i + 2]) for i in range(max(1, len(tokens) - 1))]
    return shingles + [f"id:{i}" for i in ev.identifiers]


def simhash(ev: NormalizedEvent, bits: int = 64) -> int:
    v = [0] * bits
    for feat in _features(ev):
        h = int.from_bytes(hashlib.blake2b(feat.encode(), digest_size=8).digest(), "big")
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def find_near_duplicate(sh: int, candidates: list[tuple[str, int]], max_distance: int) -> str | None:
    best: tuple[int, str] | None = None
    for uid, other in candidates:
        d = hamming(sh, other)
        if d <= max_distance and (best is None or d < best[0]):
            best = (d, uid)
    return best[1] if best else None
