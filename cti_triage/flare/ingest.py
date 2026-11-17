"""Ingestion incrémentale du flux d'événements d'un tenant Flare.

Le curseur `next` est persisté après chaque page traitée : en cas d'arrêt,
la reprise repart de la dernière page validée (au pire on rejoue une page,
la déduplication sur `metadata.uid` absorbe les doublons).
"""

from __future__ import annotations

import logging
from typing import Iterator

from ..storage import StateStore
from .client import FlareApiError, FlareClient

log = logging.getLogger(__name__)


def feed_uid(item: dict) -> str | None:
    meta = item.get("metadata") or {}
    return meta.get("uid") or item.get("uid")


def iter_new_events(client: FlareClient, store: StateStore, max_pages: int | None = None) -> Iterator[dict]:
    """Renvoie les événements bruts jamais vus. Chaque élément est l'item du
    flux, enrichi de la clé `_detail` si FLARE_FETCH_DETAILS est actif."""
    cursor = store.get_cursor()
    pages = 0
    for items, nxt in client.iter_feed_pages(cursor):
        for item in items:
            uid = feed_uid(item)
            if not uid or store.has_event(uid):
                continue
            if client.settings.fetch_details:
                try:
                    item = {**item, "_detail": client.get_event_detail(uid)}
                except FlareApiError as exc:
                    log.warning("détail indisponible pour %s : %s", uid, exc)
            yield item
        # Page entièrement consommée par l'appelant : on valide le curseur.
        if nxt:
            store.set_cursor(nxt)
        pages += 1
        if max_pages is not None and pages >= max_pages:
            return
