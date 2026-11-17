"""Client HTTP minimal pour l'API Flare (https://api.docs.flare.io).

Choix d'ingestion (cf. docs/flare-ingestion.md) :
- Auth : POST /tokens/generate avec la clé API brute dans `Authorization`
  (body optionnel {"tenant_id": ...}) -> token Bearer valable 1 h.
- Flux : POST /firework/v4/events/tenant/_search, pagination par curseur
  (`from` = `next` de la réponse précédente, autres paramètres identiques).
- Détail : GET /firework/v2/activities/?uid=<uid> (stable) ; la v4
  /firework/v4/events/?uid= est en beta.
- Rate limit : 1 req/s pour la recherche, 4 req/s sinon ; sur 429 attendre 10 s.

Pas de dépendance externe : urllib uniquement. Le SDK officiel `flareio`
peut remplacer cette classe plus tard sans toucher au reste du pipeline.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator

from ..config import FlareSettings

log = logging.getLogger(__name__)

TENANT_FEED_PATH = "/firework/v4/events/tenant/_search"
EVENT_DETAIL_V2_PATH = "/firework/v2/activities/"
EVENT_DETAIL_V4_PATH = "/firework/v4/events/"
TOKEN_PATH = "/tokens/generate"

TOKEN_TTL_SECONDS = 3600
TOKEN_REFRESH_MARGIN = 300
RATE_LIMIT_BACKOFF = 10.0


class FlareApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"Flare API {status}: {message}")
        self.status = status


class Limiter:
    """Limiteur simple : au plus un appel tous les `interval` secondes."""

    def __init__(self, interval: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = interval
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = self._clock()
            if now < self._next:
                self._sleep(self._next - now)
                now = self._next
            self._next = now + self.interval


Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


class FlareClient:
    def __init__(self, settings: FlareSettings, transport: Transport = urllib_transport,
                 sleep: Callable[[float], None] = time.sleep, max_retries: int = 5):
        self.settings = settings
        self._transport = transport
        self._sleep = sleep
        self._max_retries = max_retries
        self._token: str | None = None
        self._token_expiry = 0.0
        self.search_limiter = Limiter(1.0, sleep=sleep)
        self.default_limiter = Limiter(0.25, sleep=sleep)

    # -- authentification -------------------------------------------------
    def _ensure_token(self) -> str:
        if self._token and time.time() < self._token_expiry - TOKEN_REFRESH_MARGIN:
            return self._token
        body: dict[str, Any] = {}
        if self.settings.tenant_id is not None:
            body["tenant_id"] = self.settings.tenant_id
        status, raw = self._transport(
            "POST",
            self.settings.base_url + TOKEN_PATH,
            {"Authorization": self.settings.api_key, "Content-Type": "application/json"},
            json.dumps(body).encode(),
        )
        if status != 200:
            raise FlareApiError(status, "échec de génération du token (clé API invalide ?)")
        self._token = json.loads(raw)["token"]
        self._token_expiry = time.time() + TOKEN_TTL_SECONDS
        return self._token

    # -- requêtes ---------------------------------------------------------
    def request(self, method: str, path: str, *, json_body: Any = None,
                params: dict[str, str] | None = None, search: bool = False) -> Any:
        url = self.settings.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(json_body).encode() if json_body is not None else None
        limiter = self.search_limiter if search else self.default_limiter

        for attempt in range(self._max_retries + 1):
            limiter.wait()
            headers = {"Authorization": f"Bearer {self._ensure_token()}",
                       "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, raw = self._transport(method, url, headers, data)
            if status == 200:
                return json.loads(raw) if raw else None
            if status == 401 and attempt == 0:
                self._token = None           # token expiré : on régénère une fois
                continue
            if status == 429 or status in (502, 503, 504):
                wait = RATE_LIMIT_BACKOFF * (attempt + 1)
                log.warning("Flare %s sur %s, nouvel essai dans %.0fs", status, path, wait)
                self._sleep(wait)
                continue
            raise FlareApiError(status, raw[:500].decode(errors="replace"))
        raise FlareApiError(429, f"abandon après {self._max_retries} essais sur {path}")

    # -- flux du tenant ---------------------------------------------------
    def build_feed_query(self) -> dict[str, Any]:
        """Paramètres FIXES de la recherche : ils ne doivent pas changer entre
        deux pages ni entre deux exécutions, sinon le curseur `next` est invalide."""
        query: dict[str, Any] = {
            "size": self.settings.page_size,
            "sort": "matched_at",
            "order": "asc",           # ordre croissant : le curseur avance vers le présent
        }
        filters: dict[str, Any] = {}
        if self.settings.min_severity:
            filters["severity"] = self.settings.min_severity     # chaîne = ">="
        if self.settings.event_types:
            filters["type"] = list(self.settings.event_types)
        if filters:
            query["filters"] = filters
        return query

    def iter_feed_pages(self, cursor: str | None = None) -> Iterator[tuple[list[dict], str | None]]:
        """Itère sur les pages du flux du tenant. Renvoie (items, next).

        Une page vide n'est PAS la fin (doc Flare) : on s'arrête seulement
        quand `next` est absent, ou quand il ne bouge plus (on a rattrapé le présent).
        """
        base = self.build_feed_query()
        while True:
            body = dict(base)
            if cursor:
                body["from"] = cursor
            resp = self.request("POST", TENANT_FEED_PATH, json_body=body, search=True) or {}
            items = resp.get("items") or []
            nxt = resp.get("next")
            yield items, nxt
            if not nxt or nxt == cursor:
                return
            cursor = nxt

    def get_event_detail(self, uid: str) -> dict[str, Any]:
        resp = self.request("GET", EVENT_DETAIL_V2_PATH, params={"uid": uid}) or {}
        return resp.get("activity", resp)

