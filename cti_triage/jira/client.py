"""Export des alertes qualifiées vers JIRA Cloud (REST API v3).

- Auth Basic (email + token API) lue depuis l'environnement.
- Idempotence : label `flare-<uid>` + table locale `jira_issues`. Avant de
  créer, on vérifie en local puis par JQL qu'aucun ticket n'existe déjà.
- Mode DRY RUN par défaut (JIRA_DRY_RUN=true) : les tickets sont écrits
  dans un fichier JSONL local, rien n'est envoyé.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

from ..config import JiraSettings
from ..flare.client import Transport, urllib_transport
from ..models import TriageResult
from ..storage import StateStore

log = logging.getLogger(__name__)

PRIORITY_BY_SEVERITY = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}


def _adf_paragraph(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]} if text else {"type": "paragraph"}


def _adf_bullets(lines: list[str]) -> dict:
    return {"type": "bulletList", "content": [
        {"type": "listItem", "content": [_adf_paragraph(line)]} for line in lines]}


def build_issue_fields(result: TriageResult, settings: JiraSettings) -> dict[str, Any]:
    ev = result.event
    summary = f"[{ev.category.value}] {ev.title}"[:250]
    facts = [
        f"Flare UID : {ev.uid}",
        f"Type : {ev.source_type} — Catégorie : {ev.category.value}",
        f"Sévérité Flare : {ev.severity.value}",
        f"Score de triage : {result.score:.2f}",
        f"Détecté le : {ev.matched_at.isoformat() if ev.matched_at else 'n/a'}",
        f"Identifiants concernés : {', '.join(ev.identifiers) or 'n/a'}",
    ]
    description = {
        "type": "doc", "version": 1,
        "content": [
            {"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": "Résumé"}]},
            _adf_paragraph(ev.description[:3000]),
            {"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": "Faits"}]},
            _adf_bullets(facts),
            {"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": "Pourquoi cette alerte"}]},
            _adf_bullets(result.reasons or ["n/a"]),
        ],
    }
    return {
        "project": {"key": settings.project_key},
        "issuetype": {"name": settings.issue_type},
        "summary": summary,
        "description": description,
        "labels": ["cti-triage", f"flare-{ev.uid}"[:255], ev.category.value, ev.source_type],
        "priority": {"name": PRIORITY_BY_SEVERITY.get(ev.severity.value, "Medium")},
    }


class JiraExporter:
    def __init__(self, settings: JiraSettings, store: StateStore, transport: Transport = urllib_transport,
                 dry_run_path: str | Path = "data/jira_dry_run.jsonl"):
        self.settings = settings
        self.store = store
        self._transport = transport
        self.dry_run_path = Path(dry_run_path)

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self.settings.email}:{self.settings.api_token}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json",
                "Content-Type": "application/json"}

    def _exists_remote(self, uid: str) -> str | None:
        jql = f'project = "{self.settings.project_key}" AND labels = "flare-{uid}"'
        status, raw = self._transport(
            "POST", self.settings.base_url.rstrip("/") + "/rest/api/3/search/jql", self._headers(),
            json.dumps({"jql": jql, "maxResults": 1, "fields": ["key"]}).encode())
        if status == 200:
            issues = json.loads(raw).get("issues") or []
            return issues[0]["key"] if issues else None
        log.warning("recherche JQL impossible (%s), on continue", status)
        return None

    def export(self, result: TriageResult) -> str | None:
        uid = result.event.uid
        existing = self.store.jira_issue_for(uid)
        if existing:
            return existing
        fields = build_issue_fields(result, self.settings)

        if self.settings.dry_run:
            self.dry_run_path.parent.mkdir(parents=True, exist_ok=True)
            with self.dry_run_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"fields": fields}, ensure_ascii=False, default=str) + "\n")
            key = f"DRYRUN-{uid}"
            self.store.save_jira_issue(uid, key)
            return key

        remote = self._exists_remote(uid)
        if remote:
            self.store.save_jira_issue(uid, remote)
            return remote
        status, raw = self._transport(
            "POST", self.settings.base_url.rstrip("/") + "/rest/api/3/issue", self._headers(),
            json.dumps({"fields": fields}).encode())
        if status not in (200, 201):
            raise RuntimeError(f"JIRA {status}: {raw[:500].decode(errors='replace')}")
        key = json.loads(raw)["key"]
        self.store.save_jira_issue(uid, key)
        return key
