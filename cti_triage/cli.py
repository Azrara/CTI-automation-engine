"""Interface en ligne de commande.

  python -m cti_triage run [--max-pages N]        # Flare -> triage -> JIRA (dry-run par défaut)
  python -m cti_triage triage-file events.json    # hors ligne, depuis un export JSON local
  python -m cti_triage stats                      # statistiques sur l'historique local
  python -m cti_triage feedback <uid> <0|1>       # retour analyste
  python -m cti_triage train                      # réentraîne le modèle supervisé
  python -m cti_triage review-queue               # événements à faire labelliser en priorité
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .analytics import event_stats
from .config import AppSettings, FlareSettings, JiraSettings, load_triage_config
from .jira.client import JiraExporter
from .pipeline import load_history, run, train
from .storage import StateStore


def _print(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cti_triage")
    parser.add_argument("--config", help="chemin du fichier triage.toml")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run")
    p_run.add_argument("--max-pages", type=int)
    p_file = sub.add_parser("triage-file")
    p_file.add_argument("path")
    p_file.add_argument("--no-export", action="store_true")
    sub.add_parser("stats")
    p_fb = sub.add_parser("feedback")
    p_fb.add_argument("uid")
    p_fb.add_argument("label", type=int, choices=[0, 1])
    sub.add_parser("train")
    sub.add_parser("review-queue")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_triage_config(args.config)
    store = StateStore(AppSettings.from_env().state_db)

    if args.cmd == "run":
        from .flare.client import FlareClient
        from .flare.ingest import iter_new_events

        flare = FlareSettings.from_env()
        client = FlareClient(flare)
        exporter = JiraExporter(JiraSettings.from_env(), store)
        report = run(iter_new_events(client, store, args.max_pages), store, cfg, exporter,
                     tenant_id=str(flare.tenant_id) if flare.tenant_id else None)
        _print(report.summary())
    elif args.cmd == "triage-file":
        with open(args.path, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data.get("items", data) if isinstance(data, dict) else data
        exporter = None if args.no_export else JiraExporter(JiraSettings.from_env(), store)
        report = run(items, store, cfg, exporter)
        _print({**report.summary(), "decisions": [
            {"uid": r.event.uid, "decision": r.decision.value, "score": r.score, "reasons": r.reasons}
            for r in report.results]})
    elif args.cmd == "stats":
        _print(event_stats(load_history(store)))
    elif args.cmd == "feedback":
        store.add_feedback(args.uid, args.label)
        print(f"retour enregistré : {args.uid} -> {args.label}")
    elif args.cmd == "train":
        model = train(store, cfg)
        _print({"trained": bool(model), "top_weights": model.top_weights() if model else []})
    elif args.cmd == "review-queue":
        rows = store.conn.execute(
            "SELECT uid, score FROM decisions WHERE decision='review' "
            "AND uid NOT IN (SELECT uid FROM feedback) ORDER BY ABS(score-0.5) LIMIT 20").fetchall()
        _print([dict(r) for r in rows])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
