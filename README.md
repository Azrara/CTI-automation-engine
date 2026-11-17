# CTI Automation Engine

Moteur de triage des événements **Flare.io** d'un tenant : il récupère les
événements par l'API, les normalise, les classe en grandes catégories, calcule
des statistiques, élimine le bruit avec un modèle de triage hybride, puis crée
dans **JIRA** uniquement les alertes à notifier au client.

> Statut : premier squelette (v0.1). Fonctionne de bout en bout sur des données
> synthétiques ; à valider sur un vrai tenant.

## Architecture

```
cti_triage/
├── config.py          # variables d'environnement + config/triage.toml
├── models.py          # NormalizedEvent, Category, Severity, Decision
├── flare/
│   ├── client.py      # auth (token 1 h), rate limit, retry 429, pagination from/next
│   └── ingest.py      # ingestion incrémentale, curseur persisté
├── normalize.py       # types Flare -> type canonique -> catégorie, extraction d'attributs
├── analytics.py       # stats par catégorie/sévérité/jour, latence, pics de volume
├── triage/
│   ├── dedup.py       # empreinte exacte + SimHash (quasi-doublons)
│   ├── features.py    # vecteur de caractéristiques
│   ├── scoring.py     # score expert en log-odds, explications
│   ├── anomaly.py     # Isolation Forest (Python pur)
│   ├── learner.py     # régression logistique sur retours analystes + active learning
│   └── engine.py      # cascade : règles → dédup → contexte → scores → décision
├── jira/client.py     # création de tickets (ADF), idempotence, dry-run local
├── storage.py         # SQLite local : curseur, événements, décisions, labels, tickets
├── pipeline.py        # orchestration
└── cli.py             # ligne de commande
```

Détails : [docs/flare-ingestion.md](docs/flare-ingestion.md) (choix de l'API Flare)
et [docs/triage-model.md](docs/triage-model.md) (revue de littérature et modèle).

### Catégories

`credential_exposure`, `infected_device`, `data_leak`, `source_code_secret`,
`brand_impersonation`, `financial_fraud`, `threat_actor_chatter`,
`attack_surface`, `other`.

### Décisions

- **NOTIFY** : ticket JIRA créé (score ≥ 0,70) ;
- **REVIEW** : zone grise pour l'analyste (0,40 – 0,70) ;
- **SUPPRESS** : bruit, doublon, événement corrigé ou ignoré.

## Utilisation

Python ≥ 3.11, aucune dépendance externe.

```bash
cp .env.example .env        # remplir les variables, ne jamais commiter .env
set -a; . ./.env; set +a

python -m cti_triage triage-file tests/fixtures/sample_feed.json   # hors ligne
python -m cti_triage run --max-pages 5      # Flare -> triage -> JIRA (dry-run par défaut)
python -m cti_triage stats
python -m cti_triage review-queue           # cas incertains à labelliser en priorité
python -m cti_triage feedback <uid> 1       # 1 = à notifier, 0 = bruit
python -m cti_triage train                  # réentraîne le modèle (≥ 30 labels)
```

Tant que `JIRA_DRY_RUN=true`, aucun ticket n'est envoyé : ils sont écrits dans
`data/jira_dry_run.jsonl`. Toutes les données (état, modèle) restent dans `data/`, en local.

## Tests

```bash
python -m unittest discover -s tests -t .
```
