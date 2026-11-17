# Ingestion Flare : méthode retenue

Source : documentation API Flare (https://api.docs.flare.io), lue le 17/11/2026.

## Choix : polling incrémental du flux du tenant (v4)

| Étape | Appel | Détail |
|---|---|---|
| Authentification | `POST /tokens/generate` | Clé API brute dans `Authorization` (sans « Bearer »), body optionnel `{"tenant_id": <id>}`. Token valable 1 h, régénéré automatiquement. |
| Flux | `POST /firework/v4/events/tenant/_search` | `size` ≤ 10, `sort=matched_at`, `order=asc`, filtres optionnels `severity` (chaîne = « ≥ »), `type`, `matched_at`. |
| Pagination | `from` = `next` de la page précédente | **Tous les autres paramètres doivent rester identiques**. Une page vide n'est pas la fin ; on s'arrête quand `next` est absent. |
| Détail | `GET /firework/v2/activities/?uid=<uid>` | Le flux ne contient que le minimum. La v4 `GET /firework/v4/events/?uid=` est en beta. Permission « Read All ». |
| Limites | 1 req/s (recherche), 4 req/s (autres) | Sur HTTP 429 `RATELIMIT_REACHED`, attendre 10 s. |

Le curseur `next` est sauvegardé en SQLite après chaque page : l'exécution
suivante reprend exactement où la précédente s'est arrêtée. La déduplication
sur `metadata.uid` absorbe les éventuels rejeux.

## Alternatives écartées

- **`/firework/v2/me/feed`** : déprécié, remplacé par l'endpoint v4.
- **`/firework/v4/events/global/_search`** : recherche sur tout Flare, soumise à quota mensuel ; inutile pour un tenant.
- **Webhooks Flare** : canal d'alertes (signé HMAC-SHA256, en-tête `X-Flare-Signature`), pas un abonnement événement par événement documenté. Pourrait servir plus tard de déclencheur temps réel, mais le polling reste la source de vérité.
- **Intégration JIRA native de Flare** : crée des tickets sans filtrage de triage documenté ; c'est précisément ce qu'on veut éviter.
- **SDK `flareio`** (PyPI) : gère token et pagination (`scroll`, `scroll_events`). Non utilisé pour garder zéro dépendance, mais `FlareClient` est isolé et remplaçable.

## Points à vérifier sur un vrai tenant

- Champ de type : `metadata.type` dans le flux, `event_type` dans le détail v4 (noms différents, voir `TYPE_ALIASES` dans `cti_triage/normalize.py`).
- Structure exacte de `data` selon le type (mot de passe, cookies, acteur, volumétrie).
- Durée de validité d'un curseur `next` sauvegardé longtemps.
