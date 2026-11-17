# Modèle de triage : revue de littérature et choix d'architecture

## 1. Le problème

Flare remonte pour un tenant un flux hétérogène (identifiants, stealer logs,
ransomleaks, lookalikes, forums, pastes…). La grande majorité de ces
événements ne justifie pas une notification client. Les études de terrain sur
les SOC montrent que la fatigue d'alerte est le premier problème opérationnel :
Alahmadi et al. (USENIX Security 2022) rapportent que les analystes estiment
une écrasante majorité de faux positifs et qu'ils ignorent les alertes dont
ils ne comprennent pas la raison. Deux exigences en découlent :

1. **réduire fortement le volume** (doublons, bruit, événements anciens ou corrigés) ;
2. **expliquer chaque décision**, sinon l'analyste et le client n'ont pas confiance.

Contrainte supplémentaire : au démarrage on n'a **aucune donnée labellisée**.

## 2. Ce que dit la littérature

| Famille | Références | Ce qu'on retient |
|---|---|---|
| Fatigue d'alerte, facteur humain | Alahmadi, Axon & Martinovic, *99% False Positives*, USENIX Security 2022 ; Ban et al., *Combat Security Alert Fatigue with AI-Assisted Techniques*, CSET 2021 | L'explication de l'alerte compte autant que le score. Les approches ML purement « boîte noire » sont mal adoptées. |
| Corrélation et agrégation d'alertes | Valeur, Vigna, Kruegel & Kemmerer, *A Comprehensive Approach to Intrusion Detection Alert Correlation*, IEEE TDSC 2004 | Pipeline en étapes : normalisation, fusion des doublons, vérification, priorisation. C'est l'ossature retenue. |
| Quasi-doublons | Charikar, *Similarity Estimation Techniques from Rounding Algorithms* (SimHash), STOC 2002 ; Broder, *On the resemblance and containment of documents* (MinHash), 1997 | Les re-posts d'une même fuite sont la première source de bruit en CTI. SimHash 64 bits + distance de Hamming suffit et passe à l'échelle. |
| Triage par contexte et provenance | Hassan et al., *NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage*, NDSS 2019 | Scorer une alerte selon la rareté de son contexte dans l'historique (« ce qui est fréquent est rarement grave »). D'où le facteur d'anomalie et les pics de volume. |
| Regroupement sémantique semi-supervisé | van Ede et al., *DeepCASE: Semi-Supervised Contextual Analysis of Security Events*, IEEE S&P 2022 | Regrouper les événements similaires et faire labelliser un représentant par groupe : divise fortement l'effort analyste. Piste pour la v2. |
| Détection d'anomalies | Liu, Ting & Zhou, *Isolation Forest*, ICDM 2008 ; Aminanto et al., *Automated Threat-Alert Screening for Battling Alert Fatigue with Temporal Isolation Forest*, PST 2019 | Isolation Forest est rapide, sans label, et a été appliqué précisément au tri d'alertes. |
| Apprentissage avec l'analyste dans la boucle | Veeramachaneni et al., *AI²: Training a Big Data Machine to Defend*, IEEE BigDataSecurity 2016 ; Settles, *Active Learning Literature Survey*, 2009 | Démarrer non supervisé, puis apprendre des retours analystes en leur montrant en priorité les cas incertains (uncertainty sampling). |
| Classifieurs tabulaires | Chen & Guestrin, *XGBoost*, KDD 2016 ; Platt 1999 / Zadrozny & Elkan 2002 (calibration) | Une fois quelques milliers de labels disponibles, le gradient boosting calibré est l'état de l'art pratique sur ce type de données. |
| Priorisation par vraisemblance d'exploitation | Jacobs et al., *Exploit Prediction Scoring System (EPSS)*, Digital Threats 2021 | Séparer impact et probabilité d'exploitation ; produire une probabilité calibrée plutôt qu'un score arbitraire. |
| Risque des identifiants volés | Thomas et al., *Data Breaches, Phishing, or Malware? Understanding the Risks of Stolen Credentials*, CCS 2017 | Les identifiants issus d'infostealers/phishing sont bien plus dangereux que ceux des vieux dumps : justifie le poids fort des stealer logs, des cookies de session et des identifiants validés. |
| Typosquatting / lookalikes | Kintis et al., *Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse*, CCS 2017 | Un lookalike n'est dangereux que s'il est « armé » (MX, certificat, contenu). Signaux à extraire en v2. |
| Aide multicritère à la décision | Saaty, AHP, 1980 ; Hwang & Yoon, TOPSIS, 1981 | Formaliser impact × exploitabilité × fiabilité × criticité de l'actif × fraîcheur avec des poids révisables. |

## 3. Architecture retenue : cascade hybride

```
Flare ─► normalisation ─► règles dures ─► dédup (empreinte + SimHash)
      ─► contexte (pics de volume, Isolation Forest)
      ─► score expert (log-odds multicritère, explicable)
      ─► score appris (régression logistique, puis XGBoost) mélangé selon nb de labels
      ─► décision NOTIFY / REVIEW / SUPPRESS ─► JIRA
                                  ▲
                 retours analystes (active learning)
```

**Pourquoi des log-odds ?** Chaque critère ajoute une « évidence » w·x à la
cote de départ (fréquence de base des vrais positifs). C'est la forme d'un
Bayes naïf : interprétable (chaque terme devient une ligne « Pourquoi cette
alerte » dans JIRA), utilisable à froid, et directement mélangeable avec la
probabilité du modèle appris :

```
logit(p) = (1 − α)·logit(p_expert) + α·logit(p_ml),   α = n / (n + k)
```

Plus il y a de labels `n`, plus le modèle appris prend la main (`k = 200` par défaut).

**Critères du score expert** (poids dans `config/triage.toml`) :

- impact de la catégorie (stealer log > ransomleak > secret de code > identifiants > … > bavardage) ;
- sévérité Flare (ou override du tenant) et score de risque Flare s'il existe ;
- exploitabilité : identifiant validé, mot de passe en clair, cookies de session, secrets ;
- fiabilité de la source (inspirée du code de l'Amirauté) ;
- criticité de l'actif (identifiants critiques déclarés par client) et acteur en watchlist ;
- fraîcheur (décroissance exponentielle, demi-vie 30 j) ;
- contexte : pic de volume (z-score robuste médiane/MAD), nouveauté (Isolation Forest) ;
- pénalité de doublon.

## 4. Évaluation à mettre en place

- Jeu de test labellisé par les analystes (≥ 500 événements, stratifié par catégorie).
- Métriques : rappel sur les alertes à notifier (priorité absolue : ne rien rater),
  précision@k, taux de réduction du bruit, AUC-PR (classes déséquilibrées),
  Brier score / courbe de calibration.
- Réglage des seuils : choisir `notify` pour un rappel ≥ 95 %, puis maximiser la précision.
- Suivi de dérive : distribution des scores par catégorie semaine après semaine.

## 5. Évolutions prévues

1. Extraction fine par type d'événement (schémas du détail v2/v4), notamment lookalikes « armés ».
2. Regroupement en incidents (même stealer log, même campagne) façon DeepCASE.
3. Gradient boosting calibré quand le volume de labels le permet.
4. Profils par client (poids et identifiants critiques par tenant).
