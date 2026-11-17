# Conception et justification du score

Le score (0 à 100) est une **somme de règles pondérées**. Chaque règle déclenchée ajoute ou retire des points et laisse
une **preuve lisible** (affichée dans le tableau de bord, dans l'alerte TheHive et dans `results.csv`). Il n'y a pas
de modèle « boîte noire » : un analyste peut toujours expliquer pourquoi un e-mail a obtenu son score.

Le code se trouve dans [`analyzer/app/scoring.py`](../analyzer/app/scoring.py) (dictionnaire `WEIGHTS`).

## Seuils et décisions

| Score | Décision | Action SOAR |
|---|---|---|
| < 20 | `benign` | classement automatique et réponse « e-mail légitime » au rapporteur |
| 20 – 69 | `suspicious` | dossier créé, accusé de réception, **validation analyste** |
| ≥ 70 | `malicious` | dossier prioritaire, **validation analyste avant la purge** |
| campagne déjà confirmée | `known_campaign` | réponse automatique : purge des nouvelles copies et remerciement |

Le seuil bas (20) est volontairement **favorable au rappel** : un faux négatif (phishing classé légitime) coûte
plus cher qu'un faux positif, qui ne coûte qu'une validation d'analyste. La purge n'est **jamais** automatique sur un
nouveau dossier ; elle l'est seulement pour une campagne qu'un analyste a déjà validée.

## Principes de pondération

| Famille | Exemples de règles | Points | Justification |
|---|---|---|---|
| Renseignement | IOC connu malveillant (VirusTotal ≥ 3 moteurs, URLhaus, OTX, ou campagne interne confirmée) | +50 | Preuve externe forte : suffit presque seule à passer « malveillant » |
| Imitation | domaine expéditeur ou lien similaire à une marque protégée | +30 | Quasiment jamais légitime ; signal le plus discriminant sans réseau |
| Pièces jointes | YARA (score de la règle, max 40), extension dangereuse +25, double extension +20 | 20–40 | Vecteur de malware direct |
| Tromperie | champ de mot de passe +25, texte du lien ≠ cible réelle +20, nom affiché usurpé +20 | 20–25 | Intention de tromper, rare dans les e-mails légitimes |
| Authentification | SPF fail +15, DMARC fail +15, DKIM fail +10 ; SPF+DKIM+DMARC valides : 0 (preuve affichée) | 0–15 | Environ la moitié du phishing mesuré valide les trois : un attaquant authentifie son propre domaine |
| Infrastructure | Reply-To divergent +15, lien vers une IP +10, raccourcisseur +10, formulaire HTML +5, TLD abusé +5 | 5–15 | Fréquent aussi dans les envois marketing : poids modéré |
| Contenu | action demandée sur le compte +20, urgence +10 (+5 si ≥ 4 formules), identifiants +10, RIB +15, formule générique +5 | 5–20 | Les vraies alertes utilisent aussi ce vocabulaire, d'où une validation obligatoire avant la purge |
| Légitimité | expéditeur interne authentifié −15, newsletter authentifiée −10, fichiers connus CIRCL −10 | −10 à −15 | Réduit les faux positifs sur les envois légitimes |

Règle de conception : **aucune règle de contenu ne peut déclencher une purge**. Une demande d'action sur le compte
(+20) suffit toutefois à envoyer un e-mail en validation : c'est le compromis retenu pour améliorer le rappel.

## Évaluation réalisée

1. **Jeu d'essai** (`dataset/preparer_corpus.py`) : 1131 e-mails. Phishing : J. Nazario, `phishing-2024`
   (<https://monkey.org/~jose/phishing/>, CC-BY-4.0). Autres : Apache SpamAssassin Public Corpus (`easy_ham`,
   `hard_ham`, `spam`). Le spam compte comme non phishing. Découpage fixe en deux parties égales, par famille :
   `dev` pour le réglage, `test` pour la mesure finale.
2. **Référence** : poids d'origine sur tout le corpus, seuil 30 : rappel 21,5 %, précision 40,4 %
   (`dataset/results/v1_reference/`).
3. **Réglage** sur la partie `dev` uniquement, à partir des statistiques agrégées par règle.
4. **Mesure unique** sur la partie `test`, poids et seuil figés (`dataset/results/`).

| Partie test, 566 e-mails | VP | FN | FP | VN | Précision | Rappel | Faux positifs |
|---|---|---|---|---|---|---|---|
| Poids d'origine, seuil 30 | 39 | 161 | 58 | 308 | 40,2 % | 19,5 % | 15,8 % |
| **Poids finaux, seuil 20** | **133** | **67** | **49** | **317** | **73,1 %** | **66,5 %** | **13,4 %** |

Limites à connaître :

- La référence portait sur tout le corpus et ses statistiques ont été lues : la partie test n'est pas totalement vierge.
- Écart d'époque : non-phishing de 2002-2003, phishing de 2024. Sans règles d'authentification, le total reste
  identique, 2 phishings perdus et 2 gagnés (`no_auth` dans `metrics.json`), mais le taux de faux positifs sur une messagerie actuelle reste inconnu.
- Évaluation hors ligne : la réputation (+50) n'est pas mesurée.
- 67 phishings sur 200 restent sous le seuil et seraient classés légitimes automatiquement ; 41 obtiennent un score de 0.

Exemple de faux négatif attendu : un compte fournisseur compromis, avec authentification valide et sans lien trompeur,
que seule la réputation en ligne ou l'analyste peuvent détecter.

## Reproduire

```bash
docker exec soar-analyzer python -I /dataset/preparer_corpus.py
```

```bash
docker exec -w /app soar-analyzer python -m app.evaluate --dataset /data/corpus --as-report --split test
```

```bash
docker cp soar-analyzer:/data/corpus/results dataset/
```

Les e-mails restent dans le volume Docker. `dataset/results/` ne contient que des noms de fichiers générés, des étiquettes,
des scores et des noms de règles.
