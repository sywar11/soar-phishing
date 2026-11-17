# Projet 1 : boîte de signalement du phishing, de l'e-mail à la purge

Un SOAR (n8n) traite automatiquement les e-mails que les employés signalent :

```
E-mail signalé ─► Analyse (en-têtes, URL, PJ) ─► Réputation + YARA ─► Score + regroupement ─► Analyste valide ─► Purge + blocage DNS
                                                                            │
                                                                            └─► légitime : réponse automatique au rapporteur
```

L'analyste n'ouvre jamais l'e-mail sur son poste. Les signalements d'une même campagne forment **un seul dossier**.
Le rapporteur reçoit un retour, et les autres destinataires voient le message retiré de leur boîte et sont prévenus.

## Architecture

| Service | Rôle | URL |
|---|---|---|
| **n8n** | SOAR : orchestre les 2 workflows | http://localhost:5680 |
| **analyzer** (Python/FastAPI) | moteur d'analyse, de score et de regroupement, actions, tableau de bord analyste | http://localhost:8000 |
| **Mailpit** | messagerie de test (toutes les boîtes) + API de recherche et de suppression | http://localhost:8025 (SMTP 1025) |
| **CoreDNS** | DNS filtrant (domaines confirmés résolus en `0.0.0.0`) | port 1053 |
| **GoPhish** | campagnes de phishing de démonstration | https://localhost:3333 |
| TheHive (option) | gestion de dossiers : une alerte par campagne | http://localhost:9000 |

```
analyzer/app/
  parser.py      formats réels : .eml joint, message/rfc822 (même encodé en base64), RFC 2047, base64/QP, ZIP, HTML
  ioc.py         défanisation, domaine enregistré, clé d'URL, redirections (SafeLinks, ?url=…)
  lookalike.py   domaines similaires : homoglyphes, punycode, typosquatting, marque + mot d'appât
  yara_scan.py   + rules/*.yar   macros, HTML smuggling, formulaire de mot de passe, PE, LNK, ISO…
  enrich.py      renseignement interne, URLhaus, VirusTotal, OTX, CIRCL hashlookup (cache 24 h)
  scoring.py     score explicable (voir docs/score.md)
  cluster.py     doublons et campagnes (URL normalisée, hash, sujet normalisé, Message-ID)
  pipeline.py    chaîne complète + routage pour n8n
  response.py    confirmer, purger, bloquer, notifier, faux positif
  evaluate.py    matrice de confusion sur le jeu d'essai
n8n/workflows/   01 ingestion des signalements, 02 décision de l'analyste
scripts/report_email.py   simule des employés qui signalent un e-mail
```

## Installation

Prérequis : Docker Desktop, environ 6 Go de RAM libres (environ 9 Go avec TheHive).

```bash
cp .env.example .env
```
(Optionnel : renseigner `VT_API_KEY`, `OTX_API_KEY` et `URLHAUS_AUTH_KEY` dans `.env`. Les clés sont gratuites.)

```bash
docker compose up -d --build
```

```bash
docker exec soar-n8n n8n import:workflow --separate --input=/workflows
```

```bash
docker exec soar-n8n n8n publish:workflow --id=soarPhishIngest01
```

```bash
docker exec soar-n8n n8n publish:workflow --id=soarPhishDecide02
```

```bash
docker restart soar-n8n
```

Ouvre http://localhost:5680 et crée le compte propriétaire n8n pour voir les workflows et leurs exécutions.

## Démonstration avec GoPhish

1. Récupère le mot de passe admin initial avec `docker logs soar-gophish` (ligne « Please login with the username admin and the password … »), puis connecte-toi sur https://localhost:3333.
2. **Sending Profile** : hôte `mailpit:1025`, SMTP From `demo@c0rp-local.test` (l'adresse seule : GoPhish refuse `Nom <adresse>` et le domaine `.example`).
3. **Landing Page** et **Email Template** : écris ton propre modèle de démonstration (bouton « Import Email » pour partir d'un `.eml`).
4. **Users & Groups** : quelques adresses `prenom.nom@corp.local`.
5. **Campaign** : URL `http://c0rp-local.test:8081` (pas `localhost`, sinon le lien n'imite aucun domaine et il n'y a rien à bloquer), puis lance la campagne. Les e-mails arrivent dans Mailpit.
6. Simule les signalements :
   ```bash
   python scripts/report_email.py --query "subject:DEMO" --count 3
   ```
7. Dans la minute qui suit, n8n traite les signalements : un seul dossier apparaît sur http://localhost:8000, avec 3 signalements et le détail du score.
8. Clique sur **Confirmer le phishing**. n8n confirme le dossier, purge toutes les copies (y compris chez ceux qui n'ont rien signalé), bloque les domaines dans CoreDNS et envoie les notifications. Tu peux tout vérifier dans Mailpit et dans `coredns/blocklist.hosts`.
9. Vérifie le blocage DNS :
   ```bash
   docker run --rm --network soar-phishing_default alpine:3.20 nslookup <domaine> dns
   ```
   La réponse attendue est `0.0.0.0`.
10. Un nouveau signalement de la même campagne est maintenant traité automatiquement (route `known_campaign`).

Pour analyser un `.eml` à la main, sans rien enregistrer : http://localhost:8000/analyze.

## Jeu d'essai et matrice de confusion

**Résultat déjà mesuré** (566 e-mails de test, hors ligne, seuil 20) : VP 133, FN 67, FP 49, VN 317, soit une précision de
73,1 %, un rappel de 66,5 % et 13,4 % de faux positifs. Voir `dataset/results/confusion_matrix.md` et, pour la méthode et les
limites, [docs/score.md](docs/score.md).

Le jeu d'essai vient de corpus publics : J. Nazario, `phishing-2024` (<https://monkey.org/~jose/phishing/>, CC-BY-4.0) et
Apache SpamAssassin Public Corpus. Les e-mails restent dans le volume Docker de l'analyzer. Pour tout reconstruire
(téléchargement d'environ 20 Mo) :

```bash
docker exec soar-analyzer python -I /dataset/preparer_corpus.py
```

```bash
docker exec -w /app soar-analyzer python -m app.evaluate --dataset /data/corpus --as-report --split test
```

```bash
docker cp soar-analyzer:/data/corpus/results dataset/
```

Options : `--split dev` pour la partie réglage et `--online` pour inclure la réputation en ligne (envoie des indicateurs à
des services tiers). Pour un autre jeu d'essai, place les e-mails originaux dans `<dossier>/emails/` et décris-les dans
`<dossier>/labels.csv` (colonnes `file,label,family,split`). Résultats : `confusion_matrix.md`, `results.csv` et `metrics.json`.

## API (utilisée par n8n)

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/reports/mailpit/{id}` | traite un signalement et renvoie `route` : `benign`, `pending_validation`, `known_campaign`, `duplicate`… |
| POST | `/api/reports/{id}/reply?template=received\|benign` | réponse au rapporteur |
| POST | `/api/cases/{id}/confirm` · `/purge` · `/block-dns` · `/notify-confirmed` | étapes de réponse |
| POST | `/api/cases/{id}/respond` | réponse complète (campagne déjà confirmée) |
| POST | `/api/cases/{id}/false-positive` | clôture, déblocage DNS, information des rapporteurs |
| POST | `/api/analyze` | analyse d'un `.eml` brut, sans enregistrement |

## Sécurité du laboratoire

- L'analyste ne voit que des indicateurs **défanisés** (`hxxp://exemple[.]com`).
- `FOLLOW_REDIRECTS=false` par défaut : aucune requête n'est envoyée vers les URL suspectes. Active-le seulement dans un réseau isolé.
- La purge ne touche jamais la boîte de signalement, qui conserve les preuves. Elle ne supprime que les messages qui partagent une clé de campagne avec le dossier.
- Le blocage DNS exclut les domaines protégés, internes, de messagerie gratuite et les raccourcisseurs.

## Extensions possibles

- Capture isolée de la page cible avec un navigateur headless (conteneur sans accès au réseau interne).
- Résumé du signalement par un LLM, destiné au rapporteur.
- Remplacer Mailpit par Microsoft Graph ou l'API Gmail pour la recherche et la purge en production.
