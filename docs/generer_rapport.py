"""Génère le rapport de projet (PDF) à envoyer à l'enseignant.

    python docs/generer_rapport.py --auteur "Prénom Nom" --encadrant "Nom" --etablissement "École" --module "Module"

Si dataset/results/metrics.json existe (produit par app.evaluate), la vraie matrice de confusion est insérée
automatiquement dans la section 6.3. Dépendance : pip install reportlab. Polices : Windows (Segoe UI, Consolas).
"""
import argparse
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

PROJECT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--auteur", default="Siwar Mhamdi")
ap.add_argument("--encadrant", default="Salah Gontara")
ap.add_argument("--etablissement", default="Université Polytechnique Sousse")
ap.add_argument("--module", default="")
ap.add_argument("--date", default="Novembre 2026")
ap.add_argument("--sortie", default=str(PROJECT.parent / "Rapport_Projet_SOAR_Phishing.pdf"))
args = ap.parse_args()

F = r"C:\Windows\Fonts"
for name, file in (("UI", "segoeui"), ("UIB", "segoeuib"), ("UII", "segoeuii"), ("Mono", "consola")):
    pdfmetrics.registerFont(TTFont(name, f"{F}\\{file}.ttf"))
registerFontFamily("UI", normal="UI", bold="UIB", italic="UII", boldItalic="UIB")

INK = colors.HexColor("#1c2230")
MUTED = colors.HexColor("#5f6b7d")
ACC = colors.HexColor("#1f3f9e")
LINE = colors.HexColor("#d9dde4")
SOFT = colors.HexColor("#f1f4fb")

st = {
    "title": ParagraphStyle("title", fontName="UIB", fontSize=25, leading=32, textColor=INK, alignment=TA_CENTER),
    "sub": ParagraphStyle("sub", fontName="UI", fontSize=13, leading=19, textColor=MUTED, alignment=TA_CENTER),
    "h1": ParagraphStyle("h1", fontName="UIB", fontSize=16, leading=21, textColor=ACC, spaceBefore=14, spaceAfter=7, keepWithNext=1),
    "h2": ParagraphStyle("h2", fontName="UIB", fontSize=11.5, leading=16, textColor=INK, spaceBefore=9, spaceAfter=3, keepWithNext=1),
    "toch": ParagraphStyle("toch", fontName="UIB", fontSize=16, leading=21, textColor=ACC, spaceAfter=10),
    "p": ParagraphStyle("p", fontName="UI", fontSize=10, leading=14.5, textColor=INK, spaceAfter=5, alignment=TA_JUSTIFY),
    "li": ParagraphStyle("li", fontName="UI", fontSize=10, leading=14.5, textColor=INK, leftIndent=14, bulletIndent=4, spaceAfter=2),
    "code": ParagraphStyle("code", fontName="Mono", fontSize=8.6, leading=11.5, textColor=INK, backColor=SOFT,
                           borderPadding=(5, 6, 5, 6), leftIndent=6, rightIndent=6, spaceBefore=4, spaceAfter=8),
    "cell": ParagraphStyle("cell", fontName="UI", fontSize=8.8, leading=12, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName="UIB", fontSize=8.8, leading=12, textColor=INK),
    "cap": ParagraphStyle("cap", fontName="UII", fontSize=8.5, leading=11, textColor=MUTED, alignment=TA_CENTER, spaceAfter=9),
}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def P(t): return Paragraph(t, st["p"])
def H1(t): return Paragraph(t, st["h1"])
def H2(t): return Paragraph(t, st["h2"])
def CAP(t): return Paragraph(t, st["cap"])
def LI(items): return [Paragraph(t, st["li"], bulletText="•") for t in items]
def CODE(t): return Paragraph(esc(t).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;"), st["code"])


def TABLE(rows, widths):
    data = [[Paragraph(str(c), st["cellb" if i == 0 else "cell"]) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BACKGROUND", (0, 0), (-1, 0), SOFT), ("TOPPADDING", (0, 0), (-1, -1), 4),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


def FLOW(steps):
    cells = []
    arrow = ParagraphStyle("a", parent=st["cell"], alignment=TA_CENTER, fontSize=13)
    box = ParagraphStyle("f", parent=st["cell"], alignment=TA_CENTER, fontSize=8.5)
    for i, (a, b) in enumerate(steps):
        cells.append(Paragraph(f"<b>{a}</b><br/><font size=7.5 color='#5f6b7d'>{b}</font>", box))
        if i < len(steps) - 1:
            cells.append(Paragraph("<font color='#1f3f9e'><b>→</b></font>", arrow))
    w = (16.6 - 0.55 * (len(steps) - 1)) / len(steps)
    t = Table([cells], colWidths=[(w if i % 2 == 0 else 0.55) * cm for i in range(len(cells))])
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE")]
    for i in range(0, len(cells), 2):
        style += [("BACKGROUND", (i, 0), (i, 0), SOFT), ("BOX", (i, 0), (i, 0), 0.6, ACC)]
    t.setStyle(TableStyle(style))
    return t


class Doc(SimpleDocTemplate):
    def afterFlowable(self, f):
        if isinstance(f, Paragraph) and f.style.name == "h1":
            self.notify("TOCEntry", (0, f.getPlainText(), self.page))


def footer(c, d):
    c.saveState()
    c.setFont("UI", 8)
    c.setFillColor(MUTED)
    c.drawString(2 * cm, 1.2 * cm, "Rapport de projet : SOAR phishing, de l'e-mail à la purge")
    c.drawRightString(19 * cm, 1.2 * cm, f"Page {d.page}")
    c.restoreState()


S = []
# ------------------------------------------------------------------ garde
S += [Spacer(1, 3.5 * cm), Paragraph(esc(args.etablissement), st["sub"]), Paragraph(esc(args.module), st["sub"]),
      Spacer(1, 2 * cm), Paragraph("Rapport de projet", st["sub"]), Spacer(1, 8),
      Paragraph("Boîte de signalement du phishing : de l'e-mail à la purge", st["title"]), Spacer(1, 10),
      Paragraph("Automatisation de la réponse avec un SOAR", st["sub"]), Spacer(1, 3 * cm),
      Paragraph(f"Réalisé par : <b>{esc(args.auteur)}</b>", st["sub"]),
      Paragraph(f"Enseignant : <b>{esc(args.encadrant)}</b>", st["sub"]), Spacer(1, 8),
      Paragraph(esc(args.date), st["sub"]), PageBreak()]

# ------------------------------------------------------------------ résumé + sommaire
toc = TableOfContents()
toc.levelStyles = [ParagraphStyle("t1", fontName="UIB", fontSize=10, leading=15, textColor=INK),
                   ParagraphStyle("t2", fontName="UI", fontSize=9.2, leading=13, leftIndent=14, textColor=INK)]
S += [Paragraph("Résumé", st["toch"]),
      P("Ce projet automatise le traitement des e-mails suspects que les employés transfèrent à une boîte de signalement. "
        "Un SOAR (n8n) orchestre un moteur d'analyse écrit en Python : extraction du message signalé, défanisation des "
        "indicateurs, règles YARA, réputation, score explicable de 0 à 100 et regroupement des signalements en campagnes. "
        "Après validation par un analyste, le système purge l'e-mail dans toutes les boîtes touchées, bloque les domaines "
        "dans un DNS filtrant et informe le rapporteur et les autres destinataires."),
      P("Le système est déployable avec Docker Compose. Les 30 tests unitaires réussissent et la chaîne complète a été "
        "validée de bout en bout avec une campagne GoPhish. Le score a été évalué sur 1131 e-mails issus de corpus publics : "
        "sur la partie test (566 e-mails, sans réputation en ligne), il obtient une précision de 73 %, un rappel de 66,5 % et "
        "13 % de faux positifs. Le score sert donc au tri et ne remplace pas un analyste. La section 8 précise les limites."),
      Spacer(1, 10), Paragraph("Sommaire", st["toch"]), toc, PageBreak()]

# ------------------------------------------------------------------ 1
S += [H1("1. Contexte et problématique"),
      P("Dans une entreprise, les employés transfèrent chaque jour des dizaines d'e-mails suspects à une boîte de "
        "signalement. Les analystes les ouvrent un par un. Cette pratique pose trois problèmes :")]
S += LI(["<b>Un risque</b> : l'analyste ouvre sur son poste un e-mail potentiellement malveillant.",
         "<b>Du bruit</b> : la plupart des signalements sont inoffensifs, et un vrai phishing peut passer inaperçu.",
         "<b>Une réaction tardive</b> : quand une campagne est confirmée, les autres destinataires ont encore l'e-mail dans leur boîte."])
S += [H1("2. Objectifs et livrables"),
      H2("2.1 Objectifs")]
S += LI(["Traiter un signalement sans ouvrir l'e-mail sur le poste d'un analyste.",
         "Regrouper les signalements d'une même campagne en un seul dossier.",
         "Répondre à la fois au rapporteur et aux autres destinataires."])
S += [H2("2.2 Tâches et livrables demandés"),
      TABLE([["Élément du sujet", "Réalisation", "État"],
             ["Analyser les formats réels (.eml joint, encodages, redirections)", "parser.py, ioc.py", "Fait et testé"],
             ["Concevoir le score et le justifier sur un jeu d'essai", "scoring.py, evaluate.py, docs/score.md", "Fait et mesuré (6.3)"],
             ["Détecter les doublons et les campagnes", "cluster.py", "Fait et testé"],
             ["Rechercher et purger chez les autres destinataires", "actions.py, response.py (API Mailpit)", "Fait et testé"],
             ["Système déployable", "docker-compose.yml, README.md", "Fait et testé"],
             ["Campagne GoPhish de démonstration", "GoPhish, avec un message de test neutre (voir 7.3)", "Fait et testé"],
             ["Matrice de confusion", "evaluate.py, sur 566 e-mails de test", "Fait (6.3)"],
             ["Extension : domaines similaires", "lookalike.py", "Fait et testé"]], [7.4, 5.6, 3.6]),
      Spacer(1, 6),
      H1("3. Choix techniques"),
      TABLE([["Besoin", "Choix", "Justification"],
             ["SOAR", "n8n (plutôt que Shuffle)", "Workflows visuels, nœuds HTTP et webhook suffisants ; le code d'analyse reste dans un service testable"],
             ["Messagerie", "Mailpit (plutôt que docker-mailserver)", "API de recherche, de lecture et de suppression, indispensable à la purge ; aucune configuration de domaines"],
             ["Campagne de test", "GoPhish", "Outil proposé par le sujet ; un identifiant par destinataire, utile pour tester le regroupement"],
             ["Moteur d'analyse", "Python, FastAPI, yara-python", "Bibliothèque standard <i>email</i> pour les formats réels, API simple à appeler depuis n8n"],
             ["Réputation", "CIRCL, URLhaus, OTX, VirusTotal", "Sources gratuites et complémentaires (fichiers connus, URL, domaines, hash)"],
             ["Blocage", "CoreDNS (plugin hosts)", "Rechargement automatique d'une liste de domaines, sans redémarrage"],
             ["Dossiers", "Base SQLite + tableau de bord ; TheHive en option", "Le système reste utilisable sur une machine modeste (6 à 8 Go de RAM)"]], [2.8, 5, 8.8]),
      Spacer(1, 6)]

# ------------------------------------------------------------------ 4 archi
S += [H1("4. Architecture"),
      P("Tous les services tournent dans des conteneurs Docker. n8n décide de l'enchaînement ; l'analyzer fait l'analyse et "
        "exécute les actions à la demande de n8n."),
      FLOW([("E-mail signalé", "boîte phishing@"), ("n8n", "relève chaque minute"), ("Analyse", "en-têtes, URL, PJ"),
            ("YARA + réputation", "indicateurs"), ("Score + dossier", "campagne"), ("Tri", "3 routes")]),
      CAP("Figure 1 : traitement d'un signalement (workflow 01)"),
      FLOW([("Clic analyste", "tableau de bord"), ("Webhook n8n", "workflow 02"), ("Confirmation", "renseignement interne"),
            ("Purge", "toutes les boîtes"), ("Blocage DNS", "CoreDNS"), ("Notifications", "rapporteurs + destinataires")]),
      CAP("Figure 2 : réponse après validation (workflow 02)"),
      TABLE([["Service", "Rôle", "Port"],
             ["n8n", "SOAR : workflows d'ingestion et de décision", "5680"],
             ["analyzer", "API d'analyse et d'action, tableau de bord analyste", "8000"],
             ["Mailpit", "Messagerie de test et API", "8025 (SMTP 1025)"],
             ["CoreDNS", "DNS filtrant", "1053"],
             ["GoPhish", "Campagnes de démonstration", "3333, 8081"],
             ["TheHive (profil optionnel)", "Une alerte par campagne", "9000"]], [4.6, 9, 3]),
      Spacer(1, 4),
      P("Le workflow 01 suit la <b>route</b> renvoyée par l'analyzer : légitime (réponse au rapporteur), à valider (accusé de "
        "réception, dossier en attente) ou campagne déjà confirmée (réponse automatique). Les doublons ne déclenchent rien."),

      # ------------------------------------------------------------------ 5 réalisation
      H1("5. Réalisation"),
      H2("5.1 Lecture des formats réels"),
      P("Le rapporteur transfère l'e-mail en pièce jointe : il faut d'abord retrouver le message original, qu'il soit joint en "
        "<i>message/rfc822</i> ou en fichier <i>.eml</i>. Le module décode ensuite les en-têtes RFC 2047, les corps base64 et "
        "quoted-printable, et extrait l'expéditeur, le Reply-To, les résultats SPF/DKIM/DMARC, les relais, les URL (texte, liens, "
        "formulaires), les pièces jointes avec leurs hash et le contenu des archives ZIP."),
      H2("5.2 Indicateurs et défanisation"),
      P("Chaque URL est présentée sous forme défanisée (<i>hxxp://exemple[.]com</i>) pour éviter un clic accidentel. Les "
        "redirections visibles dans l'URL (par exemple <i>?url=</i>) sont déroulées sans aucune requête réseau. Le suivi HTTP "
        "des redirections existe mais reste désactivé par défaut."),
      H2("5.3 Domaines similaires"),
      P("Chaque domaine est comparé à une liste de marques protégées : homoglyphes (0 pour o, rn pour m), punycode, distance "
        "de Levenshtein, marque associée à un mot comme « login », et marque placée en sous-domaine."),
      H2("5.4 YARA et réputation"),
      P("Onze règles YARA analysent les pièces jointes et le contenu des ZIP : macros, HTML smuggling, formulaire de mot de "
        "passe, exécutable, raccourci LNK, image ISO, PDF actif. Le système interroge ensuite CIRCL hashlookup, URLhaus, "
        "VirusTotal (4 requêtes au maximum par analyse) et OTX, avec un cache de 24 heures. Un <b>renseignement interne</b> "
        "conserve les indicateurs des campagnes confirmées par un analyste."),
      H2("5.5 Regroupement en campagnes"),
      P("Chaque e-mail produit des clés : URL sans paramètres et avec identifiants normalisés, hash des pièces jointes, objet "
        "normalisé associé au domaine de l'expéditeur, Message-ID. Un signalement rejoint un dossier de moins de 14 jours s'il "
        "partage au moins une clé avec lui. Ainsi, le paramètre <i>?rid=</i> propre à chaque destinataire d'une campagne GoPhish "
        "n'empêche pas le regroupement. Les domaines très courants ne servent pas de clé."),
      H2("5.6 Réponse"),
      P("<b>Purge</b> : le message est recherché dans toutes les boîtes, puis chaque candidat est ré-analysé et n'est supprimé "
        "que s'il partage une clé avec le dossier. La boîte de signalement n'est jamais purgée, car elle conserve les preuves. "
        "<b>Blocage</b> : les domaines sont ajoutés à la liste de CoreDNS et résolus en 0.0.0.0 ; les domaines protégés, internes, "
        "de messagerie gratuite et les raccourcisseurs sont exclus. <b>Notifications</b> : les rapporteurs reçoivent un retour et "
        "les autres destinataires sont prévenus du retrait. <b>Faux positif</b> : le dossier est clôturé, le DNS débloqué et les "
        "rapporteurs informés ; en revanche, les e-mails déjà purgés ne sont pas restaurés."),
      H2("5.7 Tableau de bord"),
      P("L'analyste consulte les dossiers, le détail du score, les indicateurs défanisés, les copies purgées et le journal des "
        "actions, puis décide avec deux boutons : « Confirmer le phishing » ou « Faux positif »."),
      PageBreak()]

# ------------------------------------------------------------------ 6 score
S += [H1("6. Le score et son évaluation"),
      H2("6.1 Principe"),
      P("Le score est une somme de règles pondérées, bornée entre 0 et 100. Chaque règle déclenchée laisse une preuve lisible : "
        "l'analyste peut donc toujours expliquer un résultat."),
      TABLE([["Score", "Décision", "Action"],
             ["Moins de 20", "Légitime", "Classement automatique et réponse au rapporteur"],
             ["20 à 69", "Suspect", "Dossier et validation par un analyste"],
             ["70 et plus", "Malveillant", "Dossier prioritaire et validation avant la purge"],
             ["Campagne déjà confirmée", "Connue", "Réponse automatique sur les nouvelles copies"]], [4.2, 3, 9.4]),
      H2("6.2 Pondération"),
      TABLE([["Famille", "Exemples de règles", "Points", "Justification"],
             ["Réputation", "Indicateur malveillant (source externe ou campagne confirmée)", "+50", "Preuve forte"],
             ["Imitation", "Domaine expéditeur ou lien similaire à une marque", "+30", "Rarement légitime"],
             ["Pièces jointes", "YARA (40 au max.), extension dangereuse, double extension", "+20 à +40", "Vecteur direct"],
             ["Tromperie", "Champ de mot de passe (+25), texte du lien différent de la cible, nom affiché usurpé (+20)", "+20 à +25", "Intention de tromper"],
             ["Authentification", "Échec SPF, DMARC, DKIM", "+8 à +15", "Un attaquant peut authentifier son propre domaine"],
             ["Infrastructure", "Reply-To divergent, lien vers une IP, raccourcisseur, TLD abusé, formulaire HTML", "+5 à +15", "Existe aussi dans le marketing"],
             ["Contenu", "Action demandée sur le compte (+20), urgence, identifiants, RIB, formule générique", "+5 à +20", "Les vraies alertes emploient le même vocabulaire"],
             ["Légitimité", "Interne authentifié, newsletter, fichiers connus", "-10 à -15", "Limite les faux positifs"]],
            [2.8, 7, 2, 4.8]),
      Spacer(1, 4),
      P("Le seuil de 20 privilégie le rappel : manquer un phishing coûte plus cher qu'une validation par un analyste. La validation "
        "humaine reste obligatoire avant la purge d'un nouveau dossier, car purger un e-mail légitime aurait un impact sur tous ses "
        "destinataires. Conséquence assumée : une demande d'action sur le compte suffit à envoyer un e-mail en validation, mais "
        "jamais à le purger. Ces poids résultent de la mesure décrite en 6.3."),
      H2("6.3 Évaluation sur un jeu d'essai"),
      P("<b>Corpus.</b> Le phishing provient du corpus de José Nazario (phishing-2024, licence CC-BY-4.0, classé à la main). "
        "Les autres e-mails proviennent de l'Apache SpamAssassin Public Corpus. Le spam est compté comme <b>non phishing</b>, "
        "car le SOAR doit justement ne pas le traiter comme une attaque ciblée. Chaque famille est coupée en deux au hasard, "
        "avec une graine fixe : une partie sert au réglage (dev), l'autre à la mesure finale (test). Les e-mails restent dans "
        "le volume Docker : ils sont seulement lus par l'analyzer, sans ouvrir de lien ni exécuter de pièce jointe."),
      KeepTogether([TABLE([["Famille", "Source", "Réglage", "Test", "Étiquette"],
                           ["nazario_2024", "J. Nazario, 2024", "200", "200", "Phishing"],
                           ["easy_ham", "SpamAssassin, 2003", "150", "150", "Non phishing"],
                           ["hard_ham", "SpamAssassin, 2002", "115", "116", "Non phishing"],
                           ["spam", "SpamAssassin, 2003", "100", "100", "Non phishing"]], [3.4, 5, 2.2, 2, 4])]),
      Spacer(1, 4),
      P("<b>Méthode.</b> Chaque e-mail est emballé dans un signalement pour tester aussi l'extraction, puis évalué sans réputation "
        "en ligne (aucune requête externe). Une première mesure a servi de référence, avec les poids d'origine. Les corrections "
        "ont ensuite été décidées sur la partie réglage, puis figées avant une unique mesure sur la partie test. <b>Réserve :</b> "
        "cette première mesure portait sur l'ensemble du corpus, et j'en ai lu les statistiques agrégées par règle. La partie test "
        "n'est donc pas totalement vierge, et les résultats peuvent être légèrement optimistes.")]

metrics = PROJECT / "dataset" / "results" / "metrics.json"
m = json.loads(metrics.read_text(encoding="utf-8"))
v1 = json.loads((PROJECT / "dataset" / "results" / "v1_reference" / "test_split.json").read_text(encoding="utf-8-sig"))["seuils"]
c = m["main"]
fr = lambda x: f"{100 * x:.1f} %".replace(".", ",")
S += [P(f"<b>Matrice de confusion finale</b> : {m['n']} e-mails de test, seuil de {c['threshold']} :"),
      TABLE([["", "Prédit phishing", "Prédit légitime"],
             ["Phishing réel", f"VP = {c['tp']}", f"FN = {c['fn']}"],
             ["Légitime réel", f"FP = {c['fp']}", f"VN = {c['tn']}"]], [5, 5.8, 5.8]),
      Spacer(1, 4),
      P(f"Précision {fr(c['precision'])}, rappel {fr(c['recall'])}, F1 {fr(c['f1'])}, taux de faux positifs {fr(c['fpr'])}. "
        "Avec 200 phishings et 366 autres e-mails, l'incertitude reste notable : intervalle de confiance à 95 % d'environ "
        "60 à 73 % pour le rappel et de 10 à 17 % pour les faux positifs."),
      KeepTogether([P("<b>Balayage des seuils</b> (partie test). Le seuil a été choisi sur la partie réglage (rappel de 69 % et 14,8 % de "
                      "faux positifs à 20, contre 46,5 % et 9,6 % à 30), pas sur ce tableau."),
                    TABLE([["Seuil", "VP", "FN", "FP", "VN", "Précision", "Rappel", "F1"]] +
                          [[x["threshold"], x["tp"], x["fn"], x["fp"], x["tn"], x["precision"], x["recall"], x["f1"]] for x in m["sweep"]],
                          [2, 1.6, 1.6, 1.6, 1.6, 2.8, 2.8, 2.6])]),
      Spacer(1, 4),
      KeepTogether([P("<b>Apport du réglage</b>, sur les mêmes 566 e-mails de test :"),
                    TABLE([["Version", "VP", "FN", "FP", "VN", "Précision", "Rappel", "Faux positifs"],
                           ["Poids d'origine, seuil 30", v1["30"]["tp"], v1["30"]["fn"], v1["30"]["fp"], v1["30"]["tn"], fr(v1["30"]["precision"]), fr(v1["30"]["recall"]), fr(v1["30"]["fpr"])],
                           ["Poids finaux, seuil 20", c["tp"], c["fn"], c["fp"], c["tn"], fr(c["precision"]), fr(c["recall"]), fr(c["fpr"])]],
                          [4.6, 1.2, 1.2, 1.2, 1.2, 2.2, 2.2, 2.6])]),
      Spacer(1, 4),
      P("<b>Ce qui a changé.</b> Le bonus pour SPF, DKIM et DMARC valides est supprimé, car environ la moitié du phishing les "
        "valide. Le formulaire HTML est ramené à +5 (il n'apparaît jamais dans le phishing de la partie réglage, contre 16,7 % des "
        "autres e-mails), et un champ de mot de passe devient une règle distincte à +25. Une nouvelle règle détecte les demandes "
        "d'action sur le compte (24 % contre 1,6 % pour la seule formule « vérifier/confirmer »). Deux motifs trop larges "
        "sont resserrés : « auth » correspondait à « author », et un domaine cité dans une phrase comptait comme un lien trompeur."),
      KeepTogether([P("<b>Détail par famille</b> (partie test) :"),
                    TABLE([["Famille", "E-mails", "Score ≥ 20", "Score ≥ 70", "Lecture"]] +
                          [[k, v["n"], v["au_seuil_suspect"], v["au_seuil_malveillant"], lect] for k, v, lect in [
                              ("nazario_2024", m["by_family"]["nazario_2024"], "Phishing détecté"),
                              ("easy_ham", m["by_family"]["easy_ham"], "Fausses alertes"),
                              ("hard_ham", m["by_family"]["hard_ham"], "Fausses alertes (famille prévue pour être difficile)"),
                              ("spam", m["by_family"]["spam"], "Envoyés à tort en validation")]],
                          [3.4, 1.8, 2.2, 2.2, 7])]),
      Spacer(1, 4),
      P("<b>Interprétation.</b> Le score joue un rôle de tri et ne constitue pas un détecteur fiable à lui seul :")]
S += LI([f"<b>{c['fn']} phishings sur 200 restent sous le seuil</b> : ils sont classés légitimes automatiquement, et le rapporteur reçoit une "
         "réponse rassurante à tort. C'est la principale limite. Sur les 200, 41 obtiennent un score de 0.",
         f"<b>Le seuil de 70 ne détecte presque rien</b> ({m['strict']['tp']} phishings, 0 fausse alerte) : sans réputation, l'essentiel "
         "du phishing passe par la validation de l'analyste. C'est cohérent avec le choix de ne jamais purger sans validation.",
         f"<b>Écart d'époque</b> : les e-mails non phishing datent de 2002-2003 et le phishing de 2024. Ils n'ont pas d'en-têtes "
         "d'authentification et n'emploient pas le vocabulaire actuel. Sans les règles d'authentification, le résultat "
         f"reste au même total ({m['no_auth']['tp']} VP, {m['no_auth']['fp']} FP : 2 phishings perdus, 2 gagnés), mais les autres écarts ne se mesurent pas ainsi. "
         "Les termes liés à l'époque (OneDrive, SharePoint, « notification ») ont été écartés volontairement. "
         "<b>Le taux de faux positifs sur une messagerie actuelle reste inconnu</b> et pourrait être plus élevé, d'autant que le bonus d'authentification a été retiré.",
         "<b>Réputation non mesurée</b> : les règles les plus fortes (+50) sont restées inactives. Les activer aurait envoyé "
         "des indicateurs à des tiers, et le résultat aurait dépendu de la date des requêtes."])

# ------------------------------------------------------------------ 7 tests
S += [H1("7. Tests et résultats"),
      H2("7.1 Tests unitaires"),
      P("Le fichier <i>analyzer/tests/test_core.py</i> contient 30 tests, sans réseau : défanisation, clés d'URL, domaines "
        "similaires et légitimes, extraction dans les trois formats, charset invalide, motifs du score, signalements simultanés, "
        "hash, ZIP et règles YARA. Résultat : <b>30 tests réussis sur 30</b>. "
        "Seules 3 vérifications portent sur YARA : les 11 règles se compilent, mais seules 2 d'entre elles ont été déclenchées."),
      H2("7.2 Test de bout en bout"),
      P("Scénario : un message de test neutre (domaines <i>.example</i>, adresse IP de documentation) envoyé à 3 employés, signalé "
        "par 2 d'entre eux, et un e-mail interne légitime signalé par une autre personne. Ce test est passé par n8n, Mailpit, "
        "l'analyzer et CoreDNS. Il a été réalisé <b>avec les poids d'origine</b>, avant l'évaluation de la section 6.3."),
      TABLE([["Vérification", "Résultat observé"],
             ["Regroupement", "2 signalements aux liens différents : 1 seul dossier"],
             ["Score du message de test", "70/100, malveillant (domaine similaire +30, Reply-To +15, IP +15, page de connexion +10)"],
             ["E-mail légitime", "0/100, classé automatiquement, réponse envoyée au rapporteur"],
             ["Accusés de réception", "Envoyés aux 2 rapporteurs"],
             ["Validation de l'analyste", "Décision transmise au workflow n8n 02 (réponse HTTP 303, « confirm:n8n »)"],
             ["Purge", "3 copies supprimées, y compris chez la personne n'ayant rien signalé ; signalements conservés"],
             ["Blocage DNS", "nslookup via CoreDNS : 0.0.0.0"],
             ["Notifications", "2 rapporteurs remerciés, 1 destinataire non rapporteur prévenu"],
             ["Campagne déjà confirmée", "Nouveau signalement : score 100, copie purgée et rapporteur remercié automatiquement"]], [5, 11.6]),
      H2("7.3 Démonstration avec une campagne GoPhish"),
      P("La démonstration a été déroulée à nouveau <b>avec le score final et le correctif du regroupement</b>, avec de vrais "
        "envois GoPhish à partir d'un modèle de test neutre (lien vers un domaine <i>.test</i>). Les décisions ont été transmises "
        "à la route du bouton du tableau de bord. L'interface n8n confirme 2 workflows publiés, et aucune exécution en échec."),
      TABLE([["Vérification", "Résultat observé"],
             ["Campagne vers 4 employés", "4 e-mails reçus, un lien <i>?rid=</i> différent par destinataire"],
             ["3 signalements simultanés", "1 seul dossier ; score 60/100, suspect (domaine expéditeur +30, lien +30)"],
             ["E-mail légitime signalé", "0/100, classé automatiquement, réponse envoyée"],
             ["Clic sur « Confirmer le phishing »", "Passage par n8n ; 4 copies purgées, dont celle de la personne n'ayant rien signalé"],
             ["Blocage DNS", "nslookup via CoreDNS : 0.0.0.0"],
             ["2<super>e</super> campagne vers un autre employé", "Même dossier, score 100, purge et remerciement automatiques"],
             ["Décision « Faux positif »", "Dossier clôturé, DNS débloqué (NXDOMAIN après le rechargement de CoreDNS, 5 s au plus)"]], [5, 11.6]),
      Spacer(1, 6),
      H1("8. Limites et points non vérifiés"),
      P("Ces points sont signalés pour distinguer clairement ce qui a été testé de ce qui ne l'a pas été :")]
S += LI(["<b>Qualité du score</b> : un tiers du phishing de test reste sous le seuil et serait classé légitime automatiquement ; le taux de faux positifs sur une messagerie actuelle n'est pas connu (voir 6.3).",
         "<b>Campagne GoPhish</b> : elle n'a été testée qu'avec un message neutre. Le score de 60 (suspect) ne préjuge pas du score d'un e-mail plus élaboré.",
         "<b>Réputation en ligne</b> : les appels à VirusTotal, URLhaus, OTX et CIRCL sont écrits, mais n'ont pas été testés avec de vraies réponses (pas de clés API, et évaluation volontairement hors ligne).",
         "<b>TheHive</b> : l'intégration est écrite et le profil Docker est prêt, mais le service n'a pas été démarré.",
         "<b>En-têtes d'authentification</b> : Mailpit ne calcule ni SPF, ni DKIM, ni DMARC. Ces règles ne jouent que si les en-têtes sont déjà présents dans l'e-mail.",
         "<b>Sécurité de l'application</b> : le tableau de bord, l'API et le webhook n'ont pas d'authentification. C'est acceptable en laboratoire, mais pas en production.",
         "<b>Purge</b> : elle est démontrée sur Mailpit uniquement, et une purge n'est pas réversible en cas de faux positif.",
         "<b>Compte légitime compromis</b> : un tel e-mail passe l'authentification et peut obtenir un score bas, donc être classé légitime sans intervention d'un analyste.",
         "<b>Analyse statique uniquement</b> : les pages cibles ne sont pas visitées et les pièces jointes ne sont pas exécutées."])
S += [H1("9. Difficultés rencontrées"),
      TABLE([["Difficulté", "Cause", "Solution"],
             ["Message signalé lu comme vide", "Notre script de simulation joignait le message/rfc822 encodé en base64, ce que la norme interdit et que la bibliothèque Python ne décode pas", "Décodage explicite dans le parser (forme tolérée) et script corrigé"],
             ["Faux positif sur login.microsoftonline.com", "La règle « marque + mot d'appât » visait aussi ce domaine légitime ; bug révélé par les tests unitaires", "Ajout des domaines Microsoft à la liste protégée. D'autres cas similaires restent possibles"],
             ["Mots-clés détectés dans les URL", "Le mot « login » d'une URL comptait comme une demande d'identifiants, donnant 80 au lieu de 70", "Les mots-clés ne sont cherchés que dans le texte lisible"],
             ["GoPhish ne démarrait pas", "Le volume de données appartenait à root, et GoPhish ne pouvait pas y créer sa base", "Exécution du conteneur en root dans docker-compose.yml (acceptable en laboratoire)"],
             ["Adresse d'expéditeur refusée par GoPhish", "GoPhish 0.12.1 a refusé le format « Nom &lt;adresse&gt; » et le domaine .example", "Utilisation de l'adresse seule, sur un domaine .test"],
             ["Activation des workflows", "n8n 2.x remplace update:workflow par publish:workflow", "Commande documentée dans le README"],
             ["Plusieurs dossiers pour une même campagne", "n8n envoie les signalements en parallèle : chaque requête cherchait un dossier, n'en trouvait pas et créait le sien. Un test antérieur était passé par chance", "Verrou autour du rattachement et test de non-régression (7 dossiers avant le correctif, 1 après)"],
             ["Plantage sur un vrai e-mail", "Le corpus contient un charset inexistant (DEFAULT_CHARSET), qui faisait échouer l'analyse", "Repli sur UTF-8 et test ajouté"],
             ["Rappel très faible à la première mesure", "21,5 % sur tout le corpus : les poids d'origine, jamais confrontés à de vraies données, visaient un phishing éloigné de celui de 2024", "Réglage sur la partie réglage et mesure sur une partie test séparée (6.3)"]], [4.2, 7, 5.4]),
      Spacer(1, 6),
      H1("10. Conclusion et perspectives"),
      P("Les trois objectifs sont atteints sur l'environnement de test : l'e-mail n'est jamais ouvert sur le poste de l'analyste, "
        "une campagne produit un seul dossier, et la réponse touche le rapporteur comme les autres destinataires. Le système "
        "réutilise aussi ses décisions : une campagne confirmée est ensuite traitée automatiquement."),
      P("Le score a été mesuré sur 566 e-mails de test : précision de 73 %, rappel de 66,5 %, 13 % de faux positifs, sans réputation "
        "en ligne. Cette mesure a aussi révélé deux défauts réels, corrigés, que les messages de test ne montraient pas. Ce résultat "
        "suffit pour aider au tri, mais pas pour classer un e-mail légitime sans contrôle : la classification automatique devrait "
        "rester prudente tant que le rappel n'a pas progressé."),
      P("Perspectives :")]
S += LI(["Évaluer le score sur des e-mails légitimes récents et anonymisés, pour connaître le vrai taux de faux positifs.",
         "Mesurer l'apport de la réputation en ligne avec des clés API, sur des indicateurs récents.",
         "Formuler la réponse automatique comme « aucun indicateur trouvé » plutôt que « légitime ».",
         "Capture isolée de la page cible avec un navigateur headless.",
         "Résumé du signalement par un LLM, destiné au rapporteur.",
         "Connexion à Microsoft Graph ou à l'API Gmail pour une purge en production.",
         "Authentification du tableau de bord, de l'API et du webhook."])
S += [H1("Annexe A : installation"),
      CODE("cp .env.example .env\n"
           "docker compose up -d --build\n"
           "docker exec soar-n8n n8n import:workflow --separate --input=/workflows\n"
           "docker exec soar-n8n n8n publish:workflow --id=soarPhishIngest01\n"
           "docker exec soar-n8n n8n publish:workflow --id=soarPhishDecide02\n"
           "docker restart soar-n8n"),
      P("Tableau de bord : http://localhost:8000 · Mailpit : http://localhost:8025 · n8n : http://localhost:5680"),
      H1("Annexe B : lancer les tests et l'évaluation"),
      CODE('docker run --rm -v "<dossier du projet>/analyzer:/t:ro" -w /t -e RULES_DIR=/t/rules \\\n'
           "  soar-phishing-analyzer:latest python tests/test_core.py\n"
           "docker exec soar-analyzer python -I /dataset/preparer_corpus.py\n"
           "docker exec -w /app soar-analyzer python -m app.evaluate --dataset /data/corpus --as-report --split test\n"
           "docker cp soar-analyzer:/data/corpus/results dataset/"),
      P("Corpus utilisés : J. Nazario, <i>phishing-2024</i>, https://monkey.org/~jose/phishing/ (CC-BY-4.0) ; Apache SpamAssassin "
        "Public Corpus, https://spamassassin.apache.org/old/publiccorpus/."),
      H1("Annexe C : organisation du projet"),
      TABLE([["Chemin", "Contenu"],
             ["docker-compose.yml, .env.example", "Déploiement et configuration"],
             ["analyzer/app/", "parser, ioc, lookalike, yara_scan, enrich, scoring, cluster, pipeline, actions, response, thehive, store, dashboard, evaluate, main"],
             ["analyzer/rules/", "Règles YARA"],
             ["analyzer/tests/", "Tests unitaires"],
             ["n8n/workflows/", "Workflows 01 (ingestion) et 02 (décision)"],
             ["coredns/", "Configuration du DNS filtrant et liste de blocage"],
             ["scripts/report_email.py, scripts/configurer_lab.py", "Simulation des signalements, préparation de n8n et de GoPhish"],
             ["dataset/preparer_corpus.py, dataset/results/", "Construction du jeu d'essai, matrice et résultats"],
             ["docs/score.md, README.md", "Justification du score et guide d'utilisation"]], [6, 10.6])]

doc = Doc(args.sortie, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.9 * cm,
          title="Rapport de projet : SOAR phishing", author=args.auteur)
doc.multiBuild(S, onLaterPages=footer)
print("ok", args.sortie)
