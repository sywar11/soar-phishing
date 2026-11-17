"""Configuration lue depuis les variables d'environnement (.env)."""
import os


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str) -> list[str]:
    return [x.strip().lower() for x in os.getenv(name, default).split(",") if x.strip()]


REPORT_MAILBOX = os.getenv("REPORT_MAILBOX", "phishing@corp.local").lower()
SOC_SENDER = os.getenv("SOC_SENDER", "soc@corp.local")
INTERNAL_DOMAINS = _list("INTERNAL_DOMAINS", "corp.local")

THRESHOLD_SUSPICIOUS = int(os.getenv("THRESHOLD_SUSPICIOUS", "20"))
THRESHOLD_MALICIOUS = int(os.getenv("THRESHOLD_MALICIOUS", "70"))

MAILPIT_URL = os.getenv("MAILPIT_URL", "http://localhost:8025").rstrip("/")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))

ENABLE_ONLINE_LOOKUPS = _bool("ENABLE_ONLINE_LOOKUPS", True)
FOLLOW_REDIRECTS = _bool("FOLLOW_REDIRECTS", False)
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
VT_MAX_LOOKUPS = int(os.getenv("VT_MAX_LOOKUPS", "4"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "8"))

THEHIVE_URL = os.getenv("THEHIVE_URL", "").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "").strip()

DB_PATH = os.getenv("DB_PATH", "/data/soar.db")
BLOCKLIST_PATH = os.getenv("BLOCKLIST_PATH", "/dns/blocklist.hosts")
RULES_DIR = os.getenv("RULES_DIR", "/app/rules")
N8N_DECISION_WEBHOOK = os.getenv("N8N_DECISION_WEBHOOK", "").strip()
PUBLIC_ANALYZER_URL = os.getenv("PUBLIC_ANALYZER_URL", "http://localhost:8000").rstrip("/")

# Fenêtre de regroupement en campagne (jours)
CAMPAIGN_WINDOW_DAYS = int(os.getenv("CAMPAIGN_WINDOW_DAYS", "14"))

# Marques / domaines légitimes protégés : sert à la détection de domaines similaires
# et constitue une liste d'exclusion pour le blocage DNS (on ne bloque jamais ces domaines).
PROTECTED_DOMAINS = _list(
    "PROTECTED_DOMAINS",
    "corp.local,microsoft.com,microsoftonline.com,onmicrosoft.com,office.com,office365.com,outlook.com,live.com,google.com,gmail.com,"
    "apple.com,icloud.com,paypal.com,amazon.com,amazon.fr,docusign.com,docusign.net,dhl.com,"
    "laposte.fr,ameli.fr,impots.gouv.fr,linkedin.com,dropbox.com,netflix.com,adobe.com,"
    "sharepoint.com,wetransfer.com,fedex.com,ups.com,bnpparibas.net,societegenerale.fr,"
    "credit-agricole.fr,orange.fr,free.fr,sfr.fr",
)

# Domaines très courants qu'on ne bloque jamais et qu'on n'utilise pas pour regrouper des campagnes
NEVER_BLOCK = set(PROTECTED_DOMAINS) | set(
    _list(
        "NEVER_BLOCK",
        "w3.org,schemas.microsoft.com,googleapis.com,gstatic.com,facebook.com,twitter.com,x.com,"
        "instagram.com,youtube.com,bit.ly,tinyurl.com,safelinks.protection.outlook.com,"
        "mailchimp.com,list-manage.com,sendgrid.net,github.com",
    )
)
