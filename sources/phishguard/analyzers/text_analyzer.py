#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import ExtractedEmailData


@dataclass
class TextSignals:
    score: int
    reasons: list[str]


# ---------------------------------------------------------------------------
# HIGH-WEIGHT phrases (3 pts each) — strong phishing / scam / urgency signals
# ---------------------------------------------------------------------------
_HIGH_WEIGHT: tuple[str, ...] = (
    # --- English ---
    "verify your account", "confirm your account", "update your account",
    "account has been suspended", "account has been locked", "account will be closed",
    "account will be terminated", "account will be deactivated",
    "unusual activity", "suspicious activity", "unauthorized access",
    "your password has expired", "reset your password", "change your password",
    "click here to verify", "click here to confirm", "click the link below",
    "click here immediately", "click here now",
    "you have been selected", "you have won", "you are a winner",
    "congratulations you", "claim your prize", "claim your reward",
    "limited time offer", "act now", "act immediately", "respond immediately",
    "immediate action required", "action required", "response required",
    "your account will be", "we noticed suspicious", "we detected unusual",
    "failure to respond", "failure to verify", "failure to confirm",
    "your information is required", "update your information",
    "provide your details", "enter your credentials",
    "confirm your identity", "verify your identity",
    "wire transfer", "bank transfer", "money transfer", "send money",
    "gift card", "itunes card", "google play card",
    "western union", "moneygram",
    "inheritance funds", "unclaimed funds",
    "investment opportunity", "guaranteed return", "100% guaranteed",
    "make money fast", "earn money fast",
    "free money", "free gift", "free prize", "free offer",
    "your paypal", "your amazon", "your netflix", "your apple id",
    "dear customer", "dear user", "dear account holder", "dear member",
    "billing information", "payment information", "credit card information",
    "social security", "date of birth required",
    "we are unable to process", "transaction failed", "payment failed",
    "delivery failed", "package could not be delivered",
    # --- French ---
    "vérifiez votre compte", "confirmez votre compte", "mettez à jour votre compte",
    "votre compte a été suspendu", "votre compte a été bloqué", "votre compte sera fermé",
    "votre compte va être désactivé",
    "activité inhabituelle", "activité suspecte", "accès non autorisé",
    "votre mot de passe a expiré", "réinitialisez votre mot de passe",
    "cliquez ici pour vérifier", "cliquez ici pour confirmer",
    "cliquez sur le lien", "cliquez immédiatement",
    "vous avez été sélectionné", "vous avez gagné", "vous êtes gagnant",
    "félicitations vous", "réclamez votre prix",
    "offre limitée", "agissez maintenant", "agissez immédiatement",
    "action requise", "réponse requise", "répondez immédiatement",
    "votre compte sera", "nous avons détecté", "nous avons remarqué",
    "en cas de non-réponse", "si vous ne vérifiez pas",
    "fournissez vos informations", "entrez vos identifiants",
    "confirmez votre identité", "vérifiez votre identité",
    "virement bancaire", "transfert d'argent", "envoyer de l'argent",
    "carte cadeau", "carte itunes", "carte google play",
    "cher client", "cher utilisateur", "cher membre",
    "informations de paiement", "informations de carte",
    "nous ne pouvons pas traiter", "transaction échouée", "paiement échoué",
    "livraison échouée", "colis non livré",
    "offre exceptionnelle", "offre exclusive",
    "vous avez été choisi", "profitez maintenant",
    "dernière chance", "expire bientôt",
    "accès immédiat", "accès gratuit",
    "gagnez du temps", "gain de temps",
    # --- Spanish ---
    "verifique su cuenta", "confirme su cuenta", "actualice su cuenta",
    "su cuenta ha sido suspendida", "su cuenta ha sido bloqueada",
    "actividad inusual", "actividad sospechosa", "acceso no autorizado",
    "su contraseña ha expirado", "restablezca su contraseña",
    "haga clic aquí para verificar", "haga clic aquí para confirmar",
    "ha sido seleccionado", "ha ganado", "es usted el ganador",
    "reclame su premio", "oferta por tiempo limitado",
    "actúe ahora", "acción requerida",
    "su cuenta será", "proporcione sus datos",
    "confirme su identidad", "transferencia bancaria",
    "tarjeta de regalo", "estimado cliente",
    "información de pago", "transacción fallida", "pago fallido",
    # --- German ---
    "verifizieren sie ihr konto", "bestätigen sie ihr konto",
    "ihr konto wurde gesperrt", "ihr konto wurde deaktiviert",
    "ungewöhnliche aktivität", "verdächtige aktivität",
    "ihr passwort ist abgelaufen", "passwort zurücksetzen",
    "klicken sie hier um zu bestätigen",
    "sie wurden ausgewählt", "sie haben gewonnen", "herzlichen glückwunsch",
    "fordern sie ihren preis an", "zeitlich begrenztes angebot",
    "handeln sie jetzt", "sofortige maßnahme erforderlich",
    "ihr konto wird", "geben sie ihre daten ein",
    "banküberweisung", "geldtransfer", "gutscheinkarte",
    "sehr geehrter kunde", "zahlungsinformationen",
    "transaktion fehlgeschlagen",
    # --- Italian ---
    "verifica il tuo account", "conferma il tuo account",
    "il tuo account è stato sospeso", "il tuo account è stato bloccato",
    "attività insolita", "attività sospetta", "accesso non autorizzato",
    "la tua password è scaduta", "reimposta la password",
    "clicca qui per verificare", "clicca qui per confermare",
    "sei stato selezionato", "hai vinto",
    "riscatta il tuo premio", "offerta a tempo limitato",
    "agisci ora", "azione richiesta",
    "il tuo account sarà", "fornisci i tuoi dati",
    "conferma la tua identità", "bonifico bancario",
    "carta regalo", "gentile cliente",
    "informazioni di pagamento", "transazione fallita",
    # --- Portuguese ---
    "verifique sua conta", "confirme sua conta", "atualize sua conta",
    "sua conta foi suspensa", "sua conta foi bloqueada",
    "atividade incomum", "atividade suspeita", "acesso não autorizado",
    "sua senha expirou", "redefinir sua senha",
    "clique aqui para verificar", "clique aqui para confirmar",
    "você foi selecionado", "você ganhou",
    "reivindique seu prêmio", "oferta por tempo limitado",
    "aja agora", "ação necessária",
    "sua conta será", "forneça seus dados",
    "confirme sua identidade", "transferência bancária",
    "cartão presente", "caro cliente",
    "informações de pagamento", "transação falhou",
    # --- Dutch ---
    "verifieer uw account", "bevestig uw account",
    "uw account is geblokkeerd", "uw account is opgeschort",
    "ongebruikelijke activiteit", "verdachte activiteit",
    "uw wachtwoord is verlopen", "reset uw wachtwoord",
    "klik hier om te bevestigen",
    "u bent geselecteerd", "u heeft gewonnen", "gefeliciteerd",
    "claim uw prijs", "beperkte tijdaanbieding",
    "handel nu", "actie vereist",
    "bankoverschrijving", "geldoverdracht",
    "cadeaukaart", "geachte klant",
    "betalingsinformatie", "transactie mislukt",
    # --- Turkish ---
    "hesabınız askıya alındı", "hesabınız engellendi",
    "şifreniz sona erdi", "şifrenizi sıfırlayın",
    "doğrulayın hesabınızı", "tebrikler kazandınız",
    "sınırlı süreli teklif", "hemen harekete geçin",
    "banka havalesi", "hediye kartı", "sayın müşteri",
    # --- Polish ---
    "zweryfikuj swoje konto", "twoje konto zostało zablokowane",
    "twoje hasło wygasło", "zresetuj hasło",
    "kliknij tutaj aby potwierdzić", "wygrałeś",
    "gratulacje", "oferta ograniczona czasowo",
    "działaj teraz", "przelew bankowy",
    "karta podarunkowa", "drogi kliencie",
    "informacje o płatności", "transakcja nie powiodła się",
    # --- Romanian ---
    "verificați contul", "contul dvs a fost suspendat",
    "parola a expirat", "resetați parola",
    "faceți clic aici pentru confirmare", "ați câștigat",
    "felicitări", "ofertă limitată",
    "acționați acum", "transfer bancar",
    "card cadou", "stimate client",
    # --- Swedish ---
    "verifiera ditt konto", "ditt konto har spärrats",
    "ditt lösenord har gått ut", "återställ lösenordet",
    "klicka här för att bekräfta", "du har vunnit",
    "grattis", "tidsbegränsat erbjudande",
    "agera nu", "banköverföring",
    "presentkort", "kära kund",
    # --- Japanese (romaji / common phishing) ---
    "アカウントが停止", "パスワードが期限切れ", "クリックして確認",
    "おめでとう", "限定オファー", "今すぐ行動",
    # --- Chinese simplified ---
    "验证您的账户", "您的账户已被暂停", "异常活动",
    "点击此处验证", "您赢了", "恭喜", "限时优惠", "立即行动",
)

# ---------------------------------------------------------------------------
# MEDIUM-WEIGHT keywords (2 pts each)
# ---------------------------------------------------------------------------
_MEDIUM_WEIGHT: tuple[str, ...] = (
    # English
    "urgent", "immediately", "password", "verify", "confirm", "suspended",
    "locked", "login", "invoice", "payment", "security alert", "alert",
    "warning", "attention", "important notice", "final notice",
    "last chance", "expires soon", "expired", "expiring",
    "unauthorized", "suspicious", "unusual", "fraud", "fraudulent",
    "update required", "required", "mandatory",
    "prize", "winner", "reward", "bonus", "jackpot", "lottery",
    "inheritance", "beneficiary", "refund", "tax refund",
    "bitcoin", "cryptocurrency", "crypto", "wallet",
    "click here", "click now", "click below", "follow this link",
    "open the attachment", "download now", "install now",
    "your account", "your password", "your card", "your bank",
    "work from home", "free money", "free gift",
    # French
    "urgent", "immédiatement", "mot de passe", "vérifiez", "confirmez",
    "suspendu", "bloqué", "connexion", "facture", "paiement",
    "alerte", "attention", "avertissement", "avis important",
    "dernière chance", "expire bientôt", "expiré",
    "non autorisé", "suspect", "inhabituel", "fraude",
    "mise à jour requise", "obligatoire",
    "prix", "gagnant", "récompense", "loterie",
    "bitcoin", "cryptomonnaie", "portefeuille",
    "cliquez ici", "suivez ce lien", "téléchargez",
    "votre compte", "vos informations", "votre carte", "votre banque",
    "gagner", "gain", "gratuit", "gratis", "remboursement",
    "offre", "promotion", "réduction",
    # Spanish
    "urgente", "inmediatamente", "contraseña", "verificar", "confirmar",
    "suspendido", "bloqueado", "factura", "pago",
    "alerta", "atención", "aviso importante", "última oportunidad",
    "expira pronto", "expirado", "no autorizado", "sospechoso", "fraude",
    "obligatorio", "premio", "ganador", "lotería", "bitcoin",
    "haga clic aquí", "su cuenta", "su contraseña", "su tarjeta",
    # German
    "dringend", "sofort", "passwort", "verifizieren", "bestätigen",
    "gesperrt", "deaktiviert", "rechnung", "zahlung",
    "warnung", "achtung", "wichtige mitteilung", "letzte chance",
    "läuft bald ab", "abgelaufen", "unbefugt", "verdächtig", "betrug",
    "preis", "gewinner", "lotterie", "bitcoin",
    "klicken sie hier", "ihr konto", "ihr passwort",
    # Italian
    "urgente", "immediatamente", "password", "verificare", "confermare",
    "sospeso", "bloccato", "fattura", "pagamento",
    "avviso", "attenzione", "ultima possibilità", "scade presto",
    "non autorizzato", "sospetto", "frode",
    "premio", "vincitore", "lotteria", "bitcoin",
    "clicca qui", "il tuo account", "la tua password",
    # Portuguese
    "urgente", "imediatamente", "senha", "verificar", "confirmar",
    "suspenso", "bloqueado", "fatura", "pagamento",
    "alerta", "atenção", "última chance", "expira em breve",
    "não autorizado", "suspeito", "fraude",
    "prêmio", "vencedor", "loteria", "bitcoin",
    "clique aqui", "sua conta", "sua senha",
    # Dutch
    "dringend", "onmiddellijk", "wachtwoord", "verifieer", "bevestig",
    "geblokkeerd", "factuur", "betaling",
    "waarschuwing", "aandacht", "laatste kans", "verloopt binnenkort",
    "niet geautoriseerd", "verdachtig", "fraude",
    "prijs", "winnaar", "loterij", "bitcoin",
    "klik hier", "uw account", "uw wachtwoord",
    # Turkish
    "acil", "hemen", "şifre", "doğrula", "onayla",
    "askıya alındı", "engellendi", "fatura", "ödeme",
    "uyarı", "dikkat", "son şans", "süresi doldu",
    "yetkisiz", "şüpheli", "dolandırıcılık",
    "ödül", "kazanan", "piyango", "bitcoin",
    "buraya tıklayın", "hesabınız",
    # Polish
    "pilne", "natychmiast", "hasło", "zweryfikuj", "potwierdź",
    "zawieszone", "zablokowane", "faktura", "płatność",
    "ostrzeżenie", "uwaga", "ostatnia szansa", "wygasło",
    "nieautoryzowany", "podejrzany", "oszustwo",
    "nagroda", "zwycięzca", "loteria", "bitcoin",
    "kliknij tutaj", "twoje konto",
)

# ---------------------------------------------------------------------------
# SUBJECT-LINE regex patterns
# ---------------------------------------------------------------------------
_SUBJECT_PATTERNS: tuple[str, ...] = (
    r"^re\s*:", r"^fwd?\s*:", r"^tr\s*:", r"^fw\s*:",
    r"urgent", r"action required", r"action requise",
    r"verify now", r"vérifiez maintenant",
    r"account.{0,20}(suspended|locked|blocked|disabled)",
    r"compte.{0,20}(suspendu|bloqué)",
    r"you('ve| have) won", r"vous avez gagné",
    r"congratulations", r"félicitations",
    r"(invoice|facture)\s*#",
    r"payment.{0,10}(due|failed|required)",
    r"paiement.{0,10}(échoué|requis)",
    r"security.{0,10}(alert|notice|warning)",
    r"alerte.{0,15}(sécurité|de sécurité)",
    r"password.{0,10}(expired|expiring|reset)",
    r"mot de passe.{0,10}(expiré|réinitialisé)",
    r"your.{0,10}(paypal|amazon|netflix|apple|microsoft|google|bank)",
    r"votre.{0,10}(paypal|amazon|netflix|apple|microsoft|google|banque)",
    r"final.{0,10}(notice|warning|reminder)",
    r"last.{0,10}(chance|reminder)",
    r"dernière.{0,10}(chance|relance)",
    r"limited.{0,10}(time|offer)",
    r"offre.{0,10}(limitée|exclusive|spéciale)",
    r"free.{0,10}(gift|prize|money|offer)",
    r"\bgratuit\b", r"\bgain\b",
    r"earn \$", r"make \$",
    r"winner", r"gagnant",
    r"prize", r"prix",
    r"lottery", r"loterie",
    r"bitcoin", r"crypto",
    r"inheritance", r"héritage",
    r"refund", r"remboursement",
    r"suspended", r"suspendu", r"gesperrt", r"sospeso",
    r"warning", r"avertissement", r"warnung",
)


def _count_hits(lower: str, words: tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for w in words:
        if w not in seen and w in lower:
            seen.add(w)
            out.append(w)
    return out


def analyze_text(extracted: ExtractedEmailData) -> TextSignals:
    text = (extracted.body_text or "").strip()
    if not text and extracted.body_html:
        try:
            from ..utils import strip_html
            text = strip_html(extracted.body_html)
        except Exception:
            text = extracted.body_html

    subject = (extracted.subject or "").strip()
    reasons: list[str] = []
    score = 0

    if not text and not subject:
        return TextSignals(score=0, reasons=["[text] No usable textual content"])

    lower = text.lower() if text else ""

    # High-weight phrase hits (3 pts each, cap 30)
    high_hits = _count_hits(lower, _HIGH_WEIGHT)
    if high_hits:
        score += min(25, 3 * len(high_hits))
        reasons.append(
            f"[text] High-risk phrases ({len(high_hits)}): "
            f"{', '.join(high_hits[:5])}"
        )

    # Medium-weight keyword hits (2 pts each, cap 12, deduplicate against high)
    high_set = set(high_hits)
    med_hits = [w for w in _count_hits(lower, _MEDIUM_WEIGHT) if w not in high_set]
    if med_hits:
        score += min(12, 2 * len(med_hits))
        reasons.append(
            f"[text] Suspicious keywords ({len(med_hits)}): "
            f"{', '.join(med_hits[:8])}"
        )

    # Subject-line pattern scoring (2 pts per match, cap 10)
    subject_lower = subject.lower()
    subject_hits: list[str] = []
    for pat in _SUBJECT_PATTERNS:
        if re.search(pat, subject_lower) and pat not in subject_hits:
            subject_hits.append(pat)
    if subject_hits:
        score += min(10, 2 * len(subject_hits))
        readable = [p.replace("\\b", "").replace("\\s*", " ").replace("^", "")
                    for p in subject_hits[:4]]
        reasons.append(f"[text] Suspicious subject patterns: {', '.join(readable)}")

    # Short body heuristic
    if text and len(text) < 40:
        reasons.append("[text] Very short body")
        score = max(score, 5)

    # Image-only body (HTML present but no readable text — classic phishing tactic)
    if not text and extracted.body_html:
        reasons.append("[text] Body appears image-only (no readable text extracted)")
        score = max(score, 8)

    return TextSignals(score=min(35, score), reasons=reasons)
