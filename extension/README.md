# PhishGuard — Chrome Extension

Adds a floating analysis panel to Gmail, Outlook, Yahoo Mail, ProtonMail, and other webmail interfaces.

## What it does

1. You export an email from your webmail as a `.eml` file.
2. You drop it into the PhishGuard panel.
3. The extension sends it to your local PhishGuard backend (`POST /analyze/file`).
4. Results are displayed in the panel: verdict, score, sub-scores, and reasons.

## Sub-scores displayed

| Sub-score | What it checks |
|-----------|----------------|
| Texte | Phishing keywords and phrases (12 languages) |
| Headers | Sender identity, DKIM/SPF/DMARC, hop count |
| URL | Shorteners, homoglyphs, brand impersonation, TLDs |
| Domaine | WHOIS domain age |
| Réputation | DNSBL, URLhaus, OpenPhish, PhishTank |
| Pièces jointes | Risky attachment extensions |
| ML | Local ML model (if configured) |

## Installation

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode** (top right toggle).
3. Click **Load unpacked**.
4. Select the `extension/` folder from this project.
5. The PhishGuard button will appear on supported webmail pages.

## Configuration

Click **Configurer l'API** in the panel (or open the extension options) to set the backend URL.

Default: `http://127.0.0.1:8000`

Make sure the PhishGuard backend is running before analyzing emails:

```bash
cd ..
uvicorn api:app --reload
```

## Supported webmail hosts

Gmail, Outlook (Office 365 + Live), Yahoo Mail, ProtonMail, Roundcube, and any host with "mail", "inbox", or "webmail" in the URL.

## Notes

- Only `.eml` files are supported by the extension UI. The backend also accepts `.msg` files via direct API call.
- The backend processes and immediately discards the uploaded file — nothing is stored permanently.
- The extension requires the backend to be running locally. No data is sent to any external server.
