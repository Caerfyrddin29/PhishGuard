# PhishGuard Chrome Extension

The extension provides a small upload-and-result panel on supported webmail pages.
It does **not** parse mail directly in the browser. Instead, it sends an exported `.eml` or `.msg` file to the local PhishGuard backend.

---

## What it does

1. You export a message from your webmail as **`.eml`** or **`.msg`**.
2. You open the PhishGuard panel on a supported page.
3. You drop the file into the panel or choose it manually.
4. The extension sends the file to your **local** backend at `/analyze/file`.
5. The panel displays the verdict, score, confidence, sub-scores, and top reasons.

---

## Supported file types

The current UI accepts:
- `.eml`
- `.msg`

The backend also accepts both formats directly over the API.

---

## What the panel shows

### Verdict labels
- **Suspect (phishing)** → backend verdict `phishing`
- **Suspect** → backend verdict `suspicious`
- **Plutôt légitime** → backend verdict `legit`
- **Analyse inconclusive** → backend verdict/status `inconclusive`

### Sub-scores shown in the UI
- **Texte** → suspicious language and subject patterns
- **Headers** → sender identity, auth failures, reply-chain inconsistencies, routing anomalies
- **URL** → suspicious links, volume, encoding, domain patterns
- **Domaine** → domain age / trusted-domain logic
- **Réputation** → DNSBL, URLhaus, OpenPhish
- **Pièces jointes** → dangerous file extensions
- **ML** → optional machine-learning contribution
- **Bénin** → trust signals that lower the final score

Important detail:
- **Bénin** is displayed as the negative trust contribution returned by the backend.

---

## Supported webmail hosts

The extension is intentionally restricted by `manifest.json` to these hosts:
- `mail.google.com`
- `outlook.office.com`
- `outlook.live.com`
- `mail.yahoo.com`
- `proton.me`
- `mail.proton.me`
- `mail.protonmail.com`

If you want additional hosts, update `extension/manifest.json` and test them explicitly.

---

## Installation

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder from this repository
5. Open one of the supported webmail hosts
6. Start your local PhishGuard backend

Backend example:

```bash
uvicorn api:app --reload
```

---

## Backend URL configuration

The extension stores a backend URL in Chrome sync storage.
Default:

```text
http://127.0.0.1:8000
```

Important limitation:
- the manifest currently grants host permissions only for:
  - `http://127.0.0.1:8000/*`
  - `http://localhost:8000/*`
- using another host or port requires updating `manifest.json`

So in practice, the extension is meant to talk to a **local backend on port 8000** unless you also change the extension permissions.

---

## Data flow and privacy

### Browser side
- the extension sends the selected `.eml` / `.msg` file to your **local** backend
- it does not upload directly to an external SaaS endpoint

### Backend side
Depending on your backend configuration:
- the backend may perform **network reputation lookups** (DNSBL, URLhaus, OpenPhish)
- extracted attachments are **not** stored permanently unless `PHISHGUARD_SAVE_ATTACHMENTS=1`
- temporary `.msg` files used during parsing are deleted after processing

So the accurate statement is:
- **file upload stays local to your backend**, but the backend may still consult external reputation sources if enabled

---

## Result interpretation

The score is not a raw “probability of phishing”.
The backend uses a calibrated model that combines:
- risk analyzers
- trust / benign signals
- structural flags

That means:
- a message can be labeled `phishing` with a moderate-looking numeric score if a strong structural signal is present
- a noisy newsletter with many links can remain `legit` if it has strong benign/authenticated signals

---

## Troubleshooting

### The panel appears but upload fails
Check that:
- the backend is running
- the backend URL matches the local host/port allowed by the manifest
- CORS is not misconfigured on the backend

### The panel does not appear
Check that you are on one of the supported hosts listed above.

### A custom backend URL saves but requests still fail
That usually means the value is outside the hosts permitted by `manifest.json`.

---

## Files in the extension folder

- `manifest.json` → extension manifest and host permissions
- `content.js` → page UI and file-upload logic
- `background.js` → sends the file to the backend
- `options.html` / `options.js` → backend URL configuration page
- `content.css` → panel styling
