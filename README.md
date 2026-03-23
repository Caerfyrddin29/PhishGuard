# PhishGuard (recoded)

Backend FastAPI + browser extension to analyze `.eml`/`.msg` phishing emails.

## Run API

```bash
pip install -r requirements.txt
uvicorn api:app --reload
```

## Endpoints

- `GET /health`
- `POST /analyze/file` (multipart upload `.eml`/`.msg`)
- `POST /analyze/base64-eml`
- `POST /debug/parse` (returns extraction only)

## ML

Default: local scikit-learn model at `models/phishing_model.joblib` (optional).

Enable Hugging Face model:

```bash
pip install -r requirements-hf.txt
PHISHGUARD_ENABLE_HF_ML=1 uvicorn api:app --reload
```
