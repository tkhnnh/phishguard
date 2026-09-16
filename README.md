<p align="center">
  <img src="assets/phishguard-banner.svg" alt="PhishGuard" width="720">
</p>

<p align="center">
  Phishing email detection — a <b>Chrome extension</b> that flags suspicious emails directly in Gmail,<br>
  backed by a <b>Python API</b> combining local heuristics with external threat-reputation services.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.141-009688?logo=fastapi&logoColor=white">
  <img alt="Chrome MV3" src="https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white">
  <img alt="Status" src="https://img.shields.io/badge/status-active%20development-2dd4bf">
</p>

---

---

## How it works

```
Gmail (open email)
   │  content.js extracts sender, subject, body, links
   ▼
Background service worker
   │  POST /analyze
   ▼
FastAPI backend
   ├─ Local heuristics  (urgency, domain mismatch, lookalike/homograph, raw-IP links, Reply-To mismatch)
   └─ Reputation APIs   (Google Safe Browsing)
   │  → risk score + verdict + reasons
   ▼
Content script injects a colored banner (green / amber / red) at the top of the email
```

The backend returns a **risk score (0–100)**, a **verdict** (`Safe` / `Suspicious` / `Dangerous`), and a list of **signals** explaining *why*.

---

## Project structure

```
phishguard/
├── backend/                 FastAPI service
│   ├── app/
│   │   ├── main.py          App wiring, /analyze endpoint, CORS
│   │   ├── schemas.py       Pydantic models (EmailIn, Signal, AnalyzeResponse)
│   │   ├── config.py        Settings loaded from .env
│   │   ├── heuristics.py    Local detection rules
│   │   ├── scoring.py       Combine signals → score + verdict
│   │   └── reputation.py    Google Safe Browsing client
│   ├── tests/               pytest suite
│   ├── requirements.txt
│   ├── .env                 Secrets (git-ignored)
│   └── .env.example         Template of required keys
├── extension/               Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── content.js           Reads Gmail, injects the banner
│   ├── background.js         Calls the backend
│   └── styles.css            Banner styling
└── README.md
```

---

## Detection signals

| Signal | Weight | What it catches |
|--------|:-----:|-----------------|
| `urgency` | 20 | Pressure language ("verify your account", "within 24 hours") |
| `domain_mismatch` | 35 | Sender domain ≠ linked domain |
| `lookalike` | 40 | Typosquatting (`paypa1.com` vs `paypal.com`) |
| `homograph` | 35 | Punycode / mixed-script domains (`xn--…`) |
| `ip_url` | 30 | Links to a raw IP address instead of a domain |
| `reply_to_mismatch` | 25 | `Reply-To` domain differs from the sender |
| `safe_browsing` | 50 | URL flagged by Google Safe Browsing |

**Verdict thresholds:** `< 30` Safe · `30–69` Suspicious · `≥ 70` Dangerous.

---

## Setup

### Prerequisites
- Python 3.11+
- Google Chrome
- A Google Safe Browsing API key ([Google Cloud Console](https://console.cloud.google.com/))

### Backend

```bash
cd backend
python -m venv ../venv
../venv/Scripts/activate      # Windows
pip install -r requirements.txt
```

Create `backend/.env` from the template and add your key:

```
SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=
```

Run the API:

```bash
uvicorn app.main:app --reload
```

Interactive docs: <http://localhost:8000/docs>

### Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Open Gmail and click an email — a risk banner appears at the top.

> The extension calls `http://localhost:8000`, so the backend must be running.

---

## API

### `POST /analyze`

**Request**
```json
{
  "sender": "PayPal <service@paypal.com>",
  "reply_to": null,
  "subject": "Your account is suspended",
  "body_text": "Verify your account within 24 hours.",
  "urls": ["http://paypa1.com/login"]
}
```

**Response**
```json
{
  "score": 100,
  "verdict": "Dangerous",
  "signals": [
    { "code": "urgency", "message": "...", "weight": 20, "severity": "medium" },
    { "code": "lookalike", "message": "...", "weight": 40, "severity": "high" }
  ]
}
```

---

## Testing

```bash
cd backend
pytest -v
```

---

## Roadmap

- [x] Local heuristics engine (5 rules)
- [x] Google Safe Browsing integration
- [x] Chrome extension with in-Gmail banner
- [ ] Test suite
- [ ] VirusTotal integration + URL caching
- [ ] Deploy backend (currently localhost-only)
- [ ] Mobile app (React Native) reusing `/analyze`

---

## Security notes

- Secrets live in `.env` (git-ignored); `.env.example` documents required keys.
- API keys are used **server-side only** — never exposed to the extension or browser.
- CORS is currently open (`*`) for local development; restrict to the extension's origin before deploying.
