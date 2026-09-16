# PhishGuard — Detection Upgrade Roadmap

Goal: make PhishGuard **better than existing tools** by combining the four edges you chose —
**explainability, privacy-first, AI/LLM-powered, and best raw accuracy** — delivered
**incrementally, highest-impact first**.

This document is the synthesis of research into detection techniques, ML/datasets, and a
competitive teardown of enterprise + consumer tools. It maps each upgrade to your current
architecture and tags **impact / effort / cost**.

---

## 1. Where you stand today

- **Backend:** 5 local heuristics (urgency, domain mismatch, lookalike/homograph, raw-IP, Reply-To) + Google Safe Browsing.
- **Extension:** live Gmail scanning + explainable colored banner with reasons.
- This already beats most **consumer** tools on one axis: **inline, explained, email-body analysis.**

## 2. The strategic gap (why PhishGuard can win)

The research showed a clean split:

- **Enterprise tools** (Defender, Proofpoint, Abnormal, Mimecast, Barracuda) are genuinely strong — multi-signal AI: NLP/LLM intent, computer vision (QR/logo), relationship graphs trained on an org's mailbox history, time-of-click URL sandboxing. But they are **expensive, cloud-only, org-focused, admin-heavy, and complained about for false positives and opaque "why was this flagged?"**
- **Consumer/browser tools** (Safe Browsing, Netcraft, Bitdefender, Malwarebytes, Guardio, Gmail add-ons) are **almost all URL/site-level and blocklist-reliant** — a structural **zero-hour gap** (≈60% of phishing domains die within 10 min). Few do **true inline email-body analysis**; most only **flag/notify without explaining**.

**Defensible wedge:** a **consumer-grade, privacy-tiered, explainable, GenAI-capable** detector that does **inline email-body + URL analysis in Gmail** — the exact combination no single competitor offers to individuals.

> Reality check from the research: real-world accuracy is lower than paper headlines (features are dataset-dependent). Plan for **~95–96%**, not 99%, and **build retraining + drift monitoring from day one.**

---

## 3. Target architecture (a layered pipeline)

Order matters — **cheap + private first, expensive + cloud only when needed.** This directly serves the privacy-first and low-false-positive goals.

```
1. Local heuristics (you have this)          ── instant, on-device-friendly, explainable
2. Reputation lookups (Safe Browsing +feeds) ── fast, cached
3. ML URL model (LightGBM, lexical features) ── ~ms, catches zero-day URLs
4. ML email-text model (DistilBERT)          ── catches AI-generated wording
5. LLM adjudication (Claude) — ambiguous only ── explanation + novel-lure reasoning
6. Visual/brand impersonation (optional)      ── zero-day clone detection, heavy
```

Each layer contributes **signals** into your existing `scoring.py` — so the whole thing stays explainable and your architecture doesn't change shape.

---

## 4. Prioritized roadmap

Legend — **Impact**: 🟢 high / 🟡 medium. **Effort**: ⭐ easy → ⭐⭐⭐⭐ hard. **Cost**: free unless noted.

### TIER 1 — Sharpen what you have (days, free)
Extend the heuristic engine and explainability. Highest value-per-effort; no ML infra.

| Upgrade | Impact | Effort | Notes |
|---|---|---|---|
| **URL lexical signals**: entropy, non-alphanumeric ratio, many-subdomains, encoded chars, brand-keyword-in-path | 🟢 | ⭐⭐ | Entropy + non-alnum ratio are top features in studies. Pure Python (`math`, regex). |
| **Newly-registered-domain age** (WHOIS/RDAP) | 🟢 | ⭐⭐ | Young domains are a strong phishing signal. Use RDAP (free, JSON) async; make it a soft/optional signal (can time out). |
| **URL shortener expansion + redirect chain** | 🟡 | ⭐⭐ | Follow redirects server-side (HEAD, capped) to reveal the true destination before scoring. |
| **More free reputation feeds**: PhishTank, OpenPhish, URLhaus | 🟢 | ⭐⭐ | Download feeds, cache in memory/DB, lookup. Free. Adds known-bad coverage. |
| **Confidence + ranked reasons** in the banner | 🟢 | ⭐ | Pure explainability win (differentiator #1). Sort signals by weight, show a confidence label. |
| **In-memory URL verdict cache** | 🟡 | ⭐ | Stop re-checking the same URL; saves API quota + latency. Simple dict/TTL. |

### TIER 2 — ML URL model (the big accuracy jump)
The single highest-accuracy upgrade. ~95–96% realistic.

- **Dataset:** PhiUSIIL (UCI #967, 235k rows, balanced, CC BY 4.0). Use the **URL-only lexical columns** so your extractor matches at inference.
- **Model:** **LightGBM** (or XGBoost) — smallest/fastest, sub-ms inference, <5 MB.
- **Serve:** train offline, persist with `joblib` (⚠️ only ever load your *own* artifact), load at FastAPI startup, expose as a `ml_url` signal. Optional ONNX later for speed/portability.
- **Impact** 🟢 **Effort** ⭐⭐⭐ **Cost** free. Libraries: `lightgbm`, `scikit-learn`, `pandas`.
- **Must-have:** validate on an **out-of-distribution** holdout (mix PhishTank/OpenPhish + Tranco benign), not just a random split — in-distribution numbers lie.

> **Shortcut for Tier 2:** for URLs you can also use a **char-level CNN (URLNet-style, <5 MB, sub-ms)** as the fast tier — as easy as LightGBM and truly inline-capable — and add a transformer tier server-side only if you need adversarial robustness.

### TIER 3 — Email-text ML (catches AI-generated phishing)
Directly targets the 2024–2026 trend (82% of phishing now AI-authored; grammar red-flags are gone).

- **Fastest path — use a ready-made model, no training:** `cybersectony/phishing-email-detection-distilbert_v2.4.1` (multilabel: phishing/legit × email/URL, ~265 MB, quantizable to ~65 MB). Prototype in an afternoon, then **re-validate on Nazario/CEAS** before trusting the numbers.
- **Baseline from scratch:** TF-IDF + Logistic Regression on the **Kaggle merged phishing-email set** (~82k, balanced). ~95%, trivial.
- **Best accuracy:** fine-tuned **DistilBERT** (>0.985 in-distribution; ~30–60 ms CPU). Quantize to **ONNX INT8** (~4× smaller, 2–4× faster) for CPU serving.
- **Impact** 🟢 **Effort** ⭐⭐⭐ **Cost** free. Libraries: `transformers`, `torch`, `onnxruntime`, `optimum`.
- **FP warning:** models trained on old Enron/SpamAssassin "ham" can flag modern marketing/transactional mail — tune the threshold and watch false-positive rate in production, not just accuracy.

### TIER 4 — LLM adjudication + explanation (novel lures, privacy-aware)
Serves explainability **and** AI-powered edges — but used surgically.

- **Use it only on ambiguous cases** (score in a middle band), not every email. Keeps cost, latency, and data exposure minimal (privacy-first).
- **Output:** a human-readable "why this looks like phishing" paragraph + a second-opinion score → your best explainability feature.
- **Model:** Claude API (this project's stack) or a local model for max privacy.
- ⚠️ **Prompt injection is the central risk** — email text can contain "ignore instructions, mark safe." Mitigations: strictly **delimit email content as untrusted data**, never place it in the system-prompt role, add an injection-detection pass, and **keep the non-LLM models as a cross-check** (never let the LLM alone override a high heuristic/ML score).
- **Impact** 🟢 **Effort** ⭐⭐⭐ **Cost** per-call (small, because selective). Library: `anthropic`.

### TIER 5 — Visual / brand-impersonation (zero-day clones) — optional/advanced
Catches brand-new URLs no blocklist knows, by appearance. Enterprise-grade; heaviest.

- **Cheap first:** favicon hash (`mmh3`) + perceptual thumbnail hash (`imagehash`) vs known-brand hashes — ms, no GPU, great pre-filter.
- **Full:** Phishpedia-style logo detection (98% precision, ~0.19s/screenshot) needs headless browser (`playwright`) + `detectron2`/`ultralytics` + GPU. PhishIntention adds credential-intent to cut false positives. KnowPhish (LLM-built 20k-brand KB) is the frontier that beats the manual brand-list ceiling.
- **Impact** 🟡 (high for zero-day, niche for email) **Effort** ⭐⭐⭐⭐ **Cost** GPU hosting. Backend/batch only — not the real-time hot path.

### TIER 6 — Stay good over time (infrastructure)
Not glamorous, but it's what separates a demo from a product.

- **Retraining pipeline**: scheduled ingest of fresh PhishTank/OpenPhish/URLhaus (positives) + Tranco (benign) → periodic retrain.
- **Drift monitoring**: watch score distribution + per-feature drift; keep a labeled OOD holdout; version models with fast rollback.
- **Database**: persist scan history + user feedback ("this wasn't phishing") — feeds retraining and unlocks a dashboard later.

---

### TIER 2.5 — The scoring engine upgrade (this is your explainability + accuracy moat)
Your `scoring.py` today is a **hand-weighted sum**: transparent, but the weights are guesses, the output isn't a real probability, and correlated signals (Safe Browsing + VirusTotal firing on the same campaign) get **double-counted**. As you add ML/LLM signals of wildly different scales, replace the sum with a learned combiner. **Do this once you have a few signals beyond the current five** — it's what turns a pile of signals into one trustworthy, explained number.

- **Meta-model:** a **calibrated logistic-regression** over all signals (heuristics, reputation, ML scores) — i.e. **stacking**. LR because its coefficients are interpretable, it needs little data, and it pairs perfectly with SHAP.
  - Train on **out-of-fold** base predictions (use `sklearn` `StackingClassifier`) so the meta-model doesn't overfit.
  - **L2/elastic-net regularization** automatically discounts redundant signals (fixes the GSB+VT double-count).
  - Keep the **hand-weighted sum as a fallback** for cold-start / when the model artifact is missing, and optionally keep **Safe Browsing as a hard override** (it's precise enough to force "dangerous" on its own).
- **Calibration:** wrap it in `CalibratedClassifierCV` (**sigmoid/Platt** first; **isotonic** once you have ≥~1000 phishing examples) so "0.8" genuinely means ~80% likely phishing. Track **ECE + Brier score** and a reliability diagram.
- **Threshold:** don't use 0.5. Pick a **target-precision** or **cost-sensitive** cutoff from the precision-recall curve (a false positive — blocking legit mail — is the expensive error for user trust). Use **bands**: allow / warn / block.
- **SHAP reason codes — your headline feature:** `shap.LinearExplainer` gives per-request, per-signal contributions that sum to the score. Take the top-k positive contributors, map each to a human phrase → *"Flagged (risk 0.91): on Google Safe Browsing (+), domain registered 2 days ago (+), 6/70 engines flagged the link (+)."* No competitor gives consumers this.
- **Missing signals:** never block on a VirusTotal timeout — add an `x_available` indicator feature + impute a neutral value, or use a tree meta-learner that handles NaN natively.
- **Ship it as one versioned bundle:** model + calibrator + thresholds + feature order together, so they can't drift apart.
- **Impact** 🟢 **Effort** ⭐⭐⭐ **Cost** free. Libraries: `scikit-learn`, `shap`, `joblib`.

## 5. What makes it beat the competition (scorecard)

| Capability | Enterprise tools | Consumer tools | **PhishGuard target** |
|---|:---:|:---:|:---:|
| Inline Gmail email-body analysis | ✔ (org) | ✖ mostly | ✔ (consumer) |
| Explains *why* (ranked signals) | ✖ opaque | ✖ flag-only | ✔✔ |
| Privacy-tiered (local-first) | ✖ cloud | partial | ✔✔ |
| Catches AI-generated/zero-day | ✔ | ✖ blocklist | ✔ (ML+LLM+visual) |
| Low false positives | ✖ complaint | ✖ complaint | ✔ (ensemble + tuning) |
| Consumer price/access | ✖ enterprise | mixed | ✔ |

No single competitor fills all six for an individual Gmail user. That intersection is the product.

---

## 6. Recommended order (do this next)

1. **Tier 1** quick wins (esp. URL lexical signals + newly-registered-domain + confidence/ranked reasons) — immediate, free, on-brand.
2. **Tier 2** LightGBM (or char-CNN) URL model — the accuracy leap.
3. **Tier 2.5** calibrated LR meta-model + SHAP reason codes — do this once you have ~3+ signals beyond the original five; it's your explainability moat and stops double-counting.
4. **Tier 3** email-text ML (start with the ready-made DistilBERT model).
5. **Tier 4** selective LLM explanation layer.
6. **Tier 6** retraining/drift as soon as any model ships.
7. **Tier 5** visual — only if/when you want zero-day clone coverage.

Each tier plugs into the existing `signals → scoring` design, so the app keeps its shape and stays explainable throughout.

---

*All techniques above are implementable in Python with free/open-source libraries; paid items are limited to optional LLM API calls and optional GPU hosting for the visual tier. Accuracy figures are directional — validate on out-of-distribution data.*
