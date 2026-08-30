# PhishGuard

**Real-Time Phishing & Malicious URL Detection System**

PhishGuard is an end-to-end cybersecurity system for detecting phishing and malicious URLs with a latency-aware ML inference pipeline. It combines a lightweight whitelist pre-filter, fast URL-based machine learning, conditional live network inspection, browser-side protection, persistent scan analytics, and continuously refreshed threat intelligence.

## Key Features

* **3-Stage Detection Cascade**

  * **Stage 1 — Tranco Bloom Filter:** Quickly bypasses known trusted domains while still allowing brand-spoof checks.
  * **Stage 2 — Tier 1 XGBoost:** Performs lightweight URL analysis using lexical and structural features.
  * **Stage 3 — Tier 2 XGBoost:** Escalates only ambiguous predictions for live DNS/HTTP inspection.

* **Real-Time Browser Protection**

  * Chrome extension built with Manifest V3.
  * Automatically scans visited URLs and displays `SAFE`, `WARN`, or `RISK` status.
  * Includes client-side caching and a synchronous cooldown lock to reduce duplicate requests.

* **Feature Engineering**

  * URL length and path length
  * Domain length and entropy
  * Subdomain depth
  * Numeric and hyphen counts
  * Suspicious file extensions
  * Brand mentions and brand-spoofing indicators
  * Urgency/security keyword indicators
  * DNS resolution status
  * HTTP status and security headers
  * HTTPS, HSTS and X-Frame/CSP related signals

* **Threat Intelligence Pipeline**

  * Ingests malicious URLs from the **URLhaus** feed.
  * Uses SHA-256 URL fingerprints to avoid duplicate threat samples.
  * Balances newly collected malicious URLs with benign URLs.
  * Stores staged threat data in Parquet format.

* **Continuous Model Adaptation**

  * Maintains a cumulative training-data vault.
  * Buffers newly collected threat samples.
  * Periodically retrains the production XGBoost model.
  * Compares candidate models against the current production model.
  * Applies accuracy/FPR guardrails and automatically tries more conservative configurations when a candidate violates safety thresholds.
  * Keeps the existing production model when all candidate configurations fail.

* **Low-Latency Backend**

  * Redis caches scan decisions with TTL-based expiration.
  * Background tasks asynchronously persist scan logs.
  * Tier 2 network checks execute DNS resolution and HTTP header retrieval concurrently.

* **Authentication & Analytics**

  * JWT-based authentication.
  * Password hashing with bcrypt.
  * PostgreSQL persistence through SQLAlchemy.
  * Per-user scan history and risk statistics.
  * CSV export of malicious IOC reports.

## Architecture

```text
                         ┌──────────────────────┐
                         │   Chrome Extension   │
                         │    / Web Frontend    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     FastAPI API       │
                         │ Auth / Scan / Analyst │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    │               │                │
                    ▼               ▼                ▼
             ┌───────────┐   ┌────────────┐   ┌──────────────┐
             │   Redis   │   │ PostgreSQL │   │ ML Inference │
             │   Cache   │   │ Scan Logs  │   │   Pipeline   │
             └───────────┘   └────────────┘   └──────┬───────┘
                                                     │
                          ┌──────────────────────────┼────────────────────┐
                          │                          │                    │
                          ▼                          ▼                    ▼
                 Tranco Bloom Filter          Tier 1 XGBoost       Tier 2 XGBoost
                 trusted-domain filter         URL features         network features
                                                     │                    │
                                                     └──────────┬─────────┘
                                                                ▼
                                                        Final Risk Decision
```

## Detection Pipeline

For each URL:

```text
Incoming URL
     │
     ▼
Redis cache lookup
     │
     ├── HIT ───────────────► Return cached result
     │
     ▼
Tranco Bloom Filter
     │
     ├── Trusted + no brand spoof ─► SAFE
     │
     ▼
Tier 1 feature extraction
     │
     ▼
Tier 1 XGBoost probability
     │
     ├── < 20% or > 80% ─────────► Final Tier 1 decision
     │
     ▼
Tier 2 escalation
     │
     ├── DNS resolution
     ├── HTTP HEAD inspection
     ├── HTTPS / HSTS
     └── security-header signals
     │
     ▼
Tier 2 XGBoost
     │
     ▼
SAFE / SUSPICIOUS / MALICIOUS
```

The implementation escalates only predictions in the **0.20–0.80 probability band**, reducing the number of URLs requiring slower network inspection.

## Machine Learning

### Tier 1

Tier 1 uses hand-engineered lexical and structural URL features such as entropy, URL/path/domain length, subdomain count, suspicious extensions, brand mentions, spoofing indicators, and security/urgency token counts.

The repository uses **XGBoost** for classification and stores the trained model with Joblib along with feature metadata.

### Tier 2

Tier 2 extends the URL feature vector with live signals including:

* DNS resolution / liveness
* HTTP status
* HTTPS presence
* HSTS
* X-Frame-Options / CSP-related protection
* Composite web security score

DNS and HTTP header collection are performed concurrently using a thread pool.

## Keeping Up With New Phishing Trends

PhishGuard is designed so the production model can evolve as the threat landscape changes instead of relying only on a static dataset.

The threat-sync pipeline:

1. Downloads newly observed malicious URLs from URLhaus.
2. Computes SHA-256 fingerprints and removes previously seen URLs.
3. Generates a balanced benign counterpart set.
4. Extracts the same Tier-1 feature representation used in production.
5. Appends new observations to a Parquet-based monthly buffer.
6. Combines the buffer with the historical training vault.
7. Trains a candidate XGBoost model.
8. Evaluates the candidate against the current production model.
9. Accepts the candidate only when predefined accuracy and false-positive-rate guardrails are satisfied.
10. Falls back to more conservative regularization configurations when necessary.
11. Retains the existing production model when all candidates fail.

This creates a practical feedback loop between **live threat intelligence → feature extraction → retraining → evaluation → guarded model replacement**.

## Performance-Oriented Design

PhishGuard uses several mechanisms to reduce unnecessary inference and network overhead:

* Bloom-filter lookup for trusted domains.
* Redis scan-result caching with expiration.
* Conditional Tier-2 escalation.
* Concurrent DNS and HTTP checks.
* Background database logging.
* Client-side browser-extension caching and duplicate-scan suppression.

The Chrome extension also maintains a local scan cache and a synchronous cooldown lock to avoid duplicate scans caused by rapid browser navigation events.

## Backend & Security

* **FastAPI** REST API
* **SQLAlchemy** ORM
* **PostgreSQL** for production persistence
* **Redis** for caching
* **JWT** bearer authentication
* **bcrypt** password hashing
* Per-user scan history and IOC export

The database layer supports SQLite for local development and PostgreSQL with connection pooling for production deployments.  Authentication endpoints issue JWT bearer tokens and protect analyst endpoints.

## Deployment

The application is containerized with Docker and can be run with PostgreSQL and Redis using Docker Compose.

```text
PostgreSQL
    │
    ├── persistent volume
    │
Redis
    │
    ├── persistent volume
    │
FastAPI application
    │
    └── ML models + frontend + API
```

The Docker Compose configuration defines PostgreSQL, Redis, and the FastAPI service with health checks and service dependencies.  The application image uses Python 3.11 and launches the FastAPI service with Uvicorn.

## Project Structure

```text
phisguard/
├── data/
│   └── threat_intel/
├── experiments/
│   ├── 01_feature_selection.py
│   ├── 02_test_cascade.py
│   └── 03_test_dns_latency.py
├── extension/
│   ├── background.js
│   ├── content.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── frontend/
│   ├── login.html
│   └── dashboard.html
├── models/
├── src/
│   ├── api/
│   │   ├── auth.py
│   │   ├── dashboard.py
│   │   └── main.py
│   └── core/
│       ├── build_whitelist.py
│       ├── data_collector.py
│       ├── database.py
│       ├── feature_extractor.py
│       ├── redis_cache.py
│       ├── security.py
│       └── threat_sync.py
├── docker-compose.yml
├── dockerfile
└── requirements.txt
```

## Tech Stack

**Languages:** Python, JavaScript, HTML, CSS

**Backend:** FastAPI, Uvicorn, SQLAlchemy

**ML:** XGBoost, scikit-learn, pandas, Joblib

**Data:** PostgreSQL, Parquet, CSV

**Caching:** Redis

**Security:** JWT, bcrypt

**Browser:** Chrome Extension / Manifest V3

**Deployment:** Docker, Docker Compose, AWS

## Experiments & Evaluation

The repository includes experiments for:

* Feature importance ranking with XGBoost.
* Cascade simulation across a 3,000-URL test sample.
* Tier-1 vs Tier-2 latency investigation.

The cascade benchmark explicitly measures how many URLs are handled by the whitelist, Tier 1, and Tier 2 stages and evaluates overall accuracy and false-positive rate.

## Status

PhishGuard has been developed through the **AWS deployment stage**, including containerization and production-oriented database/cache configuration.

## Disclaimer

This project is intended for security research, experimentation, and defensive analysis. Detection results should not be treated as a substitute for a complete security stack or human investigation of high-risk events.
