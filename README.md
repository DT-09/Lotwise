# Lotwise

**Evidence-linked supplier lot verification for specialty food-ingredient QA teams.**

Lotwise organizes incoming supplier documents, compares extracted observations against an approved ingredient specification, flags review items and records a human disposition.

> Lotwise is decision-support software. It does not certify food safety, replace laboratory testing, establish regulatory compliance or release batches.

## Current release

**0.1.0 — Evaluation foundation**

Included:
- User registration and sign-in.
- User-scoped supplier, specification, lot, document and review records.
- Selectable-text PDF, CSV, JSON and TXT uploads.
- SHA-256 document fingerprints.
- Conservative extraction of simple test/value/unit rows.
- Exact-name specification comparisons and limited explicit unit conversions.
- Missing test, unit mismatch, out-of-limit candidate and identity review findings.
- Human disposition with rationale and audit events.
- Browser workspace, Dockerfile and Compose configuration.

Not included:
- OCR for scanned PDFs.
- General-purpose CoA understanding or fuzzy test-name mapping.
- Production-grade tenant isolation audit, managed encrypted storage or database.
- SSO/MFA, billing, customer support tooling or contractual compliance controls.
- Validated extraction accuracy or customer-proven ROI.

## Intended customer

QA Manager / Head of Quality at a specialty food-ingredient importer, manufacturer or distributor with recurring incoming-lot reviews and controlled ingredient specifications.

## Run locally

Python 3.12+ is recommended.

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    export LOTWISE_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export LOTWISE_DATA_DIR=./data
    uvicorn app.main:app --reload

Open http://127.0.0.1:8000.

## Docker

Set LOTWISE_SECRET_KEY to a long random value, then:

    docker compose up --build -d

The Compose configuration persists local data in a named volume. It is a starting point for evaluation, not a production hosting recommendation.

## Test

    pytest -q

## Product and commercial documentation

- [Product specification](docs/PRODUCT.md)
- [Commercial readiness](docs/COMMERCIAL.md)
- [Deployment and operations](docs/DEPLOYMENT.md)

## Commercial status

No customer demand, paid evaluation, payment, subscription revenue or ROI has been verified. Do not describe Lotwise as commercially validated until a real buyer has paid and used it against agreed acceptance criteria.

## Data handling warning

Do not upload confidential supplier or customer documents to an internet-accessible deployment until the deployment has appropriate access controls, encryption, retention/deletion policies, backup and recovery, security review and customer-approved data-processing terms.
