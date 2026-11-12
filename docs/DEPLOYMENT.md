# Deployment and operations

## Local
1. Install Python 3.12+.
2. Create and activate a virtual environment.
3. Install dependencies with pip install -r requirements.txt.
4. Set a stable random LOTWISE_SECRET_KEY of at least 32 random bytes.
5. Set LOTWISE_DATA_DIR to a private persistent directory.
6. Run uvicorn app.main:app --host 127.0.0.1 --port 8000.
7. Open http://127.0.0.1:8000.

## Docker
Set LOTWISE_SECRET_KEY in the environment, then run docker compose up --build -d. A named volume persists the database and uploads.

## Before real customer data
This is an evaluation release, not a hardened production service. Before processing confidential records:
- Use HTTPS behind a correctly configured reverse proxy.
- Set a strong stable secret; never use the local fallback.
- Restrict network access and configure trusted proxy headers.
- Use managed encrypted storage and a managed database with tenant isolation and tested backups.
- Add MFA/SSO where required, session revocation, rate limiting, CSRF protections for cookie auth, malware scanning and security monitoring.
- Define retention, deletion, incident response, data-processing and subprocessor terms.
- Commission an independent security review and test tenant isolation.
- Validate extraction against a representative customer-approved corpus.
- Establish support, availability, recovery and change-management commitments.

The current bearer token lasts 12 hours. The browser stores it in localStorage for this evaluation release. This is not the preferred session design for hardened production.
