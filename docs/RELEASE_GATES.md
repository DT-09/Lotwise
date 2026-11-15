# Release gates and operational truth

Lotwise is an evaluation product. A successful build or a green CI run does not make it a production service for confidential supplier records.

## What the current repository provides

- Account registration and bearer-token authentication.
- User-scoped supplier, specification, lot, document, finding, decision and audit records.
- Selectable-text PDF, CSV, JSON and TXT intake with SHA-256 fingerprints.
- Conservative numeric observation extraction and exact-name specification comparisons.
- A limited, explicit unit-conversion table.
- Evidence excerpts with source page/line metadata where the source format exposes it.
- Human disposition capture and JSON/CSV reports.
- PostgreSQL and S3-compatible storage configuration.
- Browser-based evaluation workspace and synthetic examples.

## Required before confidential customer data

1. **Identity and sessions:** replace browser localStorage bearer-token persistence with secure, HttpOnly, SameSite cookies; add session revocation, password reset, MFA or SSO where buyer requirements demand it.
2. **Abuse controls:** replace process-local authentication throttling with a shared rate limiter; add registration abuse controls and operational alerting.
3. **Tenant assurance:** complete an independent tenant-isolation review, including every query, object-storage key, report and signed-download path.
4. **Document safety:** add malware scanning, content-type/signature validation, parser resource limits, encrypted temporary storage and a documented quarantine path.
5. **Data lifecycle:** implement customer-configurable retention, deletion workflows, backup policies and tested point-in-time restore.
6. **Schema lifecycle:** add versioned database migrations and a tested upgrade/rollback procedure.
7. **Operational security:** configure managed secrets, least-privilege storage credentials, monitoring, alerting, incident response and dependency vulnerability scanning.
8. **Commercial/legal:** approve customer data-processing terms, subprocessors, retention terms, support commitments and a security review.
9. **Extraction validation:** benchmark supported formats against a customer-approved, representative corpus; publish measured coverage and known failure modes.
10. **Production verification:** deploy to a managed environment, verify HTTPS, readiness, backups, storage privacy, logs and a complete end-to-end customer workflow.

## Product boundaries

- Scanned PDFs/OCR are not supported.
- General-purpose CoA interpretation and fuzzy test-name mapping are not supported.
- Identity checks are text-presence candidates, not verified entity resolution.
- Supported unit conversions are deliberately limited.
- Findings are automated comparison candidates, not food-safety conclusions.
- A qualified customer reviewer owns every disposition. Lotwise never authorizes batch release.

## Commercial proof

Do not claim customer validation, extraction accuracy, ROI, compliance certification, paid usage or recurring revenue until each is supported by real, documented evidence. A paid evaluation must have agreed scope, lawful document access, data-handling approval, measurable acceptance criteria and verified payment.
