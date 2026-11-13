# Lotwise product specification

## Initial buyer
QA Manager / Head of Quality at a specialty food-ingredient importer, manufacturer or distributor with recurring incoming-lot reviews and approved ingredient specifications.

## Job to be done
Review supplier CoAs against approved ingredient specifications; identify missing tests, incompatible units, lot/supplier identity gaps and potential out-of-limit results; preserve evidence and record a qualified human disposition.

## Evaluation release scope
- Account registration and account-scoped records.
- Supplier and approved-specification registries.
- Incoming lot creation and document upload.
- Text extraction from selectable-text PDF, CSV, JSON and TXT.
- Conservative exact-name measurement extraction.
- Explicit unit comparison for a limited documented set.
- Missing-test, unit mismatch, out-of-limit candidate and identity review findings.
- Human disposition with rationale and audit events.
- JSON and evidence-linked CSV report retrieval.
- Tenant-scoped source document downloads.
- PostgreSQL database support and private S3-compatible object storage for production configuration.

## Known limitations
- Scanned PDFs/OCR are not supported.
- Extraction is not a general-purpose CoA parser.
- Test-name mapping is exact-match only.
- Identity checks are text-presence candidates, not verified entity resolution.
- Only explicitly implemented unit conversions are automated.
- SQLite/local filesystem storage are used in local development; production configuration supports managed PostgreSQL and private S3-compatible storage.
- No OCR, SSO/MFA, malware scanning, formal versioned migrations, configured production bucket, tested managed backups, billing or independent security audit.
- No representative customer corpus has validated accuracy.

## Safety boundary
Lotwise provides decision support only. It does not certify food safety, replace laboratory testing, establish legal compliance, or authorize/release product. A qualified customer reviewer owns disposition.

## Acceptance criteria
1. Registration and sign-in work.
2. All records are scoped to the authenticated user.
3. Supplier, approved specification and lot can be created.
4. Supported documents upload with a size limit and SHA-256.
5. Analysis reports mapped observations, missing requirements, incompatible units and out-of-limit candidates.
6. Reports state that human review is required.
7. Reviewer can record on-hold, reviewer-approved or reviewer-rejected disposition with rationale.
8. Health endpoint returns service status.
9. CSV reports retain source excerpts and reviewer disposition fields.
10. Source document downloads are scoped to the authenticated account.
11. Automated tests cover parsing, limits, unit mismatch, database parameter adaptation, object storage and password hashing.
