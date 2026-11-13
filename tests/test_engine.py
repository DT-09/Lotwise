from app.main import compare, observations, password_hash, password_ok

def test_parse_coa_lines():
    rows=observations("Moisture: 6.2 %\nCadmium: 0.12 ppm")
    assert len(rows)==2 and rows[1]["value"]==0.12

def test_missing_test_is_reported():
    out=compare([{"test":"Moisture","value":6.2,"unit":"%"}],{"tests":[{"name":"Moisture","unit":"%","max":8},{"name":"Cadmium","unit":"ppm","max":0.5}]})
    assert any(x["test"]=="Cadmium" and x["status"]=="missing" for x in out)

def test_out_of_spec_is_candidate():
    out=compare([{"test":"Cadmium","value":0.7,"unit":"ppm"}],{"tests":[{"name":"Cadmium","unit":"ppm","max":0.5}]})
    assert out[0]["status"]=="out_of_spec_candidate"

def test_incompatible_units_require_review():
    out=compare([{"test":"Moisture","value":4,"unit":"ppm"}],{"tests":[{"name":"Moisture","unit":"%","max":8}]})
    assert out[0]["status"]=="unit_review"

def test_password_hash():
    p=password_hash("a-long-test-password")
    assert password_ok("a-long-test-password",p)
    assert not password_ok("incorrect",p)


def make_client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    import app.main as service
    monkeypatch.setattr(service, "DB", tmp_path / "test.sqlite3")
    monkeypatch.setattr(service, "DATA", tmp_path)
    monkeypatch.setattr(service, "UPLOADS", tmp_path / "uploads")
    service.UPLOADS.mkdir(parents=True, exist_ok=True)
    return TestClient(service.app)


def register(client, email):
    response = client.post("/api/auth/register", json={
        "email": email, "password": "correct-horse-battery-42"
    })
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"]}


def test_customer_records_are_isolated(monkeypatch, tmp_path):
    with make_client(monkeypatch, tmp_path) as client:
        owner = register(client, "owner@example.com")
        other = register(client, "other@example.com")
        created = client.post("/api/suppliers", headers=owner,
                              json={"name": "Northstar Ingredients", "code": "SUP-1"})
        assert created.status_code == 200
        assert client.get("/api/suppliers", headers=other).json() == []


def test_complete_lot_review_flow(monkeypatch, tmp_path):
    with make_client(monkeypatch, tmp_path) as client:
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/examples/sample_coa.txt").status_code == 200
        assert client.get("/docs/COMMERCIAL.md").status_code == 200
        headers = register(client, "qa@example.com")
        supplier = client.post("/api/suppliers", headers=headers,
                               json={"name": "Northstar Ingredients", "code": "SUP-1"}).json()
        spec = client.post("/api/specifications", headers=headers, json={
            "ingredient": "Cocoa powder", "version": "1.0", "approved": True,
            "tests": [
                {"name": "Moisture", "unit": "%", "min": 0, "max": 8},
                {"name": "Cadmium", "unit": "ppm", "min": 0, "max": 0.5}
            ]
        })
        assert spec.status_code == 200, spec.text
        lot = client.post("/api/lots", headers=headers, json={
            "supplier_id": supplier["id"], "ingredient": "Cocoa powder",
            "lot_code": "LOT-42", "po_number": "PO-7", "spec_id": spec.json()["id"]
        })
        assert lot.status_code == 200, lot.text
        lot_id = lot.json()["id"]
        premature = client.post("/api/lots/" + lot_id + "/decision", headers=headers, json={
            "disposition": "on_hold", "rationale": "Review has not been run yet.",
            "reviewer": "QA Reviewer"
        })
        assert premature.status_code == 422
        uploaded = client.post("/api/lots/" + lot_id + "/documents", headers=headers,
                               files={"file": ("coa.txt",
                               "Supplier: Northstar Ingredients\nLot: LOT-42\nMoisture: 6.2 %\nCadmium: 0.7 ppm",
                               "text/plain")})
        assert uploaded.status_code == 200, uploaded.text
        downloaded = client.get("/api/documents/" + uploaded.json()["id"] + "/download", headers=headers)
        assert downloaded.status_code == 200
        assert "Northstar Ingredients" in downloaded.text
        analysis = client.post("/api/lots/" + lot_id + "/analyze", headers=headers)
        assert analysis.status_code == 200, analysis.text
        statuses = [x["status"] for x in analysis.json()["findings"]]
        assert "out_of_spec_candidate" in statuses
        assert analysis.json()["summary"]["requires_human_review"] is True
        decision = client.post("/api/lots/" + lot_id + "/decision", headers=headers, json={
            "disposition": "on_hold", "rationale": "Cadmium result requires QA investigation.",
            "reviewer": "QA Reviewer"
        })
        assert decision.status_code == 200, decision.text
        report = client.get("/api/lots/" + lot_id + "/report", headers=headers)
        assert report.status_code == 200
        assert report.json()["review_decisions"][0]["disposition"] == "on_hold"


def test_json_observations_are_extracted():
    rows=observations('{"results":[{"name":"Moisture","value":6.2,"unit":"%","page":2}]}')
    assert len(rows)==1
    assert rows[0]["test"]=="Moisture"
    assert rows[0]["source_page"]==2


def test_pdf_page_marker_is_preserved():
    rows=observations("[LOTWISE_SOURCE_PAGE:3]\nMoisture: 6.2 %")
    assert rows[0]["source_page"]==3


def test_specification_rejects_non_numeric_limits(monkeypatch, tmp_path):
    with make_client(monkeypatch, tmp_path) as client:
        headers=register(client,"spec@example.com")
        response=client.post("/api/specifications",headers=headers,json={
            "ingredient":"Cocoa powder","version":"1.0","approved":True,
            "tests":[{"name":"Moisture","unit":"%","min":"not-a-number","max":8}]
        })
        assert response.status_code==422


def test_security_headers_are_present(monkeypatch, tmp_path):
    with make_client(monkeypatch, tmp_path) as client:
        response = client.get("/health")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_authentication_throttle(monkeypatch, tmp_path):
    import app.main as service
    with make_client(monkeypatch, tmp_path) as client:
        service._auth_attempts.clear()
        for _ in range(service.AUTH_MAX_ATTEMPTS):
            response = client.post("/api/auth/login", json={
                "email": "missing@example.com", "password": "correct-horse-battery-42"
            })
            assert response.status_code == 401
        blocked = client.post("/api/auth/login", json={
            "email": "missing@example.com", "password": "correct-horse-battery-42"
        })
        assert blocked.status_code == 429
        service._auth_attempts.clear()

def test_whitespace_delimited_table_row_keeps_provenance():
    rows = observations("[LOTWISE_SOURCE_PAGE:2]" + chr(10) + "Moisture    6.2 %")
    assert len(rows) == 1
    assert rows[0]["test"] == "Moisture"
    assert rows[0]["source_page"] == 2
    assert rows[0]["source_line"] == 2
    assert rows[0]["source_excerpt"] == "Moisture    6.2 %"


def test_conflicting_results_are_not_silently_compared():
    out = compare([
        {"test": "Cadmium", "value": 0.2, "unit": "ppm", "source_excerpt": "0.2"},
        {"test": "Cadmium", "value": 0.7, "unit": "ppm", "source_excerpt": "0.7"}
    ], {"tests": [{"name": "Cadmium", "unit": "ppm", "max": 0.5}]})
    assert len(out) == 1
    assert out[0]["status"] == "conflicting_observations"
    assert len(out[0]["observed"]) == 2


def test_non_finite_json_measurement_is_ignored():
    rows = observations('{"tests":[{"name":"Moisture","value":NaN,"unit":"%"}]}')
    assert rows == []


def test_postgres_parameter_adapter_supports_qmark_queries():
    from sqlalchemy import create_engine
    from app.main import _Connection
    engine = create_engine("sqlite://")
    with engine.begin() as raw:
        db = _Connection(raw, "postgresql")
        db.execute("CREATE TABLE adapter_check (id INTEGER, label TEXT)")
        db.execute("INSERT INTO adapter_check (id, label) VALUES (?, ?)", (7, "evidence"))
        row = db.execute("SELECT id, label FROM adapter_check WHERE id = ?", (7,)).fetchone()
        assert row["id"] == 7
        assert row["label"] == "evidence"
    engine.dispose()


def test_s3_document_persistence_uses_private_encryption(monkeypatch, tmp_path):
    import app.main as service
    class FakeS3:
        def __init__(self): self.upload = None
        def upload_file(self, path, bucket, key, ExtraArgs):
            self.upload = (path, bucket, key, ExtraArgs)
    fake = FakeS3()
    monkeypatch.setattr(service, "S3_BUCKET", "lotwise-private")
    monkeypatch.setattr(service, "_S3_CLIENT", fake)
    source = tmp_path / "source.txt"
    source.write_text("synthetic evidence", encoding="utf-8")
    stored = service.persist_document(source, "tenant-1", "doc-1", ".txt", "abc123")
    assert stored == "s3://lotwise-private/tenants/tenant-1/documents/doc-1.txt"
    assert not source.exists()
    assert fake.upload[3]["ServerSideEncryption"] == "AES256"
    assert fake.upload[3]["Metadata"]["sha256"] == "abc123"
