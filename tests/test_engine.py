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
        uploaded = client.post("/api/lots/" + lot_id + "/documents", headers=headers,
                               files={"file": ("coa.txt",
                               "Supplier: Northstar Ingredients\nLot: LOT-42\nMoisture: 6.2 %\nCadmium: 0.7 ppm",
                               "text/plain")})
        assert uploaded.status_code == 200, uploaded.text
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
