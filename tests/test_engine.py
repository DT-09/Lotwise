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
