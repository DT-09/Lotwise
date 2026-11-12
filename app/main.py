from __future__ import annotations
import base64, csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Depends, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

ROOT=Path(__file__).resolve().parent.parent
WEB=ROOT/"web"
DATA=Path(os.getenv("LOTWISE_DATA_DIR","./data")).resolve()
UPLOADS=DATA/"uploads"
DB=DATA/"lotwise.sqlite3"
MAX_BYTES=int(os.getenv("LOTWISE_MAX_UPLOAD_MB","12"))*1024*1024
SECRET=os.getenv("LOTWISE_SECRET_KEY") or ("LOCAL-ONLY-"+str(DATA))
DATA.mkdir(parents=True,exist_ok=True); UPLOADS.mkdir(parents=True,exist_ok=True)
app=FastAPI(title="Lotwise",version="0.1.0",description="Evidence-linked supplier lot verification.")
auth=HTTPBearer(auto_error=False)
def stamp(): return datetime.now(timezone.utc).isoformat()
def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,pw TEXT NOT NULL,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS suppliers(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,code TEXT,created TEXT);
        CREATE TABLE IF NOT EXISTS specs(id TEXT PRIMARY KEY,owner TEXT NOT NULL,ingredient TEXT NOT NULL,version TEXT NOT NULL,tests TEXT NOT NULL,approved INTEGER NOT NULL,created TEXT);
        CREATE TABLE IF NOT EXISTS lots(id TEXT PRIMARY KEY,owner TEXT NOT NULL,supplier_id TEXT NOT NULL,ingredient TEXT NOT NULL,lot_code TEXT NOT NULL,po TEXT,spec_id TEXT,status TEXT NOT NULL,created TEXT,updated TEXT);
        CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,owner TEXT NOT NULL,lot_id TEXT NOT NULL,filename TEXT NOT NULL,stored TEXT NOT NULL,sha256 TEXT NOT NULL,extracted TEXT NOT NULL,created TEXT);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,owner TEXT NOT NULL,lot_id TEXT NOT NULL,payload TEXT NOT NULL,created TEXT);
        CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY,owner TEXT NOT NULL,lot_id TEXT NOT NULL,disposition TEXT NOT NULL,rationale TEXT NOT NULL,reviewer TEXT NOT NULL,created TEXT);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,owner TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL,created TEXT);
        CREATE INDEX IF NOT EXISTS idx_lots_owner ON lots(owner,created);
        CREATE INDEX IF NOT EXISTS idx_docs_owner_lot ON documents(owner,lot_id);
        CREATE INDEX IF NOT EXISTS idx_events_owner ON events(owner,created);
        """)
@app.on_event("startup")
def startup(): init()
def password_hash(pw,salt=None):
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac("sha256",pw.encode(),salt,240000)
    return base64.urlsafe_b64encode(salt).decode()+"."+base64.urlsafe_b64encode(digest).decode()
def password_ok(pw,stored):
    try:
        a,b=stored.split(".",1); salt=base64.urlsafe_b64decode(a); expected=base64.urlsafe_b64decode(b)
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",pw.encode(),salt,240000),expected)
    except Exception: return False
def make_token(uid):
    body=base64.urlsafe_b64encode(json.dumps({"sub":uid,"exp":int(time.time())+43200}).encode()).decode().rstrip("=")
    sig=hmac.new(SECRET.encode(),body.encode(),hashlib.sha256).digest()
    return body+"."+base64.urlsafe_b64encode(sig).decode().rstrip("=")
def user_id(creds:HTTPAuthorizationCredentials|None=Depends(auth)):
    if not creds: raise HTTPException(401,"Sign in required")
    try:
        body,sig=creds.credentials.split(".",1); expected=hmac.new(SECRET.encode(),body.encode(),hashlib.sha256).digest()
        actual=base64.urlsafe_b64decode(sig+"="*(-len(sig)%4))
        if not hmac.compare_digest(expected,actual): raise ValueError()
        claims=json.loads(base64.urlsafe_b64decode(body+"="*(-len(body)%4)))
        if claims["exp"]<time.time(): raise ValueError()
        with conn() as c: row=c.execute("SELECT id,email FROM users WHERE id=?",(claims["sub"],)).fetchone()
        if not row: raise ValueError()
        return dict(row)
    except Exception: raise HTTPException(401,"Invalid or expired session")
def audit(c,owner,entity,eid,action,details):
    c.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",(str(uuid.uuid4()),owner,entity,eid,action,json.dumps(details),stamp()))
def owned(c,table,eid,owner):
    if table not in {"suppliers","specs","lots"}: raise ValueError("table")
    row=c.execute("SELECT * FROM "+table+" WHERE id=? AND owner=?",(eid,owner)).fetchone()
    if not row: raise HTTPException(404,"Record not found")
    return row
class Credentials(BaseModel):
    email:str=Field(min_length=5,max_length=254)
    password:str=Field(min_length=12,max_length=200)
class SupplierIn(BaseModel):
    name:str=Field(min_length=2,max_length=160); code:str=""
class SpecIn(BaseModel):
    ingredient:str=Field(min_length=2,max_length=160); version:str=Field(min_length=1,max_length=60)
    approved:bool=False; tests:list[dict[str,Any]]
class LotIn(BaseModel):
    supplier_id:str; ingredient:str=Field(min_length=2,max_length=160); lot_code:str=Field(min_length=1,max_length=120)
    po_number:str=""; spec_id:str|None=None
class DecisionIn(BaseModel):
    disposition:str=Field(pattern="^(approved_by_reviewer|rejected_by_reviewer|on_hold)$")
    rationale:str=Field(min_length=5,max_length=2000); reviewer:str=Field(min_length=2,max_length=120)
def extract(path,suffix):
    if suffix==".pdf":
        if PdfReader is None: raise HTTPException(503,"PDF parser unavailable")
        try: return "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)[:500000]
        except Exception: raise HTTPException(422,"Could not extract selectable PDF text")
    try: return path.read_text(encoding="utf-8-sig")[:500000]
    except UnicodeDecodeError: raise HTTPException(422,"Only text-based CSV, JSON and TXT are supported")
def observations(text):
    found=[]
    rx=re.compile(r"(?im)^\s*([A-Za-z][A-Za-z0-9 /()_.-]{1,70}?)\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*([%a-zA-Zµμ/°0-9.-]{0,24})\s*$")
    for m in rx.finditer(text):
        found.append({"test":m.group(1).strip(),"value":float(m.group(2)),"unit":m.group(3).strip(),"source_excerpt":m.group(0).strip()})
    try:
        for row in csv.DictReader(io.StringIO(text)):
            r={str(k).strip().lower():v for k,v in row.items() if k}
            if "test" in r and "value" in r:
                try: found.append({"test":str(r["test"]).strip(),"value":float(r["value"]),"unit":str(r.get("unit") or "").strip(),"source_excerpt":json.dumps(row)})
                except (ValueError,TypeError): pass
    except Exception: pass
    unique={}
    for x in found: unique[(x["test"].casefold(),x["value"],x["unit"].casefold())]=x
    return list(unique.values())
def unit_info(unit):
    u=unit.strip().casefold().replace(" ","")
    return {"%":("percent",1),"percent":("percent",1),"ppm":("ppm",1),"mg/kg":("ppm",1),"g/kg":("ppm",1000),"mg/g":("ppm",1000),"°c":("celsius",1),"c":("celsius",1)}.get(u)
def compare(obs,spec):
    out=[]; seen=set()
    for req in spec.get("tests",[]):
        name=str(req.get("name","")).strip()
        if not name: continue
        matches=[o for o in obs if o["test"].casefold()==name.casefold()]
        if not matches: out.append({"test":name,"status":"missing","message":"Required test not found."}); continue
        for o in matches:
            seen.add((o["test"].casefold(),o["value"],o["unit"].casefold()))
            target=str(req.get("unit","")); value=o["value"]
            if target.casefold()!=o["unit"].casefold():
                a,b=unit_info(o["unit"]),unit_info(target)
                if not a or not b or a[0]!=b[0]:
                    out.append({"test":name,"status":"unit_review","observed":o,"required_unit":target,"message":"Units cannot be safely compared; reviewer mapping required."}); continue
                value=value*a[1]/b[1]
            low,high=req.get("min"),req.get("max")
            bad=(low is not None and value<float(low)) or (high is not None and value>float(high))
            out.append({"test":name,"status":"out_of_spec_candidate" if bad else "within_limit_candidate","observed":o,"normalized_value":value,"required_unit":target,"min":low,"max":high,"message":"Potential specification exception." if bad else "Within configured limits; reviewer verification required."})
    for o in obs:
        key=(o["test"].casefold(),o["value"],o["unit"].casefold())
        if key not in seen and not any(x.get("test","").casefold()==o["test"].casefold() for x in out):
            out.append({"test":o["test"],"status":"unmapped_observation","observed":o,"message":"No exact approved-specification mapping."})
    return out
@app.get("/",response_class=HTMLResponse)
def home(): return (WEB/"index.html").read_text()
@app.get("/static/{name}")
def static_file(name:str):
    if name not in {"style.css","app.js"}: raise HTTPException(404)
    return FileResponse(WEB/name)
@app.get("/health")
def health(): return {"status":"ok","service":"lotwise","version":"0.1.0"}
@app.post("/api/auth/register")
def register(data:Credentials):
    email=data.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): raise HTTPException(422,"Invalid email")
    uid=str(uuid.uuid4())
    try:
        with conn() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?)",(uid,email,password_hash(data.password),stamp()))
            audit(c,uid,"account",uid,"created",{})
    except sqlite3.IntegrityError: raise HTTPException(409,"Account already exists")
    return {"token":make_token(uid),"email":email}
@app.post("/api/auth/login")
def login(data:Credentials):
    with conn() as c: row=c.execute("SELECT * FROM users WHERE email=?",(data.email.strip().lower(),)).fetchone()
    if not row or not password_ok(data.password,row["pw"]): raise HTTPException(401,"Email or password incorrect")
    return {"token":make_token(row["id"]),"email":row["email"]}
@app.get("/api/me")
def me(u=Depends(user_id)): return {"id":u["id"],"email":u["email"]}
@app.get("/api/suppliers")
def suppliers(u=Depends(user_id)):
    with conn() as c: return [dict(r) for r in c.execute("SELECT id,name,code,created FROM suppliers WHERE owner=? ORDER BY name",(u["id"],))]
@app.post("/api/suppliers")
def add_supplier(x:SupplierIn,u=Depends(user_id)):
    eid=str(uuid.uuid4())
    with conn() as c:
        c.execute("INSERT INTO suppliers VALUES(?,?,?,?,?)",(eid,u["id"],x.name.strip(),x.code,stamp())); audit(c,u["id"],"supplier",eid,"created",{"name":x.name})
    return {"id":eid,"name":x.name}
@app.get("/api/specifications")
def specs(u=Depends(user_id)):
    with conn() as c: rows=c.execute("SELECT * FROM specs WHERE owner=? ORDER BY created DESC",(u["id"],)).fetchall()
    return [{"id":r["id"],"ingredient":r["ingredient"],"version":r["version"],"approved":bool(r["approved"]),"tests":json.loads(r["tests"])} for r in rows]
@app.post("/api/specifications")
def add_spec(x:SpecIn,u=Depends(user_id)):
    if not x.tests: raise HTTPException(422,"At least one test is required")
    for t in x.tests:
        if not t.get("name") or not t.get("unit") or (t.get("min") is None and t.get("max") is None): raise HTTPException(422,"Each test needs name, unit and at least one limit")
        if t.get("min") is not None and t.get("max") is not None and float(t["min"])>float(t["max"]): raise HTTPException(422,"Minimum exceeds maximum")
    eid=str(uuid.uuid4())
    with conn() as c:
        c.execute("INSERT INTO specs VALUES(?,?,?,?,?,?,?)",(eid,u["id"],x.ingredient,x.version,json.dumps(x.tests),int(x.approved),stamp()))
        audit(c,u["id"],"specification",eid,"created",{"ingredient":x.ingredient,"approved":x.approved})
    return {"id":eid,"ingredient":x.ingredient,"approved":x.approved}
@app.get("/api/lots")
def lots(u=Depends(user_id)):
    with conn() as c:
        rows=c.execute("""SELECT l.*,s.name supplier_name,(SELECT COUNT(*) FROM documents d WHERE d.lot_id=l.id AND d.owner=l.owner) document_count FROM lots l LEFT JOIN suppliers s ON s.id=l.supplier_id WHERE l.owner=? ORDER BY l.created DESC""",(u["id"],)).fetchall()
    return [dict(r) for r in rows]
@app.post("/api/lots")
def add_lot(x:LotIn,u=Depends(user_id)):
    eid=str(uuid.uuid4())
    with conn() as c:
        owned(c,"suppliers",x.supplier_id,u["id"])
        if x.spec_id and not owned(c,"specs",x.spec_id,u["id"])["approved"]: raise HTTPException(422,"Specification must be approved")
        c.execute("INSERT INTO lots VALUES(?,?,?,?,?,?,?,?,?,?)",(eid,u["id"],x.supplier_id,x.ingredient,x.lot_code,x.po_number,x.spec_id,"new",stamp(),stamp()))
        audit(c,u["id"],"lot",eid,"created",{"ingredient":x.ingredient,"lot_code":x.lot_code})
    return {"id":eid,"status":"new"}
@app.post("/api/lots/{lot_id}/documents")
async def upload(lot_id:str,file:UploadFile=File(...),u=Depends(user_id)):
    suffix=Path(file.filename or "").suffix.lower()
    if suffix not in {".pdf",".txt",".csv",".json"}: raise HTTPException(415,"Supported formats: PDF, TXT, CSV, JSON")
    content=await file.read(MAX_BYTES+1)
    if len(content)>MAX_BYTES: raise HTTPException(413,"File exceeds upload limit")
    with conn() as c: owned(c,"lots",lot_id,u["id"])
    did=str(uuid.uuid4()); stored=UPLOADS/u["id"]/(did+suffix); stored.parent.mkdir(parents=True,exist_ok=True); stored.write_bytes(content)
    try: text=extract(stored,suffix)
    except Exception: stored.unlink(missing_ok=True); raise
    digest=hashlib.sha256(content).hexdigest()
    with conn() as c:
        c.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?)",(did,u["id"],lot_id,Path(file.filename or "upload").name[:180],str(stored),digest,text,stamp()))
        audit(c,u["id"],"document",did,"uploaded",{"lot_id":lot_id,"sha256":digest,"bytes":len(content)})
    return {"id":did,"filename":Path(file.filename or "upload").name,"sha256":digest,"extracted_characters":len(text)}
@app.post("/api/lots/{lot_id}/analyze")
def analyze(lot_id:str,u=Depends(user_id)):
    with conn() as c:
        lot=owned(c,"lots",lot_id,u["id"])
        if not lot["spec_id"]: raise HTTPException(422,"Assign an approved specification first")
        spec=owned(c,"specs",lot["spec_id"],u["id"])
        if not spec["approved"]: raise HTTPException(422,"Specification is not approved")
        docs=c.execute("SELECT * FROM documents WHERE lot_id=? AND owner=?",(lot_id,u["id"])).fetchall()
        if not docs: raise HTTPException(422,"Upload at least one document")
        obs=[]; refs=[]; texts=[]
        for d in docs:
            items=observations(d["extracted"])
            for item in items: item.update({"document_id":d["id"],"filename":d["filename"]})
            obs.extend(items); texts.append(d["extracted"]); refs.append({"document_id":d["id"],"filename":d["filename"],"sha256":d["sha256"]})
        combined="\n".join(texts)
        findings=compare(obs,json.loads(spec["tests"]))
        findings.insert(0,{"test":"Lot identity","status":"identity_match_candidate" if lot["lot_code"].casefold() in combined.casefold() else "identity_not_confirmed","message":"Lot code appears in source text." if lot["lot_code"].casefold() in combined.casefold() else "Lot code not found; verify manually."})
        s=c.execute("SELECT name FROM suppliers WHERE id=? AND owner=?",(lot["supplier_id"],u["id"])).fetchone()
        supplier_match=bool(s and s["name"].casefold() in combined.casefold())
        findings.insert(1,{"test":"Supplier identity","status":"supplier_name_match_candidate" if supplier_match else "supplier_identity_not_confirmed","message":"Supplier name appears in source text." if supplier_match else "Supplier name not found; verify manually."})
        result={"lot_id":lot_id,"specification_id":spec["id"],"specification_version":spec["version"],"documents":refs,"observations":obs,"findings":findings,"summary":{"observation_count":len(obs),"finding_count":len(findings),"requires_human_review":True,"note":"Automated candidates only. Not a food-safety determination or batch-release decision."}}
        c.execute("INSERT INTO findings VALUES(?,?,?,?,?)",(str(uuid.uuid4()),u["id"],lot_id,json.dumps(result),stamp()))
        c.execute("UPDATE lots SET status='review_required',updated=? WHERE id=?",(stamp(),lot_id))
        audit(c,u["id"],"lot",lot_id,"analysis_completed",{"observations":len(obs),"findings":len(findings)})
    return result
@app.get("/api/lots/{lot_id}/report")
def report(lot_id:str,u=Depends(user_id)):
    with conn() as c:
        owned(c,"lots",lot_id,u["id"])
        row=c.execute("SELECT payload FROM findings WHERE lot_id=? AND owner=? ORDER BY created DESC LIMIT 1",(lot_id,u["id"])).fetchone()
        ds=c.execute("SELECT disposition,rationale,reviewer,created FROM decisions WHERE lot_id=? AND owner=? ORDER BY created DESC",(lot_id,u["id"])).fetchall()
    if not row: raise HTTPException(404,"Run verification first")
    data=json.loads(row["payload"]); data["review_decisions"]=[dict(x) for x in ds]; return data
@app.post("/api/lots/{lot_id}/decision")
def decision(lot_id:str,x:DecisionIn,u=Depends(user_id)):
    did=str(uuid.uuid4())
    with conn() as c:
        owned(c,"lots",lot_id,u["id"])
        c.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",(did,u["id"],lot_id,x.disposition,x.rationale,x.reviewer,stamp()))
        c.execute("UPDATE lots SET status=?,updated=? WHERE id=?",(x.disposition,stamp(),lot_id))
        audit(c,u["id"],"lot",lot_id,"human_disposition_recorded",{"disposition":x.disposition,"reviewer":x.reviewer})
    return {"id":did,"status":x.disposition,"recorded":True}
@app.get("/api/audit")
def audit_log(u=Depends(user_id)):
    with conn() as c: rows=c.execute("SELECT entity,entity_id,action,details,created FROM events WHERE owner=? ORDER BY created DESC LIMIT 300",(u["id"],)).fetchall()
    return [{**dict(r),"details":json.loads(r["details"])} for r in rows]
@app.exception_handler(sqlite3.Error)
async def db_error(request,exc): return JSONResponse(status_code=500,content={"detail":"Database operation failed; no disposition was recorded."})
