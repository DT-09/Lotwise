from __future__ import annotations
import base64, csv, hashlib, hmac, io, json, math, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Depends, File, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import boto3
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

ROOT=Path(__file__).resolve().parent.parent
WEB=ROOT/"web"
DATA=Path(os.getenv("LOTWISE_DATA_DIR","./data")).resolve()
UPLOADS=DATA/"uploads"
DB=DATA/"lotwise.sqlite3"
DATABASE_URL=os.getenv("DATABASE_URL","").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL=DATABASE_URL.replace("postgres://","postgresql+psycopg://",1)
S3_BUCKET=os.getenv("LOTWISE_S3_BUCKET","").strip()
S3_REGION=os.getenv("LOTWISE_S3_REGION","us-east-1").strip()
S3_ENDPOINT=os.getenv("LOTWISE_S3_ENDPOINT_URL","").strip() or None
if os.getenv("LOTWISE_ENV","development").lower()=="production":
    if not DATABASE_URL.startswith("postgresql"):
        raise RuntimeError("Production requires a managed PostgreSQL DATABASE_URL")
    if not S3_BUCKET:
        raise RuntimeError("Production requires LOTWISE_S3_BUCKET for private document storage")
_S3_CLIENT=None
def _s3():
    global _S3_CLIENT
    if _S3_CLIENT is None:
        options={"region_name":S3_REGION}
        if S3_ENDPOINT: options["endpoint_url"]=S3_ENDPOINT
        _S3_CLIENT=boto3.client("s3",**options)
    return _S3_CLIENT
def persist_document(path,owner,document_id,suffix,digest):
    if not S3_BUCKET:
        return str(path)
    key=f"tenants/{owner}/documents/{document_id}{suffix}"
    _s3().upload_file(str(path),S3_BUCKET,key,ExtraArgs={"ServerSideEncryption":"AES256","Metadata":{"sha256":digest}})
    path.unlink(missing_ok=True)
    return f"s3://{S3_BUCKET}/{key}"
_ENGINE_CACHE={}
def _engine_for(url):
    if url not in _ENGINE_CACHE:
        options={"pool_pre_ping":True}
        if url.startswith("sqlite"):
            options["connect_args"]={"check_same_thread":False}
        _ENGINE_CACHE[url]=create_engine(url,**options)
    return _ENGINE_CACHE[url]
class _Result:
    def __init__(self,result): self.result=result
    def fetchone(self):
        row=self.result.fetchone()
        return row._mapping if row is not None else None
    def fetchall(self): return [row._mapping for row in self.result.fetchall()]
class _Connection:
    def __init__(self,connection,dialect): self.connection=connection; self.dialect=dialect
    def execute(self,sql,params=()):
        if self.dialect=="sqlite":
            return _Result(self.connection.exec_driver_sql(sql,tuple(params)))
        names=[]
        def bind(_):
            name="p"+str(len(names)); names.append(name); return ":"+name
        parts=sql.split("?")
        converted=parts[0]+"".join(":"+("p"+str(i))+parts[i+1] for i in range(len(parts)-1))
        names.extend("p"+str(i) for i in range(len(parts)-1))
        values={name:value for name,value in zip(names,params)}
        return _Result(self.connection.execute(text(converted),values))
    def executescript(self,script):
        for statement in script.split(";"):
            if statement.strip(): self.execute(statement)
MAX_BYTES=int(os.getenv("LOTWISE_MAX_UPLOAD_MB","12"))*1024*1024
configured_secret=os.getenv("LOTWISE_SECRET_KEY")
if os.getenv("LOTWISE_ENV","development").lower()=="production" and (not configured_secret or len(configured_secret)<32):
    raise RuntimeError("Production requires LOTWISE_SECRET_KEY with at least 32 characters")
SECRET=configured_secret or ("LOCAL-ONLY-"+str(DATA))
DATA.mkdir(parents=True,exist_ok=True); UPLOADS.mkdir(parents=True,exist_ok=True)
app=FastAPI(title="Lotwise",version="0.1.0",description="Evidence-linked supplier lot verification.")
auth=HTTPBearer(auto_error=False)
# Process-local abuse guard. For multi-instance production, replace with a shared
# Redis-backed limiter at the edge before accepting public sign-ups.
AUTH_WINDOW_SECONDS=300
AUTH_MAX_ATTEMPTS=10
_auth_attempts={}
def _auth_rate_limited(request):
    now=time.time()
    key=request.client.host if request.client else "unknown"
    bucket=[t for t in _auth_attempts.get(key,[]) if now-t<AUTH_WINDOW_SECONDS]
    if len(bucket)>=AUTH_MAX_ATTEMPTS:
        _auth_attempts[key]=bucket
        return True
    bucket.append(now)
    _auth_attempts[key]=bucket
    if len(_auth_attempts)>5000:
        for k,v in list(_auth_attempts.items()):
            if not v or now-v[-1]>=AUTH_WINDOW_SECONDS: _auth_attempts.pop(k,None)
    return False
@app.middleware("http")
async def security_headers(request:Request,call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"]="default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'"
    if os.getenv("LOTWISE_ENV","development").lower()=="production":
        response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    return response
def stamp(): return datetime.now(timezone.utc).isoformat()
@contextmanager
def conn():
    url=DATABASE_URL or ("sqlite:///"+str(DB))
    engine=_engine_for(url)
    with engine.begin() as raw:
        if engine.dialect.name=="sqlite":
            raw.exec_driver_sql("PRAGMA foreign_keys=ON")
        yield _Connection(raw,engine.dialect.name)
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
        try:
            pages=[]
            for number,page in enumerate(PdfReader(str(path)).pages,1):
                pages.append("[LOTWISE_SOURCE_PAGE:"+str(number)+"]\n"+(page.extract_text() or ""))
            return "\n".join(pages)[:500000]
        except Exception: raise HTTPException(422,"Could not extract selectable PDF text")
    try: return path.read_text(encoding="utf-8-sig")[:500000]
    except UnicodeDecodeError: raise HTTPException(422,"Only text-based CSV, JSON and TXT are supported")
def observations(text):
    """Extract conservative numeric observations while retaining source provenance."""
    found=[]
    colon_rx=re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /()_.-]{1,70}?)\s*[:=]\s*(-?\d+(?:\.\d+)?)\s*([%a-zA-Zµμ/°0-9.-]{0,24})\s*$")
    # Only accept whitespace-delimited table rows; requiring two spaces avoids
    # interpreting ordinary prose and headings as measurements.
    table_rx=re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /()_.-]{1,70}?)\s{2,}(-?\d+(?:\.\d+)?)\s*([%a-zA-Zµμ/°0-9.-]{1,24})\s*$")
    page=None
    for line_no,line in enumerate(text.splitlines(),1):
        marker=re.search(r"\[LOTWISE_SOURCE_PAGE:(\d+)\]",line)
        if marker:
            page=int(marker.group(1))
            continue
        match=colon_rx.match(line) or table_rx.match(line)
        if not match:
            continue
        found.append({"test":match.group(1).strip(),"value":float(match.group(2)),"unit":match.group(3).strip(),
                      "source_excerpt":line.strip(),"source_page":page,"source_line":line_no})
    try:
        for row in csv.DictReader(io.StringIO(text)):
            r={str(k).strip().lower():v for k,v in row.items() if k}
            if "test" in r and "value" in r:
                try:
                    found.append({"test":str(r["test"]).strip(),"value":float(r["value"]),
                                  "unit":str(r.get("unit") or "").strip(),"source_excerpt":json.dumps(row),
                                  "source_page":None,"source_line":None})
                except (ValueError,TypeError): pass
    except Exception: pass
    try:
        payload=json.loads(text)
        records=payload if isinstance(payload,list) else payload.get("tests",payload.get("results",[]))
        for item in records if isinstance(records,list) else []:
            if not isinstance(item,dict): continue
            name=item.get("test") or item.get("name")
            if not name or item.get("value") is None: continue
            try:
                value=float(item["value"])
                if not math.isfinite(value): continue
                found.append({"test":str(name).strip(),"value":value,
                              "unit":str(item.get("unit") or "").strip(),
                              "source_excerpt":json.dumps(item,ensure_ascii=False),
                              "source_page":item.get("page"),"source_line":item.get("line")})
            except (TypeError,ValueError): pass
    except Exception: pass
    unique={}
    for item in found:
        key=(item["test"].casefold(),item["value"],item["unit"].casefold(),
             item.get("source_page"),item.get("source_line"),item.get("source_excerpt"))
        unique[key]=item
    return list(unique.values())
def unit_info(unit):
    u=unit.strip().casefold().replace(" ","")
    return {"%":("percent",1),"percent":("percent",1),"ppm":("ppm",1),"mg/kg":("ppm",1),"g/kg":("ppm",1000),"mg/g":("ppm",1000),"°c":("celsius",1),"c":("celsius",1)}.get(u)
def compare(obs,spec):
    out=[]; seen=set()
    requirements=spec.get("tests",[]) if isinstance(spec,dict) else spec
    for req in requirements:
        name=str(req.get("name","")).strip()
        if not name: continue
        matches=[o for o in obs if o["test"].casefold()==name.casefold()]
        if not matches:
            out.append({"test":name,"status":"missing","message":"Required test not found."})
            continue
        signatures={(o["value"],o["unit"].casefold()) for o in matches}
        for o in matches:
            seen.add((o["test"].casefold(),o["value"],o["unit"].casefold()))
        if len(signatures)>1:
            out.append({"test":name,"status":"conflicting_observations","observed":matches,
                        "message":"Multiple different results were found for this test. Resolve the source conflict before comparing against the specification."})
            continue
        o=matches[0]
        target=str(req.get("unit","")); value=o["value"]
        if target.casefold()!=o["unit"].casefold():
            a,b=unit_info(o["unit"]),unit_info(target)
            if not a or not b or a[0]!=b[0]:
                out.append({"test":name,"status":"unit_review","observed":o,"required_unit":target,"message":"Units cannot be safely compared; reviewer mapping required."})
                continue
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
@app.get("/examples/{name}")
def example_file(name:str):
    if name not in {"sample_coa.txt","sample_receiving_record.txt","sample_specification.json"}:
        raise HTTPException(404,"Example not found")
    return FileResponse(ROOT/"examples"/name)
@app.get("/docs/{name}")
def documentation(name:str):
    if name not in {"PRODUCT.md","COMMERCIAL.md","DEPLOYMENT.md"}:
        raise HTTPException(404,"Document not found")
    return FileResponse(ROOT/"docs"/name,media_type="text/markdown")
@app.post("/api/auth/register")
def register(data:Credentials,request:Request):
    if _auth_rate_limited(request): raise HTTPException(429,"Too many authentication attempts. Try again in five minutes.")
    email=data.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email): raise HTTPException(422,"Invalid email")
    uid=str(uuid.uuid4())
    try:
        with conn() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?)",(uid,email,password_hash(data.password),stamp()))
            audit(c,uid,"account",uid,"created",{})
    except IntegrityError: raise HTTPException(409,"Account already exists")
    return {"token":make_token(uid),"email":email}
@app.post("/api/auth/login")
def login(data:Credentials,request:Request):
    if _auth_rate_limited(request): raise HTTPException(429,"Too many authentication attempts. Try again in five minutes.")
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
    names=set()
    for t in x.tests:
        name=str(t.get("name","")).strip().casefold()
        if not name or not t.get("unit") or (t.get("min") is None and t.get("max") is None):
            raise HTTPException(422,"Each test needs a unique name, unit and at least one limit")
        if name in names: raise HTTPException(422,"Duplicate test names are not allowed")
        names.add(name)
        try:
            low=float(t["min"]) if t.get("min") is not None else None
            high=float(t["max"]) if t.get("max") is not None else None
            if (low is not None and not math.isfinite(low)) or (high is not None and not math.isfinite(high)):
                raise ValueError()
        except (TypeError,ValueError): raise HTTPException(422,"Specification limits must be finite numbers")
        if low is not None and high is not None and low>high: raise HTTPException(422,"Minimum exceeds maximum")
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
        if x.spec_id:
            selected_spec=owned(c,"specs",x.spec_id,u["id"])
            if not selected_spec["approved"]: raise HTTPException(422,"Specification must be approved")
            if selected_spec["ingredient"].strip().casefold()!=x.ingredient.strip().casefold():
                raise HTTPException(422,"Specification ingredient must match lot ingredient")
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
    did=str(uuid.uuid4()); temporary=UPLOADS/u["id"]/(did+suffix); temporary.parent.mkdir(parents=True,exist_ok=True); temporary.write_bytes(content)
    try: text=extract(temporary,suffix)
    except Exception: temporary.unlink(missing_ok=True); raise
    digest=hashlib.sha256(content).hexdigest()
    try: stored=persist_document(temporary,u["id"],did,suffix,digest)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise HTTPException(503,"Document storage is temporarily unavailable")
    with conn() as c:
        c.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?)",(did,u["id"],lot_id,Path(file.filename or "upload").name[:180],stored,digest,text,stamp()))
        audit(c,u["id"],"document",did,"uploaded",{"lot_id":lot_id,"sha256":digest,"bytes":len(content)})
    return {"id":did,"filename":Path(file.filename or "upload").name,"sha256":digest,"extracted_characters":len(text)}
@app.get("/api/documents/{document_id}/download")
def download_document(document_id:str,u=Depends(user_id)):
    with conn() as c:
        row=c.execute("SELECT filename,stored FROM documents WHERE id=? AND owner=?",(document_id,u["id"])).fetchone()
    if not row: raise HTTPException(404,"Document not found")
    stored=row["stored"]
    if stored.startswith("s3://"):
        bucket_key=stored[5:].split("/",1)
        if len(bucket_key)!=2 or bucket_key[0]!=S3_BUCKET:
            raise HTTPException(500,"Document storage reference is invalid")
        url=_s3().generate_presigned_url("get_object",Params={"Bucket":bucket_key[0],"Key":bucket_key[1]},ExpiresIn=300)
        return RedirectResponse(url,status_code=302)
    path=Path(stored).resolve()
    if not path.is_file() or UPLOADS.resolve() not in path.parents:
        raise HTTPException(404,"Document file is unavailable")
    return FileResponse(path,filename=row["filename"],content_disposition_type="attachment")

@app.post("/api/lots/{lot_id}/analyze")
def analyze(lot_id:str,u=Depends(user_id)):
    with conn() as c:
        lot=owned(c,"lots",lot_id,u["id"])
        if not lot["spec_id"]: raise HTTPException(422,"Assign an approved specification first")
        spec=owned(c,"specs",lot["spec_id"],u["id"])
        if not spec["approved"]: raise HTTPException(422,"Specification is not approved")
        if spec["ingredient"].strip().casefold()!=lot["ingredient"].strip().casefold():
            raise HTTPException(422,"Specification ingredient does not match this lot")
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
        prior=c.execute("SELECT 1 FROM findings WHERE lot_id=? AND owner=? LIMIT 1",(lot_id,u["id"])).fetchone()
        if not prior: raise HTTPException(422,"Run verification before recording a disposition")
        c.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",(did,u["id"],lot_id,x.disposition,x.rationale,x.reviewer,stamp()))
        c.execute("UPDATE lots SET status=?,updated=? WHERE id=?",(x.disposition,stamp(),lot_id))
        audit(c,u["id"],"lot",lot_id,"human_disposition_recorded",{"disposition":x.disposition,"reviewer":x.reviewer})
    return {"id":did,"status":x.disposition,"recorded":True}
@app.get("/api/audit")
def audit_log(u=Depends(user_id)):
    with conn() as c: rows=c.execute("SELECT entity,entity_id,action,details,created FROM events WHERE owner=? ORDER BY created DESC LIMIT 300",(u["id"],)).fetchall()
    return [{**dict(r),"details":json.loads(r["details"])} for r in rows]
@app.exception_handler(SQLAlchemyError)
async def db_error(request,exc): return JSONResponse(status_code=500,content={"detail":"Database operation failed; no disposition was recorded."})
