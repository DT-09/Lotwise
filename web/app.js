const $ = (id) => document.getElementById(id);
let token = sessionStorage.getItem("lotwise_token") || "";
let activeLot = "";
let latestReport = null;
const authHeaders = () => token ? { Authorization: "Bearer " + token } : {};
function message(id, value) { $(id).textContent = value || ""; }
function esc(value) { return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function signedIn() { $("auth").hidden=Boolean(token); $("app").hidden=!token; $("logout").hidden=!token; $("session").textContent=token?"Authenticated evaluation":"Not signed in"; }
function clearSession() { token=""; activeLot=""; latestReport=null; sessionStorage.removeItem("lotwise_token"); signedIn(); }
async function api(path, options={}) {
 const headers={...(options.headers||{}),...authHeaders()};
 if(options.body && !(options.body instanceof FormData)) headers["Content-Type"]="application/json";
 const response=await fetch(path,{...options,headers});
 const payload=await response.json().catch(()=>({detail:"Unexpected server response."}));
 if(response.status===401 && token){clearSession();throw new Error("Your session has expired. Sign in again.");}
 if(!response.ok) throw new Error(payload.detail||"Request failed.");
 return payload;
}
function severity(status){
 if(["within_limit_candidate","identity_match_candidate","supplier_name_match_candidate"].includes(status))return "good";
 if(["out_of_spec_candidate","missing","unit_review","conflicting_observations","identity_not_confirmed","supplier_identity_not_confirmed","unmapped_observation"].includes(status))return "attention";
 return "neutral";
}
function labelStatus(status){return String(status||"unknown").replaceAll("_"," ");}
function renderReport(data){
 latestReport=data;
 const findings=data.findings||[],docs=data.documents||[],observations=data.observations||[];
 const attention=findings.filter(f=>severity(f.status)==="attention").length;
 let html='<div class="report-summary"><div><strong>'+findings.length+'</strong><span>Review findings</span></div><div><strong>'+attention+'</strong><span>Need attention</span></div><div><strong>'+observations.length+'</strong><span>Extracted observations</span></div><div><strong>'+docs.length+'</strong><span>Source documents</span></div></div>';
 html+='<div class="report-context"><span>Specification version: '+esc(data.specification_version||"—")+'</span><span>Human review required</span></div><div class="findings-list">';
 for(const finding of findings){
  const observed=Array.isArray(finding.observed)?finding.observed:(finding.observed?[finding.observed]:[]);
  let evidence="";
  for(const item of observed){
   const file=docs.find(d=>d.document_id===item.document_id)||{};
   const location=[item.source_page?"Page "+item.source_page:"",item.source_line?"Line "+item.source_line:""].filter(Boolean).join(" · ");
   evidence+='<div class="evidence"><div class="evidence-meta"><b>'+esc(item.filename||file.filename||"Source observation")+'</b><span>'+esc(location||"Location not supplied")+'</span></div><p>'+esc(item.source_excerpt||"No source excerpt retained.")+'</p><small>Value: '+esc(item.value)+" "+esc(item.unit)+(item.normalized_value!==undefined?" · Compared value: "+esc(item.normalized_value)+" "+esc(finding.required_unit||""):"")+'</small></div>';
  }
  html+='<article class="finding"><div class="finding-head"><div><h4>'+esc(finding.test)+'</h4><span class="finding-status '+severity(finding.status)+'">'+esc(labelStatus(finding.status))+'</span></div><p>'+esc(finding.message)+'</p></div>'+(evidence||'<p class="no-evidence">No mapped measurement evidence. Check the source documents manually.</p>')+'</article>';
 }
 html+='</div><div class="report-boundary">Automated comparison candidates only. Verify each source, specification version and identity before making a quality decision. Lotwise does not determine food safety or release product.</div>';
 const decisions=data.review_decisions||[];
 if(decisions.length){html+='<div class="decision-history"><h4>Recorded dispositions</h4>';for(const d of decisions)html+='<div class="decision-entry"><b>'+esc(labelStatus(d.disposition))+'</b><span>'+esc(d.reviewer)+' · '+esc(new Date(d.created).toLocaleString())+'</span><p>'+esc(d.rationale)+'</p></div>';html+='</div>';}
 $("report").innerHTML=html;
}
function renderActivity(items){
 $("activity").innerHTML=items.length?items.map(item=>'<div class="activity-row"><span class="activity-dot"></span><div><b>'+esc(labelStatus(item.action))+'</b><small>'+esc(item.entity)+' · '+esc(item.entity_id)+'</small></div><time>'+esc(new Date(item.created).toLocaleString())+'</time></div>').join(""):"No account activity yet.";
}
async function refresh(){
 const [suppliers,specs,lots,events]=await Promise.all([api("/api/suppliers"),api("/api/specifications"),api("/api/lots"),api("/api/audit")]);
 $("supplierCount").textContent=suppliers.length;$("specCount").textContent=specs.length;$("approvedCount").textContent="Approved: "+specs.filter(x=>x.approved).length;$("lotCount").textContent=lots.length;
 $("reviewCount").textContent=lots.filter(x=>["review_required","on_hold"].includes(x.status)).length;
 $("supplierSelect").innerHTML=suppliers.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("");
 $("specSelect").innerHTML='<option value="">No specification selected</option>'+specs.map(x=>'<option value="'+esc(x.id)+'" '+(x.approved?"":"disabled")+'>'+esc(x.ingredient)+' · v'+esc(x.version)+(x.approved?"":" (not approved)")+'</option>').join("");
 $("lotSelect").innerHTML=lots.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.ingredient)+' · '+esc(x.lot_code)+' · '+esc(labelStatus(x.status))+'</option>').join("");
 if(!lots.some(x=>x.id===activeLot))activeLot=lots[0]?.id||"";
 if(activeLot){$("lotSelect").value=activeLot;await showReport();}else{latestReport=null;$("report").textContent="Create a lot and run verification to see findings.";}
 renderActivity(events);
}
async function showReport(){
 if(!activeLot)return;
 try{renderReport(await api("/api/lots/"+encodeURIComponent(activeLot)+"/report"));}
 catch(error){latestReport=null;$("report").textContent=error.message.includes("Run verification")?"No verification report exists for this lot yet.":error.message;}
}
async function authenticate(mode){
 try{const data=await api("/api/auth/"+mode,{method:"POST",body:JSON.stringify({email:$("email").value,password:$("password").value})});token=data.token;sessionStorage.setItem("lotwise_token",token);signedIn();await refresh();message("authmsg","");}
 catch(error){message("authmsg",error.message);}
}
$("login").addEventListener("click",()=>authenticate("login"));
$("register").addEventListener("click",()=>authenticate("register"));
$("logout").addEventListener("click",()=>{clearSession();$("report").textContent="Sign in to view account records.";});
$("addSupplier").addEventListener("click",async()=>{try{await api("/api/suppliers",{method:"POST",body:JSON.stringify({name:$("supplierName").value,code:$("supplierCode").value})});message("supplierMsg","Supplier saved.");await refresh();}catch(e){message("supplierMsg",e.message);}});
$("addSpec").addEventListener("click",async()=>{try{const tests=JSON.parse($("specTests").value);await api("/api/specifications",{method:"POST",body:JSON.stringify({ingredient:$("specIngredient").value,version:$("specVersion").value,approved:$("specApproved").checked,tests})});message("specMsg","Specification saved.");await refresh();}catch(e){message("specMsg",e instanceof SyntaxError?"Test requirements must be valid JSON.":e.message);}});
$("createLot").addEventListener("click",async()=>{try{const d=await api("/api/lots",{method:"POST",body:JSON.stringify({supplier_id:$("supplierSelect").value,ingredient:$("lotIngredient").value,lot_code:$("lotCode").value,po_number:$("poNumber").value,spec_id:$("specSelect").value||null})});activeLot=d.id;message("lotMsg","Incoming lot created.");await refresh();}catch(e){message("lotMsg",e.message);}});
$("uploadDocs").addEventListener("click",async()=>{try{if(!activeLot)throw Error("Create or select an active lot first.");const files=[...$("documents").files];if(!files.length)throw Error("Choose at least one document.");for(const file of files){if(file.size>12*1024*1024)throw Error(file.name+" exceeds the 12 MB limit.");const form=new FormData();form.append("file",file);await api("/api/lots/"+encodeURIComponent(activeLot)+"/documents",{method:"POST",body:form});}$("documents").value="";message("uploadMsg",files.length+" document(s) uploaded and fingerprinted.");await refresh();}catch(e){message("uploadMsg",e.message);}});
$("analyze").addEventListener("click",async()=>{try{if(!activeLot)throw Error("Create or select an active lot first.");const result=await api("/api/lots/"+encodeURIComponent(activeLot)+"/analyze",{method:"POST"});renderReport(result);message("analysisMsg","Checks complete. Human review is required.");await refresh();}catch(e){message("analysisMsg",e.message);}});
$("saveDecision").addEventListener("click",async()=>{try{if(!activeLot)throw Error("Select an active lot first.");const result=await api("/api/lots/"+encodeURIComponent(activeLot)+"/decision",{method:"POST",body:JSON.stringify({reviewer:$("reviewer").value,disposition:$("disposition").value,rationale:$("rationale").value})});message("decisionMsg","Disposition recorded: "+labelStatus(result.status)+".");await showReport();await refresh();}catch(e){message("decisionMsg",e.message);}});
$("refresh").addEventListener("click",()=>refresh().catch(e=>message("decisionMsg",e.message)));
$("lotSelect").addEventListener("change",async()=>{activeLot=$("lotSelect").value;await showReport();});
$("downloadCsv").addEventListener("click",async()=>{try{if(!activeLot||!latestReport)throw Error("Run verification before exporting a report.");const response=await fetch("/api/lots/"+encodeURIComponent(activeLot)+"/report.csv",{headers:authHeaders()});if(response.status===401){clearSession();throw Error("Your session has expired. Sign in again.");}if(!response.ok)throw Error("Could not export the report.");const url=URL.createObjectURL(await response.blob());const link=document.createElement("a");link.href=url;link.download="lotwise-review-"+activeLot+".csv";document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);}catch(e){message("decisionMsg",e.message);}});
signedIn();if(token)refresh().catch(()=>clearSession());