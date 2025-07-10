import requests
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Dict
from database import SessionLocal, init_db, RemediatedVuln
from models import RemediateRequest, SeveritySummary

app = FastAPI(title="NIST Vulnerabilities API")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Helper to fetch all current CVEs and their severities ---
def fetch_all_cves():
    # For demo: fetch only first 2 pages (NIST might have request limits)
    results = []
    start_index = 0
    max_results = 2000
    while len(results) < 4000:  # Limit for demo
        params = {"startIndex": start_index, "resultsPerPage": max_results}
        response = requests.get(NVD_API, params=params)
        if response.status_code != 200:
            break
        data = response.json()
        results += data.get("vulnerabilities", [])
        if len(data.get("vulnerabilities", [])) < max_results:
            break
        start_index += max_results
    # Map: {cve_id: severity}
    cve_severity = {}
    for vuln in results:
        cve_id = vuln["cve"]["id"]
        severity = (
            vuln.get("cve", {})
            .get("metrics", {})
            .get("cvssMetricV31", [{}])[0]
            .get("cvssData", {})
            .get("baseSeverity", "UNKNOWN")
        )
        cve_severity[cve_id] = severity
    return cve_severity

@app.on_event("startup")
def startup():
    init_db()

@app.get("/vulnerabilities/summary", response_model=List[SeveritySummary])
def get_vulns_summary():
    cve_severity = fetch_all_cves()
    summary: Dict[str, int] = {}
    for sev in cve_severity.values():
        summary[sev] = summary.get(sev, 0) + 1
    return [SeveritySummary(severity=k, count=v) for k, v in summary.items()]

@app.post("/vulnerabilities/remediate")
def remediate_vulns(req: RemediateRequest, db: Session = Depends(get_db)):
    cve_severity = fetch_all_cves()
    # Validate CVEs exist
    for cve in req.cve_ids:
        if cve not in cve_severity:
            raise HTTPException(status_code=400, detail=f"CVE not found: {cve}")
    # Insert remediated CVEs for the team
    for cve in req.cve_ids:
        exists = db.query(RemediatedVuln).filter_by(team=req.team, cve_id=cve).first()
        if not exists:
            db.add(RemediatedVuln(team=req.team, cve_id=cve))
    db.commit()
    return {"message": "Vulnerabilities marked as remediated."}

@app.get("/vulnerabilities/summary/unremediated/{team}", response_model=List[SeveritySummary])
def get_unremediated_summary(team: str, db: Session = Depends(get_db)):
    cve_severity = fetch_all_cves()
    remediated = db.query(RemediatedVuln).filter_by(team=team).all()
    remediated_cves = set([r.cve_id for r in remediated])
    summary: Dict[str, int] = {}
    for cve, sev in cve_severity.items():
        if cve not in remediated_cves:
            summary[sev] = summary.get(sev, 0) + 1
    return [SeveritySummary(severity=k, count=v) for k, v in summary.items()]