from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .middleware import add_security_headers

from .cyber_platform import (
    analyze_ot_ics_context,
    analyze_topology_context,
    build_threat_intelligence_index,
    build_unified_assessment,
    discover_dataset_files,
    evaluate_anomaly_model,
    map_observed_techniques,
    orchestrate_incident_response,
    prioritize_vulnerabilities,
    read_audit_log,
    score_behavioural_anomalies,
    simulate_attack_paths,
    suggest_defensive_actions,
    train_behavioural_anomaly_model,
)
from .model_registry import ensure_model_bundle

app = FastAPI(
    title="JETT FraudGuard",
    description="Deployment-ready cyber resilience platform for critical infrastructure with behavioural anomaly detection, ATT&CK mapping, topology awareness, OT/ICS context, vulnerability prioritization, and incident response orchestration.",
    version="1.1.0",
)
# Configure CORS so the local React dev server and any static demo pages can call the API
allowed = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app = add_security_headers(app)


class RecordsRequest(BaseModel):
    records: List[Dict[str, Any]]


class SignalsRequest(BaseModel):
    signals: List[str]


class VulnerabilityRequest(BaseModel):
    asset_count: int = 4
    threat_level: str = "medium"
    assets: List[Dict[str, Any]] = []


class IncidentRequest(BaseModel):
    signals: List[str]
    blast_radius: str = "medium"
    incident_id: Optional[str] = None


class UnifiedAssessmentRequest(BaseModel):
    records: List[Dict[str, Any]]
    signals: List[str]
    asset_count: int = 4
    threat_level: str = "medium"
    assets: List[Dict[str, Any]] = []


def validate_records(records: List[Dict[str, Any]]):
    if not records:
        raise HTTPException(status_code=400, detail="Request must contain at least one record.")
    if not isinstance(records, list):
        raise HTTPException(status_code=400, detail="Records must be a list of objects.")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "platform": "cyber-resilience",
        "datasets": discover_dataset_files(),
        "models": ensure_model_bundle(),
    }


@app.get("/dataset-status")
def dataset_status():
    return {
        "datasets": discover_dataset_files(),
        "topology": analyze_topology_context(),
        "ot_ics": analyze_ot_ics_context(),
    }


@app.get("/threat-intelligence")
def threat_intelligence():
    return build_threat_intelligence_index()


@app.post("/analyze-behavior")
def analyze_behavior(payload: RecordsRequest):
    validate_records(payload.records)
    try:
        results = score_behavioural_anomalies(payload.records)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"results": results}


@app.post("/train-anomaly-model")
def train_anomaly_model():
    try:
        return train_behavioural_anomaly_model()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/model-metrics")
def model_metrics():
    return evaluate_anomaly_model()


@app.post("/map-techniques")
def map_techniques(payload: SignalsRequest):
    if not payload.signals:
        raise HTTPException(status_code=400, detail="Signals must not be empty.")
    return {"techniques": map_observed_techniques(payload.signals)}


@app.post("/suggest-actions")
def suggest_actions(payload: SignalsRequest):
    if not payload.signals:
        raise HTTPException(status_code=400, detail="Signals must not be empty.")
    techniques = map_observed_techniques(payload.signals)
    return {"actions": suggest_defensive_actions(techniques)}


@app.post("/prioritize-vulnerabilities")
def prioritize_vulns(payload: VulnerabilityRequest):
    return {"vulnerabilities": prioritize_vulnerabilities(asset_count=payload.asset_count, threat_level=payload.threat_level, assets=payload.assets)}


@app.post("/incident-response")
def incident_response(payload: IncidentRequest):
    if not payload.signals:
        raise HTTPException(status_code=400, detail="Signals must not be empty.")
    return orchestrate_incident_response(payload.signals, blast_radius=payload.blast_radius, incident_id=payload.incident_id)


@app.post("/unified-assessment")
def unified_assessment(payload: UnifiedAssessmentRequest):
    if not payload.records:
        raise HTTPException(status_code=400, detail="Records must not be empty.")
    return build_unified_assessment(payload.records, payload.signals, asset_count=payload.asset_count, threat_level=payload.threat_level, assets=payload.assets)


@app.get("/audit-log")
def audit_log(limit: int = 100):
    """Return the newest simulated assessment and response events for SOC review."""
    return {"events": read_audit_log(limit)}


@app.post("/attack-paths")
def attack_paths(payload: VulnerabilityRequest):
    return {"paths": simulate_attack_paths(payload.asset_count, payload.threat_level, payload.assets)}


@app.post("/predict")
def predict(payload: RecordsRequest):
    validate_records(payload.records)
    results = score_behavioural_anomalies(payload.records)
    return {"predictions": results}


@app.post("/preprocess")
def preprocess():
    summary = train_behavioural_anomaly_model()
    return {"status": "trained", **summary}


@app.post("/train")
def train():
    summary = train_behavioural_anomaly_model()
    return {"status": "trained", **summary}
