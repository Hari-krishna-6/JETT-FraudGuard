from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .middleware import add_security_headers

from .cyber_platform import (
    analyze_ot_ics_context,
    analyze_topology_context,
    build_threat_intelligence_index,
    build_unified_assessment,
    discover_dataset_files,
    map_observed_techniques,
    orchestrate_incident_response,
    prioritize_vulnerabilities,
    score_behavioural_anomalies,
    suggest_defensive_actions,
    train_behavioural_anomaly_model,
)
from .model_registry import ensure_model_bundle

app = FastAPI(
    title="JETT FraudGuard",
    description="Deployment-ready cyber resilience platform for critical infrastructure with behavioural anomaly detection, ATT&CK mapping, topology awareness, OT/ICS context, vulnerability prioritization, and incident response orchestration.",
    version="1.1.0",
)
app = add_security_headers(app)


class RecordsRequest(BaseModel):
    records: List[Dict[str, Any]]


class SignalsRequest(BaseModel):
    signals: List[str]


class VulnerabilityRequest(BaseModel):
    asset_count: int = 4
    threat_level: str = "medium"


class IncidentRequest(BaseModel):
    signals: List[str]
    blast_radius: str = "medium"


class UnifiedAssessmentRequest(BaseModel):
    records: List[Dict[str, Any]]
    signals: List[str]
    asset_count: int = 4
    threat_level: str = "medium"


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
    summary = train_behavioural_anomaly_model()
    return summary


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
    return {"vulnerabilities": prioritize_vulnerabilities(asset_count=payload.asset_count, threat_level=payload.threat_level)}


@app.post("/incident-response")
def incident_response(payload: IncidentRequest):
    if not payload.signals:
        raise HTTPException(status_code=400, detail="Signals must not be empty.")
    return orchestrate_incident_response(payload.signals, blast_radius=payload.blast_radius)


@app.post("/unified-assessment")
def unified_assessment(payload: UnifiedAssessmentRequest):
    if not payload.records:
        raise HTTPException(status_code=400, detail="Records must not be empty.")
    return build_unified_assessment(payload.records, payload.signals, asset_count=payload.asset_count, threat_level=payload.threat_level)


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
