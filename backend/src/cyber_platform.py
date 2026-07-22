"""Core intelligence services for the FraudGuard demo.

The platform is deliberately safe-by-default: response playbooks are simulated until
an organisation replaces the adapter with an approved SOAR connector.
"""
from __future__ import annotations

import json
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn import __version__ as SKLEARN_VERSION
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .config import AUDIT_LOG_PATH, DATASETS_DIR, MODEL_DIR, RANDOM_STATE

SIGNAL_TECHNIQUES = {
    "credential access": ("T1110", "Brute Force", "credential-access"),
    "password spraying": ("T1110.003", "Password Spraying", "credential-access"),
    "lateral movement": ("T1021", "Remote Services", "lateral-movement"),
    "ransomware": ("T1486", "Data Encrypted for Impact", "impact"),
    "command and control": ("T1071", "Application Layer Protocol", "command-and-control"),
    "data exfiltration": ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    "phishing": ("T1566", "Phishing", "initial-access"),
    "privilege escalation": ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation"),
}

FALLBACK_VULNERABILITIES = [
    {"cve": "CVE-2023-4966", "description": "Citrix NetScaler sensitive information disclosure", "cvss": 9.4, "known_exploited": True, "ransomware": True},
    {"cve": "CVE-2021-44228", "description": "Apache Log4j remote code execution", "cvss": 10.0, "known_exploited": True, "ransomware": True},
    {"cve": "CVE-2023-34362", "description": "MOVEit Transfer SQL injection", "cvss": 9.8, "known_exploited": True, "ransomware": False},
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_audit(event_type: str, payload: Dict[str, Any]) -> str:
    """Append an inspectable, tamper-evident-in-demo JSONL event."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    event = {"event_id": event_id, "timestamp": _now(), "event_type": event_type, **payload}
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, default=str, sort_keys=True) + "\n")
    return event_id


def read_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    if not AUDIT_LOG_PATH.exists():
        return []
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()[-max(1, min(limit, 500)):]
    return [json.loads(line) for line in reversed(lines) if line.strip()]


def discover_dataset_files() -> Dict[str, str]:
    root = DATASETS_DIR
    candidates = {
        "training_set": root / "UNSW" / "raw" / "training_set.csv",
        "testing_set": root / "UNSW" / "raw" / "testing_set.csv",
        "attck_enterprise": root / "ATT&CK" / "enterprise-attack",
        "attck_ics": root / "ATT&CK" / "ics-attack",
        "vulnerabilities": root / "vulnerability" / "known_exploited_vulnerabilities.csv",
        "network_topology": root / "Network_Topology" / "telemetry",
        "ot_ics": root / "OT_ICS" / "hai",
    }
    return {key: str(path) if path.exists() else "" for key, path in candidates.items()}


def _directory_summary(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"available": False, "datasets": [], "mode": "demo_fallback"}
    children = [{"name": item.name, "type": "directory" if item.is_dir() else "file"} for item in sorted(path.iterdir()) if item.name != ".git"]
    return {"available": bool(children), "datasets": children, "mode": "repository_data"}


def analyze_topology_context() -> Dict[str, Any]:
    return _directory_summary(DATASETS_DIR / "Network_Topology" / "telemetry")


def analyze_ot_ics_context() -> Dict[str, Any]:
    return _directory_summary(DATASETS_DIR / "OT_ICS" / "hai")


def _fallback_training_data(rows: int = 500) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_STATE)
    return pd.DataFrame({
        "dur": rng.lognormal(-2.2, .45, rows), "proto": rng.choice(["tcp", "udp", "icmp"], rows, p=[.74, .22, .04]),
        "service": rng.choice(["http", "dns", "-", "ssh"], rows, p=[.45, .27, .2, .08]), "state": rng.choice(["FIN", "CON", "INT"], rows, p=[.7, .25, .05]),
        "spkts": rng.poisson(8, rows), "dpkts": rng.poisson(7, rows), "sbytes": rng.lognormal(5.2, .7, rows),
        "dbytes": rng.lognormal(5.0, .7, rows), "label": 0,
    })


def load_network_training_data() -> pd.DataFrame:
    path = DATASETS_DIR / "UNSW" / "raw" / "training_set.csv"
    return pd.read_csv(path) if path.exists() else _fallback_training_data()


def _normalize_label(value: Any) -> str:
    return "normal" if pd.isna(value) or str(value).strip().lower() in {"0", "normal", "benign", "no attack"} else "attack"


class BehavioralAnomalyEngine:
    def __init__(self, contamination: float = .05):
        self.contamination, self.model, self.feature_columns = contamination, None, []
        self.sklearn_version = SKLEARN_VERSION

    def fit(self, frame: pd.DataFrame) -> Dict[str, Any]:
        normal = frame[frame["label"].apply(_normalize_label) == "normal"].copy() if "label" in frame else frame.copy()
        if normal.empty:
            raise ValueError("No normal telemetry was supplied for baseline training")
        self.feature_columns = [c for c in normal.columns if c not in {"id", "label", "attack_cat", "asset_id", "user_id", "timestamp", "source_ip", "destination_ip"}]
        numeric = [c for c in self.feature_columns if pd.api.types.is_numeric_dtype(normal[c])]
        categorical = [c for c in self.feature_columns if c not in numeric]
        transforms = []
        if numeric: transforms.append(("num", Pipeline([( "impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), numeric))
        if categorical: transforms.append(("cat", Pipeline([( "impute", SimpleImputer(strategy="most_frequent")), ("encode", OneHotEncoder(handle_unknown="ignore"))]), categorical))
        self.model = Pipeline([("preprocess", ColumnTransformer(transforms)), ("isolation_forest", IsolationForest(contamination=self.contamination, random_state=RANDOM_STATE, n_estimators=150))])
        self.model.fit(normal[self.feature_columns])
        return {"feature_columns": self.feature_columns, "trained_on_normal_rows": len(normal)}

    def score(self, frame: pd.DataFrame) -> pd.DataFrame:
        if self.model is None: raise ValueError("The anomaly detector has not been trained")
        features = frame.copy()
        for col in self.feature_columns:
            if col not in features: features[col] = 0
        transformed = self.model.named_steps["preprocess"].transform(features[self.feature_columns])
        forest = self.model.named_steps["isolation_forest"]
        raw = -forest.decision_function(transformed)
        flags = forest.predict(transformed) == -1
        return pd.DataFrame({"anomaly_score": raw, "is_anomaly": flags}, index=frame.index)


def train_behavioural_anomaly_model(contamination: float = .05) -> Dict[str, Any]:
    engine = BehavioralAnomalyEngine(contamination); summary = engine.fit(load_network_training_data())
    MODEL_DIR.mkdir(parents=True, exist_ok=True); joblib.dump(engine, MODEL_DIR / "behavioural_anomaly_model.joblib")
    (MODEL_DIR / "behavioural_anomaly_model.meta.json").write_text(json.dumps({"sklearn_version": SKLEARN_VERSION}), encoding="utf-8")
    summary.update({"model_path": str(MODEL_DIR / "behavioural_anomaly_model.joblib"), "data_mode": "repository" if (DATASETS_DIR / "UNSW" / "raw" / "training_set.csv").exists() else "synthetic_demo_baseline"})
    _append_audit("model_trained", summary); return summary


def load_behavioural_anomaly_model() -> BehavioralAnomalyEngine:
    path = MODEL_DIR / "behavioural_anomaly_model.joblib"
    metadata_path = MODEL_DIR / "behavioural_anomaly_model.meta.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
        if path.exists() and metadata.get("sklearn_version") == SKLEARN_VERSION:
            engine = joblib.load(path)
            if getattr(engine, "sklearn_version", None) == SKLEARN_VERSION:
                return engine
    except Exception:
        pass  # Artefacts are rebuilt when sklearn versions differ.
    train_behavioural_anomaly_model(); return joblib.load(path)


def score_behavioural_anomalies(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    frame = pd.DataFrame(records); scores = load_behavioural_anomaly_model().score(frame)
    result = []
    for record, (_, row) in zip(records, scores.iterrows()):
        reasons = []
        if float(record.get("sbytes", 0) or 0) > 100000: reasons.append("unusually high outbound byte volume")
        if int(record.get("failed_logins", 0) or 0) >= 8: reasons.append("repeated failed authentication")
        if record.get("ot_command") in {"write", "firmware_update"}: reasons.append("sensitive OT command")
        anomaly = bool(row.is_anomaly) or bool(reasons)
        score = min(1.0, max(0.0, .5 + float(row.anomaly_score) + .15 * len(reasons)))
        level = "critical" if score >= .85 else "high" if score >= .65 else "medium" if anomaly else "low"
        result.append({"anomaly_score": round(score, 4), "is_anomaly": anomaly, "risk_level": level, "reasons": reasons or ["behaviour matches established baseline"], "asset_id": record.get("asset_id")})
    _append_audit("telemetry_assessed", {"record_count": len(records), "anomalies": sum(r["is_anomaly"] for r in result)})
    return result


def evaluate_anomaly_model() -> Dict[str, Any]:
    """Evaluate only against a labelled mounted benchmark; never invent performance claims."""
    test_path = DATASETS_DIR / "UNSW" / "raw" / "testing_set.csv"
    if not test_path.exists():
        return {"status": "awaiting_labelled_benchmark", "message": "Mount UNSW testing_set.csv to calculate detection rate and false-positive rate."}
    frame = pd.read_csv(test_path)
    if "label" not in frame.columns:
        return {"status": "invalid_benchmark", "message": "Benchmark requires a label column."}
    scores = load_behavioural_anomaly_model().score(frame)
    expected = frame["label"].apply(lambda value: _normalize_label(value) == "attack").to_numpy()
    observed = scores["is_anomaly"].to_numpy()
    normal = ~expected
    metrics = {"detection_recall": round(float(recall_score(expected, observed, zero_division=0)), 4), "precision": round(float(precision_score(expected, observed, zero_division=0)), 4), "false_positive_rate": round(float(observed[normal].mean()) if normal.any() else 0.0, 4), "benchmark_records": int(len(frame))}
    _append_audit("model_evaluated", metrics)
    return {"status": "evaluated", **metrics}


def build_threat_intelligence_index() -> Dict[str, Any]:
    techniques = []
    root = DATASETS_DIR / "ATT&CK"
    for path in root.rglob("*.json") if root.exists() else []:
        try: objects = json.loads(path.read_text(encoding="utf-8")).get("objects", [])
        except (json.JSONDecodeError, OSError): continue
        for item in objects:
            if item.get("type") != "attack-pattern": continue
            external = next((x.get("external_id") for x in item.get("external_references", []) if x.get("source_name", "").startswith("mitre-attack")), item.get("id"))
            phases = [x.get("phase_name") for x in item.get("kill_chain_phases", []) if x.get("phase_name")]
            techniques.append({"id": external, "name": item.get("name"), "tactic": phases[0] if phases else "unknown", "description": re.sub(r"\s+", " ", item.get("description", "")), "framework": path.parts[-2]})
    if not techniques: techniques = [{"id": v[0], "name": v[1], "tactic": v[2], "description": key, "framework": "curated_demo"} for key, v in SIGNAL_TECHNIQUES.items()]
    dedupe = {x["id"]: x for x in techniques}
    return {"techniques": list(dedupe.values()), "tactics": sorted({x["tactic"] for x in dedupe.values()}), "files_processed": len(list(root.rglob("*.json"))) if root.exists() else 0, "mode": "repository" if root.exists() else "curated_demo"}


def map_observed_techniques(observed_signals: List[str], top_k: int = 5) -> List[Dict[str, Any]]:
    signals = " ".join(observed_signals).lower(); matches = []
    for phrase, (tid, name, tactic) in SIGNAL_TECHNIQUES.items():
        if phrase in signals or set(phrase.split()) & set(signals.split()): matches.append({"id": tid, "name": name, "tactic": tactic, "confidence": 0.92 if phrase in signals else 0.6, "evidence": phrase})
    if not matches:
        for technique in build_threat_intelligence_index()["techniques"]:
            overlap = set(signals.split()) & set((technique["name"] + " " + technique["description"]).lower().split())
            if overlap: matches.append({**technique, "confidence": round(min(.7, .2 * len(overlap)), 2), "evidence": ", ".join(sorted(overlap))})
    return sorted(matches, key=lambda x: x["confidence"], reverse=True)[:top_k]


def suggest_defensive_actions(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tactics = " ".join(x.get("tactic", "") for x in techniques)
    actions = []
    if "credential" in tactics: actions.append({"action": "revoke_sessions_and_force_password_reset", "priority": "high", "blast_radius": "medium"})
    if "lateral" in tactics: actions.append({"action": "isolate_affected_endpoint", "priority": "high", "blast_radius": "low"})
    if "command-and-control" in tactics: actions.append({"action": "block_indicator_at_egress", "priority": "high", "blast_radius": "low"})
    if "impact" in tactics: actions.append({"action": "snapshot_critical_vm_and_protect_backups", "priority": "critical", "blast_radius": "high"})
    return actions or [{"action": "collect_forensic_evidence", "priority": "medium", "blast_radius": "low"}]


def _vulnerability_rows() -> List[Dict[str, Any]]:
    path = DATASETS_DIR / "vulnerability" / "known_exploited_vulnerabilities.csv"
    if not path.exists(): return FALLBACK_VULNERABILITIES
    frame = pd.read_csv(path); rows = []
    for _, r in frame.iterrows(): rows.append({"cve": r.get("cveID", r.get("cve", "unknown")), "description": r.get("shortDescription", r.get("description", "")), "cvss": float(r.get("cvss", r.get("baseScore", 7.5)) or 7.5), "known_exploited": True, "ransomware": str(r.get("knownRansomwareCampaignUse", "")).lower() == "known"})
    return rows


def prioritize_vulnerabilities(asset_count: int = 4, threat_level: str = "medium", assets: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    exposure = sum(1 for a in (assets or []) if a.get("internet_exposed")) / max(1, len(assets or [])); criticality = np.mean([float(a.get("criticality", 5)) for a in (assets or [])]) if assets else 6
    threat = {"low": .8, "medium": 1, "high": 1.15, "critical": 1.3}.get(threat_level.lower(), 1)
    ranked = []
    for item in _vulnerability_rows():
        score = min(10, (item["cvss"] * .55 + (2 if item["known_exploited"] else 0) + (1 if item["ransomware"] else 0) + exposure + criticality / 10) * threat)
        ranked.append({**item, "score": round(float(score), 2), "priority": "critical" if score >= 9 else "high" if score >= 7 else "medium", "rationale": "CVSS + known exploitation + ransomware use + asset exposure + criticality"})
    return sorted(ranked, key=lambda x: x["score"], reverse=True)[:10]


def summarize_vulnerability_dataset() -> Dict[str, Any]:
    rows = _vulnerability_rows(); return {"available": bool(rows), "row_count": len(rows), "mode": "repository" if (DATASETS_DIR / "vulnerability").exists() else "curated_demo"}


def summarize_unsw_network_dataset() -> Dict[str, Any]:
    frame = load_network_training_data(); return {"available": True, "row_count": len(frame), "column_count": len(frame.columns), "mode": "repository" if (DATASETS_DIR / "UNSW").exists() else "synthetic_demo_baseline"}


def simulate_attack_paths(asset_count: int = 4, threat_level: str = "medium", assets: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    nodes = assets or [{"asset_id": "vpn-gateway", "internet_exposed": True, "criticality": 7}, {"asset_id": "exam-db", "criticality": 10}, {"asset_id": "ics-hmi", "criticality": 9}]
    targets = sorted(nodes, key=lambda x: float(x.get("criticality", 5)), reverse=True)[:3]
    return [{"path_id": f"path-{i+1}", "source": "internet_edge", "target": t.get("asset_id", f"critical_asset_{i+1}"), "steps": ["Initial Access", "Valid Accounts", "Remote Services", "Collection"], "risk": "high" if t.get("internet_exposed") or threat_level in {"high", "critical"} else "medium", "mitigations": ["MFA", "network segmentation", "egress monitoring"]} for i, t in enumerate(targets)]


def orchestrate_incident_response(signals: List[str], blast_radius: str = "medium", incident_id: Optional[str] = None) -> Dict[str, Any]:
    incident_id = incident_id or f"inc_{uuid.uuid4().hex[:12]}"; techniques = map_observed_techniques(signals); actions = suggest_defensive_actions(techniques)
    gated = blast_radius.lower() in {"high", "critical"} or any(a["blast_radius"] == "high" for a in actions)
    steps = [{**a, "status": "pending_human_approval" if gated else "simulated_executed", "simulation": True} for a in actions]
    event_id = _append_audit("incident_response", {"incident_id": incident_id, "signals": signals, "techniques": techniques, "steps": steps, "approval_required": gated})
    return {"incident_id": incident_id, "status": "human_approval_required" if gated else "simulated_containment_complete", "execution_mode": "simulation_only", "approval_required": gated, "techniques": techniques, "playbook_steps": steps, "audit_event_id": event_id}


def summarize_data_fabric() -> Dict[str, Any]:
    index = build_threat_intelligence_index(); return {"available": True, "domains": {"attck": True, "topology": analyze_topology_context()["available"], "ot_ics": analyze_ot_ics_context()["available"], "unsw": True, "vulnerability": True}, "threat_intelligence": {"technique_count": len(index["techniques"]), "tactic_count": len(index["tactics"]), "mode": index["mode"]}}


def build_unified_assessment(records: List[Dict[str, Any]], signals: List[str], asset_count: int = 4, threat_level: str = "medium", assets: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    anomalies = score_behavioural_anomalies(records); techniques = map_observed_techniques(signals); response = orchestrate_incident_response(signals, blast_radius=threat_level)
    return {"assessment_id": f"asm_{uuid.uuid4().hex[:12]}", "anomaly_summary": {"total_records": len(records), "anomalies_detected": sum(x["is_anomaly"] for x in anomalies), "results": anomalies}, "threat_mapping": {"signals": signals, "techniques": techniques, "campaign_hypothesis": "multi-stage intrusion" if len(techniques) >= 2 else "insufficient evidence", "recommended_actions": suggest_defensive_actions(techniques)}, "attack_paths": simulate_attack_paths(asset_count, threat_level, assets), "vulnerabilities": {"ranked": prioritize_vulnerabilities(asset_count, threat_level, assets), "summary": summarize_vulnerability_dataset()}, "incident_response": response, "context": {"topology": analyze_topology_context(), "ot_ics": analyze_ot_ics_context(), "unsw": summarize_unsw_network_dataset(), "data_fabric": summarize_data_fabric()}}
