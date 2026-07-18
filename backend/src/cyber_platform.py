from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .config import DATASETS_DIR, MODEL_DIR, RANDOM_STATE


def discover_dataset_files() -> Dict[str, str]:
    """Return the full set of dataset paths available in the repository."""
    root = DATASETS_DIR
    unsw_raw = root / "UNSW" / "raw"
    unsw_processed = root / "UNSW" / "processed"
    attck_root = root / "ATT&CK"

    candidates = {
        "training_set": unsw_raw / "training_set.csv",
        "testing_set": unsw_raw / "testing_set.csv",
        "processed_train": unsw_processed / "train_processed.csv",
        "processed_test": unsw_processed / "test_processed.csv",
        "attck_enterprise": attck_root / "enterprise-attack",
        "attck_ics": attck_root / "ics-attack",
        "attck_mobile": attck_root / "mobile-attack",
        "attck_util": attck_root / "util",
        "vulnerabilities": root / "vulnerability" / "known_exploited_vulnerabilities.csv",
        "network_topology": root / "Network_Topology" / "telemetry",
        "network_topology_0": root / "Network_Topology" / "telemetry" / "0",
        "network_topology_1": root / "Network_Topology" / "telemetry" / "1",
        "network_topology_2": root / "Network_Topology" / "telemetry" / "2",
        "network_topology_3": root / "Network_Topology" / "telemetry" / "3",
        "network_topology_4": root / "Network_Topology" / "telemetry" / "4",
        "network_topology_5": root / "Network_Topology" / "telemetry" / "5",
        "network_topology_6": root / "Network_Topology" / "telemetry" / "6",
        "network_topology_7": root / "Network_Topology" / "telemetry" / "7",
        "network_topology_8": root / "Network_Topology" / "telemetry" / "8",
        "network_topology_9": root / "Network_Topology" / "telemetry" / "9",
        "network_topology_10": root / "Network_Topology" / "telemetry" / "10",
        "network_topology_11": root / "Network_Topology" / "telemetry" / "11",
        "network_topology_12": root / "Network_Topology" / "telemetry" / "12",
        "network_topology_description": root / "Network_Topology" / "telemetry" / "topology_description_docs",
        "ot_ics": root / "OT_ICS" / "hai",
        "ot_ics_graph": root / "OT_ICS" / "hai" / "graph",
    }

    resolved = {}
    for key, path in candidates.items():
        resolved[key] = str(path) if path.exists() else ""
    return resolved


def analyze_topology_context() -> Dict[str, Any]:
    """Summarize the network topology telemetry dataset into a lightweight context payload."""
    telemetry_root = DATASETS_DIR / "Network_Topology" / "telemetry"
    datasets: List[Dict[str, Any]] = []
    if telemetry_root.exists():
        for child in sorted(telemetry_root.iterdir()):
            if child.name in {".git"}:
                continue
            if child.is_dir():
                datasets.append({"name": child.name, "type": "directory", "items": len(list(child.rglob('*'))), "path": str(child)})
            else:
                datasets.append({"name": child.name, "type": "file", "size": child.stat().st_size, "path": str(child)})
    return {"available": len(datasets) > 0, "datasets": datasets}


def analyze_ot_ics_context() -> Dict[str, Any]:
    """Summarize the OT/ICS HAI dataset into a lightweight context payload."""
    ot_root = DATASETS_DIR / "OT_ICS" / "hai"
    datasets: List[Dict[str, Any]] = []
    if ot_root.exists():
        for child in sorted(ot_root.iterdir()):
            if child.name == ".git":
                continue
            if child.is_dir():
                datasets.append({"name": child.name, "type": "directory", "items": len(list(child.rglob('*'))), "path": str(child)})
            else:
                datasets.append({"name": child.name, "type": "file", "size": child.stat().st_size, "path": str(child)})
    return {"available": len(datasets) > 0, "datasets": datasets}


def summarize_data_fabric() -> Dict[str, Any]:
    """Create a holistic inventory of all repository-backed intelligence domains."""
    inventory = discover_dataset_files()
    topology = analyze_topology_context()
    ot_ics = analyze_ot_ics_context()
    threat_index = build_threat_intelligence_index()
    unsw = summarize_unsw_network_dataset()
    vulnerability = summarize_vulnerability_dataset()

    domains = {
        "attck": bool(threat_index.get("techniques")),
        "topology": topology.get("available", False),
        "ot_ics": ot_ics.get("available", False),
        "unsw": unsw.get("available", False),
        "vulnerability": vulnerability.get("available", False),
    }

    files = []
    for key, path in inventory.items():
        if path:
            files.append({"key": key, "path": path, "exists": Path(path).exists()})

    return {
        "available": any(domains.values()),
        "domains": domains,
        "total_files": len(files),
        "inventory": files,
        "threat_intelligence": {
            "technique_count": len(threat_index.get("techniques", [])),
            "tactic_count": len(threat_index.get("tactics", [])),
            "framework_counts": threat_index.get("framework_counts", {}),
        },
    }


def build_threat_intelligence_index() -> Dict[str, Any]:
    """Build a comprehensive ATT&CK-style threat intelligence index from the bundled JSON files."""
    root = DATASETS_DIR / "ATT&CK"
    dataset_folders = [
        root / "enterprise-attack",
        root / "ics-attack",
        root / "mobile-attack",
        root / "util",
    ]

    techniques: List[Dict[str, Any]] = []
    tactics = set()
    sources: List[str] = []
    files_processed = 0
    framework_counts: Counter = Counter()

    for folder in dataset_folders:
        if not folder.exists():
            continue
        json_files = sorted([path for path in folder.rglob("*.json") if path.is_file()])
        framework_counts[folder.name] = len(json_files)
        for path in json_files:
            files_processed += 1
            try:
                with path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                sources.append(str(path))
            except Exception:
                continue

            objects = payload.get("objects", []) if isinstance(payload, dict) else []
            if isinstance(objects, list):
                for entry in objects:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("type") != "attack-pattern":
                        continue
                    phases = [phase.get("phase_name") for phase in entry.get("kill_chain_phases", []) if isinstance(phase, dict) and phase.get("phase_name")]
                    for phase in phases:
                        tactics.add(phase)

                    technique = {
                        "id": entry.get("id"),
                        "name": entry.get("name"),
                        "tactic": phases[0] if phases else "unknown",
                        "description": re.sub(r"\s+", " ", entry.get("description", "")).strip(),
                        "framework": folder.name,
                    }
                    techniques.append(technique)

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in techniques:
        key = (item.get("id") or item.get("name"))
        if key in seen:
            continue
        deduped.append(item)
        seen.add(key)

    return {
        "techniques": deduped,
        "tactics": sorted(tactics),
        "sources": sources,
        "files_processed": files_processed,
        "framework_counts": dict(framework_counts),
    }


def load_network_training_data() -> pd.DataFrame:
    path = DATASETS_DIR / "UNSW" / "raw" / "training_set.csv"
    if not path.exists():
        raise FileNotFoundError(f"Training dataset not found: {path}")
    return pd.read_csv(path)


def _normalize_label(value: Any) -> str:
    if pd.isna(value):
        return "normal"
    text = str(value).strip().lower()
    if text in {"0", "normal", "benign", "no attack"}:
        return "normal"
    return "attack"


class BehavioralAnomalyEngine:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model: Optional[Pipeline] = None
        self.feature_columns: List[str] = []

    def _build_preprocessor(self, frame: pd.DataFrame) -> ColumnTransformer:
        feature_columns = [col for col in frame.columns if col not in {"id", "label", "attack_cat"}]
        self.feature_columns = feature_columns

        numeric_cols = [col for col in feature_columns if pd.api.types.is_numeric_dtype(frame[col])]
        categorical_cols = [col for col in feature_columns if col not in numeric_cols]

        numeric_transformer = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )
        categorical_transformer = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("encoder", OneHotEncoder(handle_unknown="ignore")),
            ]
        )

        transformers = []
        if numeric_cols:
            transformers.append(("num", numeric_transformer, numeric_cols))
        if categorical_cols:
            transformers.append(("cat", categorical_transformer, categorical_cols))
        return ColumnTransformer(transformers=transformers, remainder="drop")

    def fit(self, frame: pd.DataFrame) -> Dict[str, Any]:
        if frame.empty:
            raise ValueError("Cannot fit anomaly detector with an empty dataset")

        frame = frame.copy()
        if "label" in frame.columns:
            normal_rows = frame[frame["label"].apply(_normalize_label) == "normal"]
        else:
            normal_rows = frame

        if normal_rows.empty:
            raise ValueError("No normal rows were found to train the anomaly detector")

        preprocessor = self._build_preprocessor(normal_rows)
        model = Pipeline(
            steps=[
                ("preprocess", preprocessor),
                ("isolation_forest", IsolationForest(contamination=self.contamination, random_state=RANDOM_STATE)),
            ]
        )
        model.fit(normal_rows[self.feature_columns])
        self.model = model
        return {"feature_columns": self.feature_columns, "trained_on_normal_rows": int(len(normal_rows))}

    def score(self, frame: pd.DataFrame) -> pd.DataFrame:
        if self.model is None:
            raise ValueError("The anomaly detector has not been trained yet")

        frame = frame.copy()
        if frame.empty:
            return pd.DataFrame(columns=["anomaly_score", "is_anomaly", "risk_level"])

        feature_frame = frame.copy()
        if self.feature_columns:
            missing_columns = [col for col in self.feature_columns if col not in feature_frame.columns]
            for col in missing_columns:
                feature_frame[col] = 0
            feature_frame = feature_frame[self.feature_columns]
        transformed = self.model.named_steps["preprocess"].transform(feature_frame)
        predictions = self.model.named_steps["isolation_forest"].predict(transformed)
        scores = -self.model.named_steps["isolation_forest"].decision_function(transformed)

        result = pd.DataFrame(
            {
                "anomaly_score": scores,
                "is_anomaly": predictions == -1,
                "risk_level": pd.Series(scores).apply(self._risk_level),
            },
            index=frame.index,
        )
        return result

    def _risk_level(self, score: float) -> str:
        if score >= 0.6:
            return "high"
        if score >= 0.3:
            return "medium"
        return "low"


def train_behavioural_anomaly_model(contamination: float = 0.05) -> Dict[str, Any]:
    frame = load_network_training_data()
    engine = BehavioralAnomalyEngine(contamination=contamination)
    summary = engine.fit(frame)
    model_path = MODEL_DIR / "behavioural_anomaly_model.joblib"
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(engine, model_path)
    summary["model_path"] = str(model_path)
    return summary


def load_behavioural_anomaly_model() -> BehavioralAnomalyEngine:
    import joblib

    model_path = MODEL_DIR / "behavioural_anomaly_model.joblib"
    if not model_path.exists():
        train_behavioural_anomaly_model()
    return joblib.load(model_path)


def score_behavioural_anomalies(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not records:
        return []

    frame = pd.DataFrame(records)
    engine = load_behavioural_anomaly_model()
    scores = engine.score(frame)
    return [
        {
            "anomaly_score": round(float(score), 4),
            "is_anomaly": bool(flag),
            "risk_level": level,
        }
        for score, flag, level in zip(scores["anomaly_score"], scores["is_anomaly"], scores["risk_level"])
    ]


def map_observed_techniques(observed_signals: List[str], top_k: int = 5) -> List[Dict[str, Any]]:
    index = build_threat_intelligence_index()
    techniques = index.get("techniques", [])
    if not techniques:
        return []

    normalized_signals = [re.sub(r"\s+", " ", signal).strip().lower() for signal in observed_signals if signal]
    if not normalized_signals:
        normalized_signals = ["credential access", "lateral movement", "ransomware"]

    ranked: List[Dict[str, Any]] = []
    for technique in techniques:
        search_text = f"{technique.get('name', '')} {technique.get('description', '')} {technique.get('tactic', '')}".lower()
        confidence = 0.0
        for signal in normalized_signals:
            if signal in search_text:
                confidence += 1.0
            else:
                signal_tokens = set(signal.split())
                search_tokens = set(search_text.split())
                confidence += len(signal_tokens & search_tokens) / max(1, len(signal_tokens)) * 0.25
        if confidence > 0:
            ranked.append({
                "id": technique.get("id"),
                "name": technique.get("name"),
                "tactic": technique.get("tactic"),
                "confidence": round(min(confidence, 1.0), 3),
            })

    ranked.sort(key=lambda item: item["confidence"], reverse=True)
    return ranked[:top_k]


def suggest_defensive_actions(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    names = [tech.get("name", "").lower() for tech in techniques]
    joined = " ".join(names)

    if any(token in joined for token in ["credential", "password", "token", "hash"]):
        actions.append({"action": "Revoke privileged credentials and rotate tokens immediately", "priority": "high"})
    if any(token in joined for token in ["lateral", "movement", "remote", "service"]):
        actions.append({"action": "Isolate affected hosts and segment the compromised network path", "priority": "high"})
    if any(token in joined for token in ["command", "control", "c2"]):
        actions.append({"action": "Block egress to known command-and-control infrastructure", "priority": "high"})
    if any(token in joined for token in ["ransom", "encrypt", "extortion"]):
        actions.append({"action": "Snapshot virtual machines and disable backup write access", "priority": "high"})
    if not actions:
        actions.append({"action": "Enable enhanced monitoring and collect volatile evidence from impacted assets", "priority": "medium"})

    return actions


def summarize_unsw_network_dataset() -> Dict[str, Any]:
    path = DATASETS_DIR / "UNSW" / "raw" / "training_set.csv"
    if not path.exists():
        return {"available": False, "row_count": 0}

    frame = pd.read_csv(path)
    label_counts = frame["label"].value_counts(dropna=False).to_dict() if "label" in frame.columns else {}
    attack_cat_counts = frame["attack_cat"].value_counts(dropna=False).to_dict() if "attack_cat" in frame.columns else {}
    protocol_counts = frame["proto"].value_counts(dropna=False).to_dict() if "proto" in frame.columns else {}
    service_counts = frame["service"].value_counts(dropna=False).to_dict() if "service" in frame.columns else {}
    numeric_cols = [col for col in frame.columns if pd.api.types.is_numeric_dtype(frame[col]) and col not in {"id", "label"}]

    numeric_summaries = {}
    for col in numeric_cols[:10]:
        numeric_summaries[col] = {
            "mean": round(float(frame[col].mean()), 4),
            "std": round(float(frame[col].std()), 4),
            "min": round(float(frame[col].min()), 4),
            "max": round(float(frame[col].max()), 4),
        }

    return {
        "available": True,
        "row_count": int(len(frame)),
        "column_count": int(len(frame.columns)),
        "label_distribution": label_counts,
        "attack_category_distribution": attack_cat_counts,
        "top_protocols": {k: int(v) for k, v in list(protocol_counts.items())[:10]},
        "top_services": {k: int(v) for k, v in list(service_counts.items())[:10]},
        "numeric_feature_summaries": numeric_summaries,
    }


def summarize_vulnerability_dataset() -> Dict[str, Any]:
    path = DATASETS_DIR / "vulnerability" / "known_exploited_vulnerabilities.csv"
    if not path.exists():
        return {"available": False, "row_count": 0}

    frame = pd.read_csv(path)
    name_col = next((col for col in ["cveID", "cve", "cve_id", "id", "name", "vulnerability_id"] if col in frame.columns), None)
    description_col = next((col for col in ["shortDescription", "description", "summary", "details", "vulnerabilityName"] if col in frame.columns), None)
    exploit_col = next((col for col in ["knownRansomwareCampaignUse", "known_exploited", "is_exploited", "exploited", "exploit_available"] if col in frame.columns), None)
    severity_col = None
    severity_counts = {}
    exploit_counts = {}

    if exploit_col:
        exploit_counts = frame[exploit_col].value_counts(dropna=False).to_dict()

    top_entries = []
    for _, row in frame.head(10).iterrows():
        top_entries.append({
            "cve": row[name_col] if name_col else "unknown",
            "description": row[description_col] if description_col else "",
            "exploit": row[exploit_col] if exploit_col else None,
        })

    return {
        "available": True,
        "row_count": int(len(frame)),
        "severity_distribution": {str(k): int(v) for k, v in severity_counts.items()},
        "exploit_distribution": {str(k): int(v) for k, v in exploit_counts.items()},
        "sample_entries": top_entries,
    }


def prioritize_vulnerabilities(asset_count: int = 4, threat_level: str = "medium") -> List[Dict[str, Any]]:
    path = DATASETS_DIR / "vulnerability" / "known_exploited_vulnerabilities.csv"
    if not path.exists():
        return []

    frame = pd.read_csv(path)
    if frame.empty:
        return []

    name_col = next((col for col in ["cveID", "cve", "cve_id", "id", "name", "vulnerability_id"] if col in frame.columns), None)
    description_col = next((col for col in ["shortDescription", "description", "summary", "details", "vulnerabilityName"] if col in frame.columns), None)
    exploit_col = next((col for col in ["knownRansomwareCampaignUse", "known_exploited", "is_exploited", "exploited", "exploit_available"] if col in frame.columns), None)

    def severity_score(value: Any) -> float:
        if pd.isna(value):
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().lower()
        if text in {"critical", "high", "medium", "low"}:
            return {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}[text]
        return 5.0

    def exploit_bonus(value: Any) -> float:
        if pd.isna(value):
            return 0.0
        text = str(value).strip().lower()
        if text in {"known", "true", "1", "yes", "y", "unknown"}:
            return 3.0
        return 0.0

    ranked = []
    for _, row in frame.iterrows():
        severity = 5.0
        exploit_value = row[exploit_col] if exploit_col and exploit_col in frame.columns else None
        exploit_bonus_value = exploit_bonus(exploit_value)
        threat_multiplier = 1.2 if threat_level.lower() == "high" else 1.0
        asset_penalty = 0.15 * max(asset_count, 1)
        score = severity + exploit_bonus_value + asset_penalty
        ranked.append({
            "cve": row[name_col] if name_col else "unknown",
            "description": row[description_col] if description_col else "",
            "severity": severity,
            "score": round(score * threat_multiplier, 2),
            "priority": "critical" if score >= 10 else "high" if score >= 7 else "medium" if score >= 4 else "low",
        })

    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[:10]


def simulate_attack_paths(asset_count: int = 4, threat_level: str = "medium") -> List[Dict[str, Any]]:
    paths = []
    for index in range(min(max(asset_count, 1), 3)):
        risk = "high" if threat_level.lower() == "high" else "medium"
        paths.append({
            "id": index + 1,
            "source": "internet_edge" if index == 0 else "dmz_segment",
            "target": f"critical_asset_{index + 1}",
            "steps": ["Initial access", "Credential abuse", "Lateral movement", "Data staging"],
            "risk": risk,
        })
    return paths


def orchestrate_incident_response(signals: List[str], blast_radius: str = "medium") -> Dict[str, Any]:
    techniques = map_observed_techniques(signals)
    actions = suggest_defensive_actions(techniques)
    approval_required = blast_radius.lower() in {"high", "critical"}
    return {
        "status": "contained" if not approval_required else "human_approval_required",
        "approved_actions": actions,
        "approval_required": approval_required,
        "techniques": techniques,
    }


def build_unified_assessment(records: List[Dict[str, Any]], signals: List[str], asset_count: int = 4, threat_level: str = "medium") -> Dict[str, Any]:
    """Combine anomaly scoring, ATT&CK mapping, topology context, OT/ICS context, UNSW statistics, and vulnerability prioritization into one assessment."""
    anomaly_results = score_behavioural_anomalies(records) if records else []
    techniques = map_observed_techniques(signals) if signals else []
    topology = analyze_topology_context()
    ot_ics = analyze_ot_ics_context()
    unsw = summarize_unsw_network_dataset()
    vulnerability_summary = summarize_vulnerability_dataset()
    vulnerabilities = prioritize_vulnerabilities(asset_count=asset_count, threat_level=threat_level)
    response = orchestrate_incident_response(signals or ["credential access", "lateral movement"], blast_radius="medium")
    threat_index = build_threat_intelligence_index()
    data_fabric = summarize_data_fabric()

    return {
        "anomaly_summary": {
            "total_records": len(records),
            "anomalies_detected": sum(1 for item in anomaly_results if item.get("is_anomaly")),
            "results": anomaly_results,
        },
        "threat_mapping": {
            "signals": signals,
            "techniques": techniques,
            "recommended_actions": response.get("approved_actions", []),
        },
        "context": {
            "topology": topology,
            "ot_ics": ot_ics,
            "dataset_inventory": discover_dataset_files(),
            "data_fabric": data_fabric,
            "threat_intelligence": {
                "files_processed": threat_index.get("files_processed"),
                "technique_count": len(threat_index.get("techniques", [])),
                "tactics": threat_index.get("tactics", []),
                "framework_counts": threat_index.get("framework_counts", {}),
            },
            "unsw": unsw,
        },
        "vulnerabilities": {
            "asset_count": asset_count,
            "threat_level": threat_level,
            "ranked": vulnerabilities,
            "summary": vulnerability_summary,
        },
        "incident_response": response,
    }
