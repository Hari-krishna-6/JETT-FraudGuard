# JETT FraudGuard

JETT FraudGuard is a demo-ready cyber resilience platform for critical infrastructure. It turns telemetry and weak signals into behavioural risk, MITRE ATT&CK techniques, attack paths, remediation priorities, and an approval-gated containment playbook with a full audit trail.

## What is included

- Behavioural anomaly scoring with an Isolation Forest baseline plus explainable high-risk indicators
- MITRE ATT&CK technique IDs, evidence, and a multi-stage campaign hypothesis
- Attack-path simulation based on asset criticality and internet exposure
- Vulnerability prioritisation using CVSS, KEV/ransomware evidence, asset exposure, and criticality
- Approval-gated SOAR playbooks; every simulation is recorded as a JSONL audit event
- Self-contained synthetic demo baseline and curated threat intelligence when optional source datasets are not mounted

## Repository layout

- [backend/src](backend/src) - production API and core platform logic
- [backend/datasets](backend/datasets) - ATT&CK, Network Topology, OT/ICS, UNSW, and vulnerability datasets
- [backend/saved_model](backend/saved_model) - trained anomaly model artefacts
- [backend/tests](backend/tests) - regression tests for the backend

## Run locally

### Install dependencies

```bash
pip install -r requirements.txt
```

### Start the API

```bash
python backend/run.py
```

The service will be available at:

- http://localhost:8000/docs
- http://localhost:8000/health

## Key endpoints

- GET /health
- GET /dataset-status
- GET /threat-intelligence
- POST /analyze-behavior
- POST /train-anomaly-model
- GET /model-metrics
- POST /map-techniques
- POST /suggest-actions
- POST /prioritize-vulnerabilities
- POST /incident-response
- POST /unified-assessment
- POST /attack-paths
- GET /audit-log

## Example assessment request

```bash
curl -X POST http://localhost:8000/unified-assessment \
  -H "Content-Type: application/json" \
  -d '{"records":[{"asset_id":"exam-db-01","dur":0.12,"proto":"tcp","service":"-","state":"FIN","spkts":6,"dpkts":4,"sbytes":125800,"dbytes":172,"failed_logins":12}],"signals":["credential access","lateral movement","ransomware"],"threat_level":"high","assets":[{"asset_id":"exam-db-01","criticality":10,"internet_exposed":true},{"asset_id":"vpn-01","criticality":7,"internet_exposed":true}]}'
```

## Notes

- Mount UNSW, MITRE ATT&CK, OT/ICS, topology, and KEV datasets under `backend/datasets` to switch the relevant components to repository-data mode.
- `/model-metrics` reports recall, precision, and false-positive rate only when a labelled UNSW testing dataset is mounted; it deliberately does not fabricate benchmark results.
- Response actions are intentionally **simulation-only**. Replace the adapter with a customer-approved SOAR integration before enabling any live isolation, blocking, credential revocation, or VM operations.
