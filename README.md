# JETT FraudGuard

JETT FraudGuard is a deployment-ready cyber resilience platform for critical infrastructure. It combines behavioural anomaly detection, ATT&CK-based threat mapping, OT/ICS context awareness, topology-aware situational insight, vulnerability prioritisation, and incident-response orchestration on top of the repository datasets.

## What is included

- Behavioural anomaly scoring over network telemetry with an Isolation Forest model
- ATT&CK-style knowledge indexing derived from the bundled ATT&CK JSON datasets
- Topology and OT/ICS context summarisation from the supplied network and industrial datasets
- Vulnerability prioritisation based on the known exploited vulnerability feed
- FastAPI endpoints for health checks, assessment, response orchestration, and model training
- Deployment helpers for local execution and cloud-style hosting

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
- POST /map-techniques
- POST /suggest-actions
- POST /prioritize-vulnerabilities
- POST /incident-response
- POST /unified-assessment

## Example assessment request

```bash
curl -X POST http://localhost:8000/unified-assessment \
  -H "Content-Type: application/json" \
  -d '{"records":[{"dur":0.12,"proto":"tcp","service":"-","state":"FIN","spkts":6,"dpkts":4,"sbytes":258,"dbytes":172}],"signals":["credential access","lateral movement","ransomware"],"asset_count":4,"threat_level":"high"}'
```

## Notes

- The behavioural engine is trained on the UNSW telemetry data supplied in the repository.
- ATT&CK intelligence is built from all available ATT&CK JSON families in the repository.
- The unified assessment endpoint consumes the repository-backed topology, OT/ICS, UNSW, and vulnerability datasets for a richer operational view.
