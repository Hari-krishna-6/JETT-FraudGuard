from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = ROOT / "datasets"
RAW_DIR = DATASETS_DIR / "raw"
PROCESSED_DIR = DATASETS_DIR / "processed"
MODEL_DIR = ROOT / "saved_model"
STATE_DIR = ROOT / "state"
AUDIT_LOG_PATH = STATE_DIR / "audit_events.jsonl"
RANDOM_STATE = 42
TEST_SIZE = 0.2
