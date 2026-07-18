from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = ROOT / "datasets"
RAW_DIR = DATASETS_DIR / "raw"
PROCESSED_DIR = DATASETS_DIR / "processed"
MODEL_DIR = ROOT / "saved_model"
RANDOM_STATE = 42
TEST_SIZE = 0.2
