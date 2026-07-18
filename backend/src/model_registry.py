from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .config import MODEL_DIR


def list_saved_models() -> List[Dict[str, str]]:
    models = []
    for path in sorted(MODEL_DIR.glob("*.joblib")):
        models.append({"name": path.name, "path": str(path)})
    return models


def ensure_model_bundle() -> Dict[str, str]:
    saved = list_saved_models()
    return {"models": saved, "count": len(saved)}
