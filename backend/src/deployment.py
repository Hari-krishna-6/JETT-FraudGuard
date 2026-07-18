from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from .api import app
from .config import ROOT


def get_app() -> Any:
    return app


def get_runtime_metadata() -> Dict[str, Any]:
    return {
        "app_name": "JETT FraudGuard",
        "root": str(ROOT),
        "docs_url": "/docs",
        "redoc_url": "/redoc",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.src.deployment:app", host="0.0.0.0", port=8000, reload=False)
