import json
import sys
from pathlib import Path
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])

REPORT_PATH = Path("results/practice-03/report.json")

def load_report() -> Dict[str, Any]:
    mod = sys.modules.get("app.api.crypto_lab", sys.modules[__name__])
    target_path = Path(getattr(mod, "REPORT_PATH", REPORT_PATH))

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Benchmark results unavailable"
        )

    try:
        content = target_path.read_bytes()
        raw_text = content.decode("utf-8")
        if "NaN" in raw_text:
            raise ValueError("NaN values not allowed")

        data = json.loads(raw_text)
        if not isinstance(data, dict):
            raise ValueError("Report content must be a JSON object")

        return data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Benchmark results unavailable"
        )

@router.get("/benchmark-results")
def get_benchmark_results():
    return load_report()