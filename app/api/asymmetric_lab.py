import json
import sys
from pathlib import Path
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["asymmetric-lab"])

REPORT_PATH = Path("results/practice-03/report.json")
MAX_REPORT_BYTES = 10 * 1024 * 1024

def _dict_raise_on_duplicates(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            raise ValueError(f"Duplicate key: {k}")
        d[k] = v
    return d

def load_report() -> Dict[str, Any]:
    mod = sys.modules.get("app.api.asymmetric_lab", sys.modules[__name__])
    target_path = Path(getattr(mod, "REPORT_PATH", REPORT_PATH))
    max_bytes = getattr(mod, "MAX_REPORT_BYTES", MAX_REPORT_BYTES)

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="benchmark report not found"
        )

    try:
        content = target_path.read_bytes()
        if len(content) > max_bytes:
            raise ValueError("Report size exceeds limit")

        raw_text = content.decode("utf-8")
        if "NaN" in raw_text:
            raise ValueError("NaN values not allowed")

        data = json.loads(raw_text, object_pairs_hook=_dict_raise_on_duplicates)

        if not isinstance(data, dict):
            raise ValueError("Report content must be a JSON object")

        if not data or "schema_version" not in data:
            raise ValueError("Invalid or missing report schema")

        return data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="benchmark report invalid"
        )

@router.get("/asymmetric-benchmark-results")
def get_asymmetric_benchmark_results():
    return load_report()