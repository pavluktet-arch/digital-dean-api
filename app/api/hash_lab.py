import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status
from app.schemas.hash_report import HashResponse, validate_report

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["hash-lab"])

REPORT_PATH = Path("results/practice-04/report.json")
ASYMMETRIC_REPORT_PATH = Path("results/practice-03/report.json")

def load_report() -> Dict[str, Any]:
    mod = sys.modules.get("app.api.hash_lab", sys.modules[__name__])
    target_path = Path(getattr(mod, "REPORT_PATH", REPORT_PATH))

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="hash report not found"
        )
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        validate_report(raw_data)
        return raw_data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="hash report invalid"
        )

@router.get("/asymmetric-benchmark-results-hash-lab")
def get_asymmetric_benchmark_results_hash():
    mod = sys.modules.get("app.api.hash_lab", sys.modules[__name__])
    target_path = Path(getattr(mod, "ASYMMETRIC_REPORT_PATH", ASYMMETRIC_REPORT_PATH))

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="benchmark report not found"
        )
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="benchmark report invalid"
        )

@router.get("/hash-benchmark-results", response_model=HashResponse)
def get_hash_benchmark_results(
    algorithm: Optional[str] = Query(None),
    payload_bytes: Optional[int] = Query(None),
    mode: Optional[str] = Query(None)
):
    raw_data = load_report()

    valid_algos = {"sha256", "sha512", "sha3-256", "blake2b-256", "blake2s-256", "md5", "sha1"}
    if algorithm is not None and algorithm not in valid_algos:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid algorithm")

    valid_sizes = {64, 1024, 65536, 1048576}
    if payload_bytes is not None and payload_bytes not in valid_sizes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid payload_bytes")

    valid_modes = {"whole", "chunked"}
    if mode is not None and mode not in valid_modes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid mode")

    filtered_results = raw_data.get("results", [])
    if algorithm is not None:
        filtered_results = [r for r in filtered_results if r.get("algorithm") == algorithm]
    if payload_bytes is not None:
        filtered_results = [r for r in filtered_results if r.get("payload_bytes") == payload_bytes]
    if mode is not None:
        filtered_results = [r for r in filtered_results if r.get("mode") == mode]

    response_data = dict(raw_data)
    response_data["results"] = filtered_results
    return response_data