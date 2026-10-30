import json
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, status
from app.schemas.asymmetric_report import BenchmarkReport, validate_complete_report

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-asymmetric-lab"])

REPORT_PATH = Path("results/practice-03/report.json")
MAX_REPORT_BYTES = 1048576  # 1 MB


def load_report(path: Optional[Path] = None) -> dict:
    target_path = path if path is not None else REPORT_PATH

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="benchmark report not found"
        )

    try:
        file_size = target_path.stat().st_size
        if file_size > MAX_REPORT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="benchmark report invalid"
            )

        with open(target_path, "rb") as f:
            content = f.read(MAX_REPORT_BYTES + 1)
            if len(content) > MAX_REPORT_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="benchmark report invalid"
                )

        data = json.loads(content.decode("utf-8"), parse_constant=lambda x: None)
        validate_complete_report(data)
        return data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="benchmark report invalid"
        )


@router.get("/asymmetric-benchmark-results", response_model=BenchmarkReport)
def get_asymmetric_benchmark_results():
    return load_report(REPORT_PATH)