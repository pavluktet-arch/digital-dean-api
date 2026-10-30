"""Маршрут тільки читає звіт; не запускає вимірювання через HTTP."""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-02/report.json"


def load_benchmark_report(path: Path = REPORT_PATH) -> dict:
    """Прочитати й перевірити report.json."""
    if not path.exists():
        raise FileNotFoundError("Benchmark results file not found")
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception as e:
        raise ValueError(f"Failed to parse benchmark report: {e}")


@router.get("/benchmark-results", status_code=status.HTTP_200_OK)
def get_benchmark_results():
    """Повертає повний агрегований звіт результатів бенчмарку."""
    try:
        return load_benchmark_report(REPORT_PATH)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Benchmark results unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Benchmark results unavailable"
        )