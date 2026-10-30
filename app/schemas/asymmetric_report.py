from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Experiment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    series: int = Field(ge=1)
    operations_per_series: int = Field(ge=1)
    warmup: int = Field(ge=0)
    keygen_runs: int = Field(ge=1)
    direct_payload_bytes: int = Field(ge=1)
    hybrid_sizes_bytes: List[int]
    source_commit: str
    created_at_utc: str


class Environment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    python: str
    cryptography: str
    openssl: str
    os: str
    cpu: str


class KeyGenMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key_profile: str
    runs: int = Field(ge=1)
    median_ns: float = Field(ge=0)
    iqr_ns: float = Field(ge=0)
    public_key_der_bytes: int = Field(ge=1)


KeyGenerationMetric = KeyGenMetric


class OperationMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    profile: str
    group: str
    operation: str
    payload_bytes: int = Field(ge=1)
    series: int = Field(ge=1)
    operations_per_series: int = Field(ge=1)
    median_ns: float = Field(ge=0)
    iqr_ns: float = Field(ge=0)
    ciphertext_bytes: int = Field(ge=1)
    throughput_mib_s: Optional[float] = None


class CheckItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    profile: str
    name: str
    passed: bool


class BenchmarkReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: int = Field(default=1)
    experiment: Experiment
    environment: Environment
    key_generation: List[KeyGenMetric]
    results: List[OperationMetric]
    checks: List[CheckItem]


def validate_complete_report(data: Dict[str, Any]) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)

    if report.schema_version != 1:
        raise ValueError("Invalid schema_version")

    if len(report.key_generation) < 4:
        raise ValueError("key_generation must contain at least 4 profiles")

    if len(report.results) < 22:
        raise ValueError("results must contain at least 22 entries")

    if len(report.checks) < 22:
        raise ValueError("checks must contain at least 22 entries")

    failed_checks = [c for c in report.checks if not c.passed]
    if failed_checks:
        raise ValueError(f"Report contains failed checks: {failed_checks}")

    return report