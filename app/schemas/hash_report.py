import re
from datetime import datetime
from typing import List, Literal, Optional, Any, Dict
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator, field_validator

from app.security.hashing.profiles import AlgorithmID, Mode, PROFILES

COMMIT_REGEX = re.compile(r"^[0-9a-f]{40}$")

class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        allow_inf_nan=False
    )

class Parameters(StrictModel):
    sizes: List[StrictInt]
    chunk_bytes: StrictInt
    warmup: StrictInt
    series: StrictInt
    repeats_small: StrictInt
    repeats_large: StrictInt
    avalanche_trials: StrictInt
    avalanche_bytes: StrictInt

    @field_validator("sizes")
    @classmethod
    def validate_sizes(cls, v: List[int]) -> List[int]:
        if len(v) != len(set(v)):
            raise ValueError("Sizes must be unique")
        return v

    @field_validator("series", mode="before")
    @classmethod
    def validate_series_type(cls, v: Any) -> Any:
        if isinstance(v, float):
            raise ValueError("series must be integer")
        return v

class Environment(StrictModel):
    python: StrictStr
    openssl_ssl: StrictStr
    os: StrictStr
    cpu: StrictStr
    architecture: StrictStr

class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: StrictBool
    reason: Optional[Literal["not_available_in_environment"]] = None
    implementation: Optional[StrictStr] = None

    @model_validator(mode="after")
    def validate_availability(self) -> "AlgorithmStatus":
        if not self.available and self.reason is None:
            raise ValueError("Unavailable algorithm must specify reason")
        return self

class MeasurementResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: StrictInt
    digest_bytes: StrictInt
    repeats: StrictInt = Field(gt=0)
    median_ns: float = Field(gt=0)
    iqr_ns: float = Field(ge=0)
    throughput_mib_s: float = Field(gt=0)

    @field_validator("payload_bytes")
    @classmethod
    def check_payload(cls, v: int) -> int:
        if v not in (64, 1024, 65536, 1048576):
            raise ValueError("Invalid payload size")
        return v

    @field_validator("digest_bytes")
    @classmethod
    def check_digest(cls, v: int, info: Any) -> int:
        algo = info.data.get("algorithm")
        if algo and algo in PROFILES:
            expected = PROFILES[algo].digest_bytes
            if v != expected:
                raise ValueError(f"Invalid digest_bytes for {algo}")
        return v

    @field_validator("median_ns", "throughput_mib_s", mode="before")
    @classmethod
    def reject_bool_float(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("Value cannot be boolean")
        return v

    @model_validator(mode="after")
    def validate_semantics(self) -> "MeasurementResult":
        # Валідація repeats залежно від payload_bytes
        if self.payload_bytes <= 1024 and self.repeats < 1000:
            raise ValueError("Repeats must be at least 1000 for small payloads")
            
        # Валідація фізичного співвідношення throughput_mib_s та median_ns
        expected_throughput = (self.payload_bytes / (1024 * 1024)) / (self.median_ns / 1e9)
        if abs(self.throughput_mib_s - expected_throughput) > 0.01 * expected_throughput:
            raise ValueError("Inconsistent throughput_mib_s")

        return self

class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: StrictInt
    trials: StrictInt
    digest_bits: StrictInt
    min_flipped_bits: StrictInt
    max_flipped_bits: StrictInt
    mean_flipped_bits: float
    mean_fraction: float

    @field_validator("max_flipped_bits")
    @classmethod
    def check_max_bits(cls, v: int, info: Any) -> int:
        digest_bits = info.data.get("digest_bits")
        if digest_bits and v > digest_bits:
            raise ValueError("max_flipped_bits cannot exceed digest_bits")
        return v

    @field_validator("mean_fraction")
    @classmethod
    def check_fraction(cls, v: float) -> float:
        if v < 0.3 or v > 0.7:
            raise ValueError("mean_fraction out of bounds [0.3, 0.7]")
        return v

class CheckResult(StrictModel):
    algorithm: AlgorithmID
    check_name: StrictStr
    passed: StrictBool

    @model_validator(mode="before")
    @classmethod
    def prepare_check_name(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("check_name") or data.get("name")
            if val is None:
                raise ValueError("Check name is required")
            data["check_name"] = str(val)
            data.pop("name", None)
        return data

class Summary(StrictModel):
    algorithms_count: StrictInt
    available_count: StrictInt
    results_count: StrictInt
    checks_count: StrictInt
    all_checks_passed: StrictBool

class HashReport(StrictModel):
    schema_version: Literal[1]
    created_at: StrictStr
    source_commit: StrictStr
    parameters: Parameters
    environment: Environment
    algorithms: List[AlgorithmStatus]
    results: List[MeasurementResult]
    avalanche: List[AvalancheResult]
    checks: List[CheckResult]
    summary: Optional[Summary] = None

    @field_validator("schema_version", mode="before")
    @classmethod
    def check_schema_version_type(cls, v: Any) -> Any:
        if isinstance(v, (bool, float)):
            raise ValueError("schema_version must be integer 1")
        return v

    @field_validator("source_commit")
    @classmethod
    def validate_commit(cls, v: str) -> str:
        if not COMMIT_REGEX.match(v):
            raise ValueError("Invalid git commit hash")
        return v

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, v: str) -> str:
        if not v.endswith("Z"):
            raise ValueError("created_at must end with Z")
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            raise ValueError("Invalid ISO datetime string")
        return v

class HashResponse(HashReport):
    pass

def validate_report(data: Dict[str, Any]) -> HashReport:
    report = HashReport.model_validate(data)

    res_tuples = [(r.algorithm, r.mode, r.payload_bytes) for r in report.results]
    if len(res_tuples) != len(set(res_tuples)):
        raise ValueError("Duplicate measurement results found")

    ava_tuples = [a.algorithm for a in report.avalanche]
    if len(ava_tuples) != len(set(ava_tuples)):
        raise ValueError("Duplicate avalanche results found")

    chk_tuples = [(c.algorithm, c.check_name) for c in report.checks]
    if len(chk_tuples) != len(set(chk_tuples)):
        raise ValueError("Duplicate check results found")

    algo_tuples = [a.algorithm for a in report.algorithms]
    if len(algo_tuples) != len(set(algo_tuples)):
        raise ValueError("Duplicate algorithm statuses found")

    if len(algo_tuples) != 7 or set(algo_tuples) != set(PROFILES.keys()):
        raise ValueError("Must contain exactly 7 unique algorithm statuses")

    return report