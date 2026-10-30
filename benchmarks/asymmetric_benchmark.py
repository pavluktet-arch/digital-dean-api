import csv
import json
import platform
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from app.schemas.asymmetric_report import validate_complete_report
from app.security.asymmetric.adapters import (
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    KEY_PROFILES,
    PROFILES,
)

RESULTS_DIR = Path("results/practice-03")
CSV_PATH = RESULTS_DIR / "raw.csv"
JSON_PATH = RESULTS_DIR / "report.json"


def get_git_commit() -> str:
    try:
        commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        if len(commit) == 40:
            return commit
    except Exception:
        pass
    return "0" * 40


def run_key_generation_benchmarks():
    raw_rows = []
    aggregated = []

    for key_profile in KEY_PROFILES:
        _ = generate_keypair(key_profile)

        times_ns = []
        for _ in range(5):
            t0 = time.perf_counter_ns()
            priv, pub = generate_keypair(key_profile)
            t1 = time.perf_counter_ns()
            elapsed = t1 - t0
            times_ns.append(elapsed)

            raw_rows.append({
                "group": "key_generation",
                "profile": key_profile,
                "operation": "keygen",
                "payload_bytes": 0,
                "series_index": len(times_ns),
                "operations": 1,
                "elapsed_ns": elapsed,
                "ns_per_operation": float(elapsed),
                "ciphertext_bytes": 0,
            })

        q1, _, q3 = statistics.quantiles(times_ns, n=4, method="inclusive")
        med = float(statistics.median(times_ns))
        iqr = float(q3 - q1)

        _, pub = generate_keypair(key_profile)
        der_bytes = len(
            pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        aggregated.append({
            "key_profile": key_profile,
            "runs": 5,
            "median_ns": med,
            "iqr_ns": iqr,
            "public_key_der_bytes": der_bytes,
        })

    return raw_rows, aggregated


def run_crypto_operations_benchmarks():
    raw_rows = []
    aggregated_results = []
    checks = []

    keys = {kp: generate_keypair(kp) for kp in KEY_PROFILES}

    tasks = []
    for prof_name, prof in PROFILES.items():
        group = (
            "direct"
            if prof_name.startswith("rsa2048") or prof_name == "rsa3072-oaep"
            else "hybrid"
        )
        for size in prof.sizes:
            tasks.append((group, prof_name, size))

    for group, prof_name, size in tasks:
        prof = PROFILES[prof_name]
        priv, pub = keys[prof.key_profile]
        msg = b"a" * size

        for op in ("encrypt", "decrypt"):
            for _ in range(10):
                ct = encrypt(prof_name, pub, msg, CONTEXT)
                if op == "decrypt":
                    _ = decrypt(prof_name, priv, ct, CONTEXT)

            series_avg_ns = []
            ct_len = 0

            for series_idx in range(1, 6):
                if op == "encrypt":
                    t0 = time.perf_counter_ns()
                    for _ in range(20):
                        ct = encrypt(prof_name, pub, msg, CONTEXT)
                    t1 = time.perf_counter_ns()
                    elapsed = t1 - t0
                    ct_len = len(ct)
                else:
                    envelopes = [
                        encrypt(prof_name, pub, msg, CONTEXT) for _ in range(20)
                    ]
                    ct_len = len(envelopes[0])
                    t0 = time.perf_counter_ns()
                    for env in envelopes:
                        _ = decrypt(prof_name, priv, env, CONTEXT)
                    t1 = time.perf_counter_ns()
                    elapsed = t1 - t0

                avg_ns = elapsed / 20.0
                series_avg_ns.append(avg_ns)

                raw_rows.append({
                    "group": group,
                    "profile": prof_name,
                    "operation": op,
                    "payload_bytes": size,
                    "series_index": series_idx,
                    "operations": 20,
                    "elapsed_ns": elapsed,
                    "ns_per_operation": avg_ns,
                    "ciphertext_bytes": ct_len,
                })

            q1, _, q3 = statistics.quantiles(series_avg_ns, n=4, method="inclusive")
            med_ns = float(statistics.median(series_avg_ns))
            iqr_ns = float(q3 - q1)

            if group == "hybrid":
                throughput = (size * 1e9) / ((2**20) * med_ns)
            else:
                throughput = None

            aggregated_results.append({
                "profile": prof_name,
                "group": group,
                "operation": op,
                "payload_bytes": size,
                "series": 5,
                "operations_per_series": 20,
                "median_ns": med_ns,
                "iqr_ns": iqr_ns,
                "ciphertext_bytes": ct_len,
                "throughput_mib_s": throughput,
            })

    for prof_name, prof in PROFILES.items():
        priv, pub = keys[prof.key_profile]
        wrong_priv, _ = generate_keypair(prof.key_profile)

        try:
            m = (
                b"synthetic-data"
                if "rsa" in prof_name and "aes" not in prof_name
                else b"a" * prof.sizes[0]
            )
            ct = encrypt(prof_name, pub, m, CONTEXT)
            passed_rt = decrypt(prof_name, priv, ct, CONTEXT) == m
        except Exception:
            passed_rt = False
        checks.append({
            "profile": prof_name,
            "name": "roundtrip",
            "passed": passed_rt,
        })

        try:
            ct = encrypt(prof_name, pub, b"test-wrong-key", CONTEXT)
            decrypt(prof_name, wrong_priv, ct, CONTEXT)
            passed_wk = False
        except Exception:
            passed_wk = True
        checks.append({
            "profile": prof_name,
            "name": "wrong_key",
            "passed": passed_wk,
        })

        try:
            ct = bytearray(encrypt(prof_name, pub, b"test-tamper", CONTEXT))
            ct[-1] ^= 1
            decrypt(prof_name, priv, bytes(ct), CONTEXT)
            passed_tamper = False
        except Exception:
            passed_tamper = True
        checks.append({
            "profile": prof_name,
            "name": "tamper",
            "passed": passed_tamper,
        })

        try:
            ct = encrypt(prof_name, pub, b"test-ctx", CONTEXT)
            decrypt(prof_name, priv, ct, b"wrong-context")
            passed_ctx = False
        except Exception:
            passed_ctx = True
        checks.append({
            "profile": prof_name,
            "name": "wrong_context",
            "passed": passed_ctx,
        })

    for bits, p_name in [(2048, "rsa2048-oaep"), (3072, "rsa3072-oaep")]:
        priv, pub = keys[f"rsa-{bits}"]
        limit = bits // 8 - 2 * 32 - 2
        try:
            m_ok = b"x" * limit
            ct_ok = encrypt(p_name, pub, m_ok, CONTEXT)
            ok_passed = decrypt(p_name, priv, ct_ok, CONTEXT) == m_ok

            m_fail = b"x" * (limit + 1)
            try:
                encrypt(p_name, pub, m_fail, CONTEXT)
                fail_passed = False
            except ValueError:
                fail_passed = True

            passed_b = ok_passed and fail_passed
        except Exception:
            passed_b = False

        checks.append({
            "profile": p_name,
            "name": "oaep_boundary",
            "passed": passed_b,
        })

    return raw_rows, aggregated_results, checks


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Running key generation benchmarks...")
    raw_keygen, agg_keygen = run_key_generation_benchmarks()

    print("Running crypto operations benchmarks...")
    raw_ops, agg_ops, checks = run_crypto_operations_benchmarks()

    all_raw = raw_keygen + raw_ops

    fieldnames = [
        "group",
        "profile",
        "operation",
        "payload_bytes",
        "series_index",
        "operations",
        "elapsed_ns",
        "ns_per_operation",
        "ciphertext_bytes",
    ]
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_raw)

    report_data = {
        "schema_version": 1,
        "experiment": {
            "series": 5,
            "operations_per_series": 20,
            "warmup": 10,
            "keygen_runs": 5,
            "direct_payload_bytes": 64,
            "hybrid_sizes_bytes": [1024, 65536, 1048576],
            "source_commit": get_git_commit(),
            "created_at_utc": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        },
        "environment": {
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "openssl": default_backend().openssl_version_text(),
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor() or platform.machine(),
        },
        "key_generation": agg_keygen,
        "results": agg_ops,
        "checks": checks,
    }

    validate_complete_report(report_data)

    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("Benchmark finished successfully!")
    print(f"Raw data saved to: {CSV_PATH}")
    print(f"Report saved to: {JSON_PATH}")


if __name__ == "__main__":
    main()