import argparse
import csv
import json
import os
import platform
import sys
from statistics import median, quantiles
from time import perf_counter_ns
import cryptography
import Crypto

from app.security.adapters import seal_bytes, open_bytes
from app.security.context import note_aad
from app.security.nonce import NonceSequence
import app.security.profiles as profiles


def get_profile_info():
    if hasattr(profiles, "KEY_BYTES"):
        return profiles.KEY_BYTES
    return {'aes-gcm': 32, 'aes-cbc': 32}


def measure_batch(operation, arguments):
    if not arguments:
        raise ValueError("Empty batch")
    started = perf_counter_ns()
    for item in arguments:
        operation(*item)
    elapsed = perf_counter_ns() - started
    if elapsed <= 0:
        raise RuntimeError("Invalid elapsed time")
    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes):
    if len(series_mean_ns) != 5:
        raise ValueError("Five series required")
    q1, _, q3 = quantiles(
        series_mean_ns, n=4, method="inclusive"
    )
    typical = median(series_mean_ns)
    if typical <= 0:
        raise ValueError("Time must be positive")
    return {
        "median_ns": typical,
        "iqr_ns": q3 - q1,
        "throughput_mib_s": size_bytes * 1e9 / (2**20 * typical),
    }


def run_benchmark(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    raw_csv_path = os.path.join(output_dir, "raw.csv")
    report_json_path = os.path.join(output_dir, "report.json")

    key_bytes_map = get_profile_info()
    backends = ["cryptography", "pycryptodome"]
    algorithms = list(key_bytes_map.keys())
    sizes = [1024, 65536, 1048576]
    operations = ["encrypt", "decrypt"]

    raw_rows = []
    summary_results = []
    run_id = "practice-02-run-1"

    for size in sizes:
        dummy_data = b"X" * size
        sample_algo = algorithms[0]
        aad = note_aad("student-bench", "note-bench", sample_algo, "key-bench")

        for algo in algorithms:
            key_len = key_bytes_map[algo]
            key = b"\x01" * key_len

            for backend in backends:
                for op in operations:
                    series_means = []

                    warmup_seq = NonceSequence(limit=20)
                    warmup_args = []
                    for _ in range(10):
                        n = warmup_seq.next()
                        if op == "encrypt":
                            warmup_args.append((backend, algo, key, n, dummy_data, aad))
                        else:
                            ct, tag = seal_bytes(backend, algo, key, n, dummy_data, aad)
                            warmup_args.append((backend, algo, key, n, ct, tag, aad))

                    func = seal_bytes if op == "encrypt" else open_bytes
                    measure_batch(func, warmup_args)

                    for series_idx in range(1, 6):
                        seq = NonceSequence(limit=200)
                        batch_args = []
                        for _ in range(100):
                            n = seq.next()
                            if op == "encrypt":
                                batch_args.append((backend, algo, key, n, dummy_data, aad))
                            else:
                                ct, tag = seal_bytes(backend, algo, key, n, dummy_data, aad)
                                batch_args.append((backend, algo, key, n, ct, tag, aad))

                        mean_ns = measure_batch(func, batch_args)
                        total_ns = mean_ns * 100
                        series_means.append(mean_ns)

                        raw_rows.append({
                            "run_id": run_id,
                            "backend": backend,
                            "algorithm": algo,
                            "size_bytes": size,
                            "operation": op,
                            "series_index": series_idx,
                            "operations": 100,
                            "total_ns": total_ns,
                            "mean_ns": mean_ns
                        })

                    metrics = summarize(series_means, size)
                    summary_results.append({
                        "backend": backend,
                        "algorithm": algo,
                        "size_bytes": size,
                        "operation": op,
                        "series_mean_ns": series_means,
                        **metrics
                    })

    with open(raw_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "run_id", "backend", "algorithm", "size_bytes", "operation",
            "series_index", "operations", "total_ns", "mean_ns"
        ])
        writer.writeheader()
        writer.writerows(raw_rows)

    report_data = {
        "schema_version": 1,
        "run_id": run_id,
        "environment": {
            "processor": platform.processor() or platform.machine(),
            "os": platform.system(),
            "os_release": platform.release(),
            "python_version": sys.version.split()[0],
            "cryptography_version": cryptography.__version__,
            "pycryptodome_version": Crypto.__version__,
        },
        "parameters": {
            "sizes_bytes": sizes,
            "warmup": 10,
            "series": 5,
            "operations_per_series": 100,
            "aad_length_bytes": len(aad),
            "includes_library_object_creation": True
        },
        "results": summary_results
    }

    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    print(f"Успішно збережено {len(raw_rows)} сирих серій у {raw_csv_path}")
    print(f"Успішно збережено {len(summary_results)} підсумкових рядків у {report_json_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crypto benchmark runner")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    args = parser.parse_args()
    run_benchmark(args.output_dir)