"""Vẽ biểu đồ benchmark từ CSV (C-D11) -> PNG để nhúng vào báo cáo Mục 9.

Đầu vào:
- benchmarks/results/jwt_algo_comparison.csv  (A-D10: wrk 3 thuật toán)
- benchmarks/results/vault_overhead.csv       (B-D10: Vault cache ON/OFF)

Đầu ra:
- docs/images/bench_jwt_throughput.png
- docs/images/bench_jwt_latency.png
- docs/images/bench_vault_overhead.png

Chạy:
    python benchmarks/plot_results.py
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")  # không cần display, ghi thẳng ra file
import matplotlib.pyplot as plt

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS = os.path.join(ROOT, "benchmarks", "results")
IMG = os.path.join(ROOT, "docs", "images")
os.makedirs(IMG, exist_ok=True)

COLORS = ["#4C72B0", "#DD8452", "#55A868"]


def _read_csv(name):
    with open(os.path.join(RESULTS, name), newline="") as f:
        return list(csv.DictReader(f))


def plot_jwt():
    rows = _read_csv("jwt_algo_comparison.csv")
    algos = [r["Algorithm"] for r in rows]
    rps = [float(r["Average (RPS)"]) for r in rows]
    lat = [float(r["Latency Avg (ms)"]) for r in rows]

    # Throughput
    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(algos, rps, color=COLORS)
    ax.set_title("JWT Verification Throughput (wrk: 4t/100c/60s, 3 vòng)")
    ax.set_ylabel("Requests/sec (trung bình)")
    ax.bar_label(bars, fmt="%.1f", padding=3)
    ax.set_ylim(0, max(rps) * 1.15)
    fig.tight_layout()
    fig.savefig(os.path.join(IMG, "bench_jwt_throughput.png"), dpi=130)
    plt.close(fig)

    # Latency
    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(algos, lat, color=COLORS)
    ax.set_title("JWT Verification Latency trung bình")
    ax.set_ylabel("Latency (ms)")
    ax.bar_label(bars, fmt="%.1f ms", padding=3)
    ax.set_ylim(0, max(lat) * 1.2)
    fig.tight_layout()
    fig.savefig(os.path.join(IMG, "bench_jwt_latency.png"), dpi=130)
    plt.close(fig)


def plot_vault():
    rows = _read_csv("vault_overhead.csv")
    scen = [r["Scenario"] for r in rows]
    lat = [float(r["Average_Latency_ms"]) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(scen, lat, color=["#55A868", "#C44E52"])
    ax.set_title("Vault Secret Fetch — Overhead Cache ON vs OFF (1000 reqs)")
    ax.set_ylabel("Latency trung bình (ms/request)")
    ax.bar_label(bars, fmt="%.4f ms", padding=3)
    ax.set_ylim(0, max(lat) * 1.2)
    fig.tight_layout()
    fig.savefig(os.path.join(IMG, "bench_vault_overhead.png"), dpi=130)
    plt.close(fig)


if __name__ == "__main__":
    plot_jwt()
    plot_vault()
    print("[OK] charts saved to docs/images/:")
    for n in ("bench_jwt_throughput.png", "bench_jwt_latency.png", "bench_vault_overhead.png"):
        print("  -", n)
