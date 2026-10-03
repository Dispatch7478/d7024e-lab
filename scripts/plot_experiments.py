#!/usr/bin/env python3
"""
plot_experiments.py - Visualizes Kademlia experiment datasets for lab reports.
Parses data/simulation.log directly to calculate empirical statistics (mean and variance across seeds)
and generates publication-quality plots:
1. Lookup Scalability: Probes vs Network Size N (with theoretical bound O(alpha * log2(N)) and hop count)
2. Lookup Reliability: Success Rate (%) and Average Probes vs Packet Loss Rate
"""

import argparse
import csv
import json
import math
import os
import statistics
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def parse_simulation_log(log_path):
    records = []
    current_lookup = None

    if not os.path.exists(log_path):
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        return []

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(entry, dict):
                continue

            event = entry.get("event")
            if event == "lookup_start":
                try:
                    current_lookup = {
                        "experiment": str(entry.get("experiment", "unknown")),
                        "n": int(entry.get("n", 0)),
                        "loss": float(entry.get("loss", 0.0)),
                        "seed": int(entry.get("seed", 0)),
                        "trial": int(entry.get("trial", 0)),
                        "alpha": int(entry.get("alpha", 3)),
                        "target": str(entry.get("target", "")),
                        "probes": 0,
                    }
                except (ValueError, TypeError):
                    current_lookup = None
            elif event == "lookup_probe":
                if current_lookup is not None:
                    current_lookup["probes"] += 1
            elif event in ("lookup_success", "lookup_failure"):
                if current_lookup is not None:
                    current_lookup["success"] = (event == "lookup_success")
                    records.append(current_lookup)
                    current_lookup = None

    return records


def analyze_scalability(records):
    scalability_records = [r for r in records if r["experiment"] == "scalability"]
    if not scalability_records:
        return []

    sizes = sorted(list(set(r["n"] for r in scalability_records)))
    summaries = []

    for n in sizes:
        n_records = [r for r in scalability_records if r["n"] == n]
        seeds = sorted(list(set(r["seed"] for r in n_records)))

        all_probes = [r["probes"] for r in n_records]
        mean_probes = statistics.mean(all_probes) if all_probes else 0.0
        var_probes = statistics.variance(all_probes) if len(all_probes) > 1 else 0.0
        std_probes = statistics.stdev(all_probes) if len(all_probes) > 1 else 0.0

        seed_means = []
        for seed in seeds:
            seed_runs = [r for r in n_records if r["seed"] == seed]
            if seed_runs:
                seed_means.append(statistics.mean(r["probes"] for r in seed_runs))
        seed_var = statistics.variance(seed_means) if len(seed_means) > 1 else 0.0

        all_succ = [100.0 if r["success"] else 0.0 for r in n_records]
        mean_succ = statistics.mean(all_succ) if all_succ else 0.0
        alpha = n_records[0].get("alpha", 3) if n_records else 3

        summaries.append({
            "network_size_n": n,
            "run_count": len(seeds),
            "total_trials": len(n_records),
            "alpha": alpha,
            "mean_avg_probes": round(mean_probes, 2),
            "variance_avg_probes": round(var_probes, 4),
            "stddev_avg_probes": round(std_probes, 2),
            "seed_variance": round(seed_var, 4),
            "mean_success_rate": round(mean_succ, 1),
        })

    return summaries


def analyze_reliability(records):
    reliability_records = [r for r in records if r["experiment"] == "reliability"]
    if not reliability_records:
        return []

    losses = sorted(list(set(r["loss"] for r in reliability_records)))
    summaries = []

    for loss in losses:
        loss_records = [r for r in reliability_records if r["loss"] == loss]
        seeds = sorted(list(set(r["seed"] for r in loss_records)))

        all_probes = [r["probes"] for r in loss_records]
        mean_probes = statistics.mean(all_probes) if all_probes else 0.0
        var_probes = statistics.variance(all_probes) if len(all_probes) > 1 else 0.0
        std_probes = statistics.stdev(all_probes) if len(all_probes) > 1 else 0.0

        seed_success_rates = []
        for seed in seeds:
            seed_runs = [r for r in loss_records if r["seed"] == seed]
            if seed_runs:
                succ_rate = 100.0 * sum(1 for r in seed_runs if r["success"]) / len(seed_runs)
                seed_success_rates.append(succ_rate)

        mean_succ = statistics.mean(seed_success_rates) if seed_success_rates else 0.0
        var_succ = statistics.variance(seed_success_rates) if len(seed_success_rates) > 1 else 0.0
        std_succ = statistics.stdev(seed_success_rates) if len(seed_success_rates) > 1 else 0.0

        summaries.append({
            "packet_loss_rate": loss,
            "run_count": len(seeds),
            "total_trials": len(loss_records),
            "mean_success_rate": round(mean_succ, 1),
            "variance_success_rate": round(var_succ, 4),
            "stddev_success_rate": round(std_succ, 2),
            "mean_avg_probes": round(mean_probes, 2),
            "variance_avg_probes": round(var_probes, 4),
            "stddev_avg_probes": round(std_probes, 2),
        })

    return summaries


def plot_scalability(summaries, out_dir):
    if not summaries:
        print("Skipping scalability plot: no data points found.")
        return

    csv_path = os.path.join(out_dir, "scalability_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "network_size_n", "run_count", "total_trials", "alpha",
            "mean_avg_probes", "variance_avg_probes", "stddev_avg_probes",
            "seed_variance", "mean_success_rate"
        ])
        writer.writeheader()
        writer.writerows(summaries)
    print(f"✓ Scalability summary CSV saved to: {csv_path}")

    print("\nScalability Summary:")
    print(f"{'N':<6} | {'Seeds':<6} | {'Trials':<6} | {'Mean Probes':<12} | {'Variance':<10} | {'StdDev':<8} | {'Seed Var':<10} | {'Success Rate':<12}")
    print("-" * 88)
    for s in summaries:
        print(f"{s['network_size_n']:<6} | {s['run_count']:<6} | {s['total_trials']:<6} | {s['mean_avg_probes']:<12.2f} | {s['variance_avg_probes']:<10.4f} | {s['stddev_avg_probes']:<8.2f} | {s['seed_variance']:<10.4f} | {s['mean_success_rate']:<11.1f}%")
    print("-" * 88)

    sizes = [s["network_size_n"] for s in summaries]
    mean_probes = [s["mean_avg_probes"] for s in summaries]
    std_probes = [s["stddev_avg_probes"] for s in summaries]
    alpha = summaries[0].get("alpha", 3)

    theory_probes = [alpha * math.log2(n) for n in sizes]
    expected_hops = [math.log2(n) for n in sizes]

    plt.figure(figsize=(9, 5.5))
    plt.errorbar(
        sizes,
        mean_probes,
        yerr=std_probes,
        fmt="-o",
        color="#2563eb",
        ecolor="#93c5fd",
        elinewidth=2,
        capsize=5,
        capthick=1.5,
        label=rf"Observed Probes (mean ± stddev, $\alpha={alpha}$)",
    )
    plt.plot(
        sizes,
        theory_probes,
        "--",
        color="#dc2626",
        label=rf"Theoretical Bound ($\alpha \cdot \log_2 N$, $\alpha={alpha}$)",
    )
    plt.plot(
        sizes,
        expected_hops,
        ":",
        color="#7c3aed",
        label=r"Expected Hop Count ($\log_2 N$)",
    )

    plt.title("Kademlia Lookup Scalability: Probes vs. Network Size (N)", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Network Size (N nodes)", fontsize=11)
    plt.ylabel("Number of Probes Dispatched", fontsize=11)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(fontsize=10, loc="upper left")
    plt.tight_layout()

    out_path = os.path.join(out_dir, "scalability_plot.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"✓ Scalability plot saved to: {out_path}")


def plot_reliability(summaries, out_dir):
    if not summaries:
        print("Skipping reliability plot: no data points found.")
        return

    csv_path = os.path.join(out_dir, "reliability_summary.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "packet_loss_rate", "run_count", "total_trials",
            "mean_success_rate", "variance_success_rate", "stddev_success_rate",
            "mean_avg_probes", "variance_avg_probes", "stddev_avg_probes"
        ])
        writer.writeheader()
        writer.writerows(summaries)
    print(f"✓ Reliability summary CSV saved to: {csv_path}")

    print("\nReliability Summary:")
    print(f"{'Loss %':<10} | {'Seeds':<6} | {'Trials':<6} | {'Mean Success %':<16} | {'Variance':<10} | {'StdDev':<8} | {'Mean Probes':<12}")
    print("-" * 84)
    for s in summaries:
        loss_pct = s["packet_loss_rate"] * 100.0
        print(f"{loss_pct:<9.1f}% | {s['run_count']:<6} | {s['total_trials']:<6} | {s['mean_success_rate']:<15.1f}% | {s['variance_success_rate']:<10.4f} | {s['stddev_success_rate']:<8.2f} | {s['mean_avg_probes']:<12.2f}")
    print("-" * 84)

    loss_pcts = [s["packet_loss_rate"] * 100.0 for s in summaries]
    success_rates = [s["mean_success_rate"] for s in summaries]
    std_success = [s["stddev_success_rate"] for s in summaries]
    mean_probes = [s["mean_avg_probes"] for s in summaries]

    fig, ax1 = plt.subplots(figsize=(9, 5.5))

    color_succ = "#16a34a"
    ax1.set_xlabel("Simulated Packet Loss Rate (%)", fontsize=11)
    ax1.set_ylabel("Lookup Success Rate (%)", color=color_succ, fontsize=11)
    ax1.errorbar(
        loss_pcts,
        success_rates,
        yerr=std_success,
        fmt="-s",
        color=color_succ,
        ecolor="#86efac",
        elinewidth=2,
        capsize=5,
        label="Lookup Success Rate (%)",
    )
    ax1.tick_params(axis="y", labelcolor=color_succ)
    ax1.set_ylim(-5, 105)
    ax1.grid(True, linestyle="--", alpha=0.5)

    color_probes = "#d97706"
    ax2 = ax1.twinx()
    ax2.set_ylabel("Average Probes per Lookup", color=color_probes, fontsize=11)
    ax2.plot(loss_pcts, mean_probes, "--^", color=color_probes, label="Avg Probes Dispatched")
    ax2.tick_params(axis="y", labelcolor=color_probes)

    # Combine legends from both axes
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="center left", fontsize=10)

    plt.title("Kademlia Lookup Reliability vs. Packet Loss Rate", fontsize=13, fontweight="bold", pad=12)
    fig.tight_layout()

    out_path = os.path.join(out_dir, "reliability_plot.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"✓ Reliability plot saved to: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Plot Kademlia experiment datasets.")
    parser.add_argument("log_file", nargs="?", default=os.path.join(DEFAULT_DATA_DIR, "simulation.log"),
                        help="Path to simulation.log (default: data/simulation.log)")
    parser.add_argument("--out-dir", default=DEFAULT_DATA_DIR,
                        help="Output directory for plots and CSVs (default: data/)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    records = parse_simulation_log(args.log_file)
    if not records:
        print(f"No lookup records found in {args.log_file}.")
        sys.exit(1)

    print(f"Parsed {len(records)} lookup records from {args.log_file}.")
    scalability_summaries = analyze_scalability(records)
    plot_scalability(scalability_summaries, args.out_dir)

    reliability_summaries = analyze_reliability(records)
    plot_reliability(reliability_summaries, args.out_dir)


if __name__ == "__main__":
    main()
