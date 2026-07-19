#!/usr/bin/env python3
"""Generate figures/arm_benchmark.pdf."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 9,
    "legend.fontsize": 7.5,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "text.usetex": False,
    "figure.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "figures"

ARM_COLORS = {
    "total": "#D9D9D9",
    "success": "#009E73",
    "time": "#CC79A7",
    "rate": "#D55E00",
}


def plot_arm_benchmark(out_path: Path) -> None:
    """ARM benchmark: success rate and avg time by gadget count range."""
    ranges = ["200-500", "500-1K", "1K-2K", "2K-5K", "5K+"]
    n_total = [345, 290, 144, 92, 129]
    n_success = [140, 264, 135, 91, 127]
    rates = [40.6, 91.0, 93.8, 98.9, 98.4]
    avg_time_succ = [37.5, 37.6, 51.6, 63.9, 81.8]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 3.0))

    x = np.arange(len(ranges))
    width = 0.35

    ax1.bar(x - width / 2, n_total, width, color=ARM_COLORS["total"], edgecolor="white",
            linewidth=0.5, label="Total")
    bars_succ = ax1.bar(x + width / 2, n_success, width, color=ARM_COLORS["success"], edgecolor="white",
                        linewidth=0.5, label="Success")
    for bar, rate in zip(bars_succ, rates):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                 f"{rate:.1f}%", ha="center", va="bottom", fontsize=9, color=ARM_COLORS["rate"],
                 fontweight="bold")
    ax1.set_xlabel("Gadget Count Range", fontsize=11)
    ax1.set_ylabel("Number of Binaries", fontsize=11)
    ax1.set_xticks(x)
    ax1.set_xticklabels(ranges, fontsize=9)
    ax1.tick_params(axis="y", labelsize=9)
    ax1.set_title("(a) Success Rate by Gadget Pool Size", fontsize=11, pad=7)
    ax1.legend(
        handles=[
            Patch(facecolor=ARM_COLORS["total"], edgecolor="none", label="Total"),
            Patch(facecolor=ARM_COLORS["success"], edgecolor="none", label="Success"),
        ],
        frameon=False,
        fontsize=9,
        loc="upper right",
        ncol=2,
        columnspacing=0.7,
        handlelength=1.2,
        handletextpad=0.35,
        borderaxespad=0.25,
    )
    ax1.set_ylim(0, 390)
    ax1.grid(axis="y", alpha=0.25, linestyle="--", linewidth=0.5)

    bars_time = ax2.bar(x, avg_time_succ, width=0.5, color=ARM_COLORS["time"], edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars_time, avg_time_succ):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                 f"{val:.1f}s", ha="center", va="bottom", fontsize=9)
    ax2.set_xlabel("Gadget Count Range", fontsize=11)
    ax2.set_ylabel("Avg. Solve Time (s)", fontsize=11)
    ax2.set_xticks(x)
    ax2.set_xticklabels(ranges, fontsize=9)
    ax2.tick_params(axis="y", labelsize=9)
    ax2.set_title("(b) Avg. Synthesis Time (Successful Cases)", fontsize=11, pad=7)
    ax2.grid(axis="y", alpha=0.25, linestyle="--", linewidth=0.5)
    ax2.set_ylim(0, 100)

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved {out_path}")


if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    plot_arm_benchmark(OUT_DIR / "arm_benchmark.pdf")
