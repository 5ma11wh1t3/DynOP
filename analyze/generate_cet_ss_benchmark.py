#!/usr/bin/env python3
"""Generate figures/cet_ss_benchmark.pdf."""
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

COLORS = {
    "DynOP": "#0f6cbd",
    "accent": "#c43e1c",
}


def plot_cet_benchmark(out_path: Path) -> None:
    """COP/JOP-only register setting success on 987 benchmark binaries."""
    num_regs = [1, 2, 3, 4]
    success_counts = [178, 80, 16, 0]
    single_regs = ["rdx", "rdi", "rcx", "rsi"]
    single_counts = [60, 59, 48, 11]
    multi_labels = ["rcx,rdx", "rdi,rdx", "rcx,rdi", "rcx,rdi,rdx"]
    multi_counts = [27, 26, 23, 15]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 2.8), gridspec_kw={"width_ratios": [1, 1.3]})

    bars1 = ax1.bar(num_regs, success_counts, color=COLORS["DynOP"], width=0.55, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars1, success_counts):
        if val > 0:
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 3,
                     str(val), ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax1.set_xlabel("Number of Target Registers")
    ax1.set_ylabel("Successful Binaries")
    ax1.set_xticks(num_regs)
    ax1.set_title("(a) Success by Register Count", fontsize=9, pad=6)
    ax1.set_ylim(0, 210)
    ax1.grid(axis="y", alpha=0.25, linestyle="--", linewidth=0.5)

    all_labels = single_regs + multi_labels
    all_counts = single_counts + multi_counts
    colors_right = [COLORS["DynOP"]] * 4 + [COLORS["accent"]] * 4
    y_pos = np.arange(len(all_labels))
    bars2 = ax2.barh(y_pos, all_counts, color=colors_right, height=0.6, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars2, all_counts):
        ax2.text(bar.get_width() + 0.8, bar.get_y() + bar.get_height() / 2,
                 str(val), ha="left", va="center", fontsize=7.5)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(all_labels, fontsize=7.5)
    ax2.set_xlabel("Successful Binaries")
    ax2.set_title("(b) Breakdown by Register Combination", fontsize=9, pad=6)
    ax2.invert_yaxis()
    ax2.grid(axis="x", alpha=0.25, linestyle="--", linewidth=0.5)

    legend_elements = [
        Patch(facecolor=COLORS["DynOP"], label="Single register"),
        Patch(facecolor=COLORS["accent"], label="Multi-register"),
    ]
    ax2.legend(handles=legend_elements, loc="lower right", fontsize=7, frameon=True,
               fancybox=False, edgecolor="#cccccc")

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved {out_path}")


if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    plot_cet_benchmark(OUT_DIR / "cet_ss_benchmark.pdf")
