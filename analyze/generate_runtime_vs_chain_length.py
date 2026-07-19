#!/usr/bin/env python3
"""Generate figures/runtime_vs_chain_length.pdf."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

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
DATA_DIR = BASE_DIR / "data"
OUT_DIR = BASE_DIR / "figures"

CHAIN_COLORS = {
    "DynOP": "#009E73",
    "Arcanist": "#CC79A7",
}
CHAIN_LINESTYLES = {"DynOP": "-", "Arcanist": "--"}
MARKERS = {"DynOP": "o", "Arcanist": "s"}


def plot_chain_length(out_path: Path) -> None:
    df = pd.read_csv(DATA_DIR / "runtime_by_chain_length_summary.csv")

    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    legend_handles = []

    for tool in ("DynOP", "Arcanist"):
        part = df[df["tool"] == tool].copy()
        color = CHAIN_COLORS[tool]
        line, = ax.plot(
            part["chain_length"], part["median_runtime_s"],
            marker=MARKERS[tool], color=color, linestyle=CHAIN_LINESTYLES[tool],
            linewidth=1.7, markersize=4.5, label=tool,
        )
        legend_handles.append(line)
        ax.fill_between(
            part["chain_length"], part["median_runtime_s"], part["p90_runtime_s"],
            color=color, alpha=0.16, label="_nolegend_",
        )

    ax.set_yscale("log")
    ax.set_xlabel("Realized Chain Length (number of gadgets)")
    ax.set_ylabel("Runtime (s)")
    ax.set_xlim(2.5, 17)
    ax.grid(alpha=0.25, linestyle="--", linewidth=0.5)
    ax.legend(
        handles=legend_handles,
        labels=["DynOP", "Arcanist"],
        frameon=False,
        loc="upper right",
        handlelength=1.8,
        handletextpad=0.45,
        labelspacing=0.15,
        borderaxespad=0.35,
        fontsize=7,
    )
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved {out_path}")


if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    plot_chain_length(OUT_DIR / "runtime_vs_chain_length.pdf")
