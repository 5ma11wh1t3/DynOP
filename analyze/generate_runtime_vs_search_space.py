#!/usr/bin/env python3
"""Generate figures/runtime_vs_search_space.pdf."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
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

COLORS = {
    "DynOP": "#0f6cbd",
    "Arcanist": "#c43e1c",
    "ropbot": "#0a8a63",
    "SGC": "#8a4fff",
    "Cracker": "#b07a00",
}


def spearman_corr(x: pd.Series, y: pd.Series) -> float:
    return float(x.rank(method="average").corr(y.rank(method="average")))


def plot_search_space(out_path: Path) -> None:
    merged = pd.read_csv(DATA_DIR / "benchmark_task2_merged.csv")

    tools_order = ["DynOP", "Arcanist", "ropbot", "SGC", "Cracker"]
    fig, axes = plt.subplots(1, 5, figsize=(10, 2.3), sharey=True)

    for idx, tool in enumerate(tools_order):
        ax = axes[idx]
        frame = merged[merged["tool"] == tool].dropna(subset=["runtime_s", "search_space"]).copy()
        frame = frame[(frame["runtime_s"] > 0) & (frame["search_space"] > 0)]
        x = frame["search_space"].to_numpy(dtype=float)
        y = frame["runtime_s"].to_numpy(dtype=float)

        ax.scatter(x, y, s=8, alpha=0.4, color=COLORS[tool], edgecolors="none", rasterized=True)

        if len(frame) >= 2:
            coeff = np.polyfit(np.log10(x), np.log10(y), 1)
            xfit = np.geomspace(x.min(), x.max(), 200)
            yfit = 10 ** coeff[1] * xfit ** coeff[0]
            rho = spearman_corr(frame["search_space"], frame["runtime_s"])
            ax.plot(xfit, yfit, color="black", linewidth=1.0, alpha=0.7)
            ax.set_title(f"{tool}\n$\\rho$={rho:.2f}, slope={coeff[0]:.2f}", fontsize=7.5)
        else:
            ax.set_title(f"{tool}", fontsize=7.5)

        ax.set_xscale("log")
        ax.set_yscale("log")
        if idx == 0:
            ax.set_ylabel("Runtime (s)")
        if idx == 2:
            ax.set_xlabel("Initial Search Space (number of gadgets)")
        ax.grid(alpha=0.2, linestyle="--", linewidth=0.4)
        ax.tick_params(axis="both", which="major", labelsize=7)

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    print(f"  Saved {out_path}")


if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    plot_search_space(OUT_DIR / "runtime_vs_search_space.pdf")
