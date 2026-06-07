#!/usr/bin/env python3
"""plot_partition.py — render the BeeKEM partition-pressure figures from expected/.

Independent variable: the average Updates per member while partitioned (a = U/n,
swept 0..2). Updaters are sampled randomly, so this is an eyeball aid, not pass/fail.
Two figures, medianed over the CSVs' random iterations:
  partition_updater_pressure  -- wall-clock + network size vs avg updates/member
  partition_scaling           -- first post-merge Update wall-clock vs group size

Each figure's .pdf goes to the paper's Images dir, a .png copy to SERIES_DIR.
Needs matplotlib + pandas.

    ./plot_partition.py [SERIES_DIR] [IMAGES_DIR]
    # defaults: expected/  Peer_to_Peer_Group_Key_Agreement/Images
"""
import os
import sys

import matplotlib as mpl

mpl.use("Agg")  # headless; write files, never open a window
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

mpl.rcParams.update({"font.size": 10, "axes.grid": True, "grid.alpha": 0.3})

HERE = os.path.dirname(os.path.abspath(__file__))
SERIES_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "expected")
IMAGES = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    HERE, "Peer_to_Peer_Group_Key_Agreement", "Images"
)

frac = pd.read_csv(os.path.join(SERIES_DIR, "beekem-partition-fraction-sweep.csv"))
scaling = pd.read_csv(os.path.join(SERIES_DIR, "beekem-partition-scaling.csv"))

C_FIRST = "#1f77b4"   # first post-merge Update
C_REC = "#d62728"     # cumulative recovery
KEYS = ["group_size", "partitions", "total_updates", "avg_updates_per_member"]


def median(df):
    """Median over the random iterations for each parameter combination."""
    return df.groupby(KEYS, as_index=False).median(numeric_only=True).sort_values(KEYS)


def save(fig, name):
    """Write <name>.pdf into the paper Images dir and <name>.png into SERIES_DIR."""
    pdf = os.path.join(IMAGES, name + ".pdf")
    png = os.path.join(SERIES_DIR, name + ".png")
    fig.savefig(pdf, bbox_inches="tight")
    fig.savefig(png, bbox_inches="tight", dpi=130)
    plt.close(fig)
    print("wrote", pdf)
    print("wrote", png)


# ---------------------------------------------------------------- updater pressure
f = median(frac)
x = f["avg_updates_per_member"]
XLABEL = "Average updates per member while partitioned"

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 3.2))

ax1.plot(x, f["first_ms"], "o-", color=C_FIRST, label="first post-merge Update")
ax1.plot(x, f["recovery_ms"], "s-", color=C_REC, label="recovery until conflict-free")
ax1.set_xlabel(XLABEL)
ax1.set_ylabel("CPU wall-clock time (ms)")
ax1.set_title("(a) Computation")
ax1.legend(fontsize=8, loc="upper left")

ax2.plot(x, f["first_bytes"] / 1024.0, "o-", color=C_FIRST,
         label="first post-merge Update")
ax2.plot(x, f["recovery_bytes"] / 1024.0, "s-", color=C_REC,
         label="recovery until conflict-free")
ax2.set_xlabel(XLABEL)
ax2.set_ylabel("Network message size (KiB)")
ax2.set_title("(b) Communication")
ax2.legend(fontsize=8, loc="upper left")

fig.tight_layout()
save(fig, "partition_updater_pressure")

# ---------------------------------------------------------------- scaling
s = median(scaling)
sizes = sorted(s["group_size"].unique())
avgs = [0.0, 0.5, 1.0, 1.5, 2.0]
cmap = plt.cm.viridis


def first_ms_at(n, avg_target):
    count = round(avg_target * n)
    row = s[(s["group_size"] == n) & (s["total_updates"] == count)]
    return row["first_ms"].iloc[0]


fig, ax = plt.subplots(figsize=(6.4, 3.6))
for i, aval in enumerate(avgs):
    ys = [first_ms_at(n, aval) for n in sizes]
    color = cmap(i / (len(avgs) - 1))
    label = "0 (happy path)" if aval == 0 else f"{aval:g}"
    ax.plot(sizes, ys, "o-", color=color, label=label, markersize=4)

ax.set_xticks(sizes)
ax.set_xlabel("Group size $n$")
ax.set_ylabel("First post-merge Update\nCPU wall-clock time (ms)")
ax.legend(fontsize=8, loc="upper left", ncol=2, title="Avg updates/member")
fig.tight_layout()
save(fig, "partition_scaling")
