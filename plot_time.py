#!/usr/bin/env python3
"""plot_time.py — render the cross-implementation CPU-time comparison figure from *-timing.csv.

Eyeball aid for the complexity tables, not pass/fail. Linear axes on purpose: an
O(N) cost reads as a straight line, O(1) flat, O(N^2) upward. Absolute ms are not
comparable across implementations (wall clock for the Rust protocols, per-thread
CPU time for DCGKA) — read the shapes. Needs matplotlib.

    ./plot_time.py [SERIES_DIR] [OUT_PNG]   # defaults: expected/  expected/cpu-time-comparison.png
"""

import csv
import os
import sys

import matplotlib

matplotlib.use("Agg")  # headless; write a file, never open a window
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

# (file stem, legend label, colour, marker). Order = legend/draw order.
PROTOCOLS = [
    ("dcgka", "DCGKA", "#1b9e77", "o"),
    ("beekem", "BeeKEM", "#d95f02", "s"),
    ("openmls", "OpenMLS", "#7570b3", "^"),
]

# Canonical operation -> (per-protocol name in *-timing.csv, line style, label).
# Only Update and Add are drawn; Remove tracks Update closely. BeeKEM bundles the
# post-membership update into the same op, hence the *_update aliases.
OPERATIONS = [
    ("update", {"dcgka": "update", "beekem": "update", "openmls": "update"}, "-", "Update"),
    ("add", {"dcgka": "add", "beekem": "add_then_update", "openmls": "add"}, ":", "Add"),
]

# One panel per role, operations and protocols overlaid; panels with no data are dropped.
ROLES = [("sender", "Sender"), ("receiver", "Receiver"), ("new_receiver", "New receiver")]


def load(series_dir, stem):
    """series[(operation, role)] -> sorted list of (N, total_ms)."""
    path = os.path.join(series_dir, f"{stem}-timing.csv")
    series = {}
    if not os.path.exists(path):
        return series
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (row["operation"], row["role"])
            series.setdefault(key, []).append(
                (int(row["group_size"]), float(row["total_ms"]))
            )
    for key in series:
        series[key].sort()
    return series


def main():
    series_dir = sys.argv[1] if len(sys.argv) > 1 else "expected"
    out_png = sys.argv[2] if len(sys.argv) > 2 else os.path.join(series_dir, "cpu-time-comparison.png")

    data = {stem: load(series_dir, stem) for stem, _, _, _ in PROTOCOLS}

    # X-axis ticks follow the group sizes present in the data, not a fixed ladder.
    xticks = sorted({n for series in data.values() for pts in series.values() for n, _ in pts})

    # On a linear axis the small sizes bunch up near the origin, so keep a tick at
    # every N but only *label* a thinned subset: the first, then any at least ~6% of
    # the span past the last kept one (an 8..512 sweep labels 8, 64, 128, 256, 512).
    xtick_labels = []
    if xticks:
        span = max(xticks) - min(xticks) or 1
        last_kept = None
        for n in xticks:
            if last_kept is None or (n - last_kept) >= 0.06 * span:
                xtick_labels.append(str(n))
                last_kept = n
            else:
                xtick_labels.append("")

    # One panel per role; operations (line style) and protocols (colour) overlaid.
    ncols = len(ROLES)
    fig, axes = plt.subplots(1, ncols, figsize=(4.2 * ncols, 5.4), squeeze=False)

    for c, (role, role_title) in enumerate(ROLES):
        ax = axes[0][c]
        plotted_any = False
        for _canon_op, op_alias, ls, _oplabel in OPERATIONS:
            for stem, _label, colour, marker in PROTOCOLS:
                pts = data[stem].get((op_alias[stem], role))
                if not pts:
                    continue
                xs = [n for n, _ in pts]
                ys = [ms for _, ms in pts]
                ax.plot(xs, ys, marker=marker, ms=4, lw=1.6, color=colour, linestyle=ls)
                plotted_any = True
        if xticks:
            ax.set_xticks(xticks)
            ax.set_xticklabels(xtick_labels)
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
        ax.grid(True, ls=":", lw=0.5, alpha=0.6)
        if not plotted_any:
            fig.delaxes(ax)
            continue
        ax.set_title(role_title, fontsize=11)
        ax.set_xlabel("group size N")
        ax.set_ylabel("median time (ms)")

    # Two legend dimensions: colour+marker = protocol, line style = operation.
    proto_handles = [Line2D([0], [0], color=col, marker=mk, lw=1.6) for _, _, col, mk in PROTOCOLS]
    proto_labels = [lab for _, lab, _, _ in PROTOCOLS]
    op_handles = [Line2D([0], [0], color="0.3", linestyle=ls, lw=1.6) for _, _, ls, _ in OPERATIONS]
    op_labels = [lab for _, _, _, lab in OPERATIONS]

    fig.suptitle(
        "CPU time per operation — DCGKA vs BeeKEM vs OpenMLS (median ms, linear axes; eyeball aid for the tables)\n"
        "colour = protocol, line style = operation; wall clock for the Rust protocols, per-thread CPU time for DCGKA",
        fontsize=10,
    )
    fig.legend(proto_handles + op_handles, proto_labels + op_labels,
               loc="lower center", ncol=len(proto_labels) + len(op_labels),
               frameon=False, fontsize=9)
    fig.tight_layout(rect=(0, 0.06, 1, 0.93))
    fig.savefig(out_png, dpi=130)
    print(f"wrote {out_png}")


if __name__ == "__main__":
    main()
