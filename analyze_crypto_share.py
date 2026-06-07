#!/usr/bin/env python3
"""analyze_crypto_share.py — what share of each operation's wall-clock time is
asymmetric (public-key) crypto, symmetric crypto, and everything else?

Evidence behind the asymmetric-only complexity view (analyze_complexity.py): how
little wall clock the dropped symmetric primitives account for. Reads
expected/<proto>-timing.csv; per row asym = pubkey_ms, sym = sym_ms, others =
total - asym - sym (allocation, serialization, bookkeeping, GC/JVM). The share
trends with N, so each operation/role reports its value at the smallest -> largest
N plus an overall min-max range (excluding `system` to avoid double-counting).

Only DCGKA and OpenMLS are split-instrumented; BeeKEM records counts but no
per-primitive wall clock, so it is reported as "not split-instrumented". Eyeball
aid, never pass/fail.

Usage:  ./analyze_crypto_share.py [SERIES_DIR]   (default: expected/)
"""

import csv
import os
import sys

PROTOCOLS = ("dcgka", "beekem", "openmls")


def load(series_dir, proto):
    """[(operation, role, N, total, asym, sym, others)] for split rows; [] if none."""
    path = os.path.join(series_dir, f"{proto}-timing.csv")
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if not r.get("pubkey_ms") or not r.get("sym_ms"):
                continue  # not split-instrumented (e.g. BeeKEM)
            total = float(r["total_ms"])
            asym = float(r["pubkey_ms"])
            sym = float(r["sym_ms"])
            rows.append((r["operation"], r["role"], int(r["group_size"]),
                         total, asym, sym, total - asym - sym))
    return rows


def pct(part, whole):
    return 100.0 * part / whole if whole else 0.0


def main():
    series_dir = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected")

    print(f"Wall-clock crypto share from {os.path.relpath(series_dir)}/  "
          f"(eyeball only, not asserted)\n"
          f"asym = public-key primitives, sym = symmetric, others = non-crypto "
          f"(serialization, tree/graph bookkeeping, GC/JVM).\n"
          f"(pubkey_ms/sym_ms are medianed independently of total_ms, so asym%+sym% "
          f"can edge just past 100% on noisy rows; others% is clamped at 0.)\n")

    print("Shares vary with the group size N (symmetric work is O(N) while the public-key\n"
          "work is O(log N)/O(1)), so each row gives the value at the smallest N -> the\n"
          "largest N rather than a single point.\n")

    hdr = (f"{'operation/role':30} {'N: lo->hi':>10} | "
           f"{'asym% lo->hi':>15} {'sym% lo->hi':>15} {'others% lo->hi':>16}")
    for proto in PROTOCOLS:
        rows = load(series_dir, proto)
        print(f"=== {proto} ===")
        if not rows:
            print("    not split-instrumented (primitive counts only, no per-primitive wall clock)\n")
            continue
        print(hdr); print("-" * len(hdr))

        # Group by (operation, role); the smallest/largest-N endpoints bound the range.
        by_key = {}
        for r in sorted(rows):
            by_key.setdefault((r[0], r[1]), []).append(r)
        sym_shares, asym_shares = [], []
        for (op, role), rs in by_key.items():
            lo, hi = rs[0], rs[-1]  # smallest N, largest N

            def shares(r):
                # Noise can push pubkey+sym just past total; clamp others% at 0.
                total = r[3]
                return pct(r[4], total), pct(r[5], total), pct(max(r[6], 0.0), total)

            a_lo, s_lo, o_lo = shares(lo)
            a_hi, s_hi, o_hi = shares(hi)
            if role != "system":
                for r in rs:
                    sym_shares.append(pct(r[5], r[3]))
                    asym_shares.append(pct(r[4], r[3]))
            print(f"{op + '/' + role:30} {f'{lo[2]}->{hi[2]}':>10} | "
                  f"{f'{a_lo:.1f}->{a_hi:.1f}':>15} {f'{s_lo:.1f}->{s_hi:.1f}':>15} "
                  f"{f'{o_lo:.1f}->{o_hi:.1f}':>16}")

        print("-" * len(hdr))
        if sym_shares:
            print(f"    symmetric share (excl. system) ranges "
                  f"{min(sym_shares):.1f}%-{max(sym_shares):.1f}% over all (op, role, N); "
                  f"asymmetric {min(asym_shares):.1f}%-{max(asym_shares):.1f}%")
        print()


if __name__ == "__main__":
    main()
