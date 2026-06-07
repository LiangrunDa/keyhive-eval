#!/usr/bin/env python3
"""reduce_timing.py — reduce a protocol's timing run to one median table keyed by
(operation, role, group_size): total_ms, pubkey_ms, sym_ms.

Eyeball-only (timings vary run to run), never asserted. total_ms is per-operation
wall clock for the single-threaded Rust harnesses (OpenMLS, BeeKEM) and per-thread
CPU time for DCGKA (multi-threaded, so CPU removes contention). pubkey/sym are
timed inside the crypto wrappers for all three. For DCGKA we keep only rows that
performed the operation (non-zero defining primitive), dropping idle snapshots.

Modes:
  reduce_timing.py {beekem|openmls|dcgka} RAW_CSV   write the merged table to stdout
  reduce_timing.py --compare WANT GOT LABEL         print committed vs this run
"""

import csv
import statistics
import sys

# size column, total-time column, whether pubkey/sym are present, roles to keep.
# DCGKA excludes `system` (a contention-laden multi-thread aggregate, not a clean
# per-operation cost).
CFG = {
    "beekem":  dict(size="group_size", total="wall_clock_ms", split=True,  roles=None),
    "openmls": dict(size="group_size", total="wall_clock_ms", split=True,  roles=None),
    "dcgka":   dict(size="groupsize",  total="total_ms",       split=True,
                    roles={"sender", "receiver", "new_receiver"}),
}


def did_work(proto, role, r):
    if proto != "dcgka":
        return True
    if role == "sender":
        return int(r["hpke_encrypt"]) > 0 or int(r["keygen"]) > 0 or int(r["sign"]) > 0
    return int(r["prf"]) > 0 or int(r["hpke_decrypt"]) > 0


def reduce(proto, path):
    c = CFG[proto]
    samples = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            role = r["role"]
            if c["roles"] and role not in c["roles"]:
                continue
            if not did_work(proto, role, r):
                continue
            try:
                n = int(r[c["size"]])
            except ValueError:
                continue
            rec = (float(r[c["total"]]),
                   float(r["pubkey_ms"]) if c["split"] else None,
                   float(r["sym_ms"]) if c["split"] else None)
            samples.setdefault((r["operation"], role, n), []).append(rec)
    out = []
    for key in sorted(samples):
        v = samples[key]
        tot = statistics.median(x[0] for x in v)
        if c["split"]:
            pk = statistics.median(x[1] for x in v)
            sym = statistics.median(x[2] for x in v)
            out.append((*key, len(v), f"{tot:.4f}", f"{pk:.4f}", f"{sym:.4f}"))
        else:
            out.append((*key, len(v), f"{tot:.4f}", "", ""))
    return out


def emit(proto, path):
    w = csv.writer(sys.stdout)
    w.writerow(["operation", "role", "group_size", "n_samples", "total_ms", "pubkey_ms", "sym_ms"])
    for row in reduce(proto, path):
        w.writerow(row)


def compare(want_path, got_path, label):
    """Print committed vs this-run timing, side by side (eyeball only)."""
    print(f"  \033[36mtiming\033[0m {label} total | pubkey | sym ms per (operation/role, N) "
          f"— committed vs this run (eyeball only, not asserted)")
    import os
    if not os.path.exists(want_path):
        print(f"       (no committed baseline yet — run ./run.sh --update-expected to create {want_path})")
        return
    want = {}
    with open(want_path, newline="") as f:
        for r in csv.DictReader(f):
            want[(r["operation"], r["role"], r["group_size"])] = r
    with open(got_path, newline="") as f:
        for g in csv.DictReader(f):
            w = want.get((g["operation"], g["role"], g["group_size"]), {})
            def fld(d, k):
                return d.get(k) or "-"
            print(f"       {g['operation']+'/'+g['role']:20s} N={g['group_size']:<4s}"
                  f" tot {fld(w,'total_ms'):>9}|{g['total_ms']:<9}"
                  f" pk {fld(w,'pubkey_ms'):>8}|{g['pubkey_ms']:<8}"
                  f" sym {fld(w,'sym_ms'):>7}|{g['sym_ms']:<7}")


def main():
    a = sys.argv[1:]
    if len(a) == 2 and a[0] in CFG:
        emit(a[0], a[1])
    elif len(a) == 4 and a[0] == "--compare":
        compare(a[1], a[2], a[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
