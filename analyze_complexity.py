#!/usr/bin/env python3
"""analyze_complexity.py [SERIES_DIR]   (default: expected/)

Classify how each per-operation cost grows with group size N and check it against
the paper's claimed class, reading expected/<proto>-series.csv (operation,role,
group_size,n_parties,<per-primitive counts>).

Asymmetric-only: the fit sums the public-key columns (keygen/dh/sign/verify, HPKE)
and ignores the symmetric ones (still kept in the CSV). They carry little wall
clock (see analyze_crypto_share.py), and dropping them exposes TreeKEM's
logarithmic re-keying — e.g. OpenMLS update/sender is O(log n), not O(n). The
per-party cost is that sum / n_parties.

Method: for each series fit y = a + b*g(N) by OLS for g in {log N, N, N log N,
N^2} and pick the highest R^2 (a constant guard fires first). The intercept and
explicit log N basis classify cases a bare log-log slope mishandles — e.g. DCGKA
update receiver is exactly N+7 (clean O(N)) yet its log-log slope is only ~0.8.
The slope is still printed, with R^2 and the runner-up margin.
"""
import csv
import math
import os
import sys

CONST_SPREAD = 0.15   # relative (max-min)/mean below which a series is O(1)
NEAR_MARGIN = 0.02    # claim within this R^2 of the best fit -> NEAR (not FAIL)

# Claimed class of the public-key primitive cost per (protocol, operation, role).
# Confounded series (e.g. BeeKEM add_then_update, whose preloaded history also grows
# with N) are omitted and only reported.
EXPECTED = {
    # DCGKA: pairwise public-key channels — sender O(n), each receiver O(1).
    ("dcgka", "add", "sender"): "O(1)",
    ("dcgka", "add", "receiver"): "O(1)",
    ("dcgka", "add", "new_receiver"): "O(1)",
    ("dcgka", "add", "system"): "O(n)",
    ("dcgka", "update", "sender"): "O(n)",
    ("dcgka", "update", "receiver"): "O(1)",
    ("dcgka", "update", "system"): "O(n)",
    ("dcgka", "remove", "sender"): "O(n)",
    ("dcgka", "remove", "system"): "O(n)",

    # BeeKEM (TreeKEM): public-key path re-keying — sender O(log n), receiver O(1).
    ("beekem", "update", "sender"): "O(log n)",
    ("beekem", "update", "receiver"): "O(1)",
    ("beekem", "update", "system"): "O(n)",
    ("beekem", "remove_then_update", "sender"): "O(log n)",
    ("beekem", "remove_then_update", "receiver"): "O(1)",
    ("beekem", "remove_then_update", "system"): "O(n)",

    # OpenMLS (TreeKEM): same logarithmic re-keying — sender O(log n), receiver O(1).
    ("openmls", "update", "sender"): "O(log n)",
    ("openmls", "update", "receiver"): "O(1)",
    ("openmls", "update", "system"): "O(n)",
    ("openmls", "remove", "sender"): "O(log n)",
    ("openmls", "remove", "receiver"): "O(1)",
    ("openmls", "remove", "system"): "O(n)",
    ("openmls", "add", "sender"): "O(log n)",
    ("openmls", "add", "receiver"): "O(1)",
    ("openmls", "add", "system"): "O(n)",
}


def _fit(xs, ys):
    """OLS y = a + b*x; return r2."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return float("-inf")
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return 1.0 if ss_tot == 0 else 1.0 - ss_res / ss_tot


def _loglog_slope(ns, ys):
    pts = [(math.log(n), math.log(y)) for n, y in zip(ns, ys) if n > 0 and y > 0]
    if len(pts) < 2:
        return float("nan")
    xs = [p[0] for p in pts]
    ys2 = [p[1] for p in pts]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys2) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    return float("nan") if sxx == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys2)) / sxx


def _pick(xs, ys, bases):
    """Constant guard, then best-fit among the given {label: g(x)} bases by R^2."""
    mean = sum(ys) / len(ys)
    spread = (max(ys) - min(ys)) / max(abs(mean), 1e-9)
    slope = _loglog_slope(xs, ys)
    if spread < CONST_SPREAD:
        return {"best": "O(1)", "r2": {"O(1)": 1.0}, "margin": float("inf"), "slope": slope}
    r2 = {name: _fit(g, ys) for name, g in bases.items()}
    ranked = sorted(r2.items(), key=lambda kv: kv[1], reverse=True)
    return {"best": ranked[0][0], "r2": r2, "margin": ranked[0][1] - ranked[1][1], "slope": slope}


def classify(ns, ys):
    """Growth vs group size N: O(1) / O(log N) / O(N) / O(N log N) / O(N^2)."""
    return _pick(ns, ys, {
        "O(log n)": [math.log(n) for n in ns],
        "O(n)": list(ns),
        "O(n log n)": [n * math.log(n) for n in ns],
        "O(n^2)": [n * n for n in ns],
    })


def classify_h(hs, ys):
    """Growth vs history size h: O(1) / O(h) / O(h^2). No log basis (h starts at 0)."""
    return _pick(hs, ys, {"O(h)": list(hs), "O(h^2)": [h * h for h in hs]})


# Public-key (asymmetric) primitive columns across all three harnesses; the fit
# sums only these (see the module docstring).
ASYMMETRIC = {
    "keygen", "dh", "sign", "verify",                          # beekem, dcgka
    "hpke_encrypt", "hpke_decrypt",                            # dcgka
    "signature_key_gen", "verify_signature",                   # openmls
    "hpke_seal", "hpke_open", "hpke_setup_sender_and_export",
    "hpke_setup_receiver_and_export", "derive_hpke_keypair",   # openmls
}


def load_series(series_dir):
    """Return {protocol: {(operation, role): {N: per_party asymmetric-primitive sum}}}."""
    out = {}
    for proto in ("dcgka", "beekem", "openmls"):
        path = os.path.join(series_dir, f"{proto}-series.csv")
        if not os.path.exists(path):
            continue
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                key = (r["operation"], r["role"])
                n = int(r["group_size"])
                primitives = sum(float(v) for k, v in r.items() if k in ASYMMETRIC)
                val = primitives / int(r["n_parties"])
                out.setdefault(proto, {}).setdefault(key, {})[n] = val
    return out


# History sweeps (fixed group size): new-receiver replay / system work / welcome
# bytes all grow linearly with history length h.
def load_history(series_dir):
    """Return a list of (label, {h: value}, expected_class) for the history sweeps."""
    out = []

    bpath = os.path.join(series_dir, "beekem-history-summary.csv")
    if os.path.exists(bpath):
        nr, sysc, sysn = {}, {}, {}
        with open(bpath, newline="") as fh:
            for r in csv.DictReader(fh):
                h = int(r["history_size"])
                if r["role"] == "new_receiver":
                    nr[h] = float(r["total_crypto"])
                elif r["role"] == "system":
                    sysc[h] = float(r["total_crypto"])
                    sysn[h] = float(r["network_bytes"])
        out.append(("beekem/history/new_receiver primitives", nr, "O(h)"))
        out.append(("beekem/history/system primitives", sysc, "O(h)"))
        out.append(("beekem/history/system network_bytes", sysn, "O(h)"))

    dpath = os.path.join(series_dir, "dcgka-history-traffic.csv")
    if os.path.exists(dpath):
        net = {}
        with open(dpath, newline="") as fh:
            for r in csv.DictReader(fh):
                net[int(r["history_size"])] = float(r["operationsentbytes"])
        out.append(("dcgka/history/add network_bytes", net, "O(h)"))

    return out


G, R, Y, D, X = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
HEADER = (f"{'series':38} {'best fit':10} {'R^2':>6} {'margin':>7} "
          f"{'loglog':>7}  {'expected':10} verdict")


def _row(label, c, exp, by_x, show_all, tally):
    """Print one classified row; update tally [pass, near, fail]; print points if notable."""
    best, best_r2 = c["best"], c["r2"].get(c["best"], 1.0)
    verdict, color = "", D
    if exp is not None:
        if best == exp:
            verdict, color, tally[0] = "PASS", G, tally[0] + 1
        elif exp in c["r2"] and best_r2 - c["r2"][exp] <= NEAR_MARGIN:
            verdict, color, tally[1] = f"NEAR (exp {exp})", Y, tally[1] + 1
        else:
            verdict, color, tally[2] = f"FAIL (exp {exp})", R, tally[2] + 1
    margin_s = "inf" if c["margin"] == float("inf") else f"{c['margin']:.3f}"
    print(f"{label:38} {best:10} {best_r2:6.3f} {margin_s:>7} "
          f"{c['slope']:7.2f}  {(exp or '-'):10} {color}{verdict}{X}")
    if show_all or verdict.startswith(("FAIL", "NEAR")):
        print(f"{D}    points: {' '.join(f'{x}:{by_x[x]:g}' for x in sorted(by_x))}{X}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    show_all = "--all" in sys.argv[1:]
    series_dir = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected")

    series = load_series(series_dir)
    history = load_history(series_dir)
    if not series and not history:
        print(f"No baselines found in {series_dir}. Run ./run.sh first.")
        return 2

    tally = [0, 0, 0]  # pass, near, fail
    print(f"Complexity check against {os.path.relpath(series_dir)}/  "
          f"(public-key primitives only; method: best-fit of a + b*g(x) by R^2)\n")

    print("-- vs group size N --")
    print(HEADER); print("-" * len(HEADER))
    for proto in ("dcgka", "beekem", "openmls"):
        for (op, role), by_n in sorted(series.get(proto, {}).items()):
            ns = sorted(by_n)
            if len(ns) < 4:
                continue
            exp = EXPECTED.get((proto, op, role))
            if exp is None and not show_all:
                continue
            _row(f"{proto}/{op}/{role}", classify(ns, [by_n[n] for n in ns]), exp, by_n, show_all, tally)

    print("\n-- vs history size h (fixed group size) --")
    print(HEADER); print("-" * len(HEADER))
    for label, by_h, exp in history:
        hs = sorted(by_h)
        if len(hs) < 4:
            continue
        _row(label, classify_h(hs, [by_h[h] for h in hs]), exp, by_h, show_all, tally)

    print("-" * len(HEADER))
    print(f"asserted series: {G}{tally[0]} PASS{X}, {Y}{tally[1]} NEAR{X}, {R}{tally[2]} FAIL{X}")
    print(f"{D}NEAR = best fit differs from the claim but the claim's R^2 is within "
          f"{NEAR_MARGIN} (range too short to separate cleanly).{X}")
    return 1 if tally[2] else 0


if __name__ == "__main__":
    sys.exit(main())
