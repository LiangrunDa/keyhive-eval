#!/usr/bin/env python3
"""reduce_series.py — reduce a protocol's raw crypto-primitive CSV to the canonical
asserted series, broken out per primitive type:

    operation,role,group_size,n_parties,<prim_1>,<prim_2>,...

n_parties is the number of measured rows of that role; each <prim_i> is that
primitive's count summed over them, in raw-CSV column order (random_calls/_bytes
excluded — not crypto). Deterministic, so it is diffed exactly against expected/.

The sweep runs several iterations (for the timing medians, see reduce_timing.py),
each repeating every row with identical counts, so we dedup on each protocol's
within-iteration identity columns and keep the first.

Usage:  reduce_series.py {beekem|openmls|dcgka} RAW_CSV   write the series to stdout
"""

import csv
import sys

# Per protocol: the (operation, role, group size) columns, the primitive columns to
# break out (in raw-CSV order), a row filter, and the within-iteration identity
# columns used to dedup repeated iterations (see the module docstring).
CFG = {
    "beekem": dict(
        op="operation", role="role", size="group_size",
        prims=["hash", "kdf", "prf", "keygen", "dh",
               "aead_encrypt", "aead_decrypt", "sign", "verify"],
        keep=lambda r: True,
        idcols=["operation", "role", "group_size", "receiver_index", "history_size"],
    ),
    "openmls": dict(
        op="operation", role="role", size="group_size",
        prims=["hkdf_extract", "hmac", "hkdf_expand", "hash",
               "aead_encrypt", "aead_decrypt", "signature_key_gen",
               "verify_signature", "sign", "hpke_seal", "hpke_open",
               "hpke_setup_sender_and_export", "hpke_setup_receiver_and_export",
               "derive_hpke_keypair"],
        keep=lambda r: True,
        idcols=["operation", "role", "group_size", "receiver_index"],
    ),
    "dcgka": dict(
        op="operation", role="role", size="groupsize",
        prims=["hash", "aead_encrypt", "aead_decrypt", "keygen", "dh",
               "hpke_encrypt", "hpke_decrypt", "sign", "verify", "prf"],
        # Drop auxiliary-ack snapshots; only real protocol messages are asserted.
        keep=lambda r: r["is_auxiliary_ack"] != "true",
        idcols=["operation", "role", "groupsize", "receiver_index", "message_kind"],
    ),
}


def reduce(proto, path):
    c = CFG[proto]
    agg = {}  # (op, role, N) -> [n_parties, sum_prim_1, sum_prim_2, ...]
    seen = set()  # identity tuples already counted (drops repeated iterations)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if not c["keep"](r):
                continue
            idkey = tuple(r[col] for col in c["idcols"])
            if idkey in seen:
                continue
            seen.add(idkey)
            key = (r[c["op"]], r[c["role"]], int(r[c["size"]]))
            rec = agg.setdefault(key, [0] + [0] * len(c["prims"]))
            rec[0] += 1
            for i, p in enumerate(c["prims"], start=1):
                rec[i] += int(r[p])
    out = []
    for (op, role, n) in sorted(agg, key=lambda k: (k[0], k[1], k[2])):
        rec = agg[(op, role, n)]
        out.append([op, role, n] + rec)
    return out


def main():
    a = sys.argv[1:]
    if len(a) != 2 or a[0] not in CFG:
        sys.exit(__doc__)
    proto, path = a
    w = csv.writer(sys.stdout)
    w.writerow(["operation", "role", "group_size", "n_parties"] + CFG[proto]["prims"])
    for row in reduce(proto, path):
        w.writerow(row)


if __name__ == "__main__":
    main()
