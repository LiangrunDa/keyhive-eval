# Crypto-primitive evaluation artifact

This repository reproduces the **crypto-primitive cost measurements** reported in
the paper for three continuous group key agreement (CGKA) implementations:

| Directory       | Protocol           | Upstream                                                            | Language      |
| --------------- | ------------------ | ------------------------------------------------------------------ | ------------- |
| `key-agreement` | DCGKA              | [trvedata/key-agreement](https://github.com/trvedata/key-agreement) | Java / Gradle |
| `keyhive`       | BeeKEM (Keyhive)   | [inkandswitch/keyhive](https://github.com/inkandswitch/keyhive)     | Rust / Cargo  |
| `openmls`       | OpenMLS (TreeKEM)  | [openmls/openmls](https://github.com/openmls/openmls)               | Rust / Cargo  |

Each directory is an **unmodified copy of its upstream source** plus a small
instrumentation layer that counts the cryptographic primitives (hash, AEAD, DH,
sign/verify, HPKE, …) executed per protocol operation, and a harness that drives a
group-size sweep and a history-size sweep.

## What it measures

For each operation (`add` / `update` / `remove`) and role (`sender`, `receiver`,
`new_receiver`, `system`) the harness records:

- **Primitive counts** — how many of each crypto primitive run. These are
  deterministic (independent of timing), so they are checked **exactly** against
  the committed baseline in [`expected/`](expected), and their growth with group
  size `N` is classified and checked against the paper's claimed
  `O(1)` / `O(log N)` / `O(N)` / `O(N²)` classes. On this branch the fit counts
  only the **asymmetric (public-key)** primitives — the operations that drive the
  asymptotics — which exposes TreeKEM's logarithmic re-keying (BeeKEM/OpenMLS
  `update/sender` is `O(log N)`, each receiver `O(1)`, the `system` aggregate `O(N)`,
  vs DCGKA's `O(N)` sender).
- **CPU time** — median per-operation time with a public-key vs symmetric split
  (`*-timing.csv`) plus comparison figures. Timing is machine-dependent, so it is
  an **eyeball cross-check only**, never part of pass/fail.

It also reproduces two history-size sweeps and the BeeKEM **partition-pressure**
sweep (`partition_*` figures).

## Run the verification (Docker)

The two-stage [`Dockerfile`](Dockerfile) compiles every harness at build time, so
`docker run` does no compilation:

```bash
docker build -t beekem-eval .

docker run --rm \
  --shm-size=8g --memory=115g \
  -e EVAL_SCRATCH=/dev/shm \
  -e _JAVA_OPTIONS="-Xmx60g" \
  -e TIME_ITERS=5 \
  -e PARTITION_ITERS=15 \
  -v "$PWD/results:/artifact/results" \
  beekem-eval bash -lc './run.sh && ./verify_complexity.sh'
```

The default group-size ladder is the committed `8,16,32,64,128,256,512`, so this
reproduces `expected/` exactly. What it does:

1. **`run.sh`** re-runs the pre-built harnesses, reduces the output to the
   canonical per-`(operation, role, N)` primitive series, and diffs it against
   `expected/`. It prints `PASS`/`FAIL` per check and draws the figures from this
   run's data into `results/`.
2. **`verify_complexity.sh`** classifies how each per-operation cost grows and
   checks it against the paper's claimed complexity classes.

The `-v` mount brings the regenerated CSVs and figures out into `./results/`
(`cpu-time-comparison.png`, `partition_{updater_pressure,scaling}.{png,pdf}`).

### Environment knobs

| Variable            | Purpose                                                                              |
| ------------------- | ------------------------------------------------------------------------------------ |
| `EVAL_GROUP_SIZES`  | Group-size ladder (default `8,16,32,64,128,256,512`). Extend it (e.g. `…,1024`) to separate `log N` from `N` more cleanly; an extended ladder no longer matches the baseline (see note below). |
| `TIME_ITERS`        | Iterations for the CPU-time medians (default 3). Counts are deterministic, so this only steadies the timings. |
| `PARTITION_ITERS`   | Random layouts medianed per partition-sweep point (default 5).                       |
| `EVAL_SCRATCH`      | Point at RAM-backed `tmpfs` (`/dev/shm`) so DCGKA's large raw CSV never touches disk. `run.sh` aborts if it isn't tmpfs. |
| `_JAVA_OPTIONS`     | DCGKA's JVM heap; its state is `O(N²)`, so large `N` needs a large `-Xmx` (and host RAM). |

> Setting `EVAL_GROUP_SIZES` (to anything, even the default values) makes `run.sh`
> skip the exact series diff and only regenerate; the authoritative check on such a
> run is `verify_complexity.sh results` (the complexity classes the paper claims).
> Leave it unset to reproduce `expected/` exactly.

## Provenance

Each `*/` directory is the upstream source at the commit below, with only the
instrumentation + harness added. This repository's history isolates the change set:
the **first commit** vendors the three pristine upstream trees and the **second**
adds all instrumentation, so `git diff <first> <second>` is exactly the
modifications relative to upstream.

| Directory       | Upstream base commit                  | Added                                                                                 |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------- |
| `key-agreement` | `c168969` (`trvedata/key-agreement`)  | crypto-primitive counters + CLI sweep flags                                           |
| `keyhive`       | `7914692` (`inkandswitch/keyhive`)    | `keyhive_crypto` counters + `beekem/examples/{eval_primitives,eval_history,eval_partition}.rs` + a read-only `conflict_node_count` accessor |
| `openmls`       | `b3f0ba79f` (`openmls/openmls`)       | `InstrumentedOpenMlsRustCrypto` provider + `openmls/examples/eval_primitives.rs`      |

The instrumentation only *counts* primitive calls (and, for OpenMLS, wraps the
crypto provider to delegate + count); the one non-counter addition is BeeKEM's
read-only `conflict_node_count` accessor used by the partition harness. The measured
protocol behaviour is identical to upstream.
