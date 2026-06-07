#!/usr/bin/env bash
#
# run.sh — re-run the pre-built harnesses (compile first with ./build.sh), reduce
# each to the canonical per-(operation, role, N) series, and diff it against the
# committed baseline in expected/. Outputs go to results/ (git-ignored): diffed
# files reuse their expected/ name, raw harness output gets a raw- prefix.
#
# The same sweep runs a few iterations (TIME_ITERS), yielding both the asserted
# series (deterministic counts; reduce_series dedups the iterations) and an
# eyeball-only CPU-time table (*-timing.csv, the median over iterations; not
# diffed). See reduce_series.py / reduce_timing.py for the column layouts.
#
# Prereq:  ./build.sh   (compiles the harnesses run.sh invokes)
# Usage:   ./run.sh [--update-expected] [dcgka|beekem|openmls|partition]...   (default: all)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$ROOT/results"
EXPECTED="$ROOT/expected"
mkdir -p "$RESULTS" "$EXPECTED"

# Pre-built harness artifacts produced by ./build.sh (each verify_* checks its own).
DCGKA_BIN="$ROOT/key-agreement/cli_demo_local/build/install/cli_demo_local/bin/cli_demo_local"
BEEKEM_DIR="$ROOT/keyhive/target/release/examples"
OPENMLS_DIR="$ROOT/openmls/target/release/examples"

UPDATE=0
if [ "${1:-}" = "--update-expected" ]; then UPDATE=1; shift; fi

# Iterations for the (non-asserted) CPU-time medians; counts are identical every
# iteration, so this only steadies the median. Asserted series are unaffected.
TIME_ITERS="${TIME_ITERS:-3}"

# Group-size ladder for the sweep. Empty => each harness's committed default
# (8,16,32,64,128,256,512) that expected/ was generated with, so a default run diffs
# exactly. Setting this (to anything) makes the series diffs below informational —
# classify with ./verify_complexity.sh results. The Rust harnesses read it from the
# env; DCGKA gets --group-sizes (built below). History/partition use fixed sizes.
EVAL_GROUP_SIZES="${EVAL_GROUP_SIZES:-}"
export EVAL_GROUP_SIZES
CUSTOM_SIZES=0; DCGKA_SIZE_ARGS=()
if [ -n "$EVAL_GROUP_SIZES" ]; then
  CUSTOM_SIZES=1
  DCGKA_SIZE_ARGS=(--group-sizes "$EVAL_GROUP_SIZES")
fi

# DCGKA writes a large raw primitives CSV (~0.4-1.8GB) the reducers then read twice;
# on a slow disk that can saturate I/O and stall the host. Point EVAL_SCRATCH at a
# RAM-backed tmpfs (e.g. -e EVAL_SCRATCH=/dev/shm) so it never touches disk; run.sh
# verifies it really is tmpfs/ramfs and aborts the DCGKA step otherwise (never
# silently falling back to disk). Unset => the default small sweep writes under results/.
EVAL_SCRATCH="${EVAL_SCRATCH:-}"

# Random layouts to median the (eyeball-only) partition sweep over; more only smooths
# the curves. The committed figures were drawn with 15.
PARTITION_ITERS="${PARTITION_ITERS:-5}"

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
hdr() { printf '\n=== %s ===\n' "$1"; }

# check LABEL GENERATED_FILE EXPECTED_FILE  — diff, or update the baseline.
check() {
  local label="$1" got="$2" want="$3"
  if [ "$UPDATE" = 1 ]; then
    cp "$got" "$want"; printf '  \033[33mupdated\033[0m %s\n' "$want"; return
  fi
  if diff -q "$want" "$got" >/dev/null 2>&1; then
    ok "$label"
  else
    bad "$label (expected vs actual, first 12 diff lines:)"
    diff "$want" "$got" 2>&1 | head -12 | sed 's/^/      /'
  fi
}

# Like check, but a custom EVAL_GROUP_SIZES ladder can't match the baseline, so just
# note the series was regenerated (classify with ./verify_complexity.sh results).
check_series() {
  if [ "$CUSTOM_SIZES" = 1 ]; then
    printf '  \033[33mnote\033[0m %s: custom EVAL_GROUP_SIZES — regenerated, not compared to baseline (classify with ./verify_complexity.sh results)\n' "$1"
    return
  fi
  check "$@"
}

# Harnesses reuse fixed CSV names, so each run gets its own scratch dir, then its
# outputs are flattened into results/: diffed files keep their expected/ name, the
# rest get a raw- prefix.
newdir() { rm -rf "$1"; mkdir -p "$1"; }

# mvraw SCRATCHDIR SRCNAME RAWNAME — move SCRATCHDIR/SRCNAME to results/raw-RAWNAME.
mvraw() { [ -e "$1/$2" ] && mv -f "$1/$2" "$RESULTS/raw-$3"; return 0; }

# show_timing PROTO LABEL RAW_CSV — reduce a timing run to the per-(op, role, N)
# table and print committed vs this run (or update the baseline). Never PASS/FAILed.
show_timing() {
  local proto="$1" label="$2" raw="$3"
  [ -f "$raw" ] || { bad "$label timing: run produced no output ($raw)"; return; }
  python3 "$ROOT/reduce_timing.py" "$proto" "$raw" > "$RESULTS/$proto-timing.csv" || return
  if [ "$UPDATE" = 1 ]; then
    cp "$RESULTS/$proto-timing.csv" "$EXPECTED/$proto-timing.csv"
    printf '  \033[33mupdated\033[0m %s\n' "$EXPECTED/$proto-timing.csv"
  else
    python3 "$ROOT/reduce_timing.py" --compare \
      "$EXPECTED/$proto-timing.csv" "$RESULTS/$proto-timing.csv" "$label"
  fi
}

verify_dcgka() {
  hdr "DCGKA (key-agreement, Java)"
  if [ ! -x "$DCGKA_BIN" ]; then bad "DCGKA not built — run ./build.sh first"; return; fi
  # DCGKA records per-client CPU time (getCpuTime, not wall clock); no `system` timing.
  # With EVAL_SCRATCH set, require it to be a RAM-backed tmpfs/ramfs (abort otherwise);
  # unset writes the raw under results/.
  local base="$RESULTS" raw_in_ram=0
  if [ -n "$EVAL_SCRATCH" ]; then
    local fstype=""
    [ -d "$EVAL_SCRATCH" ] && fstype="$(stat -f -c %T "$EVAL_SCRATCH" 2>/dev/null)"
    if [ "$fstype" = tmpfs ] || [ "$fstype" = ramfs ]; then
      base="$EVAL_SCRATCH"; raw_in_ram=1
      printf '  DCGKA raw -> %s (%s, RAM-backed; kept off disk)\n' "$EVAL_SCRATCH" "$fstype"
    else
      bad "EVAL_SCRATCH=$EVAL_SCRATCH is not tmpfs/ramfs (got '${fstype:-missing}') — refusing to write the large DCGKA raw to disk. Mount RAM there, e.g. docker run --shm-size=8g -e EVAL_SCRATCH=/dev/shm, or unset EVAL_SCRATCH."
      return
    fi
  fi

  local sc="$base/.scratch-dcgka"; newdir "$sc"
  "$DCGKA_BIN" -o "$sc" -i "$TIME_ITERS" ${DCGKA_SIZE_ARGS[@]+"${DCGKA_SIZE_ARGS[@]}"} >/tmp/dcgka-run.log 2>&1
  if [ ! -f "$sc/dcgka-primitives.csv" ]; then
    if [ "$raw_in_ram" = 1 ] && grep -qiE "No space left|ENOSPC" /tmp/dcgka-run.log; then
      bad "DCGKA: ran out of space in $EVAL_SCRATCH — raise the tmpfs size (e.g. docker run --shm-size=16g)"
    else
      bad "DCGKA: run produced no output (see /tmp/dcgka-run.log)"
    fi
    rm -rf "$sc"; return
  fi
  python3 "$ROOT/reduce_series.py" dcgka "$sc/dcgka-primitives.csv" > "$RESULTS/dcgka-series.csv"
  check_series "DCGKA primitive series" "$RESULTS/dcgka-series.csv" "$EXPECTED/dcgka-series.csv"
  show_timing dcgka "DCGKA" "$sc/dcgka-primitives.csv"
  # Keep the raw under results/ only if it is already on disk; from tmpfs, copying it
  # back would re-introduce the large write, so discard it (the reductions are kept).
  if [ "$raw_in_ram" = 1 ]; then
    printf '  raw-dcgka (%s) kept in RAM, not copied to results/ (reduced series/timing kept)\n' \
      "$(du -h "$sc/dcgka-primitives.csv" 2>/dev/null | cut -f1)"
  else
    mvraw "$sc" dcgka-primitives.csv dcgka-primitives.csv
  fi
  rm -rf "$sc"

  # History sweep at fixed group size 32: Add/welcome bytes grow ~linearly with history.
  local sch="$RESULTS/.scratch-dcgka-history"; newdir "$sch"
  "$DCGKA_BIN" -o "$sch" -i 1 --history-sweep --fixed-group-size 32 \
      --history-sizes 0,2,4,8,16,32,64 >/tmp/dcgka-history-run.log 2>&1
  if [ ! -f "$sch/traffic.csv" ]; then
    bad "DCGKA history: run produced no output (see /tmp/dcgka-history-run.log)"; rm -rf "$sch"; return
  fi
  # Only traffic.csv is consumed (the asserted history series); the rest is discarded.
  mv -f "$sch/traffic.csv" "$RESULTS/dcgka-history-traffic.csv"
  check "DCGKA history traffic" "$RESULTS/dcgka-history-traffic.csv" "$EXPECTED/dcgka-history-traffic.csv"
  rm -rf "$sch"
}

verify_beekem() {
  hdr "BeeKEM (keyhive, Rust)"
  if [ ! -x "$BEEKEM_DIR/eval_primitives" ] || [ ! -x "$BEEKEM_DIR/eval_history" ]; then
    bad "BeeKEM not built — run ./build.sh first"; return
  fi
  local sc="$RESULTS/.scratch-beekem" sch="$RESULTS/.scratch-beekem-history"
  newdir "$sc"; newdir "$sch"
  ( "$BEEKEM_DIR/eval_primitives" "$sc" "$TIME_ITERS" \
    && "$BEEKEM_DIR/eval_history" "$sch" 32 0,1,2,4,8,16,32,64 ) \
    >/tmp/beekem-run.log 2>&1
  if [ ! -f "$sc/beekem-primitives.csv" ]; then
    bad "BeeKEM: run produced no output (see /tmp/beekem-run.log)"; rm -rf "$sc" "$sch"; return
  fi
  python3 "$ROOT/reduce_series.py" beekem "$sc/beekem-primitives.csv" > "$RESULTS/beekem-series.csv"
  check_series "BeeKEM primitive series" "$RESULTS/beekem-series.csv" "$EXPECTED/beekem-series.csv"
  show_timing beekem "BeeKEM" "$sc/beekem-primitives.csv"
  mvraw "$sc" beekem-primitives.csv beekem-primitives.csv
  rm -rf "$sc"

  # History sweep summary is already small and deterministic (no wall-clock col).
  mv -f "$sch/beekem-history-summary.csv" "$RESULTS/beekem-history-summary.csv"
  check "BeeKEM history summary" "$RESULTS/beekem-history-summary.csv" "$EXPECTED/beekem-history-summary.csv"
  mvraw "$sch" beekem-history-primitives.csv beekem-history-primitives.csv
  rm -rf "$sch"
}

verify_openmls() {
  hdr "OpenMLS (Rust)"
  if [ ! -x "$OPENMLS_DIR/eval_primitives" ]; then
    bad "OpenMLS not built — run ./build.sh first"; return
  fi
  local sc="$RESULTS/.scratch-openmls"; newdir "$sc"
  "$OPENMLS_DIR/eval_primitives" "$sc" "$TIME_ITERS" >/tmp/openmls-run.log 2>&1
  if [ ! -f "$sc/openmls-primitives.csv" ]; then
    bad "OpenMLS: run produced no output (see /tmp/openmls-run.log)"; rm -rf "$sc"; return
  fi
  python3 "$ROOT/reduce_series.py" openmls "$sc/openmls-primitives.csv" > "$RESULTS/openmls-series.csv"
  check_series "OpenMLS primitive series" "$RESULTS/openmls-series.csv" "$EXPECTED/openmls-series.csv"
  show_timing openmls "OpenMLS" "$sc/openmls-primitives.csv"
  mvraw "$sc" openmls-primitives.csv openmls-primitives.csv
  rm -rf "$sc"
}

# BeeKEM partition-pressure sweep (the paper's partition figures). Independent
# variable: average Updates per member while partitioned (a = U/n, swept 0..2),
# sampled randomly — so eyeball only, never PASS/FAILed. Figures via plot_partition.py.
verify_partition() {
  hdr "BeeKEM partition pressure (keyhive, Rust) — eyeball only"
  local BIN="$BEEKEM_DIR/eval_partition"
  if [ ! -x "$BIN" ]; then bad "partition not built — run ./build.sh first"; return; fi
  local sc="$RESULTS/.scratch-partition"; newdir "$sc"
  local H="iteration,group_size,partitions,total_updates,avg_updates_per_member,distinct_updaters,conflicts_after_merge,first_secrets,first_crypto,first_bytes,first_ms,recovery_steps,recovery_secrets,recovery_crypto,recovery_bytes,recovery_ms"

  # 1. Average-updates sweep at the paper's n=64, 4 partitions. Total updates U =
  #    a*n for a = 0..2 in steps of n/8 (so a hits 0, .125, .25, …, 2.0).
  "$BIN" "$sc/avg" 64 "0,8,16,24,32,48,64,80,96,112,128" 4 "$PARTITION_ITERS" >/tmp/partition-run.log 2>&1
  cp "$sc/avg/beekem-partition.csv" "$RESULTS/beekem-partition-fraction-sweep.csv"

  # 2. Scaling: first post-merge Update cost vs group size, at several average-update
  #    levels a in {0, 0.5, 1, 1.5, 2} (U = round(a*n)).
  echo "$H" > "$RESULTS/beekem-partition-scaling.csv"
  local n a counts
  for n in 8 16 32 64 128; do
    counts=""
    for a in 0 50 100 150 200; do counts="$counts $(( (a*n + 50)/100 ))"; done
    counts=$(echo $counts | tr ' ' '\n' | sort -n -u | paste -sd, -)
    "$BIN" "$sc/scale-$n" "$n" "$counts" 4 "$PARTITION_ITERS" >>/tmp/partition-run.log 2>&1
    tail -n +2 "$sc/scale-$n/beekem-partition.csv" >> "$RESULTS/beekem-partition-scaling.csv"
  done
  rm -rf "$sc"

  if [ "$UPDATE" = 1 ]; then
    local f
    for f in fraction-sweep scaling; do
      cp "$RESULTS/beekem-partition-$f.csv" "$EXPECTED/beekem-partition-$f.csv"
      printf '  \033[33mupdated\033[0m %s\n' "$EXPECTED/beekem-partition-$f.csv"
    done
  else
    printf '  regenerated partition CSVs into results/ (eyeball only — random sampling,'
    printf ' not PASS/FAILed; figures are drawn from expected/ by plot_partition.py)\n'
  fi
}

targets=("$@"); [ ${#targets[@]} -eq 0 ] && targets=(dcgka beekem openmls partition)
for t in "${targets[@]}"; do
  case "$t" in
    dcgka)     verify_dcgka ;;
    beekem)    verify_beekem ;;
    openmls)   verify_openmls ;;
    partition) verify_partition ;;
    *) echo "unknown target: $t (use dcgka|beekem|openmls|partition)"; exit 2 ;;
  esac
done

# Wall-clock share of asym/sym/non-crypto from expected/*-timing.csv — the evidence
# for the asymmetric-only complexity view (analyze_complexity.py). Eyeball only.
if [ "$UPDATE" != 1 ]; then
  hdr "Wall-clock crypto share (asym / sym / others — eyeball only)"
  python3 "$ROOT/analyze_crypto_share.py" "$EXPECTED"
fi

# Draw the eyeball figures from this run's results/ into results/. Best-effort (needs
# matplotlib/pandas, never fatal); --update-expected refreshes expected/ + Images/ below.
draw_figures() {
  hdr "Figures (drawn from results/ into results/ — eyeball only)"
  if python3 -c 'import matplotlib' >/dev/null 2>&1; then
    if ls "$RESULTS"/*-timing.csv >/dev/null 2>&1; then
      if python3 "$ROOT/plot_time.py" "$RESULTS" "$RESULTS/cpu-time-comparison.png" >/dev/null; then
        printf '  wrote results/cpu-time-comparison.png\n'
      else
        printf '  (cpu-time figure failed — non-fatal)\n'
      fi
    else
      printf '  (no *-timing.csv in results/ — run a group-size sweep to draw the cpu-time figure)\n'
    fi
  else
    printf '  (matplotlib not installed — skipping cpu-time figure)\n'
  fi
  if python3 -c 'import matplotlib, pandas' >/dev/null 2>&1; then
    if [ -f "$RESULTS/beekem-partition-fraction-sweep.csv" ] && [ -f "$RESULTS/beekem-partition-scaling.csv" ]; then
      if python3 "$ROOT/plot_partition.py" "$RESULTS" "$RESULTS" >/dev/null; then
        printf '  wrote results/partition_updater_pressure.{png,pdf} and results/partition_scaling.{png,pdf}\n'
      else
        printf '  (partition figures failed — non-fatal)\n'
      fi
    else
      printf '  (no partition CSVs in results/ — run the partition target to draw the partition figures)\n'
    fi
  else
    printf '  (matplotlib/pandas not installed — skipping partition figures)\n'
  fi
}
if [ "$UPDATE" != 1 ]; then draw_figures; fi

# On --update-expected, redraw the committed figures from expected/ (best-effort).
if [ "$UPDATE" = 1 ]; then
  if python3 -c 'import matplotlib' >/dev/null 2>&1; then
    python3 "$ROOT/plot_time.py" "$EXPECTED" "$EXPECTED/cpu-time-comparison.png" >/dev/null \
      && printf '  \033[33mupdated\033[0m %s\n' "$EXPECTED/cpu-time-comparison.png"
  else
    printf '  (matplotlib not installed — left expected/cpu-time-comparison.png as is; run ./plot_time.py to redraw)\n'
  fi
  if python3 -c 'import matplotlib, pandas' >/dev/null 2>&1; then
    python3 "$ROOT/plot_partition.py" "$EXPECTED" "$ROOT/Peer_to_Peer_Group_Key_Agreement/Images" >/dev/null \
      && printf '  \033[33mupdated\033[0m %s\n' "partition figures (Images/*.pdf, expected/partition_*.png)"
  else
    printf '  (matplotlib/pandas not installed — left partition figures as is; run ./plot_partition.py to redraw)\n'
  fi
fi

[ "$UPDATE" = 1 ] && { printf '\nbaselines updated.\n'; exit 0; }
printf '\n=== summary: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
