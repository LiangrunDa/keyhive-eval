#!/usr/bin/env bash
#
# build.sh — compile the three evaluation harnesses once, so run.sh can invoke the
# pre-built artifacts directly (no cargo/gradle at run time). Run before run.sh; the
# Dockerfile's builder stage runs it too.
#
# Build-time toolchains: Rust (cargo, stable), JDK 11 + the thrift CLI (DCGKA's
# bundled Gradle 5.2.1 requires JDK 11 and compiles Thrift IDL).

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "${JAVA_HOME:-}" ]; then JAVA="$JAVA_HOME/bin/java"; else JAVA="java"; fi
if ! "$JAVA" -version 2>&1 | grep -q 'version "11\.'; then
  echo "build.sh: DCGKA needs JDK 11 (its bundled Gradle does not run on newer JDKs)." >&2
  echo "          Set JAVA_HOME to a JDK 11 install, or build via the Dockerfile." >&2
  exit 1
fi
command -v thrift >/dev/null 2>&1 || {
  echo "build.sh: the 'thrift' compiler is required to build DCGKA (apt install thrift-compiler)." >&2
  exit 1
}

echo "== BeeKEM (keyhive) — cargo release examples =="
( cd "$ROOT/keyhive" && cargo build --release -p beekem \
    --example eval_primitives --example eval_history --example eval_partition )

echo "== OpenMLS — cargo release example =="
( cd "$ROOT/openmls" && cargo build --release -p openmls --example eval_primitives )

echo "== DCGKA (key-agreement) — gradle installDist =="
( cd "$ROOT/key-agreement" && ./gradlew :cli_demo_local:installDist --no-daemon -q )

echo
echo "build complete — now run ./run.sh"
