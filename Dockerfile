# Reproduce the artifact in one container. Two stages: a builder with the full
# toolchain (JDK 11 + thrift, Rust) runs ./build.sh to compile every harness, and a
# slim runtime (JRE 11 + Python/matplotlib/pandas) carries only the compiled
# artifacts, so `docker run` does no compilation.
#
# Build:   docker build -t beekem-eval .
# Run:     docker run --rm beekem-eval                  # reproduce + verify everything
#          docker run --rm beekem-eval ./run.sh beekem  # one target: dcgka|beekem|openmls|partition
# Mount a volume over results/ to keep the regenerated CSVs and figures on the host:
#          docker run --rm -v "$PWD/results:/artifact/results" beekem-eval
#
# Run-time knobs (docker run -e); see run.sh for details:
#   TIME_ITERS         CPU-time-median iterations (default 3; asserted series unaffected).
#   EVAL_GROUP_SIZES   group-size ladder (default 8,16,32,64,128,256,512). Setting it
#                      makes the series diff informational, so classify the run with
#                      ./verify_complexity.sh results; leave unset to reproduce exactly.
#   EVAL_SCRATCH       RAM-backed dir for DCGKA's large raw CSV so it never touches disk;
#                      pair with --shm-size. run.sh aborts if it isn't tmpfs/ramfs. E.g.
#                      extending the ladder past the default:
#                        docker run --rm --shm-size=24g -e EVAL_SCRATCH=/dev/shm \
#                          -e EVAL_GROUP_SIZES=8,16,32,64,128,256,512,1024 -e TIME_ITERS=5 \
#                          -v "$PWD/results:/artifact/results" beekem-eval \
#                          bash -lc './run.sh && ./verify_complexity.sh results'

# ---------------------------------------------------------------- builder
FROM eclipse-temurin:11-jdk-jammy AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates pkg-config git thrift-compiler \
    && rm -rf /var/lib/apt/lists/*

# Rust (stable, minimal profile) for the BeeKEM and OpenMLS harnesses.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal \
    && rustc --version && cargo --version

WORKDIR /artifact
# Copy only the build inputs, so editing the scripts/baselines does not invalidate
# this layer — only a change under a protocol tree forces a recompile.
COPY key-agreement ./key-agreement
COPY keyhive ./keyhive
COPY openmls ./openmls
COPY build.sh ./
# Compile all harnesses; downloads crates and Gradle, so the build needs network.
RUN ./build.sh

# ---------------------------------------------------------------- runtime
FROM eclipse-temurin:11-jre-jammy AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-matplotlib python3-pandas \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /artifact
# Scripts, baselines, and tooling from the build context (not the builder), so editing
# them rebuilds only these cheap layers and reuses the cached compile above.
COPY run.sh build.sh verify_complexity.sh ./
COPY *.py ./
COPY expected ./expected
# Compiled harness artifacts (run.sh invokes these directly).
COPY --from=builder /artifact/keyhive/target/release/examples ./keyhive/target/release/examples
COPY --from=builder /artifact/openmls/target/release/examples ./openmls/target/release/examples
COPY --from=builder /artifact/key-agreement/cli_demo_local/build/install ./key-agreement/cli_demo_local/build/install

# Reproduce the measurements (run.sh) then check the complexity classes; override to subset.
CMD ["bash", "-lc", "./run.sh && ./verify_complexity.sh"]
