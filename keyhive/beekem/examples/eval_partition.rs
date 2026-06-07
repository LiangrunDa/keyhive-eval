//! BeeKEM partition-pressure evaluation.
//!
//! Independent variable: the average Updates per member while partitioned, `a = U/n`,
//! swept 0..2. Updaters are sampled without replacement within a round (a random
//! permutation of distinct members per full round of `n`), seeded by the iteration —
//! so at `a <= 1` each update is by a distinct member and at `a > 1` the extras are
//! repeats. Metrics are medianed over iterations; eyeball only, never asserted.
//!
//! Model: member `m` is in partition `m % partitions`; an update reaches only its own
//! partition (a causal chain), so partitions are mutually concurrent. After healing we
//! merge and measure (1) the first post-merge Update — the cost before encrypted
//! traffic can resume — and (2) the cumulative recovery Updates back to conflict-free.
//! Repeat updates collapse into their partition's chain, so cost rises to `a ~ 1` then
//! plateaus: what matters is the set of updaters, not the raw count.

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use beekem::operation::CgkaOperation;
use keyhive_crypto::{
    instrumentation::{self, PrimitiveCounters},
    share_key::ShareSecretKey,
    signed::Signed,
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

type SharedOp = Arc<Signed<CgkaOperation>>;

mod common;
use common::{preload_updates, serialized_len, setup_group, Peer};

const DEFAULT_GROUP_SIZE: usize = 64;
// Total self-Updates U; average per member is U / n, so for n=64 this is a = 0..2.
const DEFAULT_UPDATE_TOTALS: &[usize] = &[0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128];
const DEFAULT_PARTITIONS: usize = 4;

struct Row {
    iteration: usize,
    group_size: usize,
    partitions: usize,
    total_updates: usize,
    avg_updates_per_member: f64,
    distinct_updaters: usize,
    conflicts_after_merge: usize,
    // First post-merge Update (metric 1).
    first_secrets: u64,
    first_crypto: u64,
    first_bytes: usize,
    first_ms: f64,
    // Cumulative recovery until conflict-free (metric 2).
    recovery_steps: usize,
    recovery_secrets: u64,
    recovery_crypto: u64,
    recovery_bytes: usize,
    recovery_ms: f64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("evaluation-results/beekem-partition-smoke"));
    let group_size = env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_GROUP_SIZE);
    let update_totals = env::args()
        .nth(3)
        .map(|s| parse_usize_list(&s))
        .unwrap_or_else(|| DEFAULT_UPDATE_TOTALS.to_vec());
    let partitions = env::args()
        .nth(4)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PARTITIONS);
    // Random layouts to average over; metrics are medianed in post-processing.
    let iterations = env::args()
        .nth(5)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    fs::create_dir_all(&output_dir).expect("create output dir");
    let path = output_dir.join("beekem-partition.csv");

    let mut rows = Vec::new();
    for iteration in 0..iterations {
        for &total in &update_totals {
            let u = total.min(2 * group_size);
            let row = run_case(iteration, group_size, u, partitions).await;
            eprintln!(
                "finished it={iteration} n={group_size} updates={u} avg={:.3} \
                 partitions={partitions} distinct={} conflicts={} first_ms={:.3}",
                row.avg_updates_per_member,
                row.distinct_updaters,
                row.conflicts_after_merge,
                row.first_ms
            );
            rows.push(row);
        }
    }

    write_csv(&path, &rows).expect("write partition csv");
}

async fn run_case(
    iteration: usize,
    group_size: usize,
    total_updates: usize,
    partitions: usize,
) -> Row {
    let mut csprng = rand::rngs::OsRng;
    let mut peers = setup_group(group_size, &mut csprng).await;
    preload_updates(&mut peers, &mut csprng).await;

    let part_count = partitions.max(1);
    let partition_of = |m: usize| m % part_count;
    // Every member belongs to a partition (not just the updaters).
    let mut partition_members: Vec<Vec<usize>> = vec![Vec::new(); part_count];
    for m in 0..group_size {
        partition_members[partition_of(m)].push(m);
    }

    // Update schedule, without replacement within each round (see module docs).
    let mut sel = StdRng::seed_from_u64(iteration as u64);
    let mut schedule: Vec<usize> = Vec::with_capacity(total_updates);
    let mut remaining = total_updates;
    while remaining > 0 {
        let mut perm: Vec<usize> = (0..group_size).collect();
        perm.shuffle(&mut sel);
        let take = remaining.min(group_size);
        schedule.extend(perm.into_iter().take(take));
        remaining -= take;
    }

    // Partition phase: perform the scheduled updates, each delivered to the other
    // members of its own partition (a causal chain); nothing crosses partitions.
    let mut partition_ops: Vec<Vec<SharedOp>> = vec![Vec::new(); part_count];
    let mut updaters: BTreeSet<usize> = BTreeSet::new();
    for &m in &schedule {
        updaters.insert(m);
        let op = update_member(&mut peers, m, &mut csprng).await;
        let pid = partition_of(m);
        for &j in &partition_members[pid] {
            if j != m {
                peers[j]
                    .cgka
                    .merge_concurrent_operation(op.clone())
                    .expect("intra-partition merge");
            }
        }
        partition_ops[pid].push(op);
    }

    // Heal: every member merges the operations of the partitions it did not belong
    // to, so all members converge to the same merged, conflicted tree.
    instrumentation::reset();
    for m in 0..group_size {
        let own = partition_of(m);
        for (pid, ops) in partition_ops.iter().enumerate() {
            if pid == own {
                continue;
            }
            for op in ops {
                peers[m]
                    .cgka
                    .merge_concurrent_operation(op.clone())
                    .expect("heal merge");
            }
        }
    }
    let conflicts_after_merge = peers[0].cgka.conflict_node_count();

    // Recovery: post-heal the network is connected, so each conflicting member
    // re-Updates once in random order (broadcast to all) until member 0 sees the tree
    // conflict-free — one pass suffices. With no updaters (a = 0) it is member 0's
    // single happy-path baseline.
    let participants: Vec<usize> = if updaters.is_empty() {
        vec![0]
    } else {
        let mut v: Vec<usize> = updaters.iter().copied().collect();
        v.shuffle(&mut sel);
        v
    };

    let mut first: Option<(u64, u64, usize, f64)> = None;
    let mut recovery_steps = 0usize;
    let mut recovery_secrets = 0u64;
    let mut recovery_crypto = 0u64;
    let mut recovery_bytes = 0usize;
    let mut recovery_ms = 0.0f64;

    for &m in &participants {
        instrumentation::reset();
        let start = Instant::now();
        let op = update_member(&mut peers, m, &mut csprng).await;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let counters = instrumentation::snapshot();

        for j in 0..group_size {
            if j != m {
                peers[j]
                    .cgka
                    .merge_concurrent_operation(op.clone())
                    .expect("recovery broadcast merge");
            }
        }

        let secrets = counters.aead_encrypt;
        let crypto = total_crypto(&counters);
        let bytes = serialized_len(&op);
        if first.is_none() {
            first = Some((secrets, crypto, bytes, elapsed_ms));
        }
        recovery_steps += 1;
        recovery_secrets += secrets;
        recovery_crypto += crypto;
        recovery_bytes += bytes;
        recovery_ms += elapsed_ms;

        if peers[0].cgka.conflict_node_count() == 0 {
            break;
        }
    }

    let (first_secrets, first_crypto, first_bytes, first_ms) = first.expect("at least one update");
    Row {
        iteration,
        group_size,
        partitions: part_count,
        total_updates,
        avg_updates_per_member: total_updates as f64 / group_size as f64,
        distinct_updaters: updaters.len(),
        conflicts_after_merge,
        first_secrets,
        first_crypto,
        first_bytes,
        first_ms,
        recovery_steps,
        recovery_secrets,
        recovery_crypto,
        recovery_bytes,
        recovery_ms,
    }
}

/// Perform a single Update for member `idx`, returning the shared signed operation.
async fn update_member(peers: &mut [Peer], idx: usize, csprng: &mut rand::rngs::OsRng) -> SharedOp {
    let signer = peers[idx].signer.clone();
    let new_sk = ShareSecretKey::generate(csprng);
    let new_pk = new_sk.share_key();
    let (_pcs_key, op) = peers[idx]
        .cgka
        .update::<future_form::Local, _, _>(new_pk, new_sk, &signer, csprng)
        .await
        .expect("member update");
    peers[idx].current_sk = new_sk;
    peers[idx].current_pk = new_pk;
    Arc::new(op)
}

fn total_crypto(c: &PrimitiveCounters) -> u64 {
    c.hash + c.kdf + c.prf + c.keygen + c.dh + c.aead_encrypt + c.aead_decrypt + c.sign + c.verify
}

fn parse_usize_list(raw: &str) -> Vec<usize> {
    raw.split(',')
        .map(|part| part.trim().parse::<usize>().expect("usize list entry"))
        .collect()
}

fn write_csv(path: &PathBuf, rows: &[Row]) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "iteration,group_size,partitions,total_updates,avg_updates_per_member,distinct_updaters,\
         conflicts_after_merge,first_secrets,first_crypto,first_bytes,first_ms,\
         recovery_steps,recovery_secrets,recovery_crypto,recovery_bytes,recovery_ms"
    )?;
    for row in rows {
        writeln!(
            writer,
            "{},{},{},{},{:.6},{},{},{},{},{},{:.6},{},{},{},{},{:.6}",
            row.iteration,
            row.group_size,
            row.partitions,
            row.total_updates,
            row.avg_updates_per_member,
            row.distinct_updaters,
            row.conflicts_after_merge,
            row.first_secrets,
            row.first_crypto,
            row.first_bytes,
            row.first_ms,
            row.recovery_steps,
            row.recovery_secrets,
            row.recovery_crypto,
            row.recovery_bytes,
            row.recovery_ms,
        )?;
    }
    Ok(())
}
