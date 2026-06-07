use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use beekem::{keys::ShareKeyMap, operation::CgkaOperation};
use future_form::Local;
use keyhive_crypto::{
    instrumentation::{self, PrimitiveCounters},
    share_key::ShareSecretKey,
    signed::Signed,
};

mod common;
use common::{history_bytes, make_pending_peer, preload_updates, serialized_len, setup_group, Peer};

const DEFAULT_GROUP_SIZE: usize = 32;
const DEFAULT_HISTORY_SIZES: &[usize] = &[0, 1, 2, 4, 8, 16, 32, 64];

struct Row {
    protocol: &'static str,
    operation: &'static str,
    group_size: usize,
    history_size: usize,
    effective_history_ops: usize,
    role: &'static str,
    receiver_index: isize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    network_bytes: usize,
    wall_clock_ms: f64,
    counters: PrimitiveCounters,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("evaluation-results/beekem-history-smoke"));
    let group_size = env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_GROUP_SIZE);
    let history_sizes = env::args()
        .nth(3)
        .map(|s| parse_history_sizes(&s))
        .unwrap_or_else(|| DEFAULT_HISTORY_SIZES.to_vec());

    fs::create_dir_all(&output_dir).expect("create output dir");
    let primitives_path = output_dir.join("beekem-history-primitives.csv");
    let summary_path = output_dir.join("beekem-history-summary.csv");

    let mut rows = Vec::new();
    for history_size in history_sizes {
        rows.extend(run_case(group_size, history_size).await);
        eprintln!("finished n={group_size} history_size={history_size}");
    }

    write_primitives(&primitives_path, &rows).expect("write primitive csv");
    write_summary(&summary_path, &rows).expect("write summary csv");
}

async fn run_case(group_size: usize, history_size: usize) -> Vec<Row> {
    let mut csprng = rand::rngs::OsRng;
    let mut peers = setup_group(group_size, &mut csprng).await;
    preload_updates(&mut peers, &mut csprng).await;
    apply_history_updates(&mut peers, history_size, &mut csprng).await;
    instrumentation::reset();

    let mut rows = Vec::new();
    let start = Instant::now();
    let pending = make_pending_peer(&mut csprng);
    let sender_signer = peers[0].signer.clone();

    instrumentation::reset();
    let add_op = peers[0]
        .cgka
        .add::<Local, _>(pending.id, pending.pk, &sender_signer)
        .await
        .expect("add")
        .expect("add op");
    let sender_counters = instrumentation::snapshot();
    let add_bytes = serialized_len(&add_op);
    let history = peers[0].cgka.ops().expect("history ops");
    let welcome_bytes = history_bytes(&history);
    let effective_history_ops = count_history_ops(&history);

    rows.push(row(
        group_size,
        history_size,
        effective_history_ops,
        "sender",
        -1,
        add_bytes,
        welcome_bytes,
        add_bytes + welcome_bytes,
        sender_counters,
        start.elapsed().as_secs_f64() * 1000.0,
    ));

    deliver_op(
        &mut peers[1..],
        &add_op,
        &mut rows,
        group_size,
        history_size,
        effective_history_ops,
        add_bytes,
    );

    let mut new_owner_sks = ShareKeyMap::new();
    new_owner_sks.insert(pending.pk, pending.sk);
    let mut new_peer_cgka = peers[0]
        .cgka
        .with_new_owner(pending.id, new_owner_sks)
        .expect("new owner state");
    instrumentation::reset();
    for epoch in history {
        for op in epoch {
            op.try_verify().expect("verify history op");
            new_peer_cgka
                .merge_concurrent_operation(op)
                .expect("merge history op");
        }
    }
    rows.push(row(
        group_size,
        history_size,
        effective_history_ops,
        "new_receiver",
        -1,
        0,
        welcome_bytes,
        welcome_bytes,
        instrumentation::snapshot(),
        0.0,
    ));

    add_system_row(
        &mut rows,
        group_size,
        history_size,
        effective_history_ops,
        add_bytes * (group_size - 1) + welcome_bytes,
        start,
    );

    rows
}

async fn apply_history_updates(
    peers: &mut [Peer],
    history_size: usize,
    csprng: &mut rand::rngs::OsRng,
) {
    for history_index in 0..history_size {
        let sender_idx = history_index % peers.len();
        let sender_signer = peers[sender_idx].signer.clone();
        let new_sk = ShareSecretKey::generate(csprng);
        let new_pk = new_sk.share_key();
        let (_pcs_key, op) = peers[sender_idx]
            .cgka
            .update::<Local, _, _>(new_pk, new_sk, &sender_signer, csprng)
            .await
            .expect("history update");
        peers[sender_idx].current_sk = new_sk;
        peers[sender_idx].current_pk = new_pk;
        let op = Arc::new(op);
        for (peer_idx, peer) in peers.iter_mut().enumerate() {
            if peer_idx == sender_idx {
                continue;
            }
            peer.cgka
                .merge_concurrent_operation(op.clone())
                .expect("history merge update");
        }
    }
    instrumentation::reset();
}

fn deliver_op(
    receivers: &mut [Peer],
    op: &Signed<CgkaOperation>,
    rows: &mut Vec<Row>,
    group_size: usize,
    history_size: usize,
    effective_history_ops: usize,
    broadcast_bytes: usize,
) {
    for (idx, peer) in receivers.iter_mut().enumerate() {
        instrumentation::reset();
        let delivered: Signed<CgkaOperation> =
            bincode::deserialize(&bincode::serialize(op).expect("serialize op"))
                .expect("deserialize op");
        delivered.try_verify().expect("verify delivered op");
        peer.cgka
            .merge_concurrent_operation(Arc::new(delivered))
            .expect("merge delivered op");
        rows.push(row(
            group_size,
            history_size,
            effective_history_ops,
            "receiver",
            idx as isize,
            broadcast_bytes,
            0,
            broadcast_bytes,
            instrumentation::snapshot(),
            0.0,
        ));
    }
}

fn count_history_ops(history: &nonempty::NonEmpty<beekem::operation::CgkaEpoch>) -> usize {
    history.iter().map(|epoch| epoch.len()).sum()
}

fn row(
    group_size: usize,
    history_size: usize,
    effective_history_ops: usize,
    role: &'static str,
    receiver_index: isize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    network_bytes: usize,
    counters: PrimitiveCounters,
    wall_clock_ms: f64,
) -> Row {
    Row {
        protocol: "beekem",
        operation: "add",
        group_size,
        history_size,
        effective_history_ops,
        role,
        receiver_index,
        broadcast_bytes,
        welcome_bytes,
        network_bytes,
        wall_clock_ms,
        counters,
    }
}

fn add_system_row(
    rows: &mut Vec<Row>,
    group_size: usize,
    history_size: usize,
    effective_history_ops: usize,
    network_bytes: usize,
    start: Instant,
) {
    let mut counters = PrimitiveCounters::default();
    for row in rows
        .iter()
        .filter(|row| row.group_size == group_size && row.history_size == history_size)
    {
        counters.hash += row.counters.hash;
        counters.kdf += row.counters.kdf;
        counters.prf += row.counters.prf;
        counters.keygen += row.counters.keygen;
        counters.dh += row.counters.dh;
        counters.aead_encrypt += row.counters.aead_encrypt;
        counters.aead_decrypt += row.counters.aead_decrypt;
        counters.sign += row.counters.sign;
        counters.verify += row.counters.verify;
    }

    rows.push(row(
        group_size,
        history_size,
        effective_history_ops,
        "system",
        -1,
        0,
        0,
        network_bytes,
        counters,
        start.elapsed().as_secs_f64() * 1000.0,
    ));
}

fn parse_history_sizes(raw: &str) -> Vec<usize> {
    raw.split(',')
        .map(|part| part.parse::<usize>().expect("history size"))
        .collect()
}

fn write_primitives(path: &PathBuf, rows: &[Row]) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "protocol,operation,group_size,history_size,effective_history_ops,role,receiver_index,broadcast_bytes,welcome_bytes,network_bytes,wall_clock_ms,hash,kdf,prf,keygen,dh,aead_encrypt,aead_decrypt,sign,verify"
    )?;
    for row in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{},{},{},{},{},{},{}",
            row.protocol,
            row.operation,
            row.group_size,
            row.history_size,
            row.effective_history_ops,
            row.role,
            row.receiver_index,
            row.broadcast_bytes,
            row.welcome_bytes,
            row.network_bytes,
            row.wall_clock_ms,
            row.counters.hash,
            row.counters.kdf,
            row.counters.prf,
            row.counters.keygen,
            row.counters.dh,
            row.counters.aead_encrypt,
            row.counters.aead_decrypt,
            row.counters.sign,
            row.counters.verify
        )?;
    }
    Ok(())
}

fn write_summary(path: &PathBuf, rows: &[Row]) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "protocol,operation,group_size,history_size,effective_history_ops,role,total_crypto,network_bytes"
    )?;
    for row in rows {
        let total_crypto = row.counters.hash
            + row.counters.kdf
            + row.counters.prf
            + row.counters.keygen
            + row.counters.dh
            + row.counters.aead_encrypt
            + row.counters.aead_decrypt
            + row.counters.sign
            + row.counters.verify;
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{}",
            row.protocol,
            row.operation,
            row.group_size,
            row.history_size,
            row.effective_history_ops,
            row.role,
            total_crypto,
            row.network_bytes
        )?;
    }
    Ok(())
}
