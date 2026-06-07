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

// Group-size ladder for the sweep. Defaults to the committed 8..512 (which the
// baselines in expected/ were generated with); override with the comma-separated
// env var EVAL_GROUP_SIZES (e.g. "8,16,32,64,128,256,512,1024") to extend the
// range. A custom ladder no longer matches the committed series baseline, so
// run.sh stops PASS/FAILing the series diff and you classify results/ instead.
const DEFAULT_GROUP_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512];

fn group_sizes() -> Vec<usize> {
    match env::var("EVAL_GROUP_SIZES") {
        Ok(s) if !s.trim().is_empty() => {
            let v: Vec<usize> = s
                .split(',')
                .filter_map(|t| t.trim().parse::<usize>().ok())
                .filter(|&n| n >= 2)
                .collect();
            if v.is_empty() {
                DEFAULT_GROUP_SIZES.to_vec()
            } else {
                v
            }
        }
        _ => DEFAULT_GROUP_SIZES.to_vec(),
    }
}

const OPERATIONS: &[Operation] = &[
    Operation::Update,
    Operation::RemoveThenUpdate,
    Operation::AddThenUpdate,
];

#[derive(Clone, Copy, Debug)]
enum Operation {
    Update,
    RemoveThenUpdate,
    AddThenUpdate,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Operation::Update => "update",
            Operation::RemoveThenUpdate => "remove_then_update",
            Operation::AddThenUpdate => "add_then_update",
        }
    }
}

struct Row {
    protocol: &'static str,
    operation: &'static str,
    group_size: usize,
    history_size: usize,
    role: &'static str,
    receiver_index: isize,
    iteration: usize,
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
        .unwrap_or_else(|| PathBuf::from("evaluation-results/beekem-smoke"));
    let iterations = env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5);

    fs::create_dir_all(&output_dir).expect("create output dir");
    let primitives_path = output_dir.join("beekem-primitives.csv");

    let sizes = group_sizes();
    let mut primitive_rows = Vec::new();
    for iteration in 0..iterations {
        for &group_size in &sizes {
            for &operation in OPERATIONS {
                let rows = run_case(group_size, operation, iteration).await;
                primitive_rows.extend(rows);
                eprintln!(
                    "finished iteration={iteration} n={group_size} operation={}",
                    operation.as_str()
                );
            }
        }
    }

    write_primitives(&primitives_path, &primitive_rows).expect("write primitive csv");
}

async fn run_case(group_size: usize, operation: Operation, iteration: usize) -> Vec<Row> {
    let mut csprng = rand::rngs::OsRng;
    let mut peers = setup_group(group_size, &mut csprng).await;
    preload_updates(&mut peers, &mut csprng).await;

    let mut rows = Vec::new();
    let start = Instant::now();
    let operation_name = operation.as_str();

    match operation {
        Operation::Update => {
            let op = measured_update_sender(&mut peers[0], &mut csprng, &mut rows, group_size, operation_name, iteration).await;
            let broadcast_bytes = serialized_len(&op);
            deliver_op(
                &mut peers[1..],
                &op,
                &mut rows,
                group_size,
                operation_name,
                iteration,
                broadcast_bytes,
                0,
            );
            add_system_row(&mut rows, group_size, operation_name, iteration, broadcast_bytes, 0, start);
        }
        Operation::RemoveThenUpdate => {
            let removed_id = peers[group_size - 1].id;
            let sender_signer = peers[0].signer.clone();
            instrumentation::reset();
            let t = Instant::now();
            let remove_op = peers[0]
                .cgka
                .remove::<Local, _>(removed_id, &sender_signer)
                .await
                .expect("remove")
                .expect("remove op");
            let new_sk = ShareSecretKey::generate(&mut csprng);
            let new_pk = new_sk.share_key();
            let (_pcs_key, update_op) = peers[0]
                .cgka
                .update::<Local, _, _>(new_pk, new_sk, &sender_signer, &mut csprng)
                .await
                .expect("post-remove update");
            let sender_elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
            peers[0].current_sk = new_sk;
            peers[0].current_pk = new_pk;
            let sender_counters = instrumentation::snapshot();
            let remove_bytes = serialized_len(&remove_op);
            let update_bytes = serialized_len(&update_op);
            rows.push(row(
                group_size,
                operation_name,
                "sender",
                -1,
                iteration,
                remove_bytes + update_bytes,
                0,
                sender_counters,
            ));
            rows.last_mut().unwrap().wall_clock_ms = sender_elapsed_ms;

            let receivers = &mut peers[1..group_size - 1];
            deliver_two_ops(
                receivers,
                &remove_op,
                &update_op,
                &mut rows,
                group_size,
                operation_name,
                iteration,
                remove_bytes + update_bytes,
                0,
            );
            add_system_row(
                &mut rows,
                group_size,
                operation_name,
                iteration,
                remove_bytes + update_bytes,
                0,
                start,
            );
        }
        Operation::AddThenUpdate => {
            let pending = make_pending_peer(&mut csprng);
            let sender_signer = peers[0].signer.clone();
            instrumentation::reset();
            let t = Instant::now();
            let add_op = peers[0]
                .cgka
                .add::<Local, _>(pending.id, pending.pk, &sender_signer)
                .await
                .expect("add")
                .expect("add op");
            let new_sk = ShareSecretKey::generate(&mut csprng);
            let new_pk = new_sk.share_key();
            let (_pcs_key, update_op) = peers[0]
                .cgka
                .update::<Local, _, _>(new_pk, new_sk, &sender_signer, &mut csprng)
                .await
                .expect("post-add update");
            let sender_elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
            peers[0].current_sk = new_sk;
            peers[0].current_pk = new_pk;
            let sender_counters = instrumentation::snapshot();
            let add_bytes = serialized_len(&add_op);
            let update_bytes = serialized_len(&update_op);
            let history = peers[0].cgka.ops().expect("history ops");
            let welcome_bytes = history_bytes(&history);
            rows.push(row(
                group_size,
                operation_name,
                "sender",
                -1,
                iteration,
                add_bytes + update_bytes,
                welcome_bytes,
                sender_counters,
            ));
            rows.last_mut().unwrap().wall_clock_ms = sender_elapsed_ms;

            deliver_two_ops(
                &mut peers[1..],
                &add_op,
                &update_op,
                &mut rows,
                group_size,
                operation_name,
                iteration,
                add_bytes + update_bytes,
                welcome_bytes,
            );

            let mut new_owner_sks = ShareKeyMap::new();
            new_owner_sks.insert(pending.pk, pending.sk);
            let mut new_peer_cgka = peers[0]
                .cgka
                .with_new_owner(pending.id, new_owner_sks)
                .expect("new owner state");
            instrumentation::reset();
            let t = Instant::now();
            for epoch in history {
                for op in epoch {
                    op.try_verify().expect("verify history op");
                    new_peer_cgka
                        .merge_concurrent_operation(op)
                        .expect("merge history op");
                }
            }
            let new_receiver_elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
            rows.push(row(
                group_size,
                operation_name,
                "new_receiver",
                -1,
                iteration,
                add_bytes + update_bytes,
                welcome_bytes,
                instrumentation::snapshot(),
            ));
            rows.last_mut().unwrap().wall_clock_ms = new_receiver_elapsed_ms;

            add_system_row(
                &mut rows,
                group_size,
                operation_name,
                iteration,
                add_bytes + update_bytes,
                welcome_bytes,
                start,
            );
        }
    }

    rows
}

async fn measured_update_sender(
    peer: &mut Peer,
    csprng: &mut rand::rngs::OsRng,
    rows: &mut Vec<Row>,
    group_size: usize,
    operation: &'static str,
    iteration: usize,
) -> Signed<CgkaOperation> {
    instrumentation::reset();
    let t = Instant::now();
    let new_sk = ShareSecretKey::generate(csprng);
    let new_pk = new_sk.share_key();
    let (_pcs_key, op) = peer
        .cgka
        .update::<Local, _, _>(new_pk, new_sk, &peer.signer, csprng)
        .await
        .expect("update");
    let elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
    peer.current_sk = new_sk;
    peer.current_pk = new_pk;
    let counters = instrumentation::snapshot();
    let broadcast_bytes = serialized_len(&op);
    rows.push(row(
        group_size,
        operation,
        "sender",
        -1,
        iteration,
        broadcast_bytes,
        0,
        counters,
    ));
    rows.last_mut().unwrap().wall_clock_ms = elapsed_ms;
    op
}

fn deliver_op(
    receivers: &mut [Peer],
    op: &Signed<CgkaOperation>,
    rows: &mut Vec<Row>,
    group_size: usize,
    operation: &'static str,
    iteration: usize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
) {
    for (idx, peer) in receivers.iter_mut().enumerate() {
        instrumentation::reset();
        let delivered: Signed<CgkaOperation> =
            bincode::deserialize(&bincode::serialize(op).expect("serialize op"))
                .expect("deserialize op");
        let t = Instant::now();
        delivered.try_verify().expect("verify delivered op");
        peer.cgka
            .merge_concurrent_operation(Arc::new(delivered))
            .expect("merge delivered op");
        let elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
        rows.push(row(
            group_size,
            operation,
            "receiver",
            idx as isize,
            iteration,
            broadcast_bytes,
            welcome_bytes,
            instrumentation::snapshot(),
        ));
        rows.last_mut().unwrap().wall_clock_ms = elapsed_ms;
    }
}

fn deliver_two_ops(
    receivers: &mut [Peer],
    first: &Signed<CgkaOperation>,
    second: &Signed<CgkaOperation>,
    rows: &mut Vec<Row>,
    group_size: usize,
    operation: &'static str,
    iteration: usize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
) {
    for (idx, peer) in receivers.iter_mut().enumerate() {
        instrumentation::reset();
        let mut elapsed_ms = 0.0;
        for op in [first, second] {
            let delivered: Signed<CgkaOperation> =
                bincode::deserialize(&bincode::serialize(op).expect("serialize op"))
                    .expect("deserialize op");
            let t = Instant::now();
            delivered.try_verify().expect("verify delivered op");
            peer.cgka
                .merge_concurrent_operation(Arc::new(delivered))
                .expect("merge delivered op");
            elapsed_ms += t.elapsed().as_secs_f64() * 1000.0;
        }
        rows.push(row(
            group_size,
            operation,
            "receiver",
            idx as isize,
            iteration,
            broadcast_bytes,
            welcome_bytes,
            instrumentation::snapshot(),
        ));
        rows.last_mut().unwrap().wall_clock_ms = elapsed_ms;
    }
}

fn row(
    group_size: usize,
    operation: &'static str,
    role: &'static str,
    receiver_index: isize,
    iteration: usize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    counters: PrimitiveCounters,
) -> Row {
    Row {
        protocol: "beekem",
        operation,
        group_size,
        history_size: 0,
        role,
        receiver_index,
        iteration,
        broadcast_bytes,
        welcome_bytes,
        network_bytes: broadcast_bytes + welcome_bytes,
        wall_clock_ms: 0.0,
        counters,
    }
}

fn add_system_row(
    rows: &mut Vec<Row>,
    group_size: usize,
    operation: &'static str,
    iteration: usize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    start: Instant,
) {
    let mut counters = PrimitiveCounters::default();
    for row in rows
        .iter()
        .filter(|row| row.group_size == group_size && row.operation == operation && row.iteration == iteration)
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
        counters.pubkey_ns += row.counters.pubkey_ns;
        counters.sym_ns += row.counters.sym_ns;
    }
    let mut system = row(
        group_size,
        operation,
        "system",
        -1,
        iteration,
        broadcast_bytes,
        welcome_bytes,
        counters,
    );
    system.wall_clock_ms = start.elapsed().as_secs_f64() * 1000.0;
    rows.push(system);
}

fn write_primitives(path: &PathBuf, rows: &[Row]) -> std::io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    writeln!(
        out,
        "protocol,operation,group_size,history_size,role,receiver_index,iteration,broadcast_bytes,welcome_bytes,network_bytes,wall_clock_ms,hash,kdf,prf,keygen,dh,aead_encrypt,aead_decrypt,sign,verify,pubkey_ms,sym_ms"
    )?;
    for row in rows {
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{},{},{:.6},{:.6}",
            row.protocol,
            row.operation,
            row.group_size,
            row.history_size,
            row.role,
            row.receiver_index,
            row.iteration,
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
            row.counters.verify,
            row.counters.pubkey_ns as f64 / 1.0e6,
            row.counters.sym_ns as f64 / 1.0e6,
        )?;
    }
    Ok(())
}
