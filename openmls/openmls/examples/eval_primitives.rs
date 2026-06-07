use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, StagedWelcome,
    },
    prelude::{KeyPackageBundle, LeafNodeIndex},
    prelude_test::KeyPackage,
    treesync::LeafNodeParameters,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::instrumentation::{
    CounterHandle, InstrumentedOpenMlsRustCrypto, PrimitiveCounters,
};
use openmls_traits::types::Ciphersuite;
use tls_codec::Serialize as TlsSerialize;

// Group-size ladder for the sweep. Defaults to the committed 8..512 (which the
// baselines in expected/ were generated with); override with the comma-separated
// env var EVAL_GROUP_SIZES (e.g. "8,16,32,64,128,256,512,1024") to extend the
// range — useful for separating neighbouring complexity classes. A custom ladder
// no longer matches the committed series baseline, so run.sh stops PASS/FAILing
// the series diff and you classify the regenerated results/ instead.
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

const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[derive(Clone, Copy)]
enum Operation {
    Update,
    Remove,
    Add,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Operation::Update => "update",
            Operation::Remove => "remove",
            Operation::Add => "add",
        }
    }
}

const OPERATIONS: &[Operation] = &[Operation::Update, Operation::Remove, Operation::Add];

struct Member {
    provider: InstrumentedOpenMlsRustCrypto,
    counters: CounterHandle,
    signer: SignatureKeyPair,
}

struct PendingMember {
    provider: InstrumentedOpenMlsRustCrypto,
    counters: CounterHandle,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    key_package: KeyPackageBundle,
}

struct Row {
    protocol: &'static str,
    operation: &'static str,
    group_size: usize,
    iteration: usize,
    role: &'static str,
    receiver_index: isize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    network_bytes: usize,
    wall_clock_ms: f64,
    counters: PrimitiveCounters,
}

fn main() {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("evaluation-results/openmls-smoke"));
    // Optional second arg: number of iterations. Primitive counts are
    // deterministic (identical every iteration); the loop exists only so the
    // wall_clock_ms column has multiple samples to take a median over.
    let iterations = env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    fs::create_dir_all(&output_dir).expect("create output dir");
    let primitives_path = output_dir.join("openmls-primitives.csv");

    let sizes = group_sizes();
    let mut rows = Vec::new();
    for iteration in 0..iterations {
        for &group_size in &sizes {
            for &operation in OPERATIONS {
                rows.extend(run_case(group_size, operation, iteration));
                eprintln!(
                    "finished iteration={iteration} n={group_size} operation={}",
                    operation.as_str()
                );
            }
        }
    }

    write_primitives(&primitives_path, &rows).expect("write primitive csv");
}

fn run_case(group_size: usize, operation: Operation, iteration: usize) -> Vec<Row> {
    let (mut groups, members, config) = setup_group(group_size);
    reset_all(&members);

    let operation_name = operation.as_str();
    let start = Instant::now();
    let mut rows = Vec::new();

    match operation {
        Operation::Update => {
            members[0].counters.reset();
            let t = Instant::now();
            let commit = self_update(&mut groups[0], &members[0]);
            let sender_ms = t.elapsed().as_secs_f64() * 1000.0;
            let sender_counters = members[0].counters.snapshot();
            let broadcast_bytes = serialized_len(&commit);
            rows.push(row(
                group_size,
                operation_name,
                iteration,
                "sender",
                -1,
                broadcast_bytes,
                0,
                broadcast_bytes,
                sender_counters,
                sender_ms,
            ));

            for idx in 1..groups.len() {
                members[idx].counters.reset();
                let t = Instant::now();
                process_commit(&mut groups[idx], &members[idx], commit.clone());
                let receiver_ms = t.elapsed().as_secs_f64() * 1000.0;
                rows.push(row(
                    group_size,
                    operation_name,
                    iteration,
                    "receiver",
                    idx as isize,
                    broadcast_bytes,
                    0,
                    broadcast_bytes,
                    members[idx].counters.snapshot(),
                    receiver_ms,
                ));
            }
            add_system_row(&mut rows, group_size, operation_name, iteration, broadcast_bytes * (group_size - 1), start);
        }
        Operation::Remove => {
            let removed_idx = group_size - 1;
            members[0].counters.reset();
            let t = Instant::now();
            let commit = remove_member(&mut groups[0], &members[0], removed_idx);
            let sender_ms = t.elapsed().as_secs_f64() * 1000.0;
            let sender_counters = members[0].counters.snapshot();
            let broadcast_bytes = serialized_len(&commit);
            rows.push(row(
                group_size,
                operation_name,
                iteration,
                "sender",
                -1,
                broadcast_bytes,
                0,
                broadcast_bytes,
                sender_counters,
                sender_ms,
            ));

            for idx in 1..removed_idx {
                members[idx].counters.reset();
                let t = Instant::now();
                process_commit(&mut groups[idx], &members[idx], commit.clone());
                let receiver_ms = t.elapsed().as_secs_f64() * 1000.0;
                rows.push(row(
                    group_size,
                    operation_name,
                    iteration,
                    "receiver",
                    idx as isize,
                    broadcast_bytes,
                    0,
                    broadcast_bytes,
                    members[idx].counters.snapshot(),
                    receiver_ms,
                ));
            }
            add_system_row(&mut rows, group_size, operation_name, iteration, broadcast_bytes * (group_size - 2), start);
        }
        Operation::Add => {
            let pending = new_member("New Member");
            pending.counters.reset();
            members[0].counters.reset();
            let t = Instant::now();
            let (commit, welcome) = add_member(&mut groups[0], &members[0], pending.key_package.key_package().clone());
            let sender_ms = t.elapsed().as_secs_f64() * 1000.0;
            let sender_counters = members[0].counters.snapshot();
            let broadcast_bytes = serialized_len(&commit);
            let welcome_bytes = serialized_len(&welcome);
            rows.push(row(
                group_size,
                operation_name,
                iteration,
                "sender",
                -1,
                broadcast_bytes,
                welcome_bytes,
                broadcast_bytes + welcome_bytes,
                sender_counters,
                sender_ms,
            ));

            for idx in 1..groups.len() {
                members[idx].counters.reset();
                let t = Instant::now();
                process_commit(&mut groups[idx], &members[idx], commit.clone());
                let receiver_ms = t.elapsed().as_secs_f64() * 1000.0;
                rows.push(row(
                    group_size,
                    operation_name,
                    iteration,
                    "receiver",
                    idx as isize,
                    broadcast_bytes,
                    0,
                    broadcast_bytes,
                    members[idx].counters.snapshot(),
                    receiver_ms,
                ));
            }

            pending.counters.reset();
            let welcome_in: MlsMessageIn = welcome.clone().into();
            let t = Instant::now();
            let staged = StagedWelcome::new_from_welcome(
                &pending.provider,
                config.join_config(),
                welcome_in.into_welcome().expect("welcome message"),
                Some(groups[0].export_ratchet_tree().into()),
            )
            .expect("stage welcome");
            let _new_group = staged.into_group(&pending.provider).expect("join group");
            let new_receiver_ms = t.elapsed().as_secs_f64() * 1000.0;
            rows.push(row(
                group_size,
                operation_name,
                iteration,
                "new_receiver",
                -1,
                0,
                welcome_bytes,
                welcome_bytes,
                pending.counters.snapshot(),
                new_receiver_ms,
            ));

            add_system_row(
                &mut rows,
                group_size,
                operation_name,
                iteration,
                broadcast_bytes * (group_size - 1) + welcome_bytes,
                start,
            );
        }
    }

    rows
}

fn setup_group(group_size: usize) -> (Vec<MlsGroup>, Vec<Member>, MlsGroupCreateConfig) {
    let config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(CIPHERSUITE)
        .build();

    let creator = new_member("Member 0");
    let creator_group = MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &config,
        creator.credential_with_key.clone(),
    )
    .expect("create group");
    let mut groups = vec![creator_group];
    let mut members = vec![Member {
        provider: creator.provider,
        counters: creator.counters,
        signer: creator.signer,
    }];

    for idx in 1..group_size {
        let pending = new_member(&format!("Member {idx}"));
        let (commit, welcome) = add_member(
            &mut groups[0],
            &members[0],
            pending.key_package.key_package().clone(),
        );

        for idx in 1..groups.len() {
            process_commit(&mut groups[idx], &members[idx], commit.clone());
        }

        let welcome_in: MlsMessageIn = welcome.into();
        let mut joined_group = StagedWelcome::new_from_welcome(
            &pending.provider,
            config.join_config(),
            welcome_in.into_welcome().expect("welcome message"),
            Some(groups[0].export_ratchet_tree().into()),
        )
        .expect("stage welcome")
        .into_group(&pending.provider)
        .expect("join group");

        let new_member = Member {
            provider: pending.provider,
            counters: pending.counters,
            signer: pending.signer,
        };

        let update_commit = self_update(&mut joined_group, &new_member);
        for idx in 0..groups.len() {
            process_commit(&mut groups[idx], &members[idx], update_commit.clone());
        }

        groups.push(joined_group);
        members.push(new_member);
    }

    (groups, members, config)
}

fn new_member(name: &str) -> PendingMember {
    let provider = InstrumentedOpenMlsRustCrypto::default();
    let counters = provider.counter_handle();
    let credential = BasicCredential::new(name.as_bytes().to_vec().into());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("signer");
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let key_package = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &provider,
            &signer,
            credential_with_key.clone(),
        )
        .expect("key package");
    PendingMember {
        provider,
        counters,
        signer,
        credential_with_key,
        key_package,
    }
}

fn self_update(group: &mut MlsGroup, member: &Member) -> MlsMessageOut {
    let commit = group
        .self_update(&member.provider, &member.signer, LeafNodeParameters::default())
        .expect("self update")
        .into_commit();
    group
        .merge_pending_commit(&member.provider)
        .expect("merge pending update");
    commit
}

fn remove_member(group: &mut MlsGroup, member: &Member, removed_idx: usize) -> MlsMessageOut {
    let (commit, _, _) = group
        .remove_members(
            &member.provider,
            &member.signer,
            &[LeafNodeIndex::new(removed_idx as u32)],
        )
        .expect("remove member");
    group
        .merge_pending_commit(&member.provider)
        .expect("merge pending remove");
    commit
}

fn add_member(group: &mut MlsGroup, member: &Member, key_package: KeyPackage) -> (MlsMessageOut, MlsMessageOut) {
    let (commit, welcome, _) = group
        .add_members(&member.provider, &member.signer, &[key_package])
        .expect("add member");
    group
        .merge_pending_commit(&member.provider)
        .expect("merge pending add");
    (commit, welcome)
}

fn process_commit(group: &mut MlsGroup, member: &Member, commit: MlsMessageOut) {
    let processed_message = group
        .process_message(
            &member.provider,
            commit.into_protocol_message().expect("protocol message"),
        )
        .expect("process commit");

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        group
            .merge_staged_commit(&member.provider, *staged_commit)
            .expect("merge staged commit");
    } else {
        panic!("expected staged commit");
    }
}

fn reset_all(members: &[Member]) {
    for member in members {
        member.counters.reset();
    }
}

fn serialized_len(message: &MlsMessageOut) -> usize {
    message.tls_serialize_detached().expect("serialize message").len()
}

fn row(
    group_size: usize,
    operation: &'static str,
    iteration: usize,
    role: &'static str,
    receiver_index: isize,
    broadcast_bytes: usize,
    welcome_bytes: usize,
    network_bytes: usize,
    counters: PrimitiveCounters,
    wall_clock_ms: f64,
) -> Row {
    Row {
        protocol: "openmls",
        operation,
        group_size,
        iteration,
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
    operation: &'static str,
    iteration: usize,
    network_bytes: usize,
    start: Instant,
) {
    let mut counters = PrimitiveCounters::default();
    for row in rows
        .iter()
        .filter(|row| {
            row.group_size == group_size
                && row.operation == operation
                && row.iteration == iteration
        })
    {
        counters.hkdf_extract += row.counters.hkdf_extract;
        counters.hmac += row.counters.hmac;
        counters.hkdf_expand += row.counters.hkdf_expand;
        counters.hash += row.counters.hash;
        counters.aead_encrypt += row.counters.aead_encrypt;
        counters.aead_decrypt += row.counters.aead_decrypt;
        counters.signature_key_gen += row.counters.signature_key_gen;
        counters.verify_signature += row.counters.verify_signature;
        counters.sign += row.counters.sign;
        counters.hpke_seal += row.counters.hpke_seal;
        counters.hpke_open += row.counters.hpke_open;
        counters.hpke_setup_sender_and_export += row.counters.hpke_setup_sender_and_export;
        counters.hpke_setup_receiver_and_export += row.counters.hpke_setup_receiver_and_export;
        counters.derive_hpke_keypair += row.counters.derive_hpke_keypair;
        counters.random_calls += row.counters.random_calls;
        counters.random_bytes += row.counters.random_bytes;
        counters.pubkey_ns += row.counters.pubkey_ns;
        counters.sym_ns += row.counters.sym_ns;
    }

    rows.push(row(
        group_size,
        operation,
        iteration,
        "system",
        -1,
        0,
        0,
        network_bytes,
        counters,
        start.elapsed().as_secs_f64() * 1000.0,
    ));
}

fn write_primitives(path: &PathBuf, rows: &[Row]) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "protocol,operation,group_size,role,receiver_index,broadcast_bytes,welcome_bytes,network_bytes,wall_clock_ms,hkdf_extract,hmac,hkdf_expand,hash,aead_encrypt,aead_decrypt,signature_key_gen,verify_signature,sign,hpke_seal,hpke_open,hpke_setup_sender_and_export,hpke_setup_receiver_and_export,derive_hpke_keypair,random_calls,random_bytes,iteration,pubkey_ms,sym_ms"
    )?;
    for row in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{:.6},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6}",
            row.protocol,
            row.operation,
            row.group_size,
            row.role,
            row.receiver_index,
            row.broadcast_bytes,
            row.welcome_bytes,
            row.network_bytes,
            row.wall_clock_ms,
            row.counters.hkdf_extract,
            row.counters.hmac,
            row.counters.hkdf_expand,
            row.counters.hash,
            row.counters.aead_encrypt,
            row.counters.aead_decrypt,
            row.counters.signature_key_gen,
            row.counters.verify_signature,
            row.counters.sign,
            row.counters.hpke_seal,
            row.counters.hpke_open,
            row.counters.hpke_setup_sender_and_export,
            row.counters.hpke_setup_receiver_and_export,
            row.counters.derive_hpke_keypair,
            row.counters.random_calls,
            row.counters.random_bytes,
            row.iteration,
            row.counters.pubkey_ns as f64 / 1.0e6,
            row.counters.sym_ns as f64 / 1.0e6,
        )?;
    }
    Ok(())
}
