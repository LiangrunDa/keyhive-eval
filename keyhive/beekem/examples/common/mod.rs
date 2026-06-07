//! Shared, pre-measurement helpers for the BeeKEM evaluation examples.
//!
//! Everything here builds and warms up group state *before* `instrumentation::reset()`,
//! or is a pure serialization helper. The measured operations and CSV writers live in the
//! individual example binaries, since they differ between the group-size and history sweeps.

use std::sync::Arc;

use beekem::{
    cgka::Cgka,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    operation::CgkaOperation,
};
use future_form::Local;
use keyhive_crypto::{
    instrumentation,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};

#[derive(Clone)]
pub struct Peer {
    // `id` is read by the group-size sweep (remove/add) and unused by the history sweep.
    #[allow(dead_code)]
    pub id: MemberId,
    pub signer: MemorySigner,
    pub current_sk: ShareSecretKey,
    pub current_pk: ShareKey,
    pub cgka: Cgka,
}

pub struct PendingPeer {
    pub id: MemberId,
    pub signer: MemorySigner,
    pub sk: ShareSecretKey,
    pub pk: ShareKey,
}

pub fn make_pending_peer(csprng: &mut rand::rngs::OsRng) -> PendingPeer {
    let signer = MemorySigner::generate(csprng);
    let id = MemberId(signer.verifying_key());
    let sk = ShareSecretKey::generate(csprng);
    let pk = sk.share_key();
    PendingPeer { id, signer, sk, pk }
}

pub async fn setup_group(group_size: usize, csprng: &mut rand::rngs::OsRng) -> Vec<Peer> {
    let doc_signer = MemorySigner::generate(csprng);
    let doc_id = TreeId(doc_signer.verifying_key());
    let mut peers = Vec::new();
    let first = make_pending_peer(csprng);
    let mut owner = Cgka::new::<Local, _>(doc_id, first.id, first.pk, &first.signer)
        .await
        .expect("new cgka");
    owner.owner_sks.insert(first.pk, first.sk);
    peers.push(Peer {
        id: first.id,
        signer: first.signer,
        current_sk: first.sk,
        current_pk: first.pk,
        cgka: owner,
    });

    for _ in 1..group_size {
        let pending = make_pending_peer(csprng);
        let signer = peers[0].signer.clone();
        let op = peers[0]
            .cgka
            .add::<Local, _>(pending.id, pending.pk, &signer)
            .await
            .expect("setup add")
            .expect("setup add op");
        for peer in peers.iter_mut().skip(1) {
            peer.cgka
                .merge_concurrent_operation(Arc::new(op.clone()))
                .expect("setup merge add");
        }
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(pending.pk, pending.sk);
        let cgka = peers[0]
            .cgka
            .with_new_owner(pending.id, owner_sks)
            .expect("setup with new owner");
        peers.push(Peer {
            id: pending.id,
            signer: pending.signer,
            current_sk: pending.sk,
            current_pk: pending.pk,
            cgka,
        });
    }

    instrumentation::reset();
    peers
}

pub async fn preload_updates(peers: &mut [Peer], csprng: &mut rand::rngs::OsRng) {
    for sender_idx in 0..peers.len() {
        let sender_signer = peers[sender_idx].signer.clone();
        let new_sk = ShareSecretKey::generate(csprng);
        let new_pk = new_sk.share_key();
        let (_pcs_key, op) = peers[sender_idx]
            .cgka
            .update::<Local, _, _>(new_pk, new_sk, &sender_signer, csprng)
            .await
            .expect("preload update");
        peers[sender_idx].current_sk = new_sk;
        peers[sender_idx].current_pk = new_pk;
        let op = Arc::new(op);
        for (peer_idx, peer) in peers.iter_mut().enumerate() {
            if peer_idx == sender_idx {
                continue;
            }
            peer.cgka
                .merge_concurrent_operation(op.clone())
                .expect("preload merge update");
        }
    }
    instrumentation::reset();
}

pub fn serialized_len(op: &Signed<CgkaOperation>) -> usize {
    bincode::serialize(op).expect("serialize op").len()
}

pub fn history_bytes(history: &nonempty::NonEmpty<beekem::operation::CgkaEpoch>) -> usize {
    history
        .iter()
        .flat_map(|epoch| epoch.iter())
        .map(|op| serialized_len(op.as_ref()))
        .sum()
}
