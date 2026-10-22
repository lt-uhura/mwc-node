//! Exact-input cache of successful fixed-generator, 64-bit range-proof batches.
//! No block identity or chain-state validation is cached. No entries persist.
use super::transaction::Error;
use mwc_crates::lru::LruCache;
use mwc_crates::secp::{pedersen::{Commitment, RangeProof}, Secp256k1};
use std::{num::NonZeroUsize, sync::{LazyLock, Mutex}, time::Instant};

// At most 1 MiB of key payload; large batches retain the original verifier path.
const ENTRIES: usize = 64;
const MAX_KEY_BYTES: usize = 16 * 1024;
struct Cache {
    entries: LruCache<Vec<u8>, ()>,
    since: Instant,
    counts: [u64; 3],
}
impl Cache {
    fn new() -> Self {
        Self { entries: LruCache::new(NonZeroUsize::new(ENTRIES).unwrap()), since: Instant::now(), counts: [0; 3] }
    }
    fn observe(&mut self, outcome: usize) {
        self.counts[outcome] += 1;
        if self.since.elapsed().as_secs() >= 15 {
            mwc_crates::log::info!("body sync proof_cache window_s={:.1} hits={} misses={} bypass={}", self.since.elapsed().as_secs_f64(), self.counts[0], self.counts[1], self.counts[2]);
            self.counts = [0; 3];
            self.since = Instant::now();
        }
    }
}
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::new()));

// Best-effort preverification only. Normal per-block validation remains the
// authority; failures never publish entries or replace its error attribution.
pub(super) fn prime(blocks: &[super::Block], secp: &mut Secp256k1) {
    if !(2..=8).contains(&blocks.len()) { return; }
    if blocks.iter().try_fold(0usize, |n, b| n.checked_add(b.outputs().len())).map_or(true, |n| n > 32) { return; }
    let batches: Vec<_> = blocks.iter().map(|b| (
        b.outputs().iter().map(|o| o.commitment()).collect::<Vec<_>>(),
        b.outputs().iter().map(|o| o.proof).collect::<Vec<_>>()
    )).collect();
    prime_with_cache(&CACHE, &batches, secp);
}

fn prime_with_cache(cache: &Mutex<Cache>, batches: &[(Vec<Commitment>, Vec<RangeProof>)], secp: &mut Secp256k1) {
    if !secp.can_verify_range_proofs() || option_env!("MWC_PROOF_CACHE") == Some("0")
        || !(2..=8).contains(&batches.len()) { return; }
    let mut keys = Vec::new();
    let mut commits = Vec::new();
    let mut proofs = Vec::new();
    for (c, p) in batches {
        if p.len() > 32 - proofs.len() { return; }
        let Some(k) = key(c, p) else { return; };
        keys.push(k);
        commits.extend_from_slice(c);
        proofs.extend_from_slice(p);
    }
    // Native multi-verifier requires equal canonical proof lengths.
    if proofs.windows(2).any(|p| p[0].plen != p[1].plen) { return; }
    let mut timing = util::sync_diagnostics::Metric::ValidationProofs.start();
    if secp.verify_bullet_proof_multi(commits, proofs, None).is_err() { return; }
    timing.success();
    if let Ok(mut cache) = cache.lock() {
        for key in keys { cache.entries.put(key, ()); }
    }
}

// Exact byte equality, not a digest: commitment + proof length + proof bytes
// for every ordered pair. Fixed-width count/length framing prevents ambiguity.
fn key(commits: &[Commitment], proofs: &[RangeProof]) -> Option<Vec<u8>> {
    if commits.is_empty() || commits.len() != proofs.len() { return None; }
    let mut size = 8usize;
    for proof in proofs {
        size = size.checked_add(33 + 8 + proof.bytes().ok()?.len())?;
        if size > MAX_KEY_BYTES { return None; }
    }
    let mut key = Vec::with_capacity(size);
    key.extend_from_slice(&(commits.len() as u64).to_le_bytes());
    for (commit, proof) in commits.iter().zip(proofs) {
        key.extend_from_slice(&commit.0);
        let bytes = proof.bytes().ok()?;
        key.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        key.extend_from_slice(bytes);
    }
    Some(key)
}

pub(super) fn verify(commits: &[Commitment], proofs: &[RangeProof], secp: &mut Secp256k1) -> Result<(), Error> {
    verify_with_cache(&CACHE, commits, proofs, secp)
}

fn verify_with_cache(cache: &Mutex<Cache>, commits: &[Commitment], proofs: &[RangeProof], secp: &mut Secp256k1) -> Result<(), Error> {
    let key = if secp.can_verify_range_proofs() && option_env!("MWC_PROOF_CACHE") != Some("0") { key(commits, proofs) } else { None };
    if let Ok(mut cache) = cache.lock() {
        let hit = key.as_ref().is_some_and(|key| cache.entries.get(key).is_some());
        cache.observe(if hit { 0 } else if key.is_some() { 1 } else { 2 });
        if hit { return Ok(()); }
    }
    // Do not hold the cache mutex during crypto. Only a successful verification
    // can insert an entry; concurrent misses may safely verify the same batch.
    secp.verify_bullet_proof_multi(commits.to_vec(), proofs.to_vec(), None)?;
    if let Some(key) = key {
        if let Ok(mut cache) = cache.lock() { cache.entries.put(key, ()); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mwc_crates::secp::{ContextFlag, SecretKey};
    use mwc_crates::rand::rngs::SysRng;

    #[test]
    fn cross_block_success_primes_exact_members_and_failure_primes_nothing() {
        let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
        let mut batches = Vec::new();
        for value in 1..=4 {
            let blind = SecretKey::new(&secp, &mut SysRng).unwrap();
            let nonce = SecretKey::new(&secp, &mut SysRng).unwrap();
            let commit = secp.commit(value, blind.clone()).unwrap();
            let proof = secp.bullet_proof(value, blind, nonce.clone(), nonce, None, None).unwrap();
            batches.push((vec![commit], vec![proof]));
        }
        let cache = Mutex::new(Cache::new());
        prime_with_cache(&cache, &batches, &mut secp);
        assert_eq!(cache.lock().unwrap().entries.len(), 4);
        for (c, p) in &batches { verify_with_cache(&cache, c, p, &mut secp).unwrap(); }
        assert_eq!(cache.lock().unwrap().counts, [4, 0, 0]);
        for index in 0..4 {
            let empty = Mutex::new(Cache::new());
            let mut invalid = batches.clone();
            invalid[index].1[0].proof[10] ^= 1;
            prime_with_cache(&empty, &invalid, &mut secp);
            assert_eq!(empty.lock().unwrap().entries.len(), 0);
            // The regular path still identifies exactly the invalid member.
            for (i, (c, p)) in invalid.iter().enumerate() {
                assert_eq!(verify_with_cache(&empty, c, p, &mut secp).is_ok(), i != index);
            }
        }
        let empty = Mutex::new(Cache::new());
        let mut mixed_lengths = batches.clone();
        mixed_lengths[0].1[0].plen -= 1;
        prime_with_cache(&empty, &mixed_lengths, &mut secp);
        let mut malformed = batches.clone();
        malformed[0].1[0].plen = mwc_crates::secp::constants::MAX_PROOF_SIZE + 1;
        prime_with_cache(&empty, &malformed, &mut secp);
        let mut mismatched = batches.clone();
        mismatched[0].0.clear();
        prime_with_cache(&empty, &mismatched, &mut secp);
        prime_with_cache(&empty, &batches[..1], &mut secp);
        prime_with_cache(&empty, &vec![batches[0].clone(); 9], &mut secp);
        let oversized = vec![(vec![batches[0].0[0]; 17], vec![batches[0].1[0]; 17]); 2];
        prime_with_cache(&empty, &oversized, &mut secp);
        let mut incapable = Secp256k1::with_caps(ContextFlag::None).unwrap();
        prime_with_cache(&empty, &batches, &mut incapable);
        assert_eq!(empty.lock().unwrap().entries.len(), 0);
        // Valid work still succeeds after all fallback cases.
        prime_with_cache(&empty, &batches, &mut secp);
        assert_eq!(empty.lock().unwrap().entries.len(), 4);
    }

    #[test]
    fn exact_success_is_reused_but_mutations_and_incapable_contexts_fail() {
        let cache = Mutex::new(Cache::new());
        let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
        let blind = SecretKey::new(&secp, &mut SysRng).unwrap();
        let nonce = SecretKey::new(&secp, &mut SysRng).unwrap();
        let commit = secp.commit(42, blind.clone()).unwrap();
        let proof = secp.bullet_proof(42, blind, nonce.clone(), nonce, None, None).unwrap();
        verify_with_cache(&cache, &[commit], &[proof], &mut secp).unwrap();
        verify_with_cache(&cache, &[commit], &[proof], &mut secp).unwrap();
        assert_eq!(cache.lock().unwrap().counts, [1, 1, 0]);
        let mut changed = proof;
        changed.proof[10] ^= 1;
        for _ in 0..2 { assert!(verify_with_cache(&cache, &[commit], &[changed], &mut secp).is_err()); }
        // A batch containing any invalid member must never populate the cache.
        assert!(verify_with_cache(&cache, &[commit, commit], &[proof, changed], &mut secp).is_err());
        assert!(key(&[commit, commit], &[proof, changed]) != key(&[commit, commit], &[changed, proof]));
        let other = secp.commit_value(43).unwrap();
        assert!(verify_with_cache(&cache, &[other], &[proof], &mut secp).is_err());
        let mut short = proof;
        short.plen -= 1;
        assert!(verify_with_cache(&cache, &[commit], &[short], &mut secp).is_err());
        assert!(verify_with_cache(&cache, &[], &[proof], &mut secp).is_err());
        let mut malformed = proof;
        malformed.plen = mwc_crates::secp::constants::MAX_PROOF_SIZE + 1;
        assert!(verify_with_cache(&cache, &[commit], &[malformed], &mut secp).is_err());
        let mut incapable = Secp256k1::with_caps(ContextFlag::None).unwrap();
        assert!(verify_with_cache(&cache, &[commit], &[proof], &mut incapable).is_err());
        assert_eq!(cache.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn keys_are_bounded_and_entries_evict() {
        let mut cache = Cache::new();
        for i in 0..ENTRIES + 1 { cache.entries.put(vec![i as u8], ()); }
        assert_eq!(cache.entries.len(), ENTRIES);
        assert!(cache.entries.get(&vec![0]).is_none());
        let commit = Commitment::from_vec(vec![0; 33]).unwrap();
        let proof = RangeProof::zero();
        let oversized_count = MAX_KEY_BYTES / 41 + 1;
        assert!(key(&vec![commit; oversized_count], &vec![proof; oversized_count]).is_none());
        assert!(key(&[commit], &[]).is_none());
    }
}
