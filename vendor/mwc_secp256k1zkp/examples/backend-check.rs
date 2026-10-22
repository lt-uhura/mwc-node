//! Deterministic public-output differential fixture and optimized microbench.
//! Run both MWC_SECP_BACKEND=32 and =64; fixture lines must match byte-for-byte.
use secp256k1zkp::{ContextFlag, Message, Secp256k1, key::{PublicKey, SecretKey}};
use std::{hint::black_box, time::Instant};

fn main() {
    let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
    let key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
    let commit = secp.commit(12345678, key.clone()).unwrap();
    let proof = secp.bullet_proof(12345678, key.clone(), key.clone(), key.clone(), None, None).unwrap();
    let message = Message::from_slice(&[2; 32]).unwrap();
    let signature = secp.sign(&message, &key).unwrap();
    let public = PublicKey::from_secret_key(&secp, &key).unwrap();
    println!("fixture commit={:?} proof={:?} signature={:?}", commit.0, &proof.proof[..proof.plen], signature.serialize_compact(&secp).unwrap());
    assert!(secp.verify_bullet_proof(commit, proof, None).is_ok());
    let wrong = secp.commit(12345679, key).unwrap();
    assert!(secp.verify_bullet_proof(wrong, proof, None).is_err());
    let mut corrupted = proof;
    corrupted.proof[10] ^= 1;
    assert!(secp.verify_bullet_proof(commit, corrupted, None).is_err());
    let start = Instant::now();
    for _ in 0..10000 { secp.validate_commitment(black_box(&commit)).unwrap(); }
    println!("commitment_parse_us={:.3}", start.elapsed().as_secs_f64()*1e6/10000.0);
    let start = Instant::now();
    for _ in 0..500 { secp.verify_bullet_proof(black_box(commit), black_box(proof), None).unwrap(); }
    println!("bulletproof_verify_us={:.3}", start.elapsed().as_secs_f64()*1e6/500.0);
    let start = Instant::now();
    for _ in 0..2000 { secp.verify(black_box(&message), black_box(&signature), black_box(&public)).unwrap(); }
    println!("ecdsa_verify_us={:.3}", start.elapsed().as_secs_f64()*1e6/2000.0);
}
