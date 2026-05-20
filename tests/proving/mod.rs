//! Test proving by means of verifying outputed proofs\
//! with the gnark solana verifier

use std::path::PathBuf;

use acir::AcirField;
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use gnark_verifier_solana::{GnarkProof, GnarkVerifier, GnarkWitness, parse_vk};

use sunspot_wasm::{GnarkWitness as SunspotWitness, Proof, prove, solve};

use crate::{gnark_witness, proving_key, r1cs};

#[test]
fn polynomial() {
    run::<1, 0>("polynomial");
}

#[test]
fn poseidon2() {
    run::<4, 0>("poseidon2");
}

#[test]
fn range() {
    run::<1, 1>("range");
}

#[test]
fn blake2s() {
    run::<0, 1>("blake2s");
}

#[test]
fn keccak_f1600() {
    run::<0, 1>("keccak_f1600");
}

#[test]
fn passport_like() {
    run::<128, 1>("passport_like");
}

fn run<const NR_INPUTS: usize, const N_COMMITMENTS: usize>(name: &str) {
    let r1cs = r1cs(name);
    let partial = gnark_witness(name);
    let pk = proving_key(name);

    let pk_keys = if pk.commitment_keys.is_empty() {
        None
    } else {
        Some(pk.commitment_keys.as_slice())
    };
    let solved = solve(&r1cs, &partial, pk_keys).expect("solve");
    let proof = prove(&r1cs, solved, &pk).expect("prove");
    assert!(proof.is_valid(), "proof failed structural checks");

    let vk_file =
        std::fs::File::open(vk_path(name)).unwrap_or_else(|e| panic!("open {}.vk: {e}", name));
    let vk = parse_vk(vk_file).expect("parse_vk");

    let gnark_proof = to_gnark_proof::<N_COMMITMENTS>(&proof);
    let gnark_witness = to_gnark_witness::<NR_INPUTS>(&partial);

    let mut verifier = GnarkVerifier::<'_, NR_INPUTS>::new(&vk);
    verifier
        .verify(gnark_proof, gnark_witness)
        .unwrap_or_else(|e| panic!("verify {name}: {e:?}"));
}

fn vk_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/noir_projects")
        .join(name)
        .join("target")
        .join(format!("{name}.vk"))
}

/// X || Y big-endian. `Affine::xy()` returns `None` for the identity; the
/// alt_bn128 syscalls expect 64 zero bytes there, which is what the zero-
/// initialised buffer yields.
fn g1_to_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    out
}

/// Gnark G2 layout: X.c1 || X.c0 || Y.c1 || Y.c0, each 32 bytes big-endian.
/// Identity → 128 zero bytes.
fn g2_to_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
        out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
        out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    }
    out
}

fn to_gnark_proof<const N_COMMITMENTS: usize>(p: &Proof) -> GnarkProof<N_COMMITMENTS> {
    assert_eq!(
        p.commitments.len(),
        N_COMMITMENTS,
        "GnarkProof const-generic must match runtime commitment count",
    );
    GnarkProof {
        ar: g1_to_bytes(&p.ar),
        bs: g2_to_bytes(&p.bs),
        krs: g1_to_bytes(&p.krs),
        commitments: p.commitments.iter().map(g1_to_bytes).collect(),
        commitment_pok: g1_to_bytes(&p.commitment_pok),
    }
}

fn to_gnark_witness<const NR_INPUTS: usize>(w: &SunspotWitness) -> GnarkWitness<NR_INPUTS> {
    assert_eq!(
        w.public.len(),
        NR_INPUTS,
        "GnarkWitness const-generic must match runtime public-input count",
    );
    let mut entries = [[0u8; 32]; NR_INPUTS];
    for (i, fe) in w.public.iter().enumerate() {
        entries[i].copy_from_slice(&fe.to_be_bytes());
    }
    GnarkWitness { entries }
}
