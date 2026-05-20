//! `#[wasm_bindgen]` adapters. Pure-Rust
//! callers should reach for [`crate::types`] and the `from_bytes` methods on
//! those types directly; this module is only a thin shim across the wasm
//! boundary.
//!
//! Threading: JS must call `initThreadPool(navigator.hardwareConcurrency)`
//! after `init()` and before invoking the solver. The host page must be
//! cross-origin isolated (`COOP: same-origin`, `COEP: require-corp`) for
//! `SharedArrayBuffer` to be available.

use acir::AcirField;
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use wasm_bindgen::prelude::*;

use crate::types;

pub use wasm_bindgen_rayon::init_thread_pool;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub struct GnarkWitness(types::GnarkWitness);

#[wasm_bindgen]
impl GnarkWitness {
    /// Build the gnark-ordered witness vector from a Noir ACIR JSON artifact
    /// and a gzipped witness-stack (`*.gz`) blob.
    #[wasm_bindgen(constructor)]
    pub fn new(
        acir_json_bytes: &[u8],
        witness_stack_bytes: &[u8],
    ) -> Result<GnarkWitness, JsError> {
        types::GnarkWitness::from_bytes(acir_json_bytes, witness_stack_bytes)
            .map(GnarkWitness)
            .map_err(err)
    }

    /// Concatenated 32-byte big-endian limbs of the public witness slots.
    pub fn public_bytes(&self) -> Vec<u8> {
        flatten(&self.0.public)
    }

    /// Concatenated 32-byte big-endian limbs of the private witness slots.
    pub fn private_bytes(&self) -> Vec<u8> {
        flatten(&self.0.private)
    }
}

fn flatten(elems: &[acir::FieldElement]) -> Vec<u8> {
    let mut out = Vec::with_capacity(elems.len() * 32);
    for fe in elems {
        out.extend_from_slice(&fe.to_be_bytes());
    }
    out
}

#[wasm_bindgen]
pub struct R1CS(types::R1CS);

#[wasm_bindgen]
impl R1CS {
    /// Parse a `*.ccs` constraint-system blob (gnark wire format).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<R1CS, JsError> {
        types::R1CS::from_bytes(bytes).map(R1CS).map_err(err)
    }
}

#[wasm_bindgen]
pub struct ProvingKey(types::ProvingKey);

#[wasm_bindgen]
impl ProvingKey {
    /// Parse a gnark Groth16 `*.pk` proving key (uncompressed BN254 points).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<ProvingKey, JsError> {
        types::ProvingKey::from_bytes(bytes)
            .map(ProvingKey)
            .map_err(err)
    }
}

/// Groth16+BSB22 proof. Byte accessors return curve points in the gnark
/// wire format consumed by the alt_bn128 syscalls (G1: X||Y, G2:
/// X.c1||X.c0||Y.c1||Y.c0, all 32-byte big-endian limbs).
#[wasm_bindgen]
pub struct Proof(types::Proof);

#[wasm_bindgen]
impl Proof {
    pub fn ar_bytes(&self) -> Vec<u8> {
        g1_to_bytes(&self.0.ar).to_vec()
    }
    pub fn bs_bytes(&self) -> Vec<u8> {
        g2_to_bytes(&self.0.bs).to_vec()
    }
    pub fn krs_bytes(&self) -> Vec<u8> {
        g1_to_bytes(&self.0.krs).to_vec()
    }
    /// Concatenated 64-byte gnark-format limbs, one per Pedersen commitment.
    pub fn commitments_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.commitments.len() * 64);
        for c in &self.0.commitments {
            out.extend_from_slice(&g1_to_bytes(c));
        }
        out
    }
    pub fn commitment_pok_bytes(&self) -> Vec<u8> {
        g1_to_bytes(&self.0.commitment_pok).to_vec()
    }
    pub fn nb_commitments(&self) -> usize {
        self.0.commitments.len()
    }
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }
}

/// Solve the witness and generate a Groth16+BSB22 proof in one shot. Bench
/// the two steps separately via `bench_solve` and `bench_prove` when wanting
/// finer-grained timing.
#[wasm_bindgen]
pub fn prove(r1cs: &R1CS, witness: &GnarkWitness, pk: &ProvingKey) -> Result<Proof, JsError> {
    let commitment_keys = if pk.0.commitment_keys.is_empty() {
        None
    } else {
        Some(pk.0.commitment_keys.as_slice())
    };
    let solved = crate::solve(&r1cs.0, &witness.0, commitment_keys).map_err(err)?;
    crate::prove(&r1cs.0, solved, &pk.0).map(Proof).map_err(err)
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
