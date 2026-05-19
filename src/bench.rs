//! In-browser benching harness.
//!
//! Build:
//! ```text
//! wasm-pack build --release --target web --features bench
//! ```

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use std::hint::black_box;
use wasm_bindgen::prelude::*;

use crate::pedersen_commitments::fold;
use crate::solver::solve;
use crate::types;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn now_ms() -> f64 {
    web_sys::window()
        .expect("no `window`")
        .performance()
        .expect("no `performance`")
        .now()
}

/// Summary statistics for one bench, in milliseconds.
#[wasm_bindgen]
pub struct BenchResult {
    iterations: u32,
    /// Wall clock from before the first sample to after the last.
    total_ms: f64,
    min_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    max_ms: f64,
}

#[wasm_bindgen]
impl BenchResult {
    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }
    #[wasm_bindgen(getter)]
    pub fn total_ms(&self) -> f64 {
        self.total_ms
    }
    #[wasm_bindgen(getter)]
    pub fn min_ms(&self) -> f64 {
        self.min_ms
    }
    #[wasm_bindgen(getter)]
    pub fn median_ms(&self) -> f64 {
        self.median_ms
    }
    #[wasm_bindgen(getter)]
    pub fn mean_ms(&self) -> f64 {
        self.mean_ms
    }
    #[wasm_bindgen(getter)]
    pub fn max_ms(&self) -> f64 {
        self.max_ms
    }
}

fn run<R>(iterations: u32, mut body: impl FnMut() -> R) -> BenchResult {
    assert!(iterations > 0, "iterations must be > 0");
    let mut samples = Vec::with_capacity(iterations as usize);
    let start_total = now_ms();
    for _ in 0..iterations {
        let t0 = now_ms();
        let r = body();
        let t1 = now_ms();
        black_box(r);
        samples.push(t1 - t0);
    }
    let total_ms = now_ms() - start_total;
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let min_ms = samples[0];
    let max_ms = samples[n - 1];
    let mean_ms = samples.iter().sum::<f64>() / n as f64;
    let median_ms = if n.is_multiple_of(2) {
        (samples[n / 2 - 1] + samples[n / 2]) / 2.0
    } else {
        samples[n / 2]
    };
    BenchResult {
        iterations,
        total_ms,
        min_ms,
        median_ms,
        mean_ms,
        max_ms,
    }
}

#[wasm_bindgen]
pub fn bench_parse_r1cs(bytes: &[u8], iterations: u32) -> Result<BenchResult, JsError> {
    // Validate inputs once before entering the timed loop.
    types::R1CS::from_bytes(bytes).map_err(err)?;
    Ok(run(iterations, || {
        types::R1CS::from_bytes(black_box(bytes)).unwrap()
    }))
}

#[wasm_bindgen]
pub fn bench_parse_proving_key(bytes: &[u8], iterations: u32) -> Result<BenchResult, JsError> {
    types::ProvingKey::from_bytes(bytes).map_err(err)?;
    Ok(run(iterations, || {
        types::ProvingKey::from_bytes(black_box(bytes)).unwrap()
    }))
}

#[wasm_bindgen]
pub fn bench_parse_gnark_witness(
    acir_json: &[u8],
    witness_stack: &[u8],
    iterations: u32,
) -> Result<BenchResult, JsError> {
    types::GnarkWitness::from_bytes(acir_json, witness_stack).map_err(err)?;
    Ok(run(iterations, || {
        types::GnarkWitness::from_bytes(black_box(acir_json), black_box(witness_stack)).unwrap()
    }))
}

/// Bench `solve` — partial witness → full witness extension, including the
/// per-constraint A·B=C checks the blueprint solver performs along the way.
/// R1CS and partial witness are parsed once outside the timed loop so only
/// the solve itself is measured. `pk_bytes` is required for circuits whose
/// hints depend on the Pedersen commitment keys (e.g. BSB22) and may be
/// omitted for algebraic-only circuits.
#[wasm_bindgen]
pub fn bench_solve(
    ccs_bytes: &[u8],
    acir_json: &[u8],
    witness_stack: &[u8],
    pk_bytes: Option<Vec<u8>>,
    iterations: u32,
) -> Result<BenchResult, JsError> {
    let r1cs = types::R1CS::from_bytes(ccs_bytes).map_err(err)?;
    let witness = types::GnarkWitness::from_bytes(acir_json, witness_stack).map_err(err)?;
    let pk = pk_bytes
        .as_deref()
        .map(types::ProvingKey::from_bytes)
        .transpose()
        .map_err(err)?;
    let commitment_keys = pk.as_ref().map(|p| p.commitment_keys.as_slice());
    solve(&r1cs, &witness, commitment_keys).map_err(err)?;
    Ok(run(iterations, || {
        solve(
            black_box(&r1cs),
            black_box(&witness),
            black_box(commitment_keys),
        )
        .unwrap()
    }))
}

/// Bench `PedersenProvingKey::commit` summed across every commitment key in
/// the PK. Values are deterministic synthetic scalars (`Fr::from(i + 1)`).
/// Returns `None` for algebraic-only circuits (no commitment keys).
#[wasm_bindgen]
pub fn bench_pedersen_commit(
    pk_bytes: &[u8],
    iterations: u32,
) -> Result<Option<BenchResult>, JsError> {
    let pk = types::ProvingKey::from_bytes(pk_bytes).map_err(err)?;
    if pk.commitment_keys.is_empty() {
        return Ok(None);
    }
    let inputs = pedersen_inputs(&pk);
    Ok(Some(run(iterations, || {
        let mut acc = G1Projective::zero();
        for (key, values) in &inputs {
            acc += key.commit(values).unwrap();
        }
        acc.into_affine()
    })))
}

/// Bench `PedersenProvingKey::prove_knowledge` across every commitment key.
/// Returns `None` for algebraic-only circuits (no commitment keys).
#[wasm_bindgen]
pub fn bench_pedersen_prove_knowledge(
    pk_bytes: &[u8],
    iterations: u32,
) -> Result<Option<BenchResult>, JsError> {
    let pk = types::ProvingKey::from_bytes(pk_bytes).map_err(err)?;
    if pk.commitment_keys.is_empty() {
        return Ok(None);
    }
    let inputs = pedersen_inputs(&pk);
    Ok(Some(run(iterations, || {
        let mut acc = G1Projective::zero();
        for (key, values) in &inputs {
            acc += key.prove_knowledge(values).unwrap();
        }
        acc.into_affine()
    })))
}

/// Bench `fold` on a synthetic vector of `num_points` distinct G1 points.
#[wasm_bindgen]
pub fn bench_fold(num_points: u32, iterations: u32) -> Result<BenchResult, JsError> {
    if num_points == 0 {
        return Err(JsError::new("num_points must be > 0"));
    }
    let g = G1Affine::generator();
    let points: Vec<G1Affine> = (1..=num_points as u64)
        .map(|i| (g * Fr::from(i)).into_affine())
        .collect();
    let coeff = Fr::from(7u64);
    Ok(run(iterations, || fold(black_box(&points), coeff)))
}

fn pedersen_inputs(pk: &types::ProvingKey) -> Vec<(&types::PedersenProvingKey, Vec<Fr>)> {
    pk.commitment_keys
        .iter()
        .map(|key| {
            let mut x = Fr::one();
            let values: Vec<Fr> = (0..key.basis.len())
                .map(|_| {
                    let v = x;
                    x += Fr::one();
                    v
                })
                .collect();
            (key, values)
        })
        .collect()
}
