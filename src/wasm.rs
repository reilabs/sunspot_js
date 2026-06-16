//! `#[wasm_bindgen]` adapters. Pure-Rust
//! callers should reach for [`crate::types`] and the `from_bytes` methods on
//! those types directly; this module is only a thin shim across the wasm
//! boundary.
//!
//! Threading: JS must call `initThreadPool(navigator.hardwareConcurrency)`
//! after `init()` and before invoking the solver. The host page must be
//! cross-origin isolated (`COOP: same-origin`, `COEP: require-corp`) for
//! `SharedArrayBuffer` to be available.

use crate::curve::{G1Affine, G2Affine};
use acir::AcirField;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys::{Reflect, Uint8Array};

use crate::types;

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub struct Witness(types::GnarkWitness);

#[wasm_bindgen]
impl Witness {
    /// Build the gnark-ordered witness vector from ACIR bytecode
    /// and a gzipped witness-stack (`*.gz`) blob.
    #[wasm_bindgen(constructor)]
    pub fn new(bytecode: &str, witness_stack_bytes: &[u8]) -> Result<Witness, JsError> {
        types::GnarkWitness::from_bytecode(bytecode, witness_stack_bytes)
            .map(Witness)
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
        types::ProvingKey::from_bytes_checked(bytes)
            .map(ProvingKey)
            .map_err(err)
    }

    pub fn new_unchecked(bytes: &[u8]) -> Result<ProvingKey, JsError> {
        types::ProvingKey::from_bytes_unchecked(bytes)
            .map(ProvingKey)
            .map_err(err)
    }

    /// Stream-parse a proving key directly from a `fetch()` response.
    pub async fn from_response(res: web_sys::Response) -> Result<ProvingKey, JsError> {
        from_response_streaming(res, true).await
    }

    /// Same as [`Self::from_response`] but skips on-curve checks. Only safe
    /// for trusted keys.
    pub async fn from_response_unchecked(res: web_sys::Response) -> Result<ProvingKey, JsError> {
        from_response_streaming(res, false).await
    }
}

async fn from_response_streaming(
    res: web_sys::Response,
    check_points: bool,
) -> Result<ProvingKey, JsError> {
    if !res.ok() {
        return Err(JsError::new(&format!(
            "fetch failed: {} {}",
            res.status(),
            res.status_text()
        )));
    }
    let body = res
        .body()
        .ok_or_else(|| JsError::new("response has no body to stream"))?;
    let reader: web_sys::ReadableStreamDefaultReader = body
        .get_reader()
        .dyn_into()
        .map_err(|_| JsError::new("expected default reader from response body"))?;

    let mut parser = types::ProvingKey::streaming_parser(check_points);
    let mut buf: Vec<u8> = Vec::new();
    while let Some(arr) = next_chunk(&reader).await? {
        let len = arr.length() as usize;
        buf.resize(len, 0);
        arr.copy_to(&mut buf);
        parser.feed(&buf).map_err(err)?;
    }
    parser.finish().map(ProvingKey).map_err(err)
}

async fn next_chunk(
    reader: &web_sys::ReadableStreamDefaultReader,
) -> Result<Option<Uint8Array>, JsError> {
    let result = JsFuture::from(reader.read()).await.map_err(jserr)?;
    let done = Reflect::get(&result, &JsValue::from_str("done"))
        .map_err(jserr)?
        .as_bool()
        .ok_or_else(|| JsError::new("stream read result missing boolean `done` field"))?;
    if done {
        return Ok(None);
    }
    let value = Reflect::get(&result, &JsValue::from_str("value")).map_err(jserr)?;
    value
        .dyn_into::<Uint8Array>()
        .map(Some)
        .map_err(|_| JsError::new("stream chunk was not a Uint8Array"))
}

fn jserr(v: JsValue) -> JsError {
    JsError::new(&v.as_string().unwrap_or_else(|| format!("{v:?}")))
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

    /// Full proof in gnark's `WriteRawTo` wire format — round-trips with
    /// gnark's `Proof.ReadFrom`. Layout:
    /// `ar(64) || bs(128) || krs(64) || u32_be(n) || commitments(n*64) || pok(64)`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let n = self.0.commitments.len();
        let mut out = Vec::with_capacity(324 + 64 * n);
        out.extend_from_slice(&g1_to_bytes(&self.0.ar));
        out.extend_from_slice(&g2_to_bytes(&self.0.bs));
        out.extend_from_slice(&g1_to_bytes(&self.0.krs));
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for c in &self.0.commitments {
            out.extend_from_slice(&g1_to_bytes(c));
        }
        out.extend_from_slice(&g1_to_bytes(&self.0.commitment_pok));
        out
    }
}

/// Solve the witness and generate a Groth16+BSB22 proof in one shot. Bench
/// the two steps separately via `bench_solve` and `bench_prove` when wanting
/// finer-grained timing.
#[wasm_bindgen]
pub fn prove(r1cs: &R1CS, witness: &Witness, pk: &ProvingKey) -> Result<Proof, JsError> {
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
