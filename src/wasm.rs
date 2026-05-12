//! `#[wasm_bindgen]` adapters. Pure-Rust
//! callers should reach for [`crate::types`] and the `from_bytes` methods on
//! those types directly; this module is only a thin shim across the wasm
//! boundary.

use acir::AcirField;
use wasm_bindgen::prelude::*;

use crate::types;

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
