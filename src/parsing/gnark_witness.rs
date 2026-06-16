//! ACIR circuit parsing.
use acir::AcirField;
use acir::FieldElement;
use acir::circuit::Program;
use acir::native_types::{Witness, WitnessStack};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::GnarkWitness;

use super::ParseError;

/// Witness vector laid out the way gnark expects: public values first
/// (matching the order of the outermost circuit's public parameters), then
/// every remaining circuit witness slot.
impl GnarkWitness {
    pub fn from_bytes(
        acir_json_bytes: &[u8],
        witness_stack_bytes: &[u8],
    ) -> Result<GnarkWitness, ParseError> {
        let program = parse_acir_program(acir_json_bytes)?;
        Self::from_program(program, witness_stack_bytes)
    }

    /// Build directly from the base64-encoded ACIR bytecode.
    pub fn from_bytecode(
        bytecode_b64: &str,
        witness_stack_bytes: &[u8],
    ) -> Result<GnarkWitness, ParseError> {
        let program = parse_acir_bytecode(bytecode_b64)?;
        Self::from_program(program, witness_stack_bytes)
    }

    fn from_program(
        program: Program<FieldElement>,
        witness_stack_bytes: &[u8],
    ) -> Result<GnarkWitness, ParseError> {
        let witness_stack = WitnessStack::<FieldElement>::deserialize(witness_stack_bytes)
            .map_err(|e| ParseError::Witness(format!("deserialize witness stack: {e}")))?;
        Self::get_witness(program, witness_stack)
    }

    /// Builds a gnark-compatible witness vector from a Noir witness stack.
    fn get_witness(
        program: Program<FieldElement>,
        witness_stack: WitnessStack<FieldElement>,
    ) -> Result<GnarkWitness, ParseError> {
        let mut stack = witness_stack;
        let mut items = Vec::with_capacity(stack.length());
        while let Some(item) = stack.pop() {
            items.push(item);
        }
        items.reverse();

        let outer = items
            .last()
            .ok_or_else(|| ParseError::Witness("witness stack is empty".into()))?;
        let outer_circuit = program.functions.get(outer.index as usize).ok_or_else(|| {
            ParseError::Acir(format!(
                "outermost stack references function {} but program has {} functions",
                outer.index,
                program.functions.len()
            ))
        })?;

        let mut public = Vec::with_capacity(outer_circuit.public_parameters.0.len());
        for witness in &outer_circuit.public_parameters.0 {
            let value = outer.witness.get(witness).ok_or_else(|| {
                ParseError::Witness(format!(
                    "public parameter {witness} missing from outermost witness map"
                ))
            })?;
            public.push(*value);
        }

        let mut private = Vec::new();
        let last_idx = items.len() - 1;
        for (i, item) in items.iter().enumerate() {
            let circuit = program.functions.get(item.index as usize).ok_or_else(|| {
                ParseError::Acir(format!(
                    "stack item references function {} but program has {} functions",
                    item.index,
                    program.functions.len()
                ))
            })?;
            let is_outer = i == last_idx;
            for j in 0..=circuit.current_witness_index {
                let w = Witness(j);
                if is_outer && outer_circuit.public_parameters.0.contains(&w) {
                    continue;
                }
                let value = item
                    .witness
                    .get(&w)
                    .copied()
                    .unwrap_or_else(FieldElement::zero);
                private.push(value);
            }
        }

        Ok(GnarkWitness { public, private })
    }
}

/// Decodes the base64 `bytecode` field of a Noir ACIR JSON artifact and
/// deserializes it into a typed [`Program`].
fn parse_acir_program(json_bytes: &[u8]) -> Result<Program<FieldElement>, ParseError> {
    let value: serde_json::Value = serde_json::from_slice(json_bytes)?;
    let bytecode = value
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError::Acir("missing bytecode".into()))?;
    parse_acir_bytecode(bytecode)
}

/// Base64-decode the bytecode field and deserialize it into a typed
/// [`Program`].
fn parse_acir_bytecode(bytecode: &str) -> Result<Program<FieldElement>, ParseError> {
    let bytecode = STANDARD.decode(bytecode)?;
    Program::<FieldElement>::deserialize_program(&bytecode)
        .map_err(|e| ParseError::Acir(format!("deserialize bytecode: {e}")))
}
