use sunspot_wasm::{CommitmentInfo, SystemType};

use crate::r1cs;

#[test]
fn sum_a_b() {
    let r1cs = r1cs("sum_a_b");

    assert_eq!(r1cs.body.system_type, SystemType::R1cs);

    // Gnark prepends the implicit constant-1 wire as the first public entry,
    // followed by the circuit's declared public inputs (one for sum_a_b: z).
    // The pipeline drops Noir-level variable names, so assert shape only.
    assert_eq!(r1cs.body.public.first().map(String::as_str), Some("1"));
    assert_eq!(r1cs.body.public.len(), 2);
    assert_eq!(r1cs.body.secret.len(), 2);

    // `x + y == z` compiles to a single R1CS constraint.
    assert_eq!(r1cs.body.nb_constraints, 1);

    // No Pedersen commitments in this circuit.
    match &r1cs.body.commitment_info {
        CommitmentInfo::Groth16(v) => assert!(v.is_empty()),
        CommitmentInfo::Plonk(_) => panic!("unexpected Plonk commitments"),
    }

    // Coefficient table is non-empty and survives wrapper/section accounting.
    assert!(!r1cs.coefficients.is_empty());
    assert_eq!(r1cs.levels.count(), r1cs.levels.offsets.len() - 1);

    // Instructions table is internally consistent.
    assert!(!r1cs.instructions.is_empty());
}
