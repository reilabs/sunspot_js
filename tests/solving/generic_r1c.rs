use ark_bn254::Fr;
use ark_ff::One;

use sunspot_wasm::{solve, verify_witness};

use crate::{gnark_witness, r1cs};

/// Polynomial evaluation: `y = Σ coefficients[i] · xⁱ`.
#[test]
fn polynomial() {
    let r1cs = r1cs("polynomial");
    let partial = gnark_witness("polynomial");

    let full = solve(&r1cs, &partial).expect("solve");
    assert_eq!(full[0], Fr::one());
    assert_eq!(full[1], Fr::from(177u64));

    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}

/// Poseidon2 permutation: `hash == poseidon2_permutation(input, 4)`.
#[test]
fn poseidon2() {
    let r1cs = r1cs("poseidon2");
    let partial = gnark_witness("poseidon2");

    let full = solve(&r1cs, &partial).expect("solve");
    verify_witness(&r1cs, full.clone()).expect("Constraints satisfied");
}
